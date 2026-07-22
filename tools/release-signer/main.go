// release-signer — Step 2 of the self-hosted update distribution channel.
//
// Contract: docs/update_distribution_plan.md (LOCKED 2026-07-22) in the source
// repo Ireoo/Secret-Chat. Byte anchor: docs/fixtures/update_distribution/vectors.json
// (generator tools/gen_vectors.go). This program's canonicalBytes() is a VERBATIM
// port of gen_vectors.go's canonicalBytes() so the CI signer, the chatserver
// upload re-verify, and the three client verifiers all agree byte-for-byte.
//
// What it does, over a flattened release-asset directory (dist/**):
//  1. maps each filename → (line, os, arch-KEY, format, version) per §6 of the plan
//     (parse "-qt-" BEFORE the generic "SChat-macos-" prefix; exclude
//     SChat-android-debug.apk / SChat-server-* / SChat-m5core2-*);
//  2. computes sha256, builds the §3.1 canonical bytes, Ed25519-signs with the
//     official private key from RELEASE_SIGN_ED25519_KEY;
//  3. POSTs each asset multipart to $UPDATE_UPLOAD_URL
//     (default https://jiami.chat/desktop/releases/upload) with a Bearer token;
//  4. writes a combined signed manifest JSON (decision #11) for the GitHub-release
//     mirror so the fallback path stays signature-verified.
//
// Uses ONLY the Go standard library (no go.sum, hermetic `go run .`).
//
// ⚠️ Per-line versions: each product line (macos / qt / android) has an INDEPENDENT
// version counter — a single release build carries e.g. macos 9.12.298, windows
// 9.12.231, linux 9.12.229, android 9.13.3 all at once. The authoritative version
// is therefore parsed FROM EACH FILENAME; -version is only a fallback for a file
// whose name has no x.y.z token, and the default label for the manifest.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// §3.1 canonical bytes — VERBATIM port of docs/fixtures/.../gen_vectors.go.
// Change here ⇒ change there ⇒ regenerate vectors.json. Do not "improve" it.
// ─────────────────────────────────────────────────────────────────────────────

// Asset is one manifest asset descriptor (the signed subset).
type Asset struct {
	Line        string `json:"-"`
	OS          string `json:"-"`
	Arch        string `json:"-"`
	Version     string `json:"-"`
	Channel     string `json:"-"`
	Format      string `json:"format"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"` // 64 lowercase hex
	URL         string `json:"url"`    // server-RELATIVE path (the SIGNED path)
	Mandatory   int    `json:"-"`      // 0 | 1
	MinVersion  string `json:"-"`      // "x.y.z" or ""
	PublishedAt int64  `json:"-"`      // epoch ms

	// derived / non-signed
	Name       string `json:"name"`
	BrowserURL string `json:"browser_download_url"`
	Sig        string `json:"sig"`
	SigKey     string `json:"sigKey"`

	// local
	path string `json:"-"`
}

// canonicalBytes builds the §3.1 signing input: the fixed field order, joined by
// LF (0x0A), NO trailing newline. Reference impl is gen_vectors.go; ported verbatim.
func canonicalBytes(a Asset) []byte {
	lines := []string{
		"schat-release/1",
		"line:" + a.Line,
		"os:" + a.OS,
		"arch:" + a.Arch,
		"version:" + a.Version,
		"channel:" + a.Channel,
		"format:" + a.Format,
		"size:" + strconv.FormatInt(a.Size, 10),
		"sha256:" + a.SHA256,
		"url:" + a.URL,
		"mandatory:" + strconv.Itoa(a.Mandatory),
		"minVersion:" + a.MinVersion,
		"publishedAt:" + strconv.FormatInt(a.PublishedAt, 10),
	}
	return []byte(strings.Join(lines, "\n"))
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ─────────────────────────────────────────────────────────────────────────────
// filename → (line, os, arch-KEY, format) mapping — §6 table.
// ─────────────────────────────────────────────────────────────────────────────

var versionRe = regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+`)

// classify maps a release asset filename to its (line, os, arch-KEY, format).
// ok=false ⇒ skip (server / android-debug / m5core2 / unknown).
// IMPORTANT: "-qt-" is parsed BEFORE the generic "SChat-macos-" prefix.
func classify(name string) (line, osTok, arch, format string, ok bool) {
	lower := strings.ToLower(name)
	switch {
	case name == "SChat-android-debug.apk":
		return "", "", "", "", false
	case strings.HasPrefix(name, "SChat-server-"):
		return "", "", "", "", false
	case strings.HasPrefix(name, "SChat-m5core2-"):
		return "", "", "", "", false

	// qt macOS universal — MUST precede the generic SChat-macos- case.
	case strings.HasPrefix(name, "SChat-macos-qt-"):
		switch filepath.Ext(lower) {
		case ".zip":
			return "qt", "mac", "universal", "zip", true
		case ".dmg":
			return "qt", "mac", "universal", "dmg", true
		}
		return "", "", "", "", false

	// native SwiftUI macOS (arm64).
	case strings.HasPrefix(name, "SChat-macos-"):
		switch filepath.Ext(lower) {
		case ".zip":
			return "macos", "mac", "arm64", "zip", true
		case ".dmg":
			return "macos", "mac", "arm64", "dmg", true
		}
		return "", "", "", "", false

	// qt Windows NSIS installer.
	case strings.HasPrefix(name, "SChat-windows-") && strings.HasSuffix(lower, "-setup.exe"):
		return "qt", "windows", "x64", "nsis-exe", true

	// qt Linux (.deb both arches + AppImage). arch key: amd64/x86_64 → x64, arm64/aarch64 → arm64.
	case strings.HasPrefix(name, "SChat-linux-"):
		switch {
		case strings.HasSuffix(lower, "-amd64.deb"):
			return "qt", "linux", "x64", "deb", true
		case strings.HasSuffix(lower, "-arm64.deb"), strings.HasSuffix(lower, "-aarch64.deb"):
			return "qt", "linux", "arm64", "deb", true
		case strings.HasSuffix(lower, "-x86_64.appimage"), strings.HasSuffix(lower, "-amd64.appimage"):
			return "qt", "linux", "x64", "appimage", true
		case strings.HasSuffix(lower, "-arm64.appimage"), strings.HasSuffix(lower, "-aarch64.appimage"):
			return "qt", "linux", "arm64", "appimage", true
		}
		return "", "", "", "", false

	// android release apk.
	case strings.HasPrefix(name, "SChat-android-release-") && strings.HasSuffix(lower, ".apk"):
		return "android", "android", "universal", "apk", true
	}
	return "", "", "", "", false
}

// ─────────────────────────────────────────────────────────────────────────────
// key loading — RELEASE_SIGN_ED25519_KEY = base64url no-pad (preferred) of either
// a 32-byte seed OR a 64-byte full Ed25519 private key. Tolerant fallbacks for the
// other common encodings so an operator can paste "the standard form".
// ─────────────────────────────────────────────────────────────────────────────

func loadPrivKey(s string) (ed25519.PrivateKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("RELEASE_SIGN_ED25519_KEY is empty")
	}
	var raw []byte
	for _, dec := range []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(s); err == nil && (len(b) == ed25519.SeedSize || len(b) == ed25519.PrivateKeySize) {
			raw = b
			break
		}
	}
	switch len(raw) {
	case ed25519.SeedSize: // 32
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize: // 64
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("key must decode to %d (seed) or %d (full) bytes; got %d (check base64url no-pad encoding)",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// sha256 of a file (streaming).
// ─────────────────────────────────────────────────────────────────────────────

func sha256File(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// upload one asset (multipart) to the release upload endpoint.
// ─────────────────────────────────────────────────────────────────────────────

func uploadAsset(client *http.Client, endpoint, token string, a Asset) error {
	f, err := os.Open(a.path)
	if err != nil {
		return err
	}
	defer f.Close()

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		var werr error
		defer func() { _ = pw.CloseWithError(werr) }()
		fields := [][2]string{
			// task-required set:
			{"line", a.Line}, {"os", a.OS}, {"arch", a.Arch},
			{"version", a.Version}, {"format", a.Format},
			{"sha256", a.SHA256}, {"sig", a.Sig}, {"sigKey", a.SigKey},
			{"channel", a.Channel},
			// needed so the server can reconstruct §3.1 canonical bytes and re-verify:
			{"publishedAt", strconv.FormatInt(a.PublishedAt, 10)},
			{"mandatory", strconv.Itoa(a.Mandatory)},
			{"minVersion", a.MinVersion},
		}
		for _, kv := range fields {
			if werr = mw.WriteField(kv[0], kv[1]); werr != nil {
				return
			}
		}
		var part io.Writer
		if part, werr = mw.CreateFormFile("file", a.Name); werr != nil {
			return
		}
		if _, werr = io.Copy(part, f); werr != nil {
			return
		}
		werr = mw.Close()
	}()

	req, err := http.NewRequest(http.MethodPost, endpoint, pr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// version comparison (x.y.z, numeric) for picking the newest per (line,os,arch).
// ─────────────────────────────────────────────────────────────────────────────

func verLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// combined manifest — an array of §1-shaped manifests (one per (line,os,arch)),
// each carrying only its newest version's assets. This is the GitHub-release
// fallback mirror (decision #11): every asset keeps its signed sha256/sig/url so
// a client verifies regardless of which host served the bytes.
// ─────────────────────────────────────────────────────────────────────────────

type lineManifest struct {
	Schema      int     `json:"schema"`
	Line        string  `json:"line"`
	OS          string  `json:"os"`
	Arch        string  `json:"arch"`
	Version     string  `json:"version"`
	TagName     string  `json:"tag_name"`
	Channel     string  `json:"channel"`
	Official    bool    `json:"official"`
	Mandatory   bool    `json:"mandatory"`
	MinVersion  *string `json:"minVersion"`
	PublishedAt int64   `json:"publishedAt"`
	Notes       string  `json:"notes"`
	Body        string  `json:"body"`
	Assets      []Asset `json:"assets"`
}

type combinedManifest struct {
	Schema      int            `json:"schema"`
	Channel     string         `json:"channel"`
	GeneratedAt int64          `json:"generatedAt"`
	Manifests   []lineManifest `json:"manifests"`
}

func main() {
	var (
		dir      = flag.String("dir", "dist", "flattened release-asset directory to walk")
		version  = flag.String("version", "", "fallback version for a filename lacking an x.y.z token (also the manifest label)")
		manifest = flag.String("manifest", "schat-update-manifest.json", "output path for the combined signed manifest JSON")
	)
	flag.Parse()

	channel := envOr("RELEASE_CHANNEL", "stable")
	sigKey := envOr("RELEASE_SIG_KEY", "official-current")
	notes := os.Getenv("RELEASE_NOTES")
	uploadURL := envOr("UPDATE_UPLOAD_URL", "https://jiami.chat/desktop/releases/upload")
	token := os.Getenv("RELEASE_UPLOAD_TOKEN")

	publishedAt := time.Now().UnixMilli()
	if s := strings.TrimSpace(os.Getenv("RELEASE_PUBLISHED_AT")); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			publishedAt = v
		}
	}

	priv, err := loadPrivKey(os.Getenv("RELEASE_SIGN_ED25519_KEY"))
	if err != nil {
		fatal("cannot load signing key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Printf("[release-signer] signing pubkey (b64url): %s\n", b64url(pub))
	fmt.Printf("[release-signer] publishedAt=%d channel=%s sigKey=%s uploadURL=%s\n",
		publishedAt, channel, sigKey, uploadURL)

	// 1. discover + classify assets.
	var assets []Asset
	err = filepath.WalkDir(*dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		line, osTok, arch, format, ok := classify(name)
		if !ok {
			return nil
		}
		ver := versionRe.FindString(name)
		if ver == "" {
			ver = *version
		}
		if ver == "" {
			fmt.Printf("[release-signer] SKIP %s (no version token and no -version fallback)\n", name)
			return nil
		}
		sum, size, err := sha256File(p)
		if err != nil {
			return fmt.Errorf("sha256 %s: %w", name, err)
		}
		url := fmt.Sprintf("/media/releases/%s/%s/%s/%s/%s", line, osTok, arch, ver, name)
		a := Asset{
			Line: line, OS: osTok, Arch: arch, Version: ver, Channel: channel,
			Format: format, Size: size, SHA256: sum, URL: url,
			Mandatory: 0, MinVersion: "", PublishedAt: publishedAt,
			Name: name, BrowserURL: "https://jiami.chat" + url, SigKey: sigKey,
			path: p,
		}
		a.Sig = b64url(ed25519.Sign(priv, canonicalBytes(a)))
		assets = append(assets, a)
		return nil
	})
	if err != nil {
		fatal("walk %s: %v", *dir, err)
	}
	if len(assets) == 0 {
		fmt.Printf("[release-signer] no signable desktop/android assets found under %s — nothing to do\n", *dir)
	}

	// 2. upload each asset (best-effort; one failure never aborts the run).
	uploaded, failed := 0, 0
	if token == "" {
		fmt.Printf("[release-signer] RELEASE_UPLOAD_TOKEN empty — skipping HTTP upload, writing manifest only\n")
	} else {
		client := &http.Client{Timeout: 20 * time.Minute}
		for _, a := range assets {
			if err := uploadAsset(client, uploadURL, token, a); err != nil {
				failed++
				fmt.Printf("[release-signer] UPLOAD FAIL %s → %s/%s/%s/%s: %v\n", a.Name, a.Line, a.OS, a.Arch, a.Format, err)
				continue
			}
			uploaded++
			fmt.Printf("[release-signer] uploaded %s → %s/%s/%s/%s v%s\n", a.Name, a.Line, a.OS, a.Arch, a.Format, a.Version)
		}
	}

	// 3. write the combined signed manifest for the GitHub-release mirror.
	cm := buildCombined(assets, channel, notes, publishedAt)
	buf, err := json.MarshalIndent(cm, "", "  ")
	if err != nil {
		fatal("marshal manifest: %v", err)
	}
	buf = append(buf, '\n')
	if err := os.WriteFile(*manifest, buf, 0o644); err != nil {
		fatal("write manifest %s: %v", *manifest, err)
	}
	fmt.Printf("[release-signer] wrote manifest %s (%d asset(s), %d group(s))\n", *manifest, len(assets), len(cm.Manifests))
	fmt.Printf("[release-signer] done: %d uploaded, %d failed, %d signed\n", uploaded, failed, len(assets))
}

// buildCombined groups signed assets by (line,os,arch), keeps only each group's
// newest version, and emits a §1-shaped manifest per group.
func buildCombined(assets []Asset, channel, notes string, publishedAt int64) combinedManifest {
	type key struct{ line, os, arch string }
	groups := map[key][]Asset{}
	for _, a := range assets {
		k := key{a.Line, a.OS, a.Arch}
		groups[k] = append(groups[k], a)
	}
	var out []lineManifest
	for k, list := range groups {
		newest := ""
		for _, a := range list {
			if newest == "" || verLess(newest, a.Version) {
				newest = a.Version
			}
		}
		var at []Asset
		for _, a := range list {
			if a.Version == newest {
				at = append(at, a)
			}
		}
		sort.Slice(at, func(i, j int) bool { return at[i].Format < at[j].Format })
		out = append(out, lineManifest{
			Schema: 1, Line: k.line, OS: k.os, Arch: k.arch,
			Version: newest, TagName: newest, Channel: channel,
			Official: true, Mandatory: false, MinVersion: nil,
			PublishedAt: publishedAt, Notes: notes, Body: notes,
			Assets: at,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		if out[i].OS != out[j].OS {
			return out[i].OS < out[j].OS
		}
		return out[i].Arch < out[j].Arch
	})
	return combinedManifest{Schema: 1, Channel: channel, GeneratedAt: publishedAt, Manifests: out}
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[release-signer] FATAL: "+format+"\n", a...)
	os.Exit(1)
}
