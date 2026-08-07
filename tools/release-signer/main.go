// release-signer — signs each release asset and maintains the **version index**.
//
// Contract: docs/update_index_refactor_plan.md (定稿 2026-08-07) in the source repo
// Ireoo/Secret-Chat, which supersedes the *取包链路* of docs/update_distribution_plan.md.
// The SIGNING contract (§3 of the old plan) is unchanged and still authoritative;
// byte anchor: docs/fixtures/update_distribution/vectors.json (generator
// tools/gen_vectors.go). This program's canonicalBytes() is a VERBATIM port of
// gen_vectors.go's canonicalBytes() so the CI signer and the three client verifiers
// all agree byte-for-byte.
//
// What it does, over a flattened release-asset directory (dist/**):
//  1. maps each filename → (line, os, arch-KEY, format, version) per the §6 table
//     (parse "-qt-" BEFORE the generic "SChat-macos-" prefix; exclude
//     SChat-android-debug.apk / SChat-server-* / SChat-m5core2-*);
//  2. computes sha256, builds the canonical bytes, Ed25519-signs with the official
//     private key from RELEASE_SIGN_ED25519_KEY;
//  3. writes the per-release combined manifest (`-manifest`) — this build, this
//     channel — which CI attaches to THIS GitHub release (老客户端的回退源);
//  4. fetches the existing version index from the fixed `version` tag, merges this
//     build's entries in by (line,os,arch,channel), and writes it back (`-index`)
//     + a stable-only schema-1 mirror (`-index-manifest`) for the same fixed tag.
//
// The self-hosted upload leg (jiami.chat) is RETIRED — clients now read the index
// off GitHub directly and pull bytes from the release assets.
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
// canonical bytes — VERBATIM port of docs/fixtures/.../gen_vectors.go.
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

// canonicalBytes builds the signing input: the fixed field order, joined by LF
// (0x0A), NO trailing newline. Reference impl is gen_vectors.go; ported verbatim.
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
// manifest shapes.
//
//	lineManifest    — one (line,os,arch[,channel]) group at one version.
//	combinedManifest— schema 1, single-channel: attached to THIS release; the
//	                  retired-but-still-read fallback for old clients.
//	versionIndex    — schema 2, ALL channels: the fixed `version` tag's version.json,
//	                  the only thing new clients read.
// ─────────────────────────────────────────────────────────────────────────────

type lineManifest struct {
	Schema      int     `json:"schema"`
	Line        string  `json:"line"`
	OS          string  `json:"os"`
	Arch        string  `json:"arch"`
	Version     string  `json:"version"`
	TagName     string  `json:"tag_name"` // = Version (alias; old parsers fall back to parseVer(tag_name))
	BuildTag    string  `json:"buildTag"` // the GitHub release tag the bytes live under (diagnostics)
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

type versionIndex struct {
	Schema      int            `json:"schema"`
	GeneratedAt int64          `json:"generatedAt"`
	Releases    []lineManifest `json:"releases"`
}

const (
	indexSchema    = 2
	indexTag       = "version"      // the FIXED tag the index lives under — never changes
	indexAssetName = "version.json" // the FIXED asset name
)

// ─────────────────────────────────────────────────────────────────────────────
// fetch the existing index off the fixed tag.
//
// Authenticated API first (authoritative + no CDN cache), public download URL as
// the fallback. A 404 (first ever run / asset missing) ⇒ empty index. ANY OTHER
// failure ⇒ fatal, deliberately: starting from an empty index would drop every
// (line,os,arch,channel) that this build didn't produce — i.e. a network hiccup
// would silently stop updates for whichever legs weren't built this run. Failing
// the (continue-on-error) step instead leaves the previous index in place, which
// is the safe direction.
// ─────────────────────────────────────────────────────────────────────────────

func fetchExistingIndex(client *http.Client, repo, token string) versionIndex {
	empty := versionIndex{Schema: indexSchema, Releases: nil}

	if token != "" {
		body, status, err := httpGet(client, fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", repo, indexTag),
			map[string]string{"Accept": "application/vnd.github+json", "Authorization": "Bearer " + token})
		switch {
		case err != nil:
			fatal("fetch index release (api): %v — refusing to publish an index built from nothing", err)
		case status == http.StatusNotFound:
			fmt.Printf("[release-signer] no `%s` release yet — starting a fresh index\n", indexTag)
			return empty
		case status != http.StatusOK:
			fatal("fetch index release (api): HTTP %d — refusing to publish an index built from nothing", status)
		}
		var rel struct {
			Assets []struct {
				Name string `json:"name"`
				URL  string `json:"url"` // API asset URL (octet-stream), not CDN
			} `json:"assets"`
		}
		if err := json.Unmarshal(body, &rel); err != nil {
			fatal("parse index release json: %v", err)
		}
		for _, a := range rel.Assets {
			if a.Name != indexAssetName {
				continue
			}
			raw, st, err := httpGet(client, a.URL,
				map[string]string{"Accept": "application/octet-stream", "Authorization": "Bearer " + token})
			if err != nil || st != http.StatusOK {
				fatal("download %s: err=%v status=%d — refusing to publish an index built from nothing", indexAssetName, err, st)
			}
			return parseIndex(raw)
		}
		fmt.Printf("[release-signer] `%s` release has no %s asset — starting a fresh index\n", indexTag, indexAssetName)
		return empty
	}

	// tokenless fallback (local runs): public CDN URL.
	raw, status, err := httpGet(client, fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repo, indexTag, indexAssetName), nil)
	switch {
	case err != nil:
		fatal("fetch %s: %v — refusing to publish an index built from nothing", indexAssetName, err)
	case status == http.StatusNotFound:
		fmt.Printf("[release-signer] %s not published yet — starting a fresh index\n", indexAssetName)
		return empty
	case status != http.StatusOK:
		fatal("fetch %s: HTTP %d — refusing to publish an index built from nothing", indexAssetName, status)
	}
	return parseIndex(raw)
}

func parseIndex(raw []byte) versionIndex {
	var idx versionIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		fatal("parse %s: %v — refusing to overwrite an index we cannot read", indexAssetName, err)
	}
	fmt.Printf("[release-signer] existing index: schema=%d entries=%d\n", idx.Schema, len(idx.Releases))
	return idx
}

func httpGet(client *http.Client, url string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "schat-release-signer")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// merge — entry key is (line, os, arch, channel).
//
// Rules (docs/update_index_refactor_plan.md §2.1 / §4.1):
//   - a four-tuple this build did NOT produce is kept verbatim (a Build All that
//     misses a leg must never erase that platform's update info);
//   - newer or EQUAL version ⇒ replace (equal covers channel promotion / rebuilds);
//   - OLDER version ⇒ skip + warn, unless force. The index is unsigned, so CI is
//     its only correctness gate — a stray run off an old branch must not walk
//     stable backwards.
// ─────────────────────────────────────────────────────────────────────────────

type entryKey struct{ line, os, arch, channel string }

func mergeIndex(existing []lineManifest, fresh []lineManifest, force bool) []lineManifest {
	byKey := map[entryKey]lineManifest{}
	var order []entryKey
	for _, e := range existing {
		k := entryKey{e.Line, e.OS, e.Arch, e.Channel}
		if _, seen := byKey[k]; !seen {
			order = append(order, k)
		}
		byKey[k] = e
	}
	for _, e := range fresh {
		k := entryKey{e.Line, e.OS, e.Arch, e.Channel}
		if old, ok := byKey[k]; ok {
			if verLess(e.Version, old.Version) && !force {
				fmt.Printf("[release-signer] ⚠️  SKIP %s/%s/%s [%s]: incoming v%s is OLDER than indexed v%s (set RELEASE_INDEX_FORCE=1 to override)\n",
					e.Line, e.OS, e.Arch, e.Channel, e.Version, old.Version)
				continue
			}
		} else {
			order = append(order, k)
		}
		byKey[k] = e
	}
	out := make([]lineManifest, 0, len(order))
	for _, k := range order {
		out = append(out, byKey[k])
	}
	sortManifests(out)
	return out
}

func sortManifests(m []lineManifest) {
	sort.Slice(m, func(i, j int) bool {
		if m[i].Line != m[j].Line {
			return m[i].Line < m[j].Line
		}
		if m[i].OS != m[j].OS {
			return m[i].OS < m[j].OS
		}
		if m[i].Arch != m[j].Arch {
			return m[i].Arch < m[j].Arch
		}
		return m[i].Channel < m[j].Channel
	})
}

// stableOnly is the schema-1 mirror attached NEXT TO the index on the fixed tag.
// It exists purely so an old client that lands on the `version` release (release
// list ordering is not something we control) still finds a valid signed manifest —
// and finds the STABLE one, never a prerelease.
func stableOnly(entries []lineManifest, generatedAt int64) combinedManifest {
	var out []lineManifest
	for _, e := range entries {
		if e.Channel == "stable" {
			out = append(out, e)
		}
	}
	return combinedManifest{Schema: 1, Channel: "stable", GeneratedAt: generatedAt, Manifests: out}
}

func main() {
	var (
		dir           = flag.String("dir", "dist", "flattened release-asset directory to walk")
		version       = flag.String("version", "", "fallback version for a filename lacking an x.y.z token (also the manifest label)")
		manifest      = flag.String("manifest", "schat-update-manifest.json", "output path for THIS release's combined signed manifest")
		indexOut      = flag.String("index", "version.json", "output path for the merged version index (fixed `version` tag)")
		indexMirror   = flag.String("index-manifest", "", "output path for the stable-only schema-1 mirror that ships next to the index (empty = skip)")
		skipIndexFlag = flag.Bool("no-index", false, "skip fetching/writing the version index (local dry runs)")
	)
	flag.Parse()

	channel := envOr("RELEASE_CHANNEL", "stable")
	sigKey := envOr("RELEASE_SIG_KEY", "official-current")
	notes := os.Getenv("RELEASE_NOTES")
	repo := envOr("RELEASE_REPO", "integemjack/schat.build")
	// The GitHub release tag THIS build's assets live under — it is what every
	// browser_download_url is built from. Empty would silently produce an index
	// whose download links 404, so refuse to run.
	buildTag := strings.TrimSpace(os.Getenv("RELEASE_TAG"))
	force := isTruthy(os.Getenv("RELEASE_INDEX_FORCE"))

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
	if buildTag == "" {
		fatal("RELEASE_TAG is empty — every asset's browser_download_url is derived from it; refusing to emit dead download links")
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Printf("[release-signer] signing pubkey (b64url): %s\n", b64url(pub))
	fmt.Printf("[release-signer] publishedAt=%d channel=%s sigKey=%s repo=%s buildTag=%s\n",
		publishedAt, channel, sigKey, repo, buildTag)

	// 1. discover + classify + sign assets.
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
		// SIGNED, host-agnostic path. The self-hosted source it was minted for is
		// retired, but it stays in the canonical bytes verbatim — dropping it would
		// mean a new signing format across four implementations for zero gain.
		url := fmt.Sprintf("/media/releases/%s/%s/%s/%s/%s", line, osTok, arch, ver, name)
		a := Asset{
			Line: line, OS: osTok, Arch: arch, Version: ver, Channel: channel,
			Format: format, Size: size, SHA256: sum, URL: url,
			Mandatory: 0, MinVersion: "", PublishedAt: publishedAt,
			Name: name, BrowserURL: assetDownloadURL(repo, buildTag, name), SigKey: sigKey,
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

	// 2. THIS release's combined manifest (schema 1, this channel) — attached to
	//    this GitHub release; still the fallback source old clients read.
	fresh := buildGroups(assets, channel, notes, publishedAt, buildTag)
	cm := combinedManifest{Schema: 1, Channel: channel, GeneratedAt: publishedAt, Manifests: fresh}
	writeJSON(*manifest, cm)
	fmt.Printf("[release-signer] wrote manifest %s (%d asset(s), %d group(s))\n", *manifest, len(assets), len(cm.Manifests))

	// 3. the version index on the fixed tag: fetch → merge → write.
	if *skipIndexFlag {
		fmt.Printf("[release-signer] -no-index set — skipping the version index\n")
		return
	}
	client := &http.Client{Timeout: 60 * time.Second}
	existing := fetchExistingIndex(client, repo, strings.TrimSpace(os.Getenv("GITHUB_TOKEN")))
	merged := mergeIndex(existing.Releases, fresh, force)
	writeJSON(*indexOut, versionIndex{Schema: indexSchema, GeneratedAt: publishedAt, Releases: merged})
	fmt.Printf("[release-signer] wrote index %s (%d entries)\n", *indexOut, len(merged))
	for _, e := range merged {
		fmt.Printf("[release-signer]   %-7s %-7s %-9s [%-6s] v%-12s %d asset(s) @ %s\n",
			e.Line, e.OS, e.Arch, e.Channel, e.Version, len(e.Assets), e.BuildTag)
	}
	if *indexMirror != "" {
		if err := os.MkdirAll(filepath.Dir(*indexMirror), 0o755); err != nil {
			fatal("mkdir for %s: %v", *indexMirror, err)
		}
		mirror := stableOnly(merged, publishedAt)
		writeJSON(*indexMirror, mirror)
		fmt.Printf("[release-signer] wrote index mirror %s (%d stable group(s))\n", *indexMirror, len(mirror.Manifests))
	}
}

// assetDownloadURL is the public GitHub release asset direct link — a CDN path,
// NOT api.github.com, so it is not subject to the 60/hour unauthenticated limit.
func assetDownloadURL(repo, tag, name string) string {
	return fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repo, tag, name)
}

// buildGroups groups signed assets by (line,os,arch), keeps only each group's
// newest version, and emits one manifest entry per group. Every asset keeps its
// signed sha256/sig/url so a client verifies regardless of which host served the bytes.
func buildGroups(assets []Asset, channel, notes string, publishedAt int64, buildTag string) []lineManifest {
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
			Version: newest, TagName: newest, BuildTag: buildTag, Channel: channel,
			Official: true, Mandatory: false, MinVersion: nil,
			PublishedAt: publishedAt, Notes: notes, Body: notes,
			Assets: at,
		})
	}
	sortManifests(out)
	return out
}

func writeJSON(path string, v any) {
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal("marshal %s: %v", path, err)
	}
	buf = append(buf, '\n')
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		fatal("write %s: %v", path, err)
	}
}

func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
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
