// Byte-exactness regression against the LOCKED byte anchor:
//
//	docs/fixtures/update_distribution/vectors.json (Ireoo/Secret-Chat).
//
// Proves this CI signer's canonicalBytes() reproduces each vector's `canonical`
// byte-for-byte, and that signing with the fixture seed reproduces each `sig` —
// i.e. the signer agrees with all client verifiers.
//
// In a standalone schat.build checkout the fixtures don't exist (they live in the
// source repo), so that test SKIPS gracefully; it runs for real in the combined
// working tree (submodule embedded next to docs/).
//
// The rest of the file guards the version-index behaviour
// (docs/update_index_refactor_plan.md §2.1 / §4.1).
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fixtureVector struct {
	Descriptor struct {
		Line        string
		OS          string
		Arch        string
		Version     string
		Channel     string
		Format      string
		Size        int64
		SHA256      string
		URL         string
		Mandatory   int
		MinVersion  string
		PublishedAt int64
	} `json:"descriptor"`
	Canonical    string `json:"canonical"`
	CanonicalHex string `json:"canonicalHex"`
	Sig          string `json:"sig"`
}

type fixtureFile struct {
	SeedHex         string          `json:"seedHex"`
	PublicKeyB64Url string          `json:"publicKeyB64Url"`
	Vectors         []fixtureVector `json:"vectors"`
}

func locateVectors(t *testing.T) string {
	_, thisFile, _, _ := runtime.Caller(0)
	base := filepath.Dir(thisFile) // …/schat.build/tools/release-signer
	candidates := []string{
		// combined working tree: repo-root/docs/... (three levels up from this dir)
		filepath.Join(base, "..", "..", "..", "docs", "fixtures", "update_distribution", "vectors.json"),
		// env override
		os.Getenv("UPDATE_VECTORS_JSON"),
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func TestCanonicalAndSigMatchFixtures(t *testing.T) {
	path := locateVectors(t)
	if path == "" {
		t.Skip("vectors.json not found (standalone CI checkout has no docs/fixtures) — set UPDATE_VECTORS_JSON to run")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var ff fixtureFile
	if err := json.Unmarshal(raw, &ff); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	seed, err := hex.DecodeString(ff.SeedHex)
	if err != nil {
		t.Fatalf("bad seedHex: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	wantPub := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if wantPub != ff.PublicKeyB64Url {
		t.Fatalf("fixture pubkey mismatch: derived %s vs file %s", wantPub, ff.PublicKeyB64Url)
	}
	if len(ff.Vectors) == 0 {
		t.Fatalf("no vectors in %s", path)
	}

	for _, v := range ff.Vectors {
		d := v.Descriptor
		a := Asset{
			Line: d.Line, OS: d.OS, Arch: d.Arch, Version: d.Version,
			Channel: d.Channel, Format: d.Format, Size: d.Size, SHA256: d.SHA256,
			URL: d.URL, Mandatory: d.Mandatory, MinVersion: d.MinVersion, PublishedAt: d.PublishedAt,
		}
		name := d.Line + "/" + d.OS + "/" + d.Arch + "/" + d.Format

		got := canonicalBytes(a)
		if string(got) != v.Canonical {
			t.Errorf("[%s] canonical string mismatch\n got: %q\nwant: %q", name, string(got), v.Canonical)
		}
		if hex.EncodeToString(got) != v.CanonicalHex {
			t.Errorf("[%s] canonicalHex mismatch\n got: %s\nwant: %s", name, hex.EncodeToString(got), v.CanonicalHex)
		}
		sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, got))
		if sig != v.Sig {
			t.Errorf("[%s] sig mismatch\n got: %s\nwant: %s", name, sig, v.Sig)
		}
		// belt-and-suspenders: the produced sig must verify against the fixture pubkey.
		pub, _ := base64.RawURLEncoding.DecodeString(ff.PublicKeyB64Url)
		rawSig, _ := base64.RawURLEncoding.DecodeString(sig)
		if !ed25519.Verify(pub, got, rawSig) {
			t.Errorf("[%s] sig failed Verify against fixture pubkey", name)
		}
	}
}

// Guards the §6 filename→(line,os,arch,format) mapping, incl. the "-qt- before
// SChat-macos-" ordering and the exclusions.
func TestClassifyMapping(t *testing.T) {
	type want struct {
		line, os, arch, format string
		ok                     bool
	}
	cases := map[string]want{
		"SChat-macos-9.12.358-arm64.zip":        {"macos", "mac", "arm64", "zip", true},
		"SChat-macos-9.12.358-arm64.dmg":        {"macos", "mac", "arm64", "dmg", true},
		"SChat-macos-qt-9.12.240-universal.zip": {"qt", "mac", "universal", "zip", true},
		"SChat-macos-qt-9.12.240-universal.dmg": {"qt", "mac", "universal", "dmg", true},
		"SChat-windows-9.12.273-x64-setup.exe":  {"qt", "windows", "x64", "nsis-exe", true},
		"SChat-linux-9.12.273-amd64.deb":        {"qt", "linux", "x64", "deb", true},
		"SChat-linux-9.12.273-x86_64.AppImage":  {"qt", "linux", "x64", "appimage", true},
		"SChat-linux-9.12.273-arm64.deb":        {"qt", "linux", "arm64", "deb", true},
		"SChat-android-release-9.13.5.apk":      {"android", "android", "universal", "apk", true},
		// exclusions:
		"SChat-android-debug.apk":       {ok: false},
		"SChat-server-linux-amd64":      {ok: false},
		"SChat-server-linux-arm64":      {ok: false},
		"SChat-m5core2-firmware.bin":    {ok: false},
		"schat-update-manifest.json":    {ok: false},
		"version.json":                  {ok: false},
		"SChat-macos-9.12.358-arm64.io": {ok: false}, // unknown ext
	}
	for name, w := range cases {
		line, osTok, arch, format, ok := classify(name)
		if ok != w.ok {
			t.Errorf("%s: ok=%v want %v", name, ok, w.ok)
			continue
		}
		if !ok {
			continue
		}
		if line != w.line || osTok != w.os || arch != w.arch || format != w.format {
			t.Errorf("%s: got %s/%s/%s/%s want %s/%s/%s/%s",
				name, line, osTok, arch, format, w.line, w.os, w.arch, w.format)
		}
	}
}

// The changelog is an UNSIGNED display mirror — it must never leak into the
// signed canonical bytes. (Regression from the era when `notes` was added to the
// upload multipart: the field is carried alongside the signature, never inside it.)
func TestNotesNeverEnterCanonicalBytes(t *testing.T) {
	a := Asset{
		Line: "qt", OS: "windows", Arch: "x64", Version: "9.12.999", Channel: "stable",
		Format: "nsis-exe", Size: 5, SHA256: "abc", URL: "/media/x",
		Name: "SChat-windows-9.12.999-x64-setup.exe", PublishedAt: 1700000000000,
	}
	if strings.Contains(string(canonicalBytes(a)), "更新内容") {
		t.Error("notes leaked into signed canonical bytes")
	}
	// `name` and `browser_download_url` are unsigned too — see the path-traversal
	// fix in update_distribution_plan.md §3.1 (on-disk name derives from `format`).
	a.BrowserURL = assetDownloadURL("integemjack/schat.build", "main-b190", a.Name)
	c := string(canonicalBytes(a))
	if strings.Contains(c, a.Name) || strings.Contains(c, "github.com") {
		t.Errorf("unsigned name/browser_download_url leaked into canonical bytes:\n%s", c)
	}
}

func TestAssetDownloadURL(t *testing.T) {
	const want = "https://github.com/integemjack/schat.build/releases/download/main-b190/SChat-windows-9.15.372-x64-setup.exe"
	got := assetDownloadURL("integemjack/schat.build", "main-b190", "SChat-windows-9.15.372-x64-setup.exe")
	if got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

func entry(line, osTok, arch, channel, version string) lineManifest {
	return lineManifest{
		Schema: 1, Line: line, OS: osTok, Arch: arch, Channel: channel,
		Version: version, TagName: version, BuildTag: "t-" + version,
	}
}

func find(t *testing.T, list []lineManifest, k entryKey) lineManifest {
	t.Helper()
	for _, e := range list {
		if (entryKey{e.Line, e.OS, e.Arch, e.Channel}) == k {
			return e
		}
	}
	t.Fatalf("entry %v not found in %d entries", k, len(list))
	return lineManifest{}
}

// The load-bearing merge property: a (line,os,arch,channel) that THIS build did
// not produce must survive verbatim. A Build All that misses a leg (the qt-mac
// universal leg has historically come and gone) would otherwise erase that
// platform's update info from the index and stop its users updating.
func TestMergeKeepsAbsentLegs(t *testing.T) {
	existing := []lineManifest{
		entry("qt", "mac", "universal", "stable", "9.15.300"),
		entry("qt", "windows", "x64", "stable", "9.15.300"),
		entry("android", "android", "universal", "beta", "9.15.29"),
	}
	fresh := []lineManifest{entry("qt", "windows", "x64", "stable", "9.15.372")}

	got := mergeIndex(existing, fresh, false)
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3 (absent legs must be preserved): %+v", len(got), got)
	}
	if v := find(t, got, entryKey{"qt", "mac", "universal", "stable"}).Version; v != "9.15.300" {
		t.Errorf("absent qt/mac leg: version %s, want untouched 9.15.300", v)
	}
	if v := find(t, got, entryKey{"android", "android", "universal", "beta"}).Version; v != "9.15.29" {
		t.Errorf("absent android beta leg: version %s, want untouched 9.15.29", v)
	}
	if v := find(t, got, entryKey{"qt", "windows", "x64", "stable"}).Version; v != "9.15.372" {
		t.Errorf("built leg: version %s, want 9.15.372", v)
	}
}

// stable and beta are SEPARATE entries — a beta build must never overwrite the
// stable row (that was the 2026-07/08 self-hosted-source incident in a new shape).
func TestMergeChannelsAreIndependent(t *testing.T) {
	existing := []lineManifest{entry("qt", "windows", "x64", "stable", "9.15.372")}
	fresh := []lineManifest{entry("qt", "windows", "x64", "beta", "9.16.5")}

	got := mergeIndex(existing, fresh, false)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2 (stable + beta side by side): %+v", len(got), got)
	}
	if v := find(t, got, entryKey{"qt", "windows", "x64", "stable"}).Version; v != "9.15.372" {
		t.Errorf("stable row was clobbered by the beta build: %s", v)
	}
	if v := find(t, got, entryKey{"qt", "windows", "x64", "beta"}).Version; v != "9.16.5" {
		t.Errorf("beta row: %s, want 9.16.5", v)
	}
}

// The index is unsigned, so CI is its only correctness gate: a stray Build All off
// an old branch must not walk a channel backwards. Equal versions DO replace
// (channel promotion / rebuild is a normal release-flow event).
func TestMergeVersionMonotonicity(t *testing.T) {
	existing := []lineManifest{entry("macos", "mac", "arm64", "stable", "9.15.409")}

	older := mergeIndex(existing, []lineManifest{entry("macos", "mac", "arm64", "stable", "9.15.100")}, false)
	if v := find(t, older, entryKey{"macos", "mac", "arm64", "stable"}).Version; v != "9.15.409" {
		t.Errorf("older build overwrote the index: %s, want 9.15.409", v)
	}

	forced := mergeIndex(existing, []lineManifest{entry("macos", "mac", "arm64", "stable", "9.15.100")}, true)
	if v := find(t, forced, entryKey{"macos", "mac", "arm64", "stable"}).Version; v != "9.15.100" {
		t.Errorf("RELEASE_INDEX_FORCE did not override: %s, want 9.15.100", v)
	}

	equal := mergeIndex(existing, []lineManifest{
		{Schema: 1, Line: "macos", OS: "mac", Arch: "arm64", Channel: "stable",
			Version: "9.15.409", TagName: "9.15.409", BuildTag: "main-b191"},
	}, false)
	if e := find(t, equal, entryKey{"macos", "mac", "arm64", "stable"}); e.BuildTag != "main-b191" {
		t.Errorf("equal version did not replace (channel promotion / rebuild): buildTag=%s", e.BuildTag)
	}

	newer := mergeIndex(existing, []lineManifest{entry("macos", "mac", "arm64", "stable", "9.16.1")}, false)
	if v := find(t, newer, entryKey{"macos", "mac", "arm64", "stable"}).Version; v != "9.16.1" {
		t.Errorf("newer build did not replace: %s, want 9.16.1", v)
	}
}

// Output ordering must be deterministic so a no-op run produces byte-identical JSON.
func TestMergeOutputIsSorted(t *testing.T) {
	got := mergeIndex(nil, []lineManifest{
		entry("qt", "windows", "x64", "stable", "1.0.0"),
		entry("android", "android", "universal", "stable", "1.0.0"),
		entry("qt", "linux", "x64", "stable", "1.0.0"),
		entry("qt", "windows", "x64", "beta", "1.0.1"),
		entry("macos", "mac", "arm64", "stable", "1.0.0"),
	}, false)
	var order []string
	for _, e := range got {
		order = append(order, e.Line+"/"+e.OS+"/"+e.Arch+"/"+e.Channel)
	}
	want := []string{
		"android/android/universal/stable",
		"macos/mac/arm64/stable",
		"qt/linux/x64/stable",
		"qt/windows/x64/beta",
		"qt/windows/x64/stable",
	}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("order:\n got %v\nwant %v", order, want)
	}
}

// The mirror that ships next to the index on the fixed `version` tag must contain
// ONLY stable — it exists so an old client that lands on that release gets a valid
// signed manifest, and it must never hand a prerelease to a stable user.
func TestStableOnlyMirror(t *testing.T) {
	m := stableOnly([]lineManifest{
		entry("qt", "windows", "x64", "stable", "9.15.372"),
		entry("qt", "windows", "x64", "beta", "9.16.5"),
		entry("android", "android", "universal", "beta", "9.16.1"),
	}, 1700000000000)
	if m.Schema != 1 || m.Channel != "stable" {
		t.Errorf("mirror header: schema=%d channel=%s, want 1/stable", m.Schema, m.Channel)
	}
	if len(m.Manifests) != 1 || m.Manifests[0].Channel != "stable" {
		t.Fatalf("mirror must contain exactly the stable entries, got %+v", m.Manifests)
	}
}

// buildGroups stamps the build tag on every group and keeps only the newest
// version's assets per (line,os,arch).
func TestBuildGroupsNewestPerGroupAndBuildTag(t *testing.T) {
	assets := []Asset{
		{Line: "qt", OS: "linux", Arch: "x64", Version: "9.15.372", Format: "deb", Name: "a.deb"},
		{Line: "qt", OS: "linux", Arch: "x64", Version: "9.15.372", Format: "appimage", Name: "a.AppImage"},
		{Line: "qt", OS: "linux", Arch: "x64", Version: "9.15.300", Format: "deb", Name: "old.deb"},
	}
	got := buildGroups(assets, "beta", "notes", 1700000000000, "v9.15-b7")
	if len(got) != 1 {
		t.Fatalf("want 1 group, got %d", len(got))
	}
	g := got[0]
	if g.Version != "9.15.372" || g.BuildTag != "v9.15-b7" || g.Channel != "beta" {
		t.Errorf("group: version=%s buildTag=%s channel=%s", g.Version, g.BuildTag, g.Channel)
	}
	if g.TagName != g.Version {
		t.Errorf("tag_name must stay the version alias (old parsers do parseVer(tag_name)): %s", g.TagName)
	}
	if len(g.Assets) != 2 {
		t.Errorf("want the 2 newest-version assets, got %d", len(g.Assets))
	}
	for _, a := range g.Assets {
		if a.Version == "9.15.300" {
			t.Error("stale-version asset leaked into the group")
		}
	}
}

// RELEASE_TAG is what every browser_download_url is built from. Empty must be a
// hard stop: an index full of dead download links looks perfectly healthy in CI
// and 404s for every user who presses 更新.
func TestMissingReleaseTagIsFatal(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles the package; skipped under -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain on PATH")
	}
	tmp := t.TempDir()
	cmd := exec.Command("go", "run", ".",
		"-dir", tmp, "-no-index",
		"-manifest", filepath.Join(tmp, "m.json"))
	cmd.Env = append(os.Environ(),
		"RELEASE_SIGN_ED25519_KEY="+base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"RELEASE_TAG=")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("empty RELEASE_TAG must fail the step; output:\n%s", out)
	}
	if !strings.Contains(string(out), "RELEASE_TAG") {
		t.Errorf("error message should name RELEASE_TAG; got:\n%s", out)
	}
}
