// Byte-exactness regression against the LOCKED byte anchor:
//
//	docs/fixtures/update_distribution/vectors.json (Ireoo/Secret-Chat).
//
// Proves this CI signer's canonicalBytes() reproduces each vector's `canonical`
// byte-for-byte, and that signing with the fixture seed reproduces each `sig` —
// i.e. the signer agrees with the chatserver verifier and all client verifiers.
//
// In a standalone schat.build checkout the fixtures don't exist (they live in the
// source repo), so the test SKIPS gracefully; it runs for real in the combined
// working tree (submodule embedded next to docs/).
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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
