package keys

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mikrotikpatch/internal/mikro"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func TestGenerateLicenseKey(t *testing.T) {
	ks, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(ks.LicensePrivate) != 64 {
		t.Errorf("license private length = %d, want 64 hex chars", len(ks.LicensePrivate))
	}
	if len(ks.LicensePublic) != 64 {
		t.Errorf("license public length = %d, want 64 hex chars", len(ks.LicensePublic))
	}

	d := mikro.BigFromLE(mustHex(t, ks.LicensePrivate))
	if d.Sign() <= 0 || d.Cmp(mikro.CurveN) >= 0 {
		t.Errorf("license scalar not in [1, n-1]: %s", d.Text(16))
	}

	point := mikro.CurveScalarMult(d, mikro.CurveG)
	if point == nil || point.Inf {
		t.Fatal("d*G is the point at infinity")
	}
	// The device reconstructs the public point with the even-y convention.
	if point.Y.Bit(0) != 0 {
		t.Error("d*G has odd y; a device would reconstruct a different point")
	}
	if got := hex.EncodeToString(mikro.LEBytes(point.X, 32)); got != ks.LicensePublic {
		t.Errorf("license public = %s, want d*G.x = %s", ks.LicensePublic, got)
	}

	// The same test through the helper that mirrors keygen.py's key derivation.
	base := mikro.CurveScalarBaseMult(d)
	if base == nil || base.Inf || hex.EncodeToString(mikro.LEBytes(base.X, 32)) != ks.LicensePublic {
		t.Error("CurveScalarBaseMult(d).x does not match the license public key")
	}
}

func TestGenerateEd25519Keys(t *testing.T) {
	ks, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	npkSeed := mustHex(t, ks.NPKSignPrivate)
	if len(npkSeed) != 32 {
		t.Fatalf("NPK sign private = %d bytes, want 32", len(npkSeed))
	}
	npkPub := mustHex(t, ks.NPKSignPublic)
	if len(npkPub) != 32 {
		t.Fatalf("NPK sign public = %d bytes, want 32", len(npkPub))
	}
	if got := mikro.EdDSAPublicFromSeed(npkSeed); !bytes.Equal(got, npkPub) {
		t.Errorf("NPK sign public = %x, want %x", got, npkPub)
	}

	cloudSeed := mustHex(t, ks.CloudPrivate)
	if len(cloudSeed) != 32 {
		t.Fatalf("cloud private = %d bytes, want 32", len(cloudSeed))
	}
	der, err := base64.StdEncoding.DecodeString(ks.CloudPublic)
	if err != nil {
		t.Fatalf("cloud public is not std base64: %v", err)
	}
	wantPrefix := []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}
	if !bytes.HasPrefix(der, wantPrefix) {
		t.Errorf("cloud SPKI prefix = %x, want %x", der[:min(len(der), len(wantPrefix))], wantPrefix)
	}
	if len(der) != len(wantPrefix)+32 {
		t.Fatalf("cloud SPKI length = %d, want %d", len(der), len(wantPrefix)+32)
	}
	if got := mikro.EdDSAPublicFromSeed(cloudSeed); !bytes.Equal(der[len(wantPrefix):], got) {
		t.Errorf("cloud SPKI payload = %x, want %x", der[len(wantPrefix):], got)
	}
}

func TestGenerateIsRandom(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if a.LicensePrivate == b.LicensePrivate || a.NPKSignPrivate == b.NPKSignPrivate || a.CloudPrivate == b.CloudPrivate {
		t.Error("two Generate calls produced the same secret material")
	}
}

func TestWriteEnvFile(t *testing.T) {
	ks, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	path := filepath.Join(t.TempDir(), "keys.env")
	if err := WriteEnvFile(path, ks); err != nil {
		t.Fatalf("WriteEnvFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 600", perm)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.HasSuffix(raw, []byte("\n")) {
		t.Error("file does not end with a newline")
	}

	wantOrder := []string{
		"CUSTOM_LICENSE_PRIVATE_KEY",
		"CUSTOM_LICENSE_PUBLIC_KEY",
		"MIKRO_LICENSE_PUBLIC_KEY",
		"CUSTOM_NPK_SIGN_PRIVATE_KEY",
		"CUSTOM_NPK_SIGN_PUBLIC_KEY",
		"MIKRO_NPK_SIGN_PUBLIC_KEY",
		"CUSTOM_CLOUD_PUBLIC_KEY",
		"MIKRO_CLOUD_PUBLIC_KEY",
		"MIKRO_LICENCE_URL",
		"MIKRO_UPGRADE_URL",
		"MIKRO_CLOUD_URL",
		"MIKRO_CLOUD2_URL",
		"CUSTOM_LICENCE_URL",
		"CUSTOM_UPGRADE_URL",
		"CUSTOM_CLOUD_URL",
		"CUSTOM_CLOUD2_URL",
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != len(wantOrder) {
		t.Fatalf("file has %d lines, want %d", len(lines), len(wantOrder))
	}
	for i, key := range wantOrder {
		if !strings.HasPrefix(lines[i], key+"=") {
			t.Errorf("line %d = %q, want %s=...", i+1, lines[i], key)
		}
	}

	vars, err := LoadEnvFile(path)
	if err != nil {
		t.Fatalf("LoadEnvFile: %v", err)
	}
	if len(vars) != len(wantOrder) {
		t.Fatalf("loaded %d variables, want %d", len(vars), len(wantOrder))
	}

	want := map[string]string{
		"CUSTOM_LICENSE_PRIVATE_KEY":  ks.LicensePrivate,
		"CUSTOM_LICENSE_PUBLIC_KEY":   ks.LicensePublic,
		"MIKRO_LICENSE_PUBLIC_KEY":    MikroLicensePublicKey,
		"CUSTOM_NPK_SIGN_PRIVATE_KEY": ks.NPKSignPrivate,
		"CUSTOM_NPK_SIGN_PUBLIC_KEY":  ks.NPKSignPublic,
		"MIKRO_NPK_SIGN_PUBLIC_KEY":   MikroNPKSignPublicKey,
		"CUSTOM_CLOUD_PUBLIC_KEY":     ks.CloudPublic,
		"MIKRO_CLOUD_PUBLIC_KEY":      MikroCloudPublicKey,
		"MIKRO_LICENCE_URL":           "licence.mikrotik.com",
		"MIKRO_UPGRADE_URL":           "upgrade.mikrotik.com",
		"MIKRO_CLOUD_URL":             "cloud.mikrotik.com",
		"MIKRO_CLOUD2_URL":            "cloud2.mikrotik.com",
		"CUSTOM_LICENCE_URL":          "licence.mikr.invalid",
		"CUSTOM_UPGRADE_URL":          "upgrade.mikr.invalid",
		"CUSTOM_CLOUD_URL":            "cloud.mikr.invalid",
		"CUSTOM_CLOUD2_URL":           "cloud2.mikr.invalid",
	}
	for key, want := range want {
		if got := vars[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestLoadEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.env")
	content := "# leading comment\n" +
		"\n" +
		"  # indented comment\n" +
		"FOO=bar\n" +
		"export BAZ=qux\n" +
		"export\tTAB=tabbed\n" +
		"QUOTED=\"hello world\"\n" +
		"SINGLE='a=b c'\n" +
		"EMPTY=\n" +
		"SPACED =  padded  \n" +
		"DUP=first\n" +
		"DUP=second\n" +
		"exportFOO=notexported\n" +
		"URL=value#notacomment\n" +
		"CRLF=windows\r\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	vars, err := LoadEnvFile(path)
	if err != nil {
		t.Fatalf("LoadEnvFile: %v", err)
	}
	want := map[string]string{
		"FOO":       "bar",
		"BAZ":       "qux",
		"TAB":       "tabbed",
		"QUOTED":    "hello world",
		"SINGLE":    "a=b c",
		"EMPTY":     "",
		"SPACED":    "padded",
		"DUP":       "second",
		"exportFOO": "notexported",
		"URL":       "value#notacomment",
		"CRLF":      "windows",
	}
	if len(vars) != len(want) {
		t.Fatalf("got %d variables (%v), want %d", len(vars), vars, len(want))
	}
	for key, want := range want {
		if got := vars[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestLoadEnvFileErrors(t *testing.T) {
	if _, err := LoadEnvFile(filepath.Join(t.TempDir(), "missing.env")); err == nil {
		t.Error("LoadEnvFile on a missing file did not fail")
	}
	path := filepath.Join(t.TempDir(), "bad.env")
	if err := os.WriteFile(path, []byte("NOT_AN_ASSIGNMENT\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := LoadEnvFile(path); err == nil {
		t.Error("LoadEnvFile on a malformed line did not fail")
	}
}

func TestMergeEnv(t *testing.T) {
	file := map[string]string{
		"FOO": "from-file",
		"BAR": "from-file",
	}
	environ := []string{
		"FOO=from-env",
		"BAZ=from-env",
		"MALFORMED",
	}

	merged := MergeEnv(file, environ)
	if got := merged["FOO"]; got != "from-file" {
		t.Errorf("FOO = %q, want file value (file wins, like `set -a; . keys.env`)", got)
	}
	if got := merged["BAR"]; got != "from-file" {
		t.Errorf("BAR = %q, want %q", got, "from-file")
	}
	if got := merged["BAZ"]; got != "from-env" {
		t.Errorf("BAZ = %q, want %q", got, "from-env")
	}
	if _, ok := merged["MALFORMED"]; ok {
		t.Error("MALFORMED environ entry was merged")
	}
	if len(merged) != 3 {
		t.Errorf("merged has %d entries, want 3", len(merged))
	}
}
