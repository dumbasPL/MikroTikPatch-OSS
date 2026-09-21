package keygen

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mikrotikpatch/internal/mikro"
)

const (
	sampleUUID       = "00112233-4455-6677-8899-aabbccddeeff"
	sampleSWIDHex    = "0011223344556677889973a000000000"
	chrSampleLicval  = "db4e0997ab453e0c005786f403000000"
	x86SampleSerial  = "ABCD-EFGH"
	x86SampleLicval  = "4c6305c09d0006160000000000000000"
	customPublicWord = "271501494893987a0a50d41dfc7500ffd4f7b32f455f2c0e7c7439d3bd7b0876"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

func stripANSI(s string) string {
	return strings.NewReplacer(CReset, "", CBlue, "", CCyan, "", CRed, "", CGreen, "").Replace(s)
}

// TestSelftest also pins the output to the reference implementation's.
func TestSelftest(t *testing.T) {
	var out bytes.Buffer
	if !Selftest(&out) {
		t.Fatalf("Selftest() = false:\n%s", out.String())
	}
	want := "  [ok] private key reproduces custom public key\n" +
		"  [ok] public key words match mode2\n" +
		"  [ok] software id checksum\n" +
		"  [ok] CHR licence value (sample)\n" +
		"  [ok] CHR System ID = b7UCXuaR+wA\n" +
		"  [ok] CHR empty-UUID uses 16 zero bytes\n" +
		"  [ok] licence sign/verify\n" +
		"  [ok] licence verifies on the device point\n" +
		"selftest: PASS\n"
	if out.String() != want {
		t.Errorf("Selftest output:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestCustomKeyPair(t *testing.T) {
	d := CustomPrivateKey()
	if got := d.Text(16); got != "bad10f55d25b46d50738ed9227342a0222800bcc15d9ef9f30d8fbfbaf4c735" {
		t.Errorf("CustomPrivateKey = %s", got)
	}
	pubx := CustomPublicKeyX()
	if got := pubx.Text(16); got != "76087bbdd339747c0e2c5f452fb3f7d4ff0075fc1dd4500a7a98934849011527" {
		t.Errorf("CustomPublicKeyX = %s", got)
	}
	if got := hex.EncodeToString(transformBlob(CustomKeyPublic)); got != customPublicWord {
		t.Errorf("public key words = %s, want %s", got, customPublicWord)
	}
	p := mikro.CurveScalarMult(d, mikro.CurveGKeygen)
	if p.Inf || p.X.Cmp(pubx) != 0 {
		t.Error("private key does not reproduce the custom public key")
	}
	if p.Y.Bit(0) != 1 {
		t.Error("d*G does not have the device's (odd) y")
	}
}

func TestParseUUID(t *testing.T) {
	cases := []struct{ text, want string }{
		{sampleUUID, "00112233445566778899aabbccddeeff"},
		{"", "00000000000000000000000000000000"},
		{"1122334455", "11223344550000000000000000000000"},
		{"00112233-4455-6677-8899-aabbccddeeff\n", "00112233445566778899aabbccddeeff"},
	}
	for _, tc := range cases {
		got := hex.EncodeToString(ParseUUID(tc.text))
		if got != tc.want {
			t.Errorf("ParseUUID(%q) = %s, want %s", tc.text, got, tc.want)
		}
	}
}

func TestSWID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		id, err := GenerateSWID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 16 {
			t.Fatalf("GenerateSWID returned %d bytes", len(id))
		}
		if !bytes.Equal(id[12:], make([]byte, 4)) {
			t.Errorf("GenerateSWID tail = %x, want zeros", id[12:])
		}
		if !SWIDValid(id) {
			t.Fatalf("SWIDValid rejected a generated id %x", id)
		}
		seen[string(id)] = true
	}
	if len(seen) < 2 {
		t.Error("GenerateSWID did not produce random ids")
	}

	id, _ := GenerateSWID()
	id[10]++ // flip the low checksum byte: the checksum only covers the first 10
	if SWIDValid(id) {
		t.Error("SWIDValid accepted a corrupted id")
	}
	if SWIDValid(id[:15]) {
		t.Error("SWIDValid accepted a short id")
	}
	if swidChecksum(mustHex(t, "00112233445566778899")) == 0 {
		t.Error("swidChecksum returned zero for a non-trivial input")
	}
}

func TestChrLicVal(t *testing.T) {
	swid := mustHex(t, sampleSWIDHex)
	lv := ChrLicVal(sampleUUID, swid)
	if got := hex.EncodeToString(lv); got != chrSampleLicval {
		t.Errorf("ChrLicVal = %s, want %s", got, chrSampleLicval)
	}
	if got := mikro.MTB64Encode(lv[:8], false); got != "b7UCXuaR+wA" {
		t.Errorf("System ID = %s, want b7UCXuaR+wA", got)
	}
	// An unreadable UUID behaves as 16 zero bytes.
	empty := ChrLicVal("", swid)
	zero := mikro.MTSHA256(append(make([]byte, 16), swid...))[:8]
	if !bytes.Equal(empty[:8], zero) {
		t.Errorf("ChrLicVal(\"\") = %x, want %x", empty, zero)
	}

	// The mode paths of run_generate.
	cfg := make([]byte, ConfigSize)
	cfg[OffMode] = 1
	copy(cfg[OffSWID:], swid)
	got, systemID, err := LicenceValueFromConfig(cfg, sampleUUID, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, lv) || systemID != "b7UCXuaR+wA" {
		t.Errorf("LicenceValueFromConfig(chr) = %x, %q", got, systemID)
	}
	cfg[OffMode] = 0
	got, systemID, err = LicenceValueFromConfig(cfg, sampleUUID, x86SampleSerial)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != x86SampleLicval || systemID != x86SampleSerial {
		t.Errorf("LicenceValueFromConfig(x86) = %x, %q", got, systemID)
	}
}

func TestX86LicVal(t *testing.T) {
	lv, err := X86LicVal(x86SampleSerial)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(lv); got != x86SampleLicval {
		t.Errorf("X86LicVal(%q) = %s, want %s", x86SampleSerial, got, x86SampleLicval)
	}
	empty, err := X86LicVal("")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(empty); got != "00000000000006160000000000000000" {
		t.Errorf("X86LicVal(\"\") = %s", got)
	}
	if _, err := X86LicVal("abcd-efgh"); err == nil {
		t.Error("X86LicVal accepted a lowercase serial")
	}
	if _, err := X86LicVal(strings.Repeat("A", 16)); err == nil {
		t.Error("X86LicVal accepted a serial that does not fit in 6 bytes")
	}
}

func TestMakeParseLicense(t *testing.T) {
	lv := mustHex(t, chrSampleLicval)
	text, err := MakeLicense(lv)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) != 4 || lines[0] != LicHeader || lines[3] != LicFooter {
		t.Fatalf("MakeLicense frame = %q", lines)
	}
	if len(lines[1]) != 44 || len(lines[2]) != 44 {
		t.Errorf("MakeLicense body lengths = %d, %d, want 44, 44", len(lines[1]), len(lines[2]))
	}

	parsed, witness, sig := ParseLicense(text)
	if !bytes.Equal(parsed, lv) {
		t.Errorf("ParseLicense licval = %x, want %x", parsed, lv)
	}
	if len(witness) != 16 || len(sig) != 32 {
		t.Fatalf("ParseLicense witness/sig = %d/%d bytes", len(witness), len(sig))
	}
	full := append(append([]byte{}, witness...), sig...)
	pubx := mikro.LEBytes(CustomPublicKeyX(), 32)
	if !mikro.KCDSAVerifyKeygen(lv, full, pubx) {
		t.Error("keygen verifier rejected a fresh licence")
	}
	if !mikro.KCDSAVerifyDevice(lv, full, pubx) {
		t.Error("device verifier rejected a fresh licence")
	}

	// Bare base64 body parses the same way.
	bare := strings.Join(lines[1:3], "\n")
	if parsed, _, _ := ParseLicense(bare); !bytes.Equal(parsed, lv) {
		t.Errorf("ParseLicense(bare) = %x, want %x", parsed, lv)
	}
	if lv, w, s := ParseLicense(""); lv != nil || w != nil || s != nil {
		t.Error("ParseLicense(\"\") did not return nils")
	}
	if _, err := SignLicVal(make([]byte, 15)); err == nil {
		t.Error("SignLicVal accepted a short licence value")
	}
}

// setupDevice points KEYGEN_FLASH at a missing path and KEYGEN_DISK at a fresh
// 512-byte file, returning the disk path.
func setupDevice(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	disk := filepath.Join(dir, "root-disk")
	if err := os.WriteFile(disk, make([]byte, ConfigSize), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYGEN_FLASH", filepath.Join(dir, "missing-flash"))
	t.Setenv("KEYGEN_DISK", disk)
	return disk
}

func TestConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	disk := filepath.Join(dir, "root-disk")
	flash := filepath.Join(dir, "flash")
	if err := os.WriteFile(disk, make([]byte, ConfigSize), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(flash, []byte("not a config"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYGEN_FLASH", flash) // regular file: the ioctl fails, so the disk is used
	t.Setenv("KEYGEN_DISK", disk)

	cfg, err := ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg) != ConfigSize {
		t.Fatalf("ReadConfig returned %d bytes", len(cfg))
	}
	cfg[OffSWID] = 0x42
	cfg[OffMode] = 1
	if err := WriteConfig(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, cfg) {
		t.Errorf("config round trip = %x, want %x", got, cfg)
	}

	// A short disk file is zero-padded.
	if err := os.WriteFile(disk, []byte{1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != ConfigSize || got[0] != 1 || got[1] != 2 || got[2] != 3 || got[3] != 0 {
		t.Errorf("short config read = %x...", got[:8])
	}
}

func TestRunGenerateChr(t *testing.T) {
	disk := setupDevice(t)
	uuidFile := filepath.Join(t.TempDir(), "uuid")
	if err := os.WriteFile(uuidFile, []byte(sampleUUID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYGEN_UUID", uuidFile)
	cfg := make([]byte, ConfigSize)
	cfg[OffMode] = 1
	if err := os.WriteFile(disk, cfg, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := RunGenerate(&out); err != nil {
		t.Fatal(err)
	}
	got, err := ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	swid := got[OffSWID : OffSWID+16]
	if !SWIDValid(swid) {
		t.Fatalf("RunGenerate wrote an invalid software id %x", swid)
	}
	want := ChrLicVal(sampleUUID+"\n", swid)
	if !bytes.Equal(mikro.MTTransform(got[OffLic:OffLic+16]), want) {
		t.Errorf("stored licence value = %x, want %x", mikro.MTTransform(got[OffLic:OffLic+16]), want)
	}
	pubx := mikro.LEBytes(CustomPublicKeyX(), 32)
	if !mikro.KCDSAVerifyDevice(want, got[OffLic+16:OffLic+64], pubx) {
		t.Error("stored CHR licence does not verify on the device point")
	}
	if !strings.Contains(out.String(), CBlue+"System ID: "+CCyan+mikro.MTB64Encode(want[:8], false)) {
		t.Errorf("RunGenerate output missing the system id:\n%q", stripANSI(out.String()))
	}
	if parsed, _, _ := ParseLicense(stripANSI(out.String())); !bytes.Equal(parsed, want) {
		t.Errorf("printed licence = %x, want %x", parsed, want)
	}
}

func TestRunGenerateX86(t *testing.T) {
	setupDevice(t)
	keyman := filepath.Join(t.TempDir(), "keyman")
	script := "#!/bin/sh\nprintf 'banner\\n\\n" + x86SampleSerial + "\\n'\n"
	if err := os.WriteFile(keyman, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYGEN_KEYMAN", keyman)

	var out bytes.Buffer
	if err := RunGenerate(&out); err != nil {
		t.Fatal(err)
	}
	got, err := ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !SWIDValid(got[OffSWID : OffSWID+16]) {
		t.Fatalf("RunGenerate wrote an invalid software id %x", got[OffSWID:OffSWID+16])
	}
	want, _ := X86LicVal(x86SampleSerial)
	if !bytes.Equal(mikro.MTTransform(got[OffLic:OffLic+16]), want) {
		t.Errorf("stored licence value = %x, want %x", mikro.MTTransform(got[OffLic:OffLic+16]), want)
	}
	if !strings.Contains(out.String(), "System ID: "+CCyan+x86SampleSerial) {
		t.Errorf("RunGenerate output missing the serial:\n%q", stripANSI(out.String()))
	}
}

func TestKeymanSoftwareID(t *testing.T) {
	keyman := filepath.Join(t.TempDir(), "keyman")
	script := "#!/bin/sh\nprintf 'first\\n\\n" + x86SampleSerial + "\\r\\n'\n"
	if err := os.WriteFile(keyman, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYGEN_KEYMAN", keyman)
	if got := KeymanSoftwareID(); got != x86SampleSerial {
		t.Errorf("KeymanSoftwareID = %q, want %q", got, x86SampleSerial)
	}
	t.Setenv("KEYGEN_KEYMAN", filepath.Join(t.TempDir(), "missing"))
	if got := KeymanSoftwareID(); got != "" {
		t.Errorf("KeymanSoftwareID = %q, want empty", got)
	}
}

func TestMainPrint(t *testing.T) {
	var out bytes.Buffer
	if code := Main([]string{"--print", "--uuid", sampleUUID, "--software-id", sampleSWIDHex}, nil, &out); code != 0 {
		t.Fatalf("Main(--print) = %d:\n%s", code, out.String())
	}
	if want := CBlue + "System ID: " + CCyan + "b7UCXuaR+wA" + CReset + "\n"; !strings.Contains(out.String(), want) {
		t.Errorf("System ID line missing:\n%q", out.String())
	}
	lv, w, s := ParseLicense(stripANSI(out.String()))
	if hex.EncodeToString(lv) != chrSampleLicval {
		t.Errorf("printed licence value = %x, want %s", lv, chrSampleLicval)
	}
	pubx := mikro.LEBytes(CustomPublicKeyX(), 32)
	if !mikro.KCDSAVerifyKeygen(lv, append(append([]byte{}, w...), s...), pubx) {
		t.Error("printed CHR licence does not verify")
	}

	out.Reset()
	if code := Main([]string{"--print", "--serial", x86SampleSerial}, nil, &out); code != 0 {
		t.Fatalf("Main(--print --serial) = %d:\n%s", code, out.String())
	}
	lv, _, _ = ParseLicense(stripANSI(out.String()))
	if hex.EncodeToString(lv) != x86SampleLicval {
		t.Errorf("printed x86 licence value = %x, want %s", lv, x86SampleLicval)
	}
	if !strings.Contains(out.String(), "System ID: "+CCyan+x86SampleSerial) {
		t.Errorf("x86 System ID line missing:\n%q", out.String())
	}

	out.Reset()
	if code := Main([]string{"--print"}, nil, &out); code != 2 {
		t.Errorf("Main(--print without inputs) = %d, want 2", code)
	}
	out.Reset()
	if code := Main([]string{"bogus"}, nil, &out); code != 2 {
		t.Errorf("Main(bogus) = %d, want 2", code)
	}
}

func TestMainSelftestAndVerify(t *testing.T) {
	var out bytes.Buffer
	if code := Main([]string{"--selftest"}, nil, &out); code != 0 {
		t.Fatalf("Main(--selftest) = %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "selftest: PASS") {
		t.Errorf("selftest output:\n%s", out.String())
	}

	dir := t.TempDir()
	lv := mustHex(t, chrSampleLicval)
	text, err := MakeLicense(lv)
	if err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "licence.txt")
	if err := os.WriteFile(good, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := Main([]string{"--verify", good}, nil, &out); code != 0 {
		t.Fatalf("Main(--verify valid) = %d, want 0", code)
	}
	if out.String() != "valid\n" {
		t.Errorf("verify output = %q, want %q", out.String(), "valid\n")
	}

	body := strings.Split(strings.TrimRight(text, "\n"), "\n")
	c := body[1][0]
	if c == 'A' {
		c = 'B'
	} else {
		c = 'A'
	}
	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(bad, []byte(body[0]+"\n"+string(c)+body[1][1:]+"\n"+body[2]+"\n"+body[3]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := Main([]string{"--verify", bad}, nil, &out); code != 1 {
		t.Errorf("Main(--verify corrupt) = %d, want 1", code)
	}
	if out.String() != "INVALID\n" {
		t.Errorf("verify output = %q, want %q", out.String(), "INVALID\n")
	}
}

func TestMainMode(t *testing.T) {
	setupDevice(t)
	var out bytes.Buffer
	if code := Main([]string{"chr"}, strings.NewReader("n\n"), &out); code != 0 {
		t.Fatalf("Main(chr) = %d:\n%s", code, out.String())
	}
	if !strings.Contains(stripANSI(out.String()), "RouterOS has been set to chr mode\nReboot your device [Y/n]: ") {
		t.Errorf("mode output = %q", out.String())
	}
	cfg, err := ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg[OffMode] != 1 || !SWIDValid(cfg[OffSWID:OffSWID+16]) {
		t.Errorf("chr mode config: mode=%d valid=%v", cfg[OffMode], SWIDValid(cfg[OffSWID:OffSWID+16]))
	}
	swid := append([]byte{}, cfg[OffSWID:OffSWID+16]...)

	out.Reset()
	if code := Main([]string{"x86"}, strings.NewReader("N\n"), &out); code != 0 {
		t.Fatalf("Main(x86) = %d:\n%s", code, out.String())
	}
	cfg, err = ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg[OffMode] != 0 {
		t.Errorf("x86 mode config mode = %d, want 0", cfg[OffMode])
	}
	if !bytes.Equal(cfg[OffSWID:OffSWID+16], swid) {
		t.Errorf("software id changed across the mode switch: %x -> %x", swid, cfg[OffSWID:OffSWID+16])
	}
}
