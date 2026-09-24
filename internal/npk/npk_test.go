package npk

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// testNPK returns the path of a real RouterOS NPK, or skips.
func testNPK(t *testing.T) string {
	t.Helper()
	for _, p := range []string{
		os.Getenv("NPK_TEST_FILE"),
		"/tmp/build/7.24.4/routeros-7.24.4.npk",
		"/tmp/build/7.24.4-arm64/routeros-7.24.4-arm64.npk",
	} {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	t.Skip("no test NPK available (set NPK_TEST_FILE)")
	return ""
}

func TestParseAndExtract(t *testing.T) {
	path := testNPK(t)
	pkg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if pkg.Get(PartNameInfo) == nil {
		t.Fatal("no NAME_INFO")
	}
	fc, err := pkg.FindSystemContainer()
	if err != nil {
		t.Fatalf("FindSystemContainer: %v", err)
	}
	if fc == nil {
		t.Fatal("no system package")
	}
	var milo, bash *FileItem
	for _, item := range fc.Items {
		switch string(item.Name) {
		case "bin/milo":
			milo = item
		case "bin/bash":
			bash = item
		}
	}
	if milo != nil {
		if len(milo.Data) < 4 || !bytes.Equal(milo.Data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
			t.Errorf("bin/milo is not an ELF (first bytes %x)", milo.Data[:min(4, len(milo.Data))])
		}
	}
	if bash == nil {
		t.Log("note: no bin/bash in this package")
	}
	// File container round trip: the serialised stream must be byte-identical
	// (the stock tooling uses zlib level 0 with 32 KiB stored blocks, and the
	// parser must not shift any metadata field).
	raw, err := fc.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	orig := pkg.Get(PartFileContainer).Bytes()
	if !bytes.Equal(raw, orig) {
		t.Fatalf("container round trip changed the bytes (%d -> %d)", len(orig), len(raw))
	}
	fc2, err := UnserializeFileContainer(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(fc2.Items) != len(fc.Items) {
		t.Fatalf("item count %d != %d", len(fc2.Items), len(fc.Items))
	}
	for i := range fc.Items {
		a, b := fc.Items[i], fc2.Items[i]
		if string(a.Name) != string(b.Name) || !bytes.Equal(a.Data, b.Data) || a.Perm != b.Perm || a.Type != b.Type {
			t.Fatalf("item %d differs after round trip", i)
		}
		// The metadata must survive the round trip (a field-offset bug here
		// used to mangle ModifyTime/Revision/... on re-serialisation).
		if a.ModifyTime != b.ModifyTime || a.Revision != b.Revision || a.RC != b.RC ||
			a.Minor != b.Minor || a.Major != b.Major || a.CreateTime != b.CreateTime ||
			a.Unknown != b.Unknown || a.UsrOrGrp != b.UsrOrGrp {
			t.Fatalf("item %d metadata differs after round trip: %+v vs %+v", i, a, b)
		}
	}
}

func TestSignAndVerify(t *testing.T) {
	path := testNPK(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := hex.DecodeString("3b9d7e74c2fe15523489a370e1bff3b79fc9f19abcde91c89e3f1a5039b91105")
	pub, _ := hex.DecodeString("a7a7f00e6459d9f5c20c992dc6a4ce43a640bbcf01b723e6a0445f59e3155f39")
	edPriv, _ := hex.DecodeString("183ded0453bc993c88be1a5bfb399fee5369f56e8fd6f58e69af5db68ea468b7")
	edPub, _ := hex.DecodeString("32770a4fe7c2969a3e8674b072dce6264ce46f43b82b5650cfbc042779cc719e")

	// Sign with an explicit build time and check it lands in the package info.
	const buildTime = 1700000000
	if err := pkg.Sign(priv, edPriv, time.Unix(buildTime, 0)); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if pkgInfo := pkg.Get(PartPkgInfo); pkgInfo != nil && pkgInfo.Info != nil {
		if got := pkgInfo.Info.BuildTime.Unix(); got != buildTime {
			t.Errorf("PKG_INFO build time = %d, want %d", got, buildTime)
		}
	}
	if nameInfo := pkg.Get(PartNameInfo); nameInfo != nil && nameInfo.Info != nil {
		if got := nameInfo.Info.BuildTime.Unix(); got != buildTime {
			t.Errorf("NAME_INFO build time = %d, want %d", got, buildTime)
		}
	}
	// The signature must verify against the custom public keys and survive a
	// serialise/parse round trip.
	if err := pkg.Verify(pub, edPub); err != nil {
		t.Fatalf("Verify after sign: %v", err)
	}
	out := pkg.Marshal()
	pkg2, err := Unmarshal(out)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := pkg2.Verify(pub, edPub); err != nil {
		t.Fatalf("Verify after round trip: %v", err)
	}
	sig := pkg2.Get(PartSignature)
	if sig == nil || len(sig.Bytes()) != SignatureSize {
		t.Fatalf("bad signature part: %v", sig)
	}
	// The signature must be deterministic apart from the KCDSA nonce, and a
	// wrong key must fail.
	other, _ := hex.DecodeString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err := pkg2.Verify(other, edPub); err == nil {
		t.Error("Verify accepted a wrong public key")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestParseBuildTime(t *testing.T) {
	zero, err := ParseBuildTime("")
	if err != nil || !zero.IsZero() {
		t.Fatalf("empty: %v %v", zero, err)
	}
	got, err := ParseBuildTime(" 1789558341 ")
	if err != nil || got.Unix() != 1789558341 {
		t.Fatalf("value: %v %v", got, err)
	}
	if _, err := ParseBuildTime("tomorrow"); err == nil {
		t.Fatal("invalid build time accepted")
	}
}
