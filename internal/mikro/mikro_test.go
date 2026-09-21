package mikro

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

type vectors struct {
	MTSHA256 []struct {
		In  string `json:"in"`
		Out string `json:"out"`
	} `json:"mt_sha256"`
	Transform []struct {
		Stored string `json:"stored"`
		Licval string `json:"licval"`
	} `json:"transform"`
	B64 []struct {
		Raw    string `json:"raw"`
		Enc    string `json:"enc"`
		EncPad string `json:"enc_pad"`
	} `json:"b64"`
	Ed25519 struct {
		Seed string `json:"seed"`
		Pub  string `json:"pub"`
		Msg  string `json:"msg"`
		Sig  string `json:"sig"`
	} `json:"ed25519"`
	KCDSAMikro struct {
		Priv string `json:"priv"`
		Pub  string `json:"pub"`
		Data string `json:"data"`
		Sig  string `json:"sig"`
	} `json:"kcdsa_mikro"`
	KCDSAKeygen struct {
		D      string `json:"d"`
		PubX   string `json:"pubx"`
		Licval string `json:"licval"`
		Sig    string `json:"sig"`
	} `json:"kcdsa_keygen"`
	CustomKey struct {
		PrivateRaw         string `json:"private_raw"`
		PublicRaw          string `json:"public_raw"`
		PrivateTransformed string `json:"private_transformed"`
		PublicTransformed  string `json:"public_transformed"`
		D                  string `json:"d"`
		PubX               string `json:"pubx"`
	} `json:"custom_key"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func loadVectors(t *testing.T) *vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return &v
}

func TestMTSHA256(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.MTSHA256 {
		got := hex.EncodeToString(MTSHA256(mustHex(t, tc.In)))
		if got != tc.Out {
			t.Errorf("MTSHA256(%s) = %s, want %s", tc.In, got, tc.Out)
		}
	}
}

func TestTransform(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.Transform {
		stored := mustHex(t, tc.Stored)
		got := hex.EncodeToString(MTTransform(stored))
		if got != tc.Licval {
			t.Errorf("MTTransform = %s, want %s", got, tc.Licval)
		}
		if rev := hex.EncodeToString(MTTransformRev(mustHex(t, tc.Licval))); rev != tc.Stored {
			t.Errorf("MTTransformRev = %s, want %s", rev, tc.Stored)
		}
	}
}

func TestMTB64(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.B64 {
		raw := mustHex(t, tc.Raw)
		if got := MTB64Encode(raw, false); got != tc.Enc {
			t.Errorf("MTB64Encode(%s) = %q, want %q", tc.Raw, got, tc.Enc)
		}
		if got := MTB64Encode(raw, true); got != tc.EncPad {
			t.Errorf("MTB64Encode pad(%s) = %q, want %q", tc.Raw, got, tc.EncPad)
		}
		dec, err := MTB64Decode(tc.EncPad)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(dec) != tc.Raw {
			t.Errorf("MTB64Decode(%q) = %x, want %s", tc.EncPad, dec, tc.Raw)
		}
	}
}

func TestEd25519(t *testing.T) {
	v := loadVectors(t)
	seed := mustHex(t, v.Ed25519.Seed)
	msg := mustHex(t, v.Ed25519.Msg)
	pub := mustHex(t, v.Ed25519.Pub)
	sig := mustHex(t, v.Ed25519.Sig)
	if got := hex.EncodeToString(EdDSASign(msg, seed)); got != v.Ed25519.Sig {
		t.Errorf("EdDSASign = %s, want %s", got, v.Ed25519.Sig)
	}
	if !EdDSAVerify(msg, sig, pub) {
		t.Error("EdDSAVerify rejected the reference signature")
	}
	if hex.EncodeToString(EdDSAPublicFromSeed(seed)) != v.Ed25519.Pub {
		t.Error("EdDSAPublicFromSeed mismatch")
	}
}

func TestKCDSAVerifyReference(t *testing.T) {
	v := loadVectors(t)
	data := mustHex(t, v.KCDSAMikro.Data)
	pub := mustHex(t, v.KCDSAMikro.Pub)
	sig := mustHex(t, v.KCDSAMikro.Sig)
	if !KCDSAVerify(data, sig, pub) {
		t.Error("KCDSAVerify rejected the mikro.py signature")
	}

	licval := mustHex(t, v.KCDSAKeygen.Licval)
	pubx := mustHex(t, v.KCDSAKeygen.PubX)
	sig2 := mustHex(t, v.KCDSAKeygen.Sig)
	if !KCDSAVerifyKeygen(licval, sig2, pubx) {
		t.Error("KCDSAVerifyKeygen rejected the keygen.py signature")
	}
	if !KCDSAVerifyDevice(licval, sig2, pubx) {
		t.Error("KCDSAVerifyDevice rejected the keygen.py signature")
	}
}

func TestKCDSARoundTrip(t *testing.T) {
	v := loadVectors(t)
	// Package signer (mask 0x7F).
	priv := mustHex(t, v.KCDSAMikro.Priv)
	pub := mustHex(t, v.KCDSAMikro.Pub)
	data := mustHex(t, v.KCDSAMikro.Data)
	sig, err := KCDSASign(data, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !KCDSAVerify(data, sig, pub) {
		t.Error("KCDSASign produced a signature that KCDSAVerify rejects")
	}
	// Keygen signer (mask 0x3F).
	d := BigFromLE(mustHex(t, v.KCDSAKeygen.D))
	pubx := mustHex(t, v.KCDSAKeygen.PubX)
	licval := mustHex(t, v.KCDSAKeygen.Licval)
	sig2, err := KCDSASignKeygen(licval, d)
	if err != nil {
		t.Fatal(err)
	}
	if !KCDSAVerifyKeygen(licval, sig2, pubx) {
		t.Error("KCDSASignKeygen produced a signature that KCDSAVerifyKeygen rejects")
	}
	if !KCDSAVerifyDevice(licval, sig2, pubx) {
		t.Error("KCDSASignKeygen produced a signature that KCDSAVerifyDevice rejects")
	}
}

// TestCustomKeyMaterial checks the recovered custom key maths: applying
// MTTransform to each half of the stored blobs, negating the scalar and
// normalising the point parity reproduces the expected private scalar and
// public x-coordinate.
func TestCustomKeyMaterial(t *testing.T) {
	v := loadVectors(t)
	priv := mustHex(t, v.CustomKey.PrivateRaw)
	if got := hex.EncodeToString(MTTransform(priv[:16])); got != v.CustomKey.PrivateTransformed[:32] {
		t.Errorf("transform(private[0:16]) = %s", got)
	}
	if got := hex.EncodeToString(MTTransform(priv[16:])); got != v.CustomKey.PrivateTransformed[32:] {
		t.Errorf("transform(private[16:32]) = %s", got)
	}
	if got := hex.EncodeToString(MTTransformMust(mustHex(t, v.CustomKey.PublicRaw))); got != v.CustomKey.PublicTransformed {
		t.Errorf("transform(public) = %s, want %s", got, v.CustomKey.PublicTransformed)
	}

	// Reproduce keygen.py's custom_private_key(): d = -m mod n, with parity
	// normalisation against the keygen generator.
	m := BigFromLE(mustHex(t, v.CustomKey.PrivateTransformed))
	d := new(big.Int).Neg(m)
	d.Mod(d, CurveN)
	p := CurveScalarMult(d, CurveGKeygen)
	if p.Y.Bit(0) == 0 {
		d.Sub(CurveN, d)
	}
	if got := hex.EncodeToString(LEBytes(d, 32)); got != v.CustomKey.D {
		t.Errorf("custom private scalar = %s, want %s", got, v.CustomKey.D)
	}
	pubx := BigFromLE(mustHex(t, v.CustomKey.PublicTransformed))
	if got := hex.EncodeToString(LEBytes(pubx, 32)); got != v.CustomKey.PubX {
		t.Errorf("custom public x = %s, want %s", got, v.CustomKey.PubX)
	}
}

// MTTransformMust transforms two 16-byte halves.
func MTTransformMust(b []byte) []byte {
	return append(MTTransform(b[:16]), MTTransform(b[16:32])...)
}
