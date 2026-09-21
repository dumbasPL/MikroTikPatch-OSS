package lzma

import (
	"bytes"
	"os"
	"testing"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDecodeCompat decodes streams produced by Python's lzma module (same
// liblzma) to prove the filter chains are understood.
func TestDecodeCompat(t *testing.T) {
	payload := read(t, "compat.bin")
	for _, name := range []string{"compat_bcj.xz", "compat_lzma2.xz"} {
		got, err := Decode(read(t, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("%s: decoded payload differs", name)
		}
	}
}

// TestEncodeCompat checks byte-for-byte equality with Python's lzma output for
// the same filter settings.
func TestEncodeCompat(t *testing.T) {
	payload := read(t, "compat.bin")
	cases := []struct {
		name string
		file string
		opt  Options
	}{
		{"bcj", "compat_bcj.xz", Options{BCJX86: true, Preset: 6, DictSize: 1 << 20, Check: CheckCRC32}},
		{"lzma2", "compat_lzma2.xz", Options{Preset: 6, DictSize: 1 << 20, Check: CheckCRC32}},
	}
	for _, tc := range cases {
		got, err := Encode(payload, tc.opt)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		want := read(t, tc.file)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: encoded %d bytes, Python produced %d bytes", tc.name, len(got), len(want))
		}
	}
}

// TestRoundTrip exercises arbitrary data through encode/decode.
func TestRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte("RouterOS key material \x00\x01\x02\xff"), 5000)
	enc, err := Encode(data, Options{BCJX86: true, Preset: 9, DictSize: 1 << 20, LC: 4, PB: 0, SetProps: true, Check: CheckCRC32})
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, data) {
		t.Fatal("round trip mismatch")
	}
}
