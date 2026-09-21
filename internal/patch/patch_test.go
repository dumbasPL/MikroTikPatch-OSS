package patch

import (
	"bytes"
	"encoding/binary"
	"testing"

	"mikrotikpatch/internal/lzma"
)

func TestArmLoadImm(t *testing.T) {
	// Value 0xCFBB40A6 must load as MOVW r3,#0x40A6 / MOVT r3,#0xCFBB / NOP.
	got := ArmLoadImm(3, 0xCFBB40A6, "movt")
	want := []uint32{0xE30430A6, 0xE34C3FBB, 0xE1A00000}
	for i, w := range want {
		if v := binary.LittleEndian.Uint32(got[i]); v != w {
			t.Errorf("movt word %d = %#x, want %#x", i, v, w)
		}
	}
	// ORR style: MOVW r3,#0xA4C6 / ORR r3,r3,#0xCE0000 / ORR r3,r3,#0x43000000
	got = ArmLoadImm(3, 0x43CEA4C6, "orr")
	want = []uint32{0xE30A34C6, 0xE38338CE, 0xE3833443}
	for i, w := range want {
		if v := binary.LittleEndian.Uint32(got[i]); v != w {
			t.Errorf("orr word %d = %#x, want %#x", i, v, w)
		}
	}
}

func TestReplaceChunks(t *testing.T) {
	cases := []struct {
		name string
		old  [][]byte
		new  [][]byte
		data []byte
		want []byte
	}{
		{
			name: "contiguous",
			old:  [][]byte{{1, 2}, {3, 4}},
			new:  [][]byte{{9, 8}, {7, 6}},
			data: []byte{0, 1, 2, 3, 4, 0},
			want: []byte{0, 9, 8, 7, 6, 0},
		},
		{
			name: "gap preserved",
			old:  [][]byte{{1}, {2}},
			new:  [][]byte{{9}, {8}},
			data: []byte{1, 0xaa, 0xbb, 2},
			want: []byte{9, 0xaa, 0xbb, 8},
		},
		{
			name: "greedy takes the farthest match within six bytes",
			old:  [][]byte{{1}, {2}},
			new:  [][]byte{{9}, {8}},
			data: []byte{1, 0, 0, 2, 0, 2},
			want: []byte{9, 0, 0, 2, 0, 8},
		},
		{
			name: "no match beyond six bytes",
			old:  [][]byte{{1}, {2}},
			new:  [][]byte{{9}, {8}},
			data: []byte{1, 0, 0, 0, 0, 0, 0, 0, 2},
			want: []byte{1, 0, 0, 0, 0, 0, 0, 0, 2},
		},
		{
			name: "greedy consumes the rest of the buffer",
			old:  [][]byte{{1}, {2}},
			new:  [][]byte{{9}, {8}},
			data: []byte{1, 2, 5, 1, 2},
			want: []byte{9, 2, 5, 1, 8},
		},
	}
	for _, tc := range cases {
		got := ReplaceChunks(tc.old, tc.new, tc.data, tc.name)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s: got %x, want %x", tc.name, got, tc.want)
		}
	}
}

func TestReplaceKeySynthetic(t *testing.T) {
	old := make([]byte, 32)
	newKey := make([]byte, 32)
	for i := range old {
		old[i] = byte(i)
		newKey[i] = byte(0x80 + i)
	}
	data := append([]byte("prefix"), old...)
	data = append(data, []byte("suffix")...)
	got := ReplaceKeyArch(old, newKey, data, "test", "x86")
	if !bytes.Equal(got, append(append([]byte("prefix"), newKey...), []byte("suffix")...)) {
		t.Fatalf("key replacement failed: %x", got)
	}
	// A second pass must be a no-op (the old key is gone).
	again := ReplaceKeyArch(old, newKey, got, "test", "x86")
	if !bytes.Equal(again, got) {
		t.Fatal("second replacement changed the data")
	}
}

func TestPatchInitrdXZ(t *testing.T) {
	old := bytes.Repeat([]byte{0x41}, 32)
	newKey := bytes.Repeat([]byte{0x42}, 32)
	payload := append([]byte("some initramfs data "), old...)
	payload = append(payload, bytes.Repeat([]byte(" padding"), 200)...)
	stream, err := lzma.Encode(payload, lzma.Options{Preset: 6, Check: lzma.CheckCRC32})
	if err != nil {
		t.Fatal(err)
	}
	// Give the recompressed stream room by making the original stream larger.
	padded := append(append([]byte(nil), stream...), make([]byte, len(stream)/4+64)...)
	got, err := PatchInitrdXZ(padded, []KeyPair{{Old: old, New: newKey}}, "x86", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(padded) {
		t.Fatalf("padded result is %d bytes, want %d", len(got), len(padded))
	}
	dec, err := lzma.Decode(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(dec, newKey) || bytes.Contains(dec, old) {
		t.Fatal("initrd was not patched correctly")
	}
}

func TestFindXZStreams(t *testing.T) {
	stream, err := lzma.Encode([]byte("hello xz"), lzma.Options{Preset: 6, Check: lzma.CheckCRC32})
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte("junk"), stream...)
	data = append(data, []byte("middle")...)
	data = append(data, stream...)
	streams := FindXZStreams(data)
	if len(streams) != 2 {
		t.Fatalf("found %d streams, want 2", len(streams))
	}
	for i, s := range streams {
		if !bytes.Equal(data[s.Start:s.End], stream) {
			t.Errorf("stream %d does not match", i)
		}
	}
	if last := Find7zXZData(data); !bytes.Equal(last, stream) {
		t.Error("Find7zXZData did not return the last stream")
	}
}

func TestArmKeyTable(t *testing.T) {
	// The word table order is a fixed permutation of the key's words.
	old := make([]byte, 32)
	newKey := make([]byte, 32)
	for i := range old {
		old[i] = byte(0x10 + i)
		newKey[i] = byte(0x90 + i)
	}
	oldChunks := chunk4(old)
	newChunks := chunk4(newKey)
	oldBytes := concat(oldChunks[4], oldChunks[5], oldChunks[2], oldChunks[0], oldChunks[1], oldChunks[6], oldChunks[7])
	newBytes := concat(newChunks[4], newChunks[5], newChunks[2], newChunks[0], newChunks[1], newChunks[6], newChunks[7])
	data := append([]byte("x"), oldBytes...)
	data = append(data, []byte("y")...)
	got := ReplaceKeyArch(old, newKey, data, "arm", "arm64")
	if !bytes.Equal(got, append(append([]byte("x"), newBytes...), 'y')) {
		t.Fatalf("ARM word table replacement failed: %x", got)
	}
}
