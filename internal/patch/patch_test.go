package patch

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"mikrotikpatch/internal/lzma"
	"mikrotikpatch/internal/squashfs"
)

// TestPatchLicenceBinariesLoader covers the x86-mode boot gate: mode2 is the
// stock licence manager the keygen hands over to, so it must get the custom
// key like mode and keyman, while loader must stay stock (re-signing it makes
// sys2 abort and the boot loop).
func TestPatchLicenceBinariesLoader(t *testing.T) {
	old := make([]byte, 32)
	newKey := make([]byte, 32)
	for i := range old {
		old[i] = byte(i)
		newKey[i] = byte(0x80 + i)
	}
	dir := &squashfs.Node{Name: "bin", Type: squashfs.TypeDir}
	for _, name := range []string{"mode", "keyman", "mode2", "loader"} {
		dir.Children = append(dir.Children, &squashfs.Node{
			Name: name,
			Type: squashfs.TypeFile,
			Data: append([]byte("blob"), old...),
		})
	}
	keys := []KeyPair{{Old: old, New: newKey}}
	if err := patchLicenceBinaries(dir, keys, "x86", "/nova/bin", nil); err != nil {
		t.Fatalf("patchLicenceBinaries: %v", err)
	}
	for _, c := range dir.Children {
		patched := bytes.Contains(c.Data, newKey) && !bytes.Contains(c.Data, old)
		if c.Name == "loader" {
			if patched {
				t.Error("loader must not be re-signed")
			}
			continue
		}
		if !patched {
			t.Errorf("%s was not patched", c.Name)
		}
	}

	// A verifier without the stock key must fail the build instead of
	// shipping an unpatched binary.
	bad := &squashfs.Node{Name: "bin", Type: squashfs.TypeDir, Children: []*squashfs.Node{
		{Name: "mode", Type: squashfs.TypeFile, Data: []byte("no key here")},
		{Name: "keyman", Type: squashfs.TypeFile, Data: []byte("no key here")},
	}}
	if err := patchLicenceBinaries(bad, keys, "x86", "/nova/bin", nil); err == nil {
		t.Fatal("a verifier without the stock key did not fail")
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

func TestReplaceKeyArchScheduledChunks(t *testing.T) {
	// RouterOS 7.25's x86 compiler scheduled the licence-key loads with words
	// 6 and 5 swapped.  The resulting stack image is unchanged, but the bytes
	// in the instruction stream are no longer in key order.
	old := mustHex("8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32")
	newKey := mustHex("c0ffee00deadbeef0123456789abcdeffedcba98765432100badf00dcafe1234")
	oldChunks := chunk4(old)
	newChunks := chunk4(newKey)
	order := []int{0, 1, 2, 3, 4, 6, 5, 7}
	var data, want []byte
	for i, idx := range order {
		var insn []byte
		if i%2 == 0 {
			insn = []byte{0xC7, 0x45, byte(0x80 - 4*i)} // mov dword [ebp+disp8], imm32
		} else {
			insn = []byte{0xC7, 0x85, 0x78, 0xFF, 0xFF, 0xFF} // mov dword [ebp+disp32], imm32
		}
		data = append(data, insn...)
		data = append(data, oldChunks[idx]...)
		want = append(want, insn...)
		want = append(want, newChunks[idx]...)
	}

	got := ReplaceKeyArch(old, newKey, data, "mode", "x86")
	if !bytes.Equal(got, want) {
		t.Fatalf("scheduled key was not patched:\n got %x\nwant %x", got, want)
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

func armTestWord(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		fmt.Sscanf(s[2*i:2*i+2], "%02x", &b[i])
	}
	return b
}

func armTestPut(buf []byte, off int, order []int, words [][]byte) {
	for i, idx := range order {
		copy(buf[off+4*i:], words[idx])
	}
}

func armTestAddImm(reg int, imm8, rot uint32) []byte {
	return armWord(0xE2800000 | uint32(reg)<<16 | uint32(reg)<<12 | rot<<8 | imm8)
}

func armTestLdrPc(reg, target, off int) []byte {
	imm := target - (off + 8)
	return armWord(0xE59F0000 | uint32(reg)<<12 | uint32(imm&0xfff))
}

func armTestStrSp(reg, imm int) []byte {
	return armWord(0xE58D0000 | uint32(reg)<<12 | uint32(imm&0xfff))
}

var (
	armTestOld = armTestWord("8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32")
	armTestNew = armTestWord("c0ffee00deadbeef0123456789abcdeffedcba98765432100badf00dcafe1234")
)

func TestArmFullWordTableAnyOrder(t *testing.T) {
	// All eight words present: the order is irrelevant and no instruction
	// sequence has to be rewritten.
	oldChunks := chunk4(armTestOld)
	newChunks := chunk4(armTestNew)
	order := []int{7, 0, 6, 1, 5, 2, 4, 3}
	var oldBytes, newBytes []byte
	for _, idx := range order {
		oldBytes = append(oldBytes, oldChunks[idx]...)
		newBytes = append(newBytes, newChunks[idx]...)
	}
	data := append([]byte("pre"), oldBytes...)
	data = append(data, []byte("post")...)
	want := append([]byte("pre"), newBytes...)
	want = append(want, []byte("post")...)
	if got := ReplaceKeyArch(armTestOld, armTestNew, data, "table", "arm64"); !bytes.Equal(got, want) {
		t.Fatalf("ARM full table replacement failed:\n got %x\nwant %x", got, want)
	}
}

func TestArmDerivedTableAnyOrder(t *testing.T) {
	// Seven words in a shuffled order plus the stock add sequence that
	// derives chunk3 from chunk2.  The matcher must find the table as a set
	// and rewrite the arithmetic even though its register and position differ
	// from the stock build.
	oldChunks := chunk4(armTestOld)
	newChunks := chunk4(armTestNew)
	order := []int{6, 4, 1, 0, 7, 5, 2}
	const tableOff = 0x200
	const insOff = tableOff - 64
	data := make([]byte, tableOff+4*len(order)+32)
	armTestPut(data, tableOff, order, oldChunks)

	basePos := -1
	for i, idx := range order {
		if idx == 2 {
			basePos = i
		}
	}
	baseOff := tableOff + 4*basePos
	copy(data[insOff:], armTestLdrPc(5, baseOff, insOff))
	copy(data[insOff+4:], armTestAddImm(5, 0x79, 5))   // + 0x1e400000
	copy(data[insOff+8:], armTestAddImm(5, 0xfd, 10))  // + 0x000fd000
	copy(data[insOff+12:], armTestAddImm(5, 0x19, 13)) // + 0x00000640
	copy(data[insOff+16:], armTestStrSp(5, 12))

	got := ReplaceKeyArch(armTestOld, armTestNew, data, "derived", "arm64")
	want := append([]byte(nil), data...)
	armTestPut(want, tableOff, order, newChunks)
	word := binary.LittleEndian.Uint32(newChunks[3])
	copy(want[insOff+4:], armMovwInsn(5, uint16(word)))
	copy(want[insOff+8:], armMovtInsn(5, uint16(word>>16)))
	copy(want[insOff+12:], armNop())
	if !bytes.Equal(got, want) {
		t.Fatalf("ARM derived table replacement failed:\n got %x\nwant %x", got, want)
	}
}

func TestArmDerivedTableAtomic(t *testing.T) {
	// A table match without a usable derived-word sequence must not change
	// anything: a half-patched key would be worse than no patch at all.
	oldChunks := chunk4(armTestOld)
	order := []int{6, 4, 1, 0, 7, 5, 2}
	data := make([]byte, 0x200+4*len(order)+32)
	armTestPut(data, 0x200, order, oldChunks)
	if got := ReplaceKeyArch(armTestOld, armTestNew, data, "atomic", "arm64"); !bytes.Equal(got, data) {
		t.Fatal("ARM table was patched without a derived-word rewrite")
	}
}

func TestArmPackedTableAnyOrder(t *testing.T) {
	oldWords := packedWords(armTestOld)
	newWords := packedWords(armTestNew)
	order := []int{9, 4, 0, 8, 1, 5, 2, 6, 3, 7}
	var oldBytes, newBytes []byte
	for _, idx := range order {
		oldBytes = append(oldBytes, oldWords[idx]...)
		newBytes = append(newBytes, newWords[idx]...)
	}
	data := append([]byte("pre"), oldBytes...)
	data = append(data, []byte("post")...)
	want := append([]byte("pre"), newBytes...)
	want = append(want, []byte("post")...)
	if got := ReplaceKeyArch(armTestOld, armTestNew, data, "packed", "arm64"); !bytes.Equal(got, want) {
		t.Fatalf("ARM packed table replacement failed:\n got %x\nwant %x", got, want)
	}
}

func TestArmPackedDerivedTable(t *testing.T) {
	oldWords := packedWords(armTestOld)
	newWords := packedWords(armTestNew)
	order := []int{6, 4, 0, 9, 1, 5, 2, 7, 3}
	const tableOff = 0x200
	const insOff = tableOff - 64
	data := make([]byte, tableOff+4*len(order)+32)
	armTestPut(data, tableOff, order, oldWords)

	basePos := -1
	for i, idx := range order {
		if idx == 7 {
			basePos = i
		}
	}
	baseOff := tableOff + 4*basePos
	copy(data[insOff:], armTestLdrPc(4, baseOff, insOff))
	copy(data[insOff+4:], armTestAddImm(4, 0x71, 7))   // + 0x01c40000
	copy(data[insOff+8:], armTestAddImm(4, 0x22, 10))  // + 0x00022000
	copy(data[insOff+12:], armTestAddImm(4, 0x8d, 15)) // + 0x00000234
	copy(data[insOff+16:], armTestStrSp(4, 16))

	got := ReplaceKeyArch(armTestOld, armTestNew, data, "packed-derived", "arm64")
	want := append([]byte(nil), data...)
	armTestPut(want, tableOff, order, newWords)
	word := binary.LittleEndian.Uint32(newWords[8])
	copy(want[insOff+4:], armMovwInsn(4, uint16(word)))
	copy(want[insOff+8:], armMovtInsn(4, uint16(word>>16)))
	copy(want[insOff+12:], armNop())
	if !bytes.Equal(got, want) {
		t.Fatalf("ARM packed derived table replacement failed:\n got %x\nwant %x", got, want)
	}
}
