package image

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

// --- helpers ---------------------------------------------------------------

func newTestImage(t *testing.T, bios []byte) (*Image, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "chr.img")
	im, err := Create(path, bios)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { im.Close() })
	return im, path
}

func readAt(t *testing.T, path string, off int64, n int) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := f.ReadAt(b, off); err != nil {
		t.Fatalf("read %d bytes at %d: %v", n, off, err)
	}
	return b
}

// sudoAvailable reports whether passwordless sudo is usable.
func sudoAvailable() bool {
	return exec.Command("sudo", "-n", "true").Run() == nil
}

// mountAndCheck mounts a partition of the image read-only (with a loop
// offset) and compares the contents of want against the mounted files.  It
// is skipped when sudo is not available.
func mountAndCheck(t *testing.T, img string, start, count uint64, fstype string, want map[string][]byte) {
	t.Helper()
	if !sudoAvailable() {
		t.Skip("passwordless sudo unavailable; skipping mount test")
	}
	mnt := filepath.Join(t.TempDir(), "mnt")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	opts := fmt.Sprintf("loop,ro,offset=%d", int64(start)*sectorSize)
	out, err := exec.Command("sudo", "-n", "mount", "-t", fstype, "-o", opts, img, mnt).CombinedOutput()
	if err != nil {
		t.Fatalf("mount -t %s -o %s: %v: %s", fstype, opts, err, bytes.TrimSpace(out))
	}
	defer func() {
		if out, err := exec.Command("sudo", "-n", "umount", mnt).CombinedOutput(); err != nil {
			t.Errorf("umount %s: %v: %s", mnt, err, bytes.TrimSpace(out))
		}
	}()
	for name, wantData := range want {
		got, err := os.ReadFile(filepath.Join(mnt, name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		if !bytes.Equal(got, wantData) {
			t.Errorf("%s: mounted content differs (%d bytes vs %d bytes)", name, len(got), len(wantData))
		}
	}
}

// --- GPT / MBR -------------------------------------------------------------

func TestCreate(t *testing.T) {
	bios := make([]byte, 446)
	for i := range bios {
		bios[i] = byte(i*7 + 1)
	}
	_, path := newTestImage(t, bios)

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != DiskSize {
		t.Errorf("image size = %d, want %d", st.Size(), DiskSize)
	}

	mbr := readAt(t, path, 0, sectorSize)
	wantBios := append([]byte(nil), bios...)
	wantBios[0x150] = 1 // the CHR mode byte lives inside the boot code area
	if !bytes.Equal(mbr[:446], wantBios) {
		t.Errorf("BIOS boot code not written at offset 0")
	}
	wantMBR, err := hex.DecodeString(
		"800023008314100422000000deff0000" +
			"00141104830f3f100000010000f00200" +
			"00000200ee0022000100000021000000" +
			"00000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mbr[446:510], wantMBR) {
		t.Errorf("MBR partition entries = %x\nwant %x", mbr[446:510], wantMBR)
	}
	if mbr[510] != 0x55 || mbr[511] != 0xAA {
		t.Errorf("MBR signature = %#x %#x, want 0x55 0xAA", mbr[510], mbr[511])
	}
	if mbr[0x150] != 1 {
		t.Errorf("CHR mode byte at 0x150 = %d, want 1", mbr[0x150])
	}

	hdr := readAt(t, path, 512, 92)
	checkGPTHeader(t, hdr, 1, gptBackupHeaderLBA, gptEntryLBA)

	entries := readAt(t, path, gptEntryLBA*sectorSize, gptEntryCount*gptEntrySize)
	if got, want := binary.LittleEndian.Uint32(hdr[88:]), crc32.ChecksumIEEE(entries); got != want {
		t.Errorf("partition entry array CRC = %#x, want %#x", got, want)
	}
	checkPartEntry(t, entries[0:128], "28732ac11ff8d211ba4b00a0c93ec93b", BootStart, BootEnd, "RouterOS Boot")
	checkPartEntry(t, entries[128:256], "af3dc60f838472478e793d69d8477de4", ROSStart, ROSEnd, "RouterOS")
	for i := 2; i < gptEntryCount; i++ {
		if !bytes.Equal(entries[i*128:(i+1)*128], make([]byte, 128)) {
			t.Errorf("partition entry %d is not empty", i+1)
		}
	}

	// Backup header and entry array.
	backupHdr := readAt(t, path, gptBackupHeaderLBA*sectorSize, 92)
	checkGPTHeader(t, backupHdr, gptBackupHeaderLBA, 1, gptBackupEntryLBA)
	backupEntries := readAt(t, path, gptBackupEntryLBA*sectorSize, gptEntryCount*gptEntrySize)
	if !bytes.Equal(backupEntries, entries) {
		t.Errorf("backup partition entry array differs from primary")
	}
}

func checkGPTHeader(t *testing.T, hdr []byte, current, backup, entryLBA uint64) {
	t.Helper()
	le := binary.LittleEndian
	if string(hdr[:8]) != "EFI PART" {
		t.Errorf("GPT signature = %q, want %q", hdr[:8], "EFI PART")
	}
	if got := le.Uint32(hdr[8:]); got != gptRevision {
		t.Errorf("GPT revision = %#x, want %#x", got, gptRevision)
	}
	if got := le.Uint32(hdr[12:]); got != gptHeaderSize {
		t.Errorf("GPT header size = %d, want %d", got, gptHeaderSize)
	}
	if got := le.Uint32(hdr[20:]); got != 0 {
		t.Errorf("GPT reserved field = %#x, want 0", got)
	}
	if got := le.Uint64(hdr[24:]); got != current {
		t.Errorf("GPT current LBA = %d, want %d", got, current)
	}
	if got := le.Uint64(hdr[32:]); got != backup {
		t.Errorf("GPT backup LBA = %d, want %d", got, backup)
	}
	if got := le.Uint64(hdr[40:]); got != gptFirstUsable {
		t.Errorf("GPT first usable LBA = %d, want %d", got, gptFirstUsable)
	}
	if got := le.Uint64(hdr[48:]); got != gptLastUsable {
		t.Errorf("GPT last usable LBA = %d, want %d", got, gptLastUsable)
	}
	if got := le.Uint64(hdr[72:]); got != entryLBA {
		t.Errorf("GPT entry array LBA = %d, want %d", got, entryLBA)
	}
	if got := le.Uint32(hdr[80:]); got != gptEntryCount {
		t.Errorf("GPT entry count = %d, want %d", got, gptEntryCount)
	}
	if got := le.Uint32(hdr[84:]); got != gptEntrySize {
		t.Errorf("GPT entry size = %d, want %d", got, gptEntrySize)
	}
	z := append([]byte(nil), hdr[:gptHeaderSize]...)
	le.PutUint32(z[16:], 0)
	if got, want := le.Uint32(hdr[16:]), crc32.ChecksumIEEE(z); got != want {
		t.Errorf("GPT header CRC = %#x, want %#x", got, want)
	}
	if bytes.Equal(hdr[56:72], make([]byte, 16)) {
		t.Errorf("GPT disk GUID is empty")
	}
}

func checkPartEntry(t *testing.T, e []byte, typeHex string, first, last uint64, name string) {
	t.Helper()
	wantType, err := hex.DecodeString(typeHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(e[0:16], wantType) {
		t.Errorf("partition type = %x, want %s", e[0:16], typeHex)
	}
	if bytes.Equal(e[16:32], make([]byte, 16)) {
		t.Errorf("partition unique GUID is empty")
	}
	le := binary.LittleEndian
	if got := le.Uint64(e[32:]); got != first {
		t.Errorf("partition first LBA = %d, want %d", got, first)
	}
	if got := le.Uint64(e[40:]); got != last {
		t.Errorf("partition last LBA = %d, want %d", got, last)
	}
	if got := le.Uint64(e[48:]); got != 0 {
		t.Errorf("partition attributes = %#x, want 0", got)
	}
	if got := decodeUTF16(e[56:128]); got != name {
		t.Errorf("partition name = %q, want %q", got, name)
	}
}

func decodeUTF16(b []byte) string {
	var u []uint16
	for i := 0; i+1 < len(b); i += 2 {
		v := binary.LittleEndian.Uint16(b[i:])
		if v == 0 {
			break
		}
		u = append(u, v)
	}
	return string(utf16.Decode(u))
}

func TestCreateErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chr.img")
	if _, err := Create(path, make([]byte, 447)); err == nil {
		t.Errorf("Create accepted 447 bytes of BIOS code")
	}
}

// --- FAT16 -----------------------------------------------------------------

// parseFAT16 walks a FAT16 partition and returns its files by path.
func parseFAT16(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	le := binary.LittleEndian
	bps := int(le.Uint16(data[11:]))
	spc := int(data[13])
	rsvd := int(le.Uint16(data[14:]))
	nfats := int(data[16])
	rootEnt := int(le.Uint16(data[17:]))
	fatSectors := int(le.Uint16(data[22:]))
	clusterBytes := bps * spc
	fatOff := rsvd * bps
	rootOff := fatOff + nfats*fatSectors*bps
	dataOff := rootOff + rootEnt*32

	fatEntry := func(c int) int {
		return int(le.Uint16(data[fatOff+c*2:]))
	}
	readChain := func(first int) []byte {
		var out []byte
		for c := first; c >= 2 && c < 0xFFF8; {
			start := dataOff + (c-2)*clusterBytes
			if start+clusterBytes > len(data) {
				t.Fatalf("cluster %d outside partition", c)
			}
			out = append(out, data[start:start+clusterBytes]...)
			c = fatEntry(c)
			if len(out) > len(data) {
				t.Fatal("FAT cluster chain loop")
			}
		}
		return out
	}
	type dirent struct {
		name  string
		attr  byte
		first int
		size  int
	}
	readDir := func(area []byte) []dirent {
		var out []dirent
		for off := 0; off+32 <= len(area); off += 32 {
			e := area[off : off+32]
			if e[0] == 0 {
				break
			}
			if e[0] == 0xE5 {
				continue
			}
			if e[11] == 0x0F {
				t.Fatal("unexpected long file name entry")
			}
			name := strings.TrimRight(string(e[0:8]), " ")
			if ext := strings.TrimRight(string(e[8:11]), " "); ext != "" {
				name += "." + ext
			}
			out = append(out, dirent{name, e[11], int(le.Uint16(e[26:])), int(le.Uint32(e[28:]))})
		}
		return out
	}
	files := map[string][]byte{}
	var walk func(prefix string, area []byte)
	walk = func(prefix string, area []byte) {
		for _, e := range readDir(area) {
			if e.name == "." || e.name == ".." || e.attr&fatAttrVolume != 0 {
				continue
			}
			p := prefix + e.name
			if e.attr&fatAttrDir != 0 {
				walk(p+"/", readChain(e.first))
				continue
			}
			body := readChain(e.first)
			if e.size > len(body) {
				t.Fatalf("%s: size %d exceeds %d bytes of clusters", p, e.size, len(body))
			}
			files[p] = body[:e.size]
		}
	}
	walk("", data[rootOff:rootOff+rootEnt*32])
	return files
}

func TestFAT16(t *testing.T) {
	im, path := newTestImage(t, nil)
	payload := bytes.Repeat([]byte("EFI payload!"), 700) // 8400 bytes, spans clusters
	version := []byte("7.24.4\n")
	entries := []Entry{
		{Path: "EFI/BOOT/BOOTX64.EFI", Data: payload},
		{Path: "VERSION", Data: version},
	}
	if err := im.WriteFAT16(entries); err != nil {
		t.Fatalf("WriteFAT16: %v", err)
	}

	data := readAt(t, path, int64(BootStart)*sectorSize, int(BootEnd-BootStart+1)*sectorSize)
	le := binary.LittleEndian
	if got := data[0:3]; !bytes.Equal(got, []byte{0xEB, 0x3C, 0x90}) {
		t.Errorf("boot jump = %x, want eb3c90", got)
	}
	if got := string(data[3:11]); got != "mkfs.fat" {
		t.Errorf("OEM = %q, want %q", got, "mkfs.fat")
	}
	checks := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"bytes/sector", uint32(le.Uint16(data[11:])), 512},
		{"sectors/cluster", uint32(data[13]), 4},
		{"reserved sectors", uint32(le.Uint16(data[14:])), 4},
		{"number of FATs", uint32(data[16]), 2},
		{"root entries", uint32(le.Uint16(data[17:])), 512},
		{"total sectors", uint32(le.Uint16(data[19:])), 65502},
		{"media", uint32(data[21]), 0xF8},
		{"sectors/FAT", uint32(le.Uint16(data[22:])), 64},
		{"hidden sectors", le.Uint32(data[28:]), BootStart},
		{"drive number", uint32(data[36]), 0x80},
		{"boot signature", uint32(data[38]), 0x29},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if got := strings.TrimRight(string(data[43:54]), " "); got != "BOOT" {
		t.Errorf("volume label = %q, want %q", got, "BOOT")
	}
	if got := string(data[54:62]); got != "FAT16   " {
		t.Errorf("filesystem type = %q, want %q", got, "FAT16   ")
	}
	if data[510] != 0x55 || data[511] != 0xAA {
		t.Errorf("boot sector signature = %#x %#x, want 0x55 0xAA", data[510], data[511])
	}

	// The two FATs must be identical and start with the media descriptor.
	fatSectors := int(le.Uint16(data[22:]))
	fat0 := data[4*512 : 4*512+fatSectors*512]
	fat1 := data[4*512+fatSectors*512 : 4*512+2*fatSectors*512]
	if !bytes.Equal(fat0, fat1) {
		t.Errorf("the two FATs differ")
	}
	if got := le.Uint16(fat0[0:]); got != 0xFFF8 {
		t.Errorf("FAT[0] = %#x, want 0xFFF8", got)
	}
	if got := le.Uint16(fat0[2:]); got != 0xFFFF {
		t.Errorf("FAT[1] = %#x, want 0xFFFF", got)
	}

	files := parseFAT16(t, data)
	want := map[string][]byte{
		"EFI/BOOT/BOOTX64.EFI": payload,
		"VERSION":              version,
	}
	for name, wantData := range want {
		got, ok := files[name]
		if !ok {
			t.Errorf("FAT16: %s not found (have %v)", name, keys(files))
			continue
		}
		if !bytes.Equal(got, wantData) {
			t.Errorf("FAT16: %s differs", name)
		}
	}
}

func TestFAT16Names(t *testing.T) {
	im, _ := newTestImage(t, nil)
	if err := im.WriteFAT16([]Entry{{Path: "EFI/BOOT/longfilename.efi"}}); err == nil {
		t.Errorf("WriteFAT16 accepted a name that is not 8.3")
	}
	if err := im.WriteFAT16([]Entry{{Path: "A", Data: []byte("a")}, {Path: "a", Data: []byte("b")}}); err == nil {
		t.Errorf("WriteFAT16 accepted colliding 8.3 names")
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// --- ext2 / ext4 -----------------------------------------------------------

type testExtFS struct {
	data      []byte
	blockSize uint32
	firstData uint32
	ipg       uint32
	itables   []uint32
}

func openTestExt(t *testing.T, data []byte) *testExtFS {
	t.Helper()
	le := binary.LittleEndian
	sb := data[1024:2048]
	if got := le.Uint16(sb[56:]); got != extMagic {
		t.Fatalf("ext magic = %#x, want %#x", got, extMagic)
	}
	fs := &testExtFS{
		data:      data,
		blockSize: 1024 << le.Uint32(sb[24:]),
		firstData: le.Uint32(sb[20:]),
		ipg:       le.Uint32(sb[40:]),
	}
	blocks := le.Uint32(sb[4:])
	bpg := le.Uint32(sb[32:])
	ngroups := (blocks - fs.firstData + bpg - 1) / bpg
	gdt := (fs.firstData + 1) * fs.blockSize
	for i := uint32(0); i < ngroups; i++ {
		d := data[gdt+i*32:]
		fs.itables = append(fs.itables, le.Uint32(d[8:]))
	}
	return fs
}

func (fs *testExtFS) inode(t *testing.T, ino uint32) []byte {
	t.Helper()
	g := (ino - 1) / fs.ipg
	idx := (ino - 1) % fs.ipg
	if int(g) >= len(fs.itables) {
		t.Fatalf("inode %d is outside the filesystem", ino)
	}
	off := fs.itables[g]*fs.blockSize + idx*extInodeSize
	return fs.data[off : off+extInodeSize]
}

func (fs *testExtFS) extents(t *testing.T, ino uint32) []extent {
	t.Helper()
	i := fs.inode(t, ino)
	b := i[40:100]
	le := binary.LittleEndian
	if got := le.Uint16(b[0:]); got != extentsMagic {
		t.Fatalf("inode %d: extent magic = %#x, want %#x", ino, got, extentsMagic)
	}
	if got := le.Uint16(b[6:]); got != 0 {
		t.Fatalf("inode %d: extent depth = %d, want 0", ino, got)
	}
	var out []extent
	for i := 0; i < int(le.Uint16(b[2:])); i++ {
		o := 12 + i*12
		out = append(out, extent{
			logical: le.Uint32(b[o:]),
			length:  le.Uint16(b[o+4:]),
			start:   le.Uint32(b[o+8:]),
		})
	}
	return out
}

func (fs *testExtFS) readFile(t *testing.T, ino uint32) []byte {
	t.Helper()
	i := fs.inode(t, ino)
	size := binary.LittleEndian.Uint32(i[4:])
	var out []byte
	for _, e := range fs.extents(t, ino) {
		for k := uint32(0); k < uint32(e.length); k++ {
			off := (e.start + k) * fs.blockSize
			out = append(out, fs.data[off:off+fs.blockSize]...)
		}
	}
	if uint32(len(out)) < size {
		t.Fatalf("inode %d: %d bytes of extents for size %d", ino, len(out), size)
	}
	return out[:size]
}

func (fs *testExtFS) readDir(t *testing.T, ino uint32) map[string]uint32 {
	t.Helper()
	i := fs.inode(t, ino)
	size := binary.LittleEndian.Uint32(i[4:])
	var dir []byte
	for _, e := range fs.extents(t, ino) {
		for k := uint32(0); k < uint32(e.length); k++ {
			off := (e.start + k) * fs.blockSize
			dir = append(dir, fs.data[off:off+fs.blockSize]...)
		}
	}
	if uint32(len(dir)) < size {
		t.Fatalf("inode %d: directory shorter than its size", ino)
	}
	out := map[string]uint32{}
	for off := uint32(0); off < size; {
		e := dir[off:]
		recLen := binary.LittleEndian.Uint16(e[4:])
		if recLen < 8 || recLen%4 != 0 || off+uint32(recLen) > size {
			t.Fatalf("inode %d: bad directory entry rec_len %d at %d", ino, recLen, off)
		}
		if child := binary.LittleEndian.Uint32(e[0:]); child != 0 {
			out[string(e[8:8+e[6]])] = child
		}
		off += uint32(recLen)
	}
	return out
}

func (fs *testExtFS) readTree(t *testing.T) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	var walk func(ino uint32, prefix string)
	walk = func(ino uint32, prefix string) {
		for name, child := range fs.readDir(t, ino) {
			if name == "." || name == ".." {
				continue
			}
			mode := binary.LittleEndian.Uint16(fs.inode(t, child)[0:])
			if mode&modeDir != 0 {
				walk(child, prefix+name+"/")
				continue
			}
			files[prefix+name] = fs.readFile(t, child)
		}
	}
	walk(2, "")
	return files
}

func testExtEntries(t *testing.T) []Entry {
	t.Helper()
	return []Entry{
		{Path: "var/pdb/system/image", Data: bytes.Repeat([]byte("NPK!"), 30000)}, // 120000 bytes
		{Path: "bin/milo", Data: []byte("\x7fELF milo"), Mode: 0o755},
		{Path: "bin/bash", Data: bytes.Repeat([]byte("bash"), 100), Mode: 0o755},
		{Path: "boot", Mode: 0o755}, // empty directory
		{Path: "rw/disk/rc.local", Data: []byte("#!/bin/sh\n")},
		{Path: "empty", Data: []byte{}},
		{Path: "nested/a/b/c/file.txt", Data: []byte("deep")},
	}
}

func wantExtFiles(t *testing.T, entries []Entry) map[string][]byte {
	t.Helper()
	want := map[string][]byte{}
	for _, e := range entries {
		if isDirEntry(e) {
			continue
		}
		want[strings.Trim(e.Path, "/")] = e.Data
	}
	return want
}

func checkExtSuperblock(t *testing.T, data []byte, blockSize int, label string, partSize int) {
	t.Helper()
	le := binary.LittleEndian
	sb := data[1024:2048]
	if got := le.Uint16(sb[56:]); got != extMagic {
		t.Fatalf("magic = %#x, want %#x", got, extMagic)
	}
	if got := le.Uint16(sb[58:]); got != extStateClean {
		t.Errorf("state = %d, want %d", got, extStateClean)
	}
	if got := le.Uint16(sb[60:]); got != extErrorsContinue {
		t.Errorf("errors = %d, want %d", got, extErrorsContinue)
	}
	if got := le.Uint16(sb[62:]); got != 0 {
		t.Errorf("minor revision = %d, want 0", got)
	}
	if got := le.Uint32(sb[76:]); got != extRevDynamic {
		t.Errorf("revision = %d, want %d", got, extRevDynamic)
	}
	if got := le.Uint32(sb[84:]); got != extFirstIno {
		t.Errorf("first inode = %d, want %d", got, extFirstIno)
	}
	if got := le.Uint16(sb[88:]); got != extInodeSize {
		t.Errorf("inode size = %d, want %d", got, extInodeSize)
	}
	if got := le.Uint32(sb[92:]); got != extFeatureCompat {
		t.Errorf("compat features = %#x, want %#x", got, extFeatureCompat)
	}
	if got := le.Uint32(sb[96:]); got != extFeatureIncompat {
		t.Errorf("incompat features = %#x, want %#x", got, extFeatureIncompat)
	}
	if got := le.Uint32(sb[100:]); got != extFeatureROCompat {
		t.Errorf("ro compat features = %#x, want %#x", got, extFeatureROCompat)
	}
	if got := le.Uint32(sb[24:]); got != logBlockSize(blockSize) {
		t.Errorf("log block size = %d, want %d", got, logBlockSize(blockSize))
	}
	if got := le.Uint32(sb[28:]); got != logBlockSize(blockSize) {
		t.Errorf("log cluster size = %d, want %d", got, logBlockSize(blockSize))
	}
	if got := le.Uint32(sb[32:]); got != uint32(8*blockSize) {
		t.Errorf("blocks per group = %d, want %d", got, 8*blockSize)
	}
	if got := le.Uint32(sb[4:]); got != uint32(partSize/blockSize) {
		t.Errorf("block count = %d, want %d", got, partSize/blockSize)
	}
	if got := le.Uint32(sb[0:]); got == 0 {
		t.Errorf("inode count is zero")
	}
	if got := le.Uint32(sb[12:]); got == 0 || got > le.Uint32(sb[4:]) {
		t.Errorf("free block count = %d, want 0 < free <= %d", got, le.Uint32(sb[4:]))
	}
	if got := le.Uint32(sb[16:]); got == 0 || got > le.Uint32(sb[0:]) {
		t.Errorf("free inode count = %d, want 0 < free <= %d", got, le.Uint32(sb[0:]))
	}
	if got := strings.TrimRight(string(sb[120:136]), "\x00"); got != label {
		t.Errorf("volume label = %q, want %q", got, label)
	}
	if bytes.Equal(sb[104:120], make([]byte, 16)) {
		t.Errorf("filesystem UUID is empty")
	}
	if got := sb[136:200]; !bytes.Equal(got, make([]byte, 64)) {
		t.Errorf("last mounted field is not empty: %q", got)
	}
	if got := le.Uint32(sb[20:]); got != uint32(1024/blockSize) {
		t.Errorf("first data block = %d, want %d", got, 1024/blockSize)
	}
}

// checkExtAccounting verifies the free counts in the superblock against the
// bitmaps.
func checkExtAccounting(t *testing.T, fs *testExtFS) {
	t.Helper()
	le := binary.LittleEndian
	sb := fs.data[1024:2048]
	blocks := le.Uint32(sb[4:])
	bpg := le.Uint32(sb[32:])
	ngroups := (blocks - fs.firstData + bpg - 1) / bpg
	gdt := (fs.firstData + 1) * fs.blockSize

	var freeBlocks, freeInodes uint32
	for i := uint32(0); i < ngroups; i++ {
		d := fs.data[gdt+i*32:]
		bb := le.Uint32(d[0:])
		ib := le.Uint32(d[4:])
		gstart := fs.firstData + i*bpg
		gblocks := blocks - gstart
		if gblocks > bpg {
			gblocks = bpg
		}
		for j := uint32(0); j < gblocks; j++ {
			if fs.data[bb*fs.blockSize+j/8]&(1<<(j%8)) == 0 {
				freeBlocks++
			}
		}
		for j := uint32(0); j < fs.ipg; j++ {
			if fs.data[ib*fs.blockSize+j/8]&(1<<(j%8)) == 0 {
				freeInodes++
			}
		}
	}
	if got, want := le.Uint32(sb[12:]), freeBlocks; got != want {
		t.Errorf("superblock free blocks = %d, bitmaps say %d", got, want)
	}
	if got, want := le.Uint32(sb[16:]), freeInodes; got != want {
		t.Errorf("superblock free inodes = %d, bitmaps say %d", got, want)
	}
}

func TestExt4(t *testing.T) {
	im, path := newTestImage(t, nil)
	entries := testExtEntries(t)
	if err := im.WriteExt4(entries); err != nil {
		t.Fatalf("WriteExt4: %v", err)
	}
	partSize := int(ROSEnd-ROSStart+1) * sectorSize
	data := readAt(t, path, int64(ROSStart)*sectorSize, partSize)

	checkExtSuperblock(t, data, 4096, "RouterOS", partSize)
	fs := openTestExt(t, data)
	if fs.blockSize != 4096 {
		t.Fatalf("block size = %d, want 4096", fs.blockSize)
	}
	checkExtAccounting(t, fs)

	files := fs.readTree(t)
	want := wantExtFiles(t, entries)
	for name, wantData := range want {
		got, ok := files[name]
		if !ok {
			t.Errorf("ext4: %s not found (have %v)", name, keys(files))
			continue
		}
		if !bytes.Equal(got, wantData) {
			t.Errorf("ext4: %s differs (%d bytes vs %d)", name, len(got), len(wantData))
		}
	}
	if len(files) != len(want) {
		t.Errorf("ext4: found %d files, want %d", len(files), len(want))
	}
}

func TestExt2(t *testing.T) {
	im, path := newTestImage(t, nil)
	entries := testExtEntries(t)
	if err := im.WriteExt2(entries); err != nil {
		t.Fatalf("WriteExt2: %v", err)
	}
	partSize := int(BootEnd-BootStart+1) * sectorSize
	data := readAt(t, path, int64(BootStart)*sectorSize, partSize)

	checkExtSuperblock(t, data, 1024, "RouterOS Boot", partSize)
	fs := openTestExt(t, data)
	if fs.blockSize != 1024 {
		t.Fatalf("block size = %d, want 1024", fs.blockSize)
	}
	if len(fs.itables) < 2 {
		t.Errorf("expected several block groups for the 1 KiB filesystem, got %d", len(fs.itables))
	}
	checkExtAccounting(t, fs)

	files := fs.readTree(t)
	want := wantExtFiles(t, entries)
	for name, wantData := range want {
		got, ok := files[name]
		if !ok {
			t.Errorf("ext2: %s not found (have %v)", name, keys(files))
			continue
		}
		if !bytes.Equal(got, wantData) {
			t.Errorf("ext2: %s differs (%d bytes vs %d)", name, len(got), len(wantData))
		}
	}
	if len(files) != len(want) {
		t.Errorf("ext2: found %d files, want %d", len(files), len(want))
	}
}

func TestTreeErrors(t *testing.T) {
	im, _ := newTestImage(t, nil)
	cases := [][]Entry{
		{{Path: "a", Data: []byte("1")}, {Path: "a", Data: []byte("2")}},
		{{Path: "a", Data: []byte("1")}, {Path: "a/b", Data: []byte("2")}},
		{{Path: "a/b", Data: []byte("1")}, {Path: "a", Data: []byte("2")}},
		{{Path: ""}},
		{{Path: "a/../b"}},
	}
	for _, entries := range cases {
		if err := im.WriteExt4(entries); err == nil {
			t.Errorf("WriteExt4 accepted entries %+v", entries)
		}
	}
}

// --- root-only mount tests -------------------------------------------------

func TestMountFAT16(t *testing.T) {
	im, path := newTestImage(t, nil)
	payload := bytes.Repeat([]byte("BOOTX64.EFI payload\n"), 5000)
	entries := []Entry{
		{Path: "EFI/BOOT/BOOTX64.EFI", Data: payload},
		{Path: "VERSION", Data: []byte("7.24.4\n")},
	}
	if err := im.WriteFAT16(entries); err != nil {
		t.Fatalf("WriteFAT16: %v", err)
	}
	mountAndCheck(t, path, BootStart, BootEnd-BootStart+1, "vfat", map[string][]byte{
		"EFI/BOOT/BOOTX64.EFI": payload,
		"VERSION":              []byte("7.24.4\n"),
	})
}

func TestMountExt4(t *testing.T) {
	im, path := newTestImage(t, nil)
	entries := testExtEntries(t)
	if err := im.WriteExt4(entries); err != nil {
		t.Fatalf("WriteExt4: %v", err)
	}
	mountAndCheck(t, path, ROSStart, ROSEnd-ROSStart+1, "ext4", wantExtFiles(t, entries))
}

func TestMountExt2(t *testing.T) {
	im, path := newTestImage(t, nil)
	entries := testExtEntries(t)
	if err := im.WriteExt2(entries); err != nil {
		t.Fatalf("WriteExt2: %v", err)
	}
	mountAndCheck(t, path, BootStart, BootEnd-BootStart+1, "ext4", wantExtFiles(t, entries))
}

// TestImageLayout is a smoke test for the whole CHR layout: a FAT boot
// partition and an ext4 RouterOS partition in one image.
func TestImageLayout(t *testing.T) {
	im, path := newTestImage(t, make([]byte, 446))
	if err := im.WriteFAT16([]Entry{{Path: "EFI/BOOT/BOOTX64.EFI", Data: []byte("efi")}}); err != nil {
		t.Fatal(err)
	}
	if err := im.WriteExt4([]Entry{{Path: "var/pdb/system/image", Data: []byte("npk")}}); err != nil {
		t.Fatal(err)
	}
	if err := im.Close(); err != nil {
		t.Fatal(err)
	}
	fat := readAt(t, path, int64(BootStart)*sectorSize, int(BootEnd-BootStart+1)*sectorSize)
	if got := parseFAT16(t, fat); !bytes.Equal(got["EFI/BOOT/BOOTX64.EFI"], []byte("efi")) {
		t.Errorf("FAT16 boot file missing: %v", keys(got))
	}
	partSize := int(ROSEnd-ROSStart+1) * sectorSize
	ros := readAt(t, path, int64(ROSStart)*sectorSize, partSize)
	fs := openTestExt(t, ros)
	if got := fs.readTree(t)["var/pdb/system/image"]; !bytes.Equal(got, []byte("npk")) {
		t.Errorf("ext4 system image missing")
	}
}
