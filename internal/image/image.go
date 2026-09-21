// Package image builds MikroTik CHR disk images in userspace.
//
// A CHR image is a 128 MiB GPT disk with a hybrid MBR.  Partition 1 is the
// 32 MiB boot partition (FAT16 for UEFI boot, ext2 for the legacy BIOS
// loader) and partition 2 is the 94 MiB RouterOS partition (ext4).  All of
// the on-disk structures are written directly to the image file, replacing
// sgdisk, mkfs.fat, mkfs.ext2, mkfs.ext4, qemu-nbd and mount.
package image

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"os"
	"strings"
	"unicode/utf16"
)

// Disk geometry, in 512-byte sectors.
const (
	// DiskSize is the size of a CHR disk image in bytes.
	DiskSize = 128 << 20
	// BootStart and BootEnd delimit partition 1, the boot partition.
	BootStart = 34
	BootEnd   = 65535
	// ROSStart and ROSEnd delimit partition 2, the RouterOS partition.
	ROSStart = 65536
	ROSEnd   = 258047
)

const (
	sectorSize = 512

	// GPT layout.
	gptEntryLBA        = 2
	gptEntryCount      = 128
	gptEntrySize       = 128
	gptFirstUsable     = 34
	gptLastUsable      = 262110
	gptBackupEntryLBA  = 262111
	gptBackupHeaderLBA = 262143
	gptHeaderSize      = 92
	gptRevision        = 0x00010000
)

// Entry describes one file or directory to place in a filesystem.
//
// Path is slash separated, for example "EFI/BOOT/BOOTX64.EFI" or
// "var/pdb/system/image".  Intermediate directories are created implicitly
// with mode 0755.  An entry describes a directory if Path ends with a slash,
// if Mode has the S_IFDIR bit set (see DirMode) or, for an entry without
// data, if Mode is exactly 0755; directories always get mode 0755.  Every
// other entry is a regular file whose permissions come from Mode (0644 when
// Mode is zero).
type Entry struct {
	Path string
	Data []byte
	Mode uint16
}

// DirMode is the S_IFDIR bit; setting it in Entry.Mode marks an entry as a
// directory.  Directories always get mode 0755.
const DirMode = 0o040000

// Image is an open CHR disk image.  Partitions can be formatted in any
// order; each write only touches its own partition.
type Image struct {
	f *os.File
}

// Create creates or truncates the 128 MiB disk image at path and writes the
// GPT and hybrid MBR of a MikroTik CHR image.  biosCode, when non-nil, is
// the legacy BIOS boot code written at offset 0 (at most 446 bytes).
func Create(path string, biosCode []byte) (*Image, error) {
	if len(biosCode) > 446 {
		return nil, fmt.Errorf("image: BIOS boot code is %d bytes, maximum is 446", len(biosCode))
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}
	im := &Image{f: f}
	if err := f.Truncate(DiskSize); err != nil {
		im.Close()
		return nil, err
	}
	if err := im.writeMBR(biosCode); err != nil {
		im.Close()
		return nil, err
	}
	if err := im.writeGPT(); err != nil {
		im.Close()
		return nil, err
	}
	return im, nil
}

// Close flushes and closes the image file.
func (im *Image) Close() error {
	err := im.f.Sync()
	if cerr := im.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// mbrEntries is the hybrid MBR partition table of a CHR image, byte for byte
// as found in the official images.  Entry 1 marks the FAT boot partition
// active, entry 2 describes the RouterOS partition and entry 3 is the
// protective GPT entry covering LBA 1..33.
var mbrEntries = [4][16]byte{
	{0x80, 0x00, 0x23, 0x00, 0x83, 0x14, 0x10, 0x04, 0x22, 0x00, 0x00, 0x00, 0xDE, 0xFF, 0x00, 0x00},
	{0x00, 0x14, 0x11, 0x04, 0x83, 0x0F, 0x3F, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0xF0, 0x02, 0x00},
	{0x00, 0x00, 0x02, 0x00, 0xEE, 0x00, 0x22, 0x00, 0x01, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00},
	{},
}

// writeMBR writes the boot code, the hybrid MBR partition table, the active
// CHR mode byte and the 0x55AA signature.
func (im *Image) writeMBR(biosCode []byte) error {
	var mbr [sectorSize]byte
	copy(mbr[:], biosCode)
	for i := range mbrEntries {
		copy(mbr[446+i*16:], mbrEntries[i][:])
	}
	mbr[0x150] = 1 // active CHR mode
	mbr[510] = 0x55
	mbr[511] = 0xAA
	return im.writeAt(0, mbr[:])
}

// writeGPT writes the primary GPT header and entry array at LBA 1..33 and
// the backup copies at the end of the disk.
func (im *Image) writeGPT() error {
	diskGUID, err := randomGUID()
	if err != nil {
		return err
	}
	part1GUID, err := randomGUID()
	if err != nil {
		return err
	}
	part2GUID, err := randomGUID()
	if err != nil {
		return err
	}
	entries := make([]byte, gptEntryCount*gptEntrySize)
	putPartEntry(entries[0*gptEntrySize:], espTypeGUID, part1GUID, BootStart, BootEnd, "RouterOS Boot")
	putPartEntry(entries[1*gptEntrySize:], linuxTypeGUID, part2GUID, ROSStart, ROSEnd, "RouterOS")
	entryCRC := crc32.ChecksumIEEE(entries)

	primary := marshalGPTHeader(gptHeader{
		current:  1,
		backup:   gptBackupHeaderLBA,
		entryLBA: gptEntryLBA,
		entryCRC: entryCRC,
		diskGUID: diskGUID,
	})
	backup := marshalGPTHeader(gptHeader{
		current:  gptBackupHeaderLBA,
		backup:   1,
		entryLBA: gptBackupEntryLBA,
		entryCRC: entryCRC,
		diskGUID: diskGUID,
	})
	if err := im.writeAt(1*sectorSize, primary); err != nil {
		return err
	}
	if err := im.writeAt(gptEntryLBA*sectorSize, entries); err != nil {
		return err
	}
	if err := im.writeAt(gptBackupEntryLBA*sectorSize, entries); err != nil {
		return err
	}
	return im.writeAt(gptBackupHeaderLBA*sectorSize, backup)
}

// gptHeader is the variable part of a GPT header.
type gptHeader struct {
	current  uint64
	backup   uint64
	entryLBA uint64
	entryCRC uint32
	diskGUID [16]byte
}

// marshalGPTHeader serialises a 92-byte GPT header, filling in the CRC.
func marshalGPTHeader(h gptHeader) []byte {
	b := make([]byte, gptHeaderSize)
	copy(b, "EFI PART")
	le := binary.LittleEndian
	le.PutUint32(b[8:], gptRevision)
	le.PutUint32(b[12:], gptHeaderSize)
	le.PutUint64(b[24:], h.current)
	le.PutUint64(b[32:], h.backup)
	le.PutUint64(b[40:], gptFirstUsable)
	le.PutUint64(b[48:], gptLastUsable)
	copy(b[56:], h.diskGUID[:])
	le.PutUint64(b[72:], h.entryLBA)
	le.PutUint32(b[80:], gptEntryCount)
	le.PutUint32(b[84:], gptEntrySize)
	le.PutUint32(b[88:], h.entryCRC)
	le.PutUint32(b[16:], crc32.ChecksumIEEE(b))
	return b
}

// putPartEntry serialises one 128-byte GPT partition entry.
func putPartEntry(b []byte, typ, unique [16]byte, first, last uint64, name string) {
	copy(b[0:16], typ[:])
	copy(b[16:32], unique[:])
	le := binary.LittleEndian
	le.PutUint64(b[32:], first)
	le.PutUint64(b[40:], last)
	// attributes (48:56) stay zero
	for i, r := range utf16.Encode([]rune(name)) {
		if i >= 36 {
			break
		}
		le.PutUint16(b[56+2*i:], r)
	}
}

var (
	// EFI System partition type; on disk 28732ac1-1ff8-d211-ba4b-00a0c93ec93b.
	espTypeGUID = mustGUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
	// Linux filesystem partition type; on disk af3dc60f-8384-7247-8e79-3d69d8477de4.
	linuxTypeGUID = mustGUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
)

// mustGUID converts a canonical GUID string to the mixed-endian byte order
// used on disk by GPT.
func mustGUID(s string) [16]byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		panic("image: bad GUID " + s)
	}
	var g [16]byte
	g[0], g[1], g[2], g[3] = b[3], b[2], b[1], b[0]
	g[4], g[5] = b[5], b[4]
	g[6], g[7] = b[7], b[6]
	copy(g[8:], b[8:])
	return g
}

// randomGUID returns a random version 4 GUID in on-disk byte order.
func randomGUID() ([16]byte, error) {
	var g [16]byte
	if _, err := rand.Read(g[:]); err != nil {
		return g, err
	}
	g[7] = g[7]&0x0F | 0x40
	g[8] = g[8]&0x3F | 0x80
	return g, nil
}

// writeAt writes b at the given byte offset of the image file.
func (im *Image) writeAt(off int64, b []byte) error {
	if _, err := im.f.WriteAt(b, off); err != nil {
		return fmt.Errorf("image: write at offset %d: %w", off, err)
	}
	return nil
}

// partitionRange returns the byte offset and size of a partition.
func partitionRange(start, end uint64) (int64, int) {
	return int64(start) * sectorSize, int((end - start + 1) * sectorSize)
}
