package patch

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"mikrotikpatch/internal/lzma"
)

// KeyPair is an old -> new public key replacement.
type KeyPair struct {
	Old []byte
	New []byte
}

var (
	xzHeader = []byte{0xFD, '7', 'z', 'X', 'Z', 0x00, 0x00, 0x01}
	xzFooter = []byte{0x00, 0x00, 0x00, 0x00, 0x01, 'Y', 'Z'}

	cpioHeaderMagic = []byte("07070100")
	cpioFooterMagic = []byte("TRAILER!!!\x00\x00\x00\x00")
)

// PatchBzImage patches an x86 bzImage with its embedded initramfs.  arch is
// the RouterOS architecture (ARCH-style, e.g. "x86" or "arm64").
func PatchBzImage(data []byte, keys []KeyPair, arch string) ([]byte, error) {
	const (
		peTextSectionOffset       = 414
		headerPayloadOffset       = 584
		headerPayloadLengthOffset = headerPayloadOffset + 4
	)
	if len(data) < headerPayloadLengthOffset+4 {
		return nil, errors.New("patch: bzImage too short")
	}
	textSectionRawData := binary.LittleEndian.Uint32(data[peTextSectionOffset:])
	payloadOffset := int(textSectionRawData) + int(binary.LittleEndian.Uint32(data[headerPayloadOffset:]))
	payloadLength := int(binary.LittleEndian.Uint32(data[headerPayloadLengthOffset:])) - 4
	if payloadOffset < 0 || payloadOffset+payloadLength+4 > len(data) || payloadLength <= 0 {
		return nil, errors.New("patch: invalid bzImage payload offsets")
	}
	zOutputLen := binary.LittleEndian.Uint32(data[payloadOffset+payloadLength:])
	vmlinuxXZ := data[payloadOffset : payloadOffset+payloadLength]
	vmlinux, err := lzma.Decode(vmlinuxXZ)
	if err != nil {
		return nil, fmt.Errorf("patch: decompress vmlinux: %w", err)
	}
	if int(zOutputLen) != len(vmlinux) {
		return nil, errors.New("patch: vmlinux size does not match the header")
	}

	cpioOffset := bytes.Index(vmlinux, cpioHeaderMagic)
	if cpioOffset < 0 {
		return nil, errors.New("patch: cpio initramfs not found")
	}
	initramfs := vmlinux[cpioOffset:]
	cpioEnd := bytes.Index(initramfs, cpioFooterMagic)
	if cpioEnd < 0 {
		return nil, errors.New("patch: cpio trailer not found")
	}
	cpioEnd += len(cpioFooterMagic)
	initramfs = initramfs[:cpioEnd]

	newInitramfs := initramfs
	for _, k := range keys {
		newInitramfs = ReplaceKeyArch(k.Old, k.New, newInitramfs, "initramfs", arch)
	}
	newVmlinux := bytes.ReplaceAll(vmlinux, initramfs, newInitramfs)
	newVmlinuxXZ, err := lzma.Encode(newVmlinux, lzma.Options{
		BCJX86:   true,
		Preset:   9 | lzma.PresetExtreme,
		DictSize: 32 * 1024 * 1024,
		LC:       4, LP: 0, PB: 0,
		SetProps: true,
		Check:    lzma.CheckCRC32,
	})
	if err != nil {
		return nil, fmt.Errorf("patch: compress vmlinux: %w", err)
	}
	if len(newVmlinuxXZ) > payloadLength {
		return nil, fmt.Errorf("patch: new vmlinux.xz size is too big (%d > %d)", len(newVmlinuxXZ), payloadLength)
	}
	newPayloadLength := len(newVmlinuxXZ) + 4

	var zlen [4]byte
	binary.LittleEndian.PutUint32(zlen[:], zOutputLen)
	vmlinuxXZ = append(append([]byte(nil), vmlinuxXZ...), zlen[:]...)
	newVmlinuxXZ = append(newVmlinuxXZ, zlen[:]...)
	if len(newVmlinuxXZ) < len(vmlinuxXZ) {
		newVmlinuxXZ = append(newVmlinuxXZ, make([]byte, len(vmlinuxXZ)-len(newVmlinuxXZ))...)
	}

	newData := append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(newData[headerPayloadLengthOffset:], uint32(newPayloadLength))
	return bytes.ReplaceAll(newData, vmlinuxXZ, newVmlinuxXZ), nil
}

// PatchInitrdXZ replaces the keys in an XZ-compressed initrd and recompresses
// it.  LZMA2 presets are raised until the result fits the original size; with
// pad the result is zero-padded to the original length.  arch is the RouterOS
// architecture (ARCH-style, e.g. "x86" or "arm64").
func PatchInitrdXZ(initrdXZ []byte, keys []KeyPair, arch string, pad bool) ([]byte, error) {
	initrd, err := lzma.Decode(initrdXZ)
	if err != nil {
		header := initrdXZ
		if len(header) > 20 {
			header = header[:20]
		}
		footer := initrdXZ
		if len(footer) > 20 {
			footer = footer[len(footer)-20:]
		}
		return nil, fmt.Errorf("patch: failed to decompress initrd (size %d, header %X, footer %X): %w",
			len(initrdXZ), header, footer, err)
	}
	for _, k := range keys {
		initrd = ReplaceKeyArch(k.Old, k.New, initrd, "initrd", arch)
	}

	compress := func(opt lzma.Options) ([]byte, error) {
		return lzma.Encode(initrd, opt)
	}
	var result []byte
	for preset := uint32(6); preset <= 9; preset++ {
		r, err := compress(lzma.Options{Preset: preset, Check: lzma.CheckCRC32})
		if err != nil {
			return nil, fmt.Errorf("patch: compress initrd: %w", err)
		}
		if len(r) <= len(initrdXZ) {
			result = r
			break
		}
	}
	if result == nil {
		result, err = compress(lzma.Options{
			Preset:   9 | lzma.PresetExtreme,
			DictSize: 32 * 1024 * 1024,
			LC:       4, LP: 0, PB: 0,
			SetProps: true,
			Check:    lzma.CheckCRC32,
		})
		if err != nil {
			return nil, fmt.Errorf("patch: compress initrd: %w", err)
		}
	}
	if pad {
		if len(result) > len(initrdXZ) {
			return nil, fmt.Errorf("patch: new initrd xz size is too big (%d > %d)", len(result), len(initrdXZ))
		}
		result = append(result, make([]byte, len(initrdXZ)-len(result))...)
	}
	return result, nil
}

// XZStream is a (start, end) span of an XZ stream in a byte slice.
type XZStream struct {
	Start int
	End   int
}

// FindXZStreams returns the span of every XZ stream in data.
func FindXZStreams(data []byte) []XZStream {
	var streams []XZStream
	offset := 0
	for {
		start := bytes.Index(data[offset:], xzHeader)
		if start < 0 {
			break
		}
		start += offset
		footer := bytes.Index(data[start:], xzFooter)
		if footer < 0 {
			break
		}
		end := start + footer + len(xzFooter)
		streams = append(streams, XZStream{Start: start, End: end})
		offset = end
	}
	return streams
}

// Find7zXZData returns the last XZ stream in data (the initramfs); earlier
// streams are left untouched.
func Find7zXZData(data []byte) []byte {
	start := bytes.LastIndex(data, xzHeader)
	end := bytes.LastIndex(data, xzFooter)
	if start < 0 || end < start {
		return nil
	}
	return data[start : end+len(xzFooter)]
}

// PatchELF patches the initramfs stream carried in an ELF kernel.  arch is the
// RouterOS architecture (ARCH-style).
func PatchELF(data []byte, keys []KeyPair, arch string) ([]byte, error) {
	initrdXZ := Find7zXZData(data)
	if len(initrdXZ) == 0 {
		return nil, errors.New("patch: XZ initrd stream not found")
	}
	newXZ, err := PatchInitrdXZ(initrdXZ, keys, arch, true)
	if err != nil {
		return nil, err
	}
	return bytes.ReplaceAll(data, initrdXZ, newXZ), nil
}

// PatchPE patches the initramfs inside a PE/EFI kernel image.
func PatchPE(data []byte, keys []KeyPair, arch string) ([]byte, error) {
	vmlinuxXZ := Find7zXZData(data)
	if len(vmlinuxXZ) == 0 {
		return nil, errors.New("patch: XZ vmlinux stream not found")
	}
	vmlinux, err := lzma.Decode(vmlinuxXZ)
	if err != nil {
		return nil, fmt.Errorf("patch: decompress vmlinux: %w", err)
	}
	initrdOffset := bytes.Index(vmlinux, xzHeader)
	if initrdOffset < 0 {
		return nil, errors.New("patch: initramfs stream not found in vmlinux")
	}
	initrdEnd := bytes.Index(vmlinux[initrdOffset:], xzFooter)
	if initrdEnd < 0 {
		return nil, errors.New("patch: initramfs footer not found in vmlinux")
	}
	initrdSize := initrdEnd + len(xzFooter)
	initrdXZ := vmlinux[initrdOffset : initrdOffset+initrdSize]
	newInitrdXZ, err := PatchInitrdXZ(initrdXZ, keys, arch, true)
	if err != nil {
		return nil, err
	}
	newVmlinux := bytes.ReplaceAll(vmlinux, initrdXZ, newInitrdXZ)
	newVmlinuxXZ, err := lzma.Encode(newVmlinux, lzma.Options{Preset: 9, Check: lzma.CheckCRC32})
	if err != nil {
		return nil, fmt.Errorf("patch: compress vmlinux: %w", err)
	}
	if len(newVmlinuxXZ) > len(vmlinuxXZ) {
		return nil, fmt.Errorf("patch: new vmlinux xz size is too big (%d > %d)", len(newVmlinuxXZ), len(vmlinuxXZ))
	}
	newVmlinuxXZ = append(newVmlinuxXZ, make([]byte, len(vmlinuxXZ)-len(newVmlinuxXZ))...)
	return bytes.ReplaceAll(data, vmlinuxXZ, newVmlinuxXZ), nil
}

// PatchKernel dispatches on the container format.  arch is the RouterOS
// architecture (ARCH-style, e.g. "x86" or "arm64").
func PatchKernel(data []byte, keys []KeyPair, arch string) ([]byte, error) {
	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		if len(data) >= 60 && string(data[56:60]) == "ARM\x64" {
			Logf("patching arm64 EFI kernel\n")
			return PatchELF(data, keys, arch)
		}
		Logf("patching x86_64 bzImage kernel\n")
		return PatchBzImage(data, keys, arch)
	}
	if bytes.HasPrefix(data, []byte{0x7F, 'E', 'L', 'F'}) {
		Logf("patching ELF kernel\n")
		return PatchELF(data, keys, arch)
	}
	if bytes.HasPrefix(data, []byte{0xFD, '7', 'z', 'X', 'Z'}) {
		Logf("patching initrd\n")
		return PatchInitrdXZ(data, keys, arch, false)
	}
	return nil, errors.New("patch: unknown kernel format")
}

// peSection is a PE section table entry.
type peSection struct {
	name                string
	virtualAddress      uint32
	sizeOfRawData       uint32
	pointerToRawData    uint32
	sizeOfRawDataOffset int // file offset of the SizeOfRawData field
}

// parsePE finds a section by name in a PE image.
func parsePE(data []byte) (*peSection, error) {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return nil, errors.New("patch: not a PE image")
	}
	lfanew := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if lfanew+24 > len(data) || string(data[lfanew:lfanew+4]) != "PE\x00\x00" {
		return nil, errors.New("patch: invalid PE header")
	}
	nSections := int(binary.LittleEndian.Uint16(data[lfanew+6:]))
	optSize := int(binary.LittleEndian.Uint16(data[lfanew+20:]))
	table := lfanew + 24 + optSize
	if table+nSections*40 > len(data) {
		return nil, errors.New("patch: truncated PE section table")
	}
	for i := 0; i < nSections; i++ {
		off := table + i*40
		entry := data[off : off+40]
		name := string(bytes.TrimRight(entry[:8], "\x00"))
		if name != ".data" {
			continue
		}
		return &peSection{
			name:                name,
			virtualAddress:      binary.LittleEndian.Uint32(entry[12:]),
			sizeOfRawData:       binary.LittleEndian.Uint32(entry[16:]),
			pointerToRawData:    binary.LittleEndian.Uint32(entry[20:]),
			sizeOfRawDataOffset: off + 16,
		}, nil
	}
	return nil, errors.New("patch: .data section not found")
}

// BuildEFI builds the UEFI executable from the arm64 kernel.  The kernel ELF
// carries two XZ streams in its initrd section (the EFI stub and the cpio
// initramfs); the stub's .data section is extended with the cpio stream and
// only the part of the PE file up to that section is kept.
func BuildEFI(inputFile, outputFile string) error {
	f, err := elf.Open(inputFile)
	if err != nil {
		return fmt.Errorf("patch: open ELF: %w", err)
	}
	defer f.Close()
	section := f.Section("initrd")
	if section == nil {
		return errors.New("patch: initrd section not found")
	}
	sectionData, err := section.Data()
	if err != nil {
		return fmt.Errorf("patch: read initrd section: %w", err)
	}
	streams := FindXZStreams(sectionData)
	if len(streams) != 2 {
		return errors.New("patch: only kernels with 2 XZ streams are supported")
	}
	efiXZ := sectionData[streams[0].Start:streams[0].End]
	cpioXZ := sectionData[streams[1].Start:streams[1].End]

	efi, err := lzma.Decode(efiXZ)
	if err != nil {
		return fmt.Errorf("patch: decompress EFI stub: %w", err)
	}
	sec, err := parsePE(efi)
	if err != nil {
		return err
	}
	addr := int(sec.pointerToRawData)
	end := addr + int(sec.sizeOfRawData)
	if addr < 0 || end > len(efi) {
		return errors.New("patch: .data section out of range")
	}
	old := efi[addr:end]
	align := (4096 - (int(sec.virtualAddress)+len(old))%4096) % 4096
	newData := make([]byte, 0, len(old)+align+4+len(cpioXZ))
	newData = append(newData, old...)
	newData = append(newData, make([]byte, align)...)
	var cpioLen [4]byte
	binary.LittleEndian.PutUint32(cpioLen[:], uint32(len(cpioXZ)))
	newData = append(newData, cpioLen[:]...)
	newData = append(newData, cpioXZ...)

	out := append([]byte(nil), efi...)
	binary.LittleEndian.PutUint32(out[sec.sizeOfRawDataOffset:], uint32(len(newData)))
	out = append(out[:addr], newData...)
	if err := os.WriteFile(outputFile, out, 0644); err != nil {
		return err
	}
	return nil
}
