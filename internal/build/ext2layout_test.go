package build

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"mikrotikpatch/internal/image"
)

// TestExt2FileLayout builds a boot partition with the image writer and checks
// that the layout parser recovers the block lists (reading the data back from
// the reported blocks must reproduce the files).
func TestExt2FileLayout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "disk.img")
	im, err := image.Create(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	efi := make([]byte, 3*1024*1024+123)
	for i := range efi {
		efi[i] = byte(i * 31)
	}
	mapData := make([]byte, 60000)
	for i := range mapData {
		mapData[i] = byte(i * 7)
	}
	if err := im.WriteExt2([]image.Entry{
		{Path: "EFI/BOOT/BOOTX64.EFI", Data: efi, Mode: 0o644},
		{Path: "map", Data: mapData, Mode: 0o644},
	}); err != nil {
		t.Fatal(err)
	}
	if err := im.Close(); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := ext2FileLayout(disk, image.BootStart)
	if err != nil {
		t.Fatalf("ext2FileLayout: %v", err)
	}
	if len(layout["EFI/BOOT/BOOTX64.EFI"]) == 0 || len(layout["map"]) == 0 {
		t.Fatalf("layout missing files: %v", keysOf(layout))
	}
	// Read the data back through the reported blocks.
	readFile := func(name string, size int) []byte {
		var out []byte
		for _, block := range layout[name] {
			off := int(image.BootStart)*512 + int(block)*1024
			end := off + 1024
			if end > len(disk) {
				end = len(disk)
			}
			out = append(out, disk[off:end]...)
		}
		if len(out) < size {
			t.Fatalf("%s: only %d bytes at the reported blocks, want %d", name, len(out), size)
		}
		return out[:size]
	}
	if got := readFile("EFI/BOOT/BOOTX64.EFI", len(efi)); !bytes.Equal(got, efi) {
		t.Error("EFI file does not round-trip through the layout")
	}
	if got := readFile("map", len(mapData)); !bytes.Equal(got, mapData) {
		t.Error("map file does not round-trip through the layout")
	}
}

func keysOf(m map[string][]uint64) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
