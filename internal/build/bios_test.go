package build

import (
	"os"
	"path/filepath"
	"testing"

	"mikrotikpatch/internal/image"
	"mikrotikpatch/internal/npk"
)

// TestBuildBIOSImage builds a legacy-BIOS image from a patched NPK.  It is
// gated on BIOS_TEST_NPK because it needs a real RouterOS package and milo:
//
//	BIOS_TEST_NPK=publish/7.24.4/routeros-7.24.4.npk go test ./internal/build/
func TestBuildBIOSImage(t *testing.T) {
	npkPath := os.Getenv("BIOS_TEST_NPK")
	if npkPath == "" {
		t.Skip("BIOS_TEST_NPK not set")
	}
	pkg, err := npk.Load(npkPath)
	if err != nil {
		t.Fatal(err)
	}
	efi, err := pkg.ExtractFile("boot/EFI/BOOT/BOOTX64.EFI")
	if err != nil {
		t.Fatal(err)
	}
	miloBin, err := pkg.ExtractFile("bin/milo")
	if err != nil {
		t.Fatal(err)
	}
	bash, err := pkg.ExtractFile("bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	imageData, err := os.ReadFile(npkPath)
	if err != nil {
		t.Fatal(err)
	}
	var ros []image.Entry
	for _, dir := range []string{"var", "var/pdb", "var/pdb/system", "boot", "bin", "rw", "rw/disk"} {
		ros = append(ros, image.Entry{Path: dir, Mode: image.DirMode | 0o755})
	}
	ros = append(ros, image.Entry{Path: "var/pdb/system/image", Data: imageData})
	ros = append(ros, image.Entry{Path: "bin/bash", Data: bash, Mode: 0o755})

	c := &Config{Options: Options{Version: "test"}}
	target := filepath.Join(t.TempDir(), "chr-test-legacy-bios.img")
	if err := c.buildBIOSImage(target, efi, miloBin, ros); err != nil {
		t.Fatalf("buildBIOSImage: %v", err)
	}
	st, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != image.DiskSize {
		t.Fatalf("image size %d, want %d", st.Size(), image.DiskSize)
	}
	// The boot partition's boot sector must carry milo's VBR (EB xx ...).
	f, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	vbr := make([]byte, 4)
	if _, err := f.ReadAt(vbr, int64(image.BootStart)*512); err != nil {
		t.Fatal(err)
	}
	if vbr[0] != 0xEB {
		t.Fatalf("first boot sector bytes %x, want an EB jump", vbr)
	}
}
