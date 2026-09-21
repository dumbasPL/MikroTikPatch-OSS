package squashfs_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"mikrotikpatch/internal/npk"
	"mikrotikpatch/internal/squashfs"
)

// TestReadComponentNPKs reads the squashfs image of every .npk in a directory;
// it covers the extended-inode, sparse-block and 512K-block variants used by
// the component packages.
//
//	SQUASHFS_TEST_NPK_DIR=/tmp/build/7.24.4-arm64/all_packages go test ./internal/squashfs/
func TestReadComponentNPKs(t *testing.T) {
	dir := os.Getenv("SQUASHFS_TEST_NPK_DIR")
	if dir == "" {
		t.Skip("SQUASHFS_TEST_NPK_DIR not set")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	read := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".npk" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		pkg, err := npk.Unmarshal(data)
		if err != nil {
			t.Errorf("%s: %v", e.Name(), err)
			continue
		}
		parts := [][]byte{}
		if part := pkg.Get(npk.PartSquashfs); part != nil {
			parts = append(parts, part.Bytes())
		}
		for _, p := range pkg.Packages {
			if part := p.Get(npk.PartSquashfs); part != nil {
				parts = append(parts, part.Bytes())
			}
		}
		for _, part := range parts {
			if _, err := squashfs.ReadAll(bytes.NewReader(part), int64(len(part))); err != nil {
				t.Errorf("%s: %v", e.Name(), err)
			} else {
				read++
			}
		}
	}
	t.Logf("read %d squashfs images", read)
}
