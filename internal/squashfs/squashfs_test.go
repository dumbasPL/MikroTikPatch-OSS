package squashfs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestReadStockImage verifies the reader against a stock RouterOS squashfs and
// a reference extraction made with unsquashfs:
//
//	SQUASHFS_TEST_IMAGE=/path/system.squashfs \
//	SQUASHFS_TEST_TREE=/path/unsquashfs-output go test ./internal/squashfs/
func TestReadStockImage(t *testing.T) {
	image := os.Getenv("SQUASHFS_TEST_IMAGE")
	tree := os.Getenv("SQUASHFS_TEST_TREE")
	if image == "" || tree == "" {
		t.Skip("SQUASHFS_TEST_IMAGE/SQUASHFS_TEST_TREE not set")
	}
	data, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	root, err := ReadAll(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	var files, dirs, links int
	err = root.Walk(func(path string, n *Node) error {
		if path == "" {
			return nil
		}
		ref := filepath.Join(tree, path)
		switch n.Type {
		case TypeDir:
			dirs++
			st, err := os.Stat(ref)
			if err != nil || !st.IsDir() {
				return os.ErrNotExist
			}
		case TypeFile:
			files++
			want, err := os.ReadFile(ref)
			if err != nil {
				return err
			}
			if !bytes.Equal(want, n.Data) {
				t.Errorf("%s: content differs (%d vs %d bytes)", path, len(want), len(n.Data))
			}
		case TypeSymlink:
			links++
			want, err := os.Readlink(ref)
			if err != nil {
				return err
			}
			if want != string(n.Data) {
				t.Errorf("%s: symlink %q != %q", path, n.Data, want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	t.Logf("verified %d files, %d dirs, %d symlinks", files, dirs, links)
}
