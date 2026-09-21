package iso

import (
	"encoding/binary"
	"os"
	"testing"
)

const (
	isoAMD64 = "/tmp/build/7.24.4/mikrotik-7.24.4.iso"
	isoARM64 = "/tmp/build/7.24.4-arm64/mikrotik-7.24.4-arm64.iso"
)

// openTestImage opens an image for a test, skipping the test when the image
// is not present on this machine.
func openTestImage(t *testing.T, path string) *Image {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("test ISO not available: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	im, err := Open(f, fi.Size())
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	return im
}

// checkNPK verifies the RouterOS NPK magic 0xBAD0F11E and that the embedded
// payload length at bytes 4..8 matches the rest of the file.
func checkNPK(t *testing.T, data []byte) {
	t.Helper()
	if len(data) < 8 {
		t.Fatalf("file too short: %d bytes", len(data))
	}
	if data[0] != 0x1e || data[1] != 0xf1 || data[2] != 0xd0 || data[3] != 0xba {
		t.Fatalf("bad NPK magic % x, want 1e f1 d0 ba", data[:4])
	}
	if got := binary.LittleEndian.Uint32(data[4:8]); uint64(got) != uint64(len(data))-8 {
		t.Fatalf("embedded length %d does not match file size-8 (%d)", got, len(data)-8)
	}
}

func TestOpenRouterOSISO(t *testing.T) {
	im := openTestImage(t, isoAMD64)

	root := im.Root()
	if root == nil || !root.IsDir {
		t.Fatal("root is not a directory")
	}
	want := []string{
		"calea-7.24.4.npk",
		"container-7.24.4.npk",
		"dude-7.24.4.npk",
		"wireless-7.24.4.npk",
	}
	names := make(map[string]bool, len(root.Children))
	for _, c := range root.Children {
		names[c.Name] = true
	}
	for _, w := range want {
		if !names[w] {
			t.Errorf("root does not contain %q (root entries: %v)", w, keys(names))
		}
	}

	data, err := im.ReadFile("routeros-7.24.4.npk")
	if err != nil {
		t.Fatalf("ReadFile(routeros-7.24.4.npk): %v", err)
	}
	checkNPK(t, data)
}

func TestOpenRouterOSISOARM64(t *testing.T) {
	im := openTestImage(t, isoARM64)

	data, err := im.ReadFile("routeros-7.24.4-arm64.npk")
	if err != nil {
		t.Fatalf("ReadFile(routeros-7.24.4-arm64.npk): %v", err)
	}
	checkNPK(t, data)
}

func TestReadFileErrors(t *testing.T) {
	im := openTestImage(t, isoAMD64)

	for _, path := range []string{
		"",
		"no-such-file.npk",
		"routeros-7.24.4.npk/nested",
	} {
		if _, err := im.ReadFile(path); err == nil {
			t.Errorf("ReadFile(%q) returned no error", path)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
