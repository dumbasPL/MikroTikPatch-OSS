package build

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPackagesForArch(t *testing.T) {
	csv := "arch,name,size\n" +
		"x86,calea,24721\n" +
		"arm64,container,1187985\n" +
		"x86,container,1175697\n" +
		"arm64,calea,20625\n"
	got, err := packagesForArch(csv, "x86")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "calea" || got[1] != "container" {
		t.Fatalf("x86 packages = %v", got)
	}
	got, err = packagesForArch(csv, "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "container" || got[1] != "calea" {
		t.Fatalf("arm64 packages = %v", got)
	}
	if _, err := packagesForArch("not,a,csv\n", "x86"); err != nil {
		// A missing header is tolerated; no rows are expected.
		t.Logf("note: %v", err)
	}
}

func TestZipDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out.zip")
	if err := zipDir(dir, dest); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	if len(zr.File) != 2 {
		t.Fatalf("zip has %d entries, want 2", len(zr.File))
	}
	// Entries are sorted by name.
	if zr.File[0].Name != "a.txt" || zr.File[1].Name != "b.txt" {
		t.Fatalf("zip entries = %s, %s", zr.File[0].Name, zr.File[1].Name)
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	buf := make([]byte, 16)
	n, _ := rc.Read(buf)
	if strings.TrimSpace(string(buf[:n])) != "first" {
		t.Fatalf("a.txt content = %q", buf[:n])
	}
}

func TestArchExt(t *testing.T) {
	if archExt("x86") != "" {
		t.Error("x86 extension must be empty")
	}
	if archExt("arm64") != "-arm64" {
		t.Error("arm64 extension must be -arm64")
	}
}

func TestRepoRoot(t *testing.T) {
	root, err := RepoRoot()
	if err != nil {
		t.Skipf("not running from the repo: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "keygen", "keygen.c")); err != nil {
		t.Fatalf("RepoRoot %q does not look like the repo: %v", root, err)
	}
}

// TestCheckKeygenEmbedded covers the stale-keygen guard: keygen.c compiles the
// licence public key in as an ASCII hex string, and a keygen built without it
// carries the built-in fallback key instead.
func TestCheckKeygenEmbedded(t *testing.T) {
	key := "a7a7f00e6459d9f51234567890abcdef1234567890abcdef1234567890abcdef"
	path := filepath.Join(t.TempDir(), "keygen_x86")
	if err := os.WriteFile(path, []byte("binary junk "+strings.ToUpper(key)+" trailer"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkKeygenEmbedded(path, key); err != nil {
		t.Errorf("matching keygen rejected: %v", err)
	}
	if err := checkKeygenEmbedded(path, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"); err == nil {
		t.Error("non-matching key accepted")
	}
	if err := checkKeygenEmbedded(filepath.Join(t.TempDir(), "missing"), key); err == nil {
		t.Error("missing keygen accepted")
	}
	if err := checkKeygenEmbedded(path, ""); err == nil {
		t.Error("empty key accepted")
	}
}

// TestMoveFile covers the cross-device fallback: the default build dir is
// /tmp (a tmpfs) and the publish dir usually lives on another filesystem.
func TestMoveFile(t *testing.T) {
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "component.npk")
	content := []byte("signed package bytes")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}
	// Same filesystem: a plain rename.
	sameDir := t.TempDir()
	dst := filepath.Join(sameDir, "component.npk")
	if err := moveFile(src, dst); err != nil {
		t.Fatalf("same-device move: %v", err)
	}
	if got, err := os.ReadFile(dst); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("same-device move content: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("source still exists after move")
	}

	// Cross filesystem: find a second writable directory on another device.
	other := ""
	for _, cand := range []string{os.Getenv("MOVE_FILE_OTHER_FS"), "/dev/shm"} {
		if cand == "" {
			continue
		}
		st, err := os.Stat(cand)
		if err != nil || !st.IsDir() {
			continue
		}
		base, err := os.Stat(srcDir)
		if err != nil {
			continue
		}
		a, ok1 := st.Sys().(*syscall.Stat_t)
		b, ok2 := base.Sys().(*syscall.Stat_t)
		if ok1 && ok2 && a.Dev != b.Dev {
			other = cand
			break
		}
	}
	if other == "" {
		t.Skip("no second filesystem available for the EXDEV fallback")
	}
	src2 := filepath.Join(srcDir, "component2.npk")
	if err := os.WriteFile(src2, content, 0o644); err != nil {
		t.Fatal(err)
	}
	dst2, err := os.MkdirTemp(other, "movefile")
	if err != nil {
		t.Skipf("cannot create a directory on %s: %v", other, err)
	}
	defer os.RemoveAll(dst2)
	target := filepath.Join(dst2, "component2.npk")
	if err := moveFile(src2, target); err != nil {
		t.Fatalf("cross-device move: %v", err)
	}
	if got, err := os.ReadFile(target); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("cross-device move content: %v", err)
	}
	if _, err := os.Stat(src2); !os.IsNotExist(err) {
		t.Fatal("cross-device source still exists")
	}
}
