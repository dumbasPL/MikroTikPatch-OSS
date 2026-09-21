package squashfs

import (
	"bytes"
	"testing"
)

func sampleTree() *Node {
	file := func(name string, data []byte, mode uint16) *Node {
		return &Node{Name: name, Type: TypeFile, Mode: mode, Data: data, MTime: 1700000000}
	}
	dir := func(name string, children ...*Node) *Node {
		return &Node{Name: name, Type: TypeDir, Mode: 0o755, Children: children, MTime: 1700000000}
	}
	big := make([]byte, 600*1024)
	for i := range big {
		big[i] = byte(i * 7)
	}
	empty := []byte{}
	return dir("",
		file("a.txt", []byte("hello world\n"), 0o644),
		file("empty", empty, 0o644),
		file("big.bin", big, 0o600),
		&Node{Name: "link", Type: TypeSymlink, Mode: 0o777, Data: []byte("a.txt"), MTime: 1700000000},
		dir("sub", file("b.txt", []byte("nested\n"), 0o644)),
		dir("sub2"),
	)
}

func TestWriteReadRoundTrip(t *testing.T) {
	root := sampleTree()
	data, err := Marshal(root, nil)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := ReadAll(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	var files int
	err = got.Walk(func(path string, n *Node) error {
		want := root.Find(path)
		if want == nil {
			t.Errorf("%s: unexpected node", path)
			return nil
		}
		if n.Type != want.Type {
			t.Errorf("%s: type %d != %d", path, n.Type, want.Type)
		}
		if n.Mode != want.Mode {
			t.Errorf("%s: mode %o != %o", path, n.Mode, want.Mode)
		}
		if !bytes.Equal(n.Data, want.Data) {
			t.Errorf("%s: data mismatch (%d vs %d bytes)", path, len(n.Data), len(want.Data))
		}
		if n.Type == TypeFile {
			files++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files != 4 {
		t.Errorf("walked %d files, want 4", files)
	}
	// The root must also see every entry.
	if len(got.Children) != 6 {
		t.Errorf("root has %d children, want 6", len(got.Children))
	}
	if got.Find("sub2") == nil || got.Find("sub/b.txt") == nil {
		t.Error("nested entries missing")
	}
}

func TestWriteEmptyRoot(t *testing.T) {
	data, err := Marshal(&Node{Type: TypeDir, Mode: 0o755, Name: ""}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadAll(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Children) != 0 {
		t.Error("expected empty root")
	}
}

func TestWriteDeterministic(t *testing.T) {
	opts := &WriteOptions{MTime: 12345}
	a, err := Marshal(sampleTree(), opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Marshal(sampleTree(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("Marshal is not deterministic")
	}
}
