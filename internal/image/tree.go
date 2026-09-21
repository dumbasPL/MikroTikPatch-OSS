package image

import (
	"fmt"
	"sort"
	"strings"
)

// node is one file or directory of the in-memory tree built from the
// caller's entries.  The filesystem writers fill in the per-filesystem
// fields (inode numbers, cluster chains, extents) as they lay the image out.
type node struct {
	name   string
	dir    bool
	data   []byte // regular file contents
	mode   uint16 // permission bits (files only)
	parent *node
	childs []*node

	ino     uint32   // ext inode number
	dirData []byte   // ext directory contents
	blocks  []uint32 // ext data blocks
	extents []extent // ext extents

	fatName  [11]byte // FAT 8.3 name
	clusters []uint32 // FAT cluster chain
}

const (
	modeDir  = 0o040000
	modeFile = 0o100000
)

// buildTree turns entries into a directory tree.  Parent directories are
// created implicitly; duplicate paths and file/directory conflicts are
// errors.  Children are sorted by name.
func buildTree(entries []Entry) (*node, error) {
	root := &node{dir: true, mode: 0o755}
	byPath := map[string]*node{"": root}
	for _, e := range entries {
		isDir := isDirEntry(e)
		p := strings.Trim(e.Path, "/")
		if p == "" {
			return nil, fmt.Errorf("image: empty entry path %q", e.Path)
		}
		parts := strings.Split(p, "/")
		cur := root
		for i, part := range parts {
			if part == "" || part == "." || part == ".." {
				return nil, fmt.Errorf("image: invalid path %q", e.Path)
			}
			full := strings.Join(parts[:i+1], "/")
			last := i == len(parts)-1
			n := byPath[full]
			switch {
			case n == nil:
				n = &node{name: part, dir: true, mode: 0o755, parent: cur}
				if last && !isDir {
					n.dir = false
					n.data = e.Data
					n.mode = e.Mode & 0o7777
					if n.mode == 0 {
						n.mode = 0o644
					}
				}
				cur.childs = append(cur.childs, n)
				byPath[full] = n
			case !last:
				if !n.dir {
					return nil, fmt.Errorf("image: %q is not a directory", full)
				}
			case isDir:
				if !n.dir {
					return nil, fmt.Errorf("image: %q is already a file", full)
				}
			default:
				if n.dir {
					return nil, fmt.Errorf("image: %q is already a directory", full)
				}
				return nil, fmt.Errorf("image: duplicate entry %q", full)
			}
			cur = n
		}
	}
	sortTree(root)
	return root, nil
}

// isDirEntry reports whether an entry describes a directory.  A directory
// can be marked with a trailing slash, with the S_IFDIR bit or, for entries
// without data, with mode 0755.
func isDirEntry(e Entry) bool {
	return strings.HasSuffix(e.Path, "/") ||
		e.Mode&0o170000 == modeDir ||
		(e.Data == nil && e.Mode&0o7777 == 0o755)
}

// sortTree sorts every directory's children by name.
func sortTree(n *node) {
	sort.Slice(n.childs, func(i, j int) bool { return n.childs[i].name < n.childs[j].name })
	for _, c := range n.childs {
		if c.dir {
			sortTree(c)
		}
	}
}

// walk calls fn for n and every descendant in pre-order.
func (n *node) walk(fn func(*node) error) error {
	if err := fn(n); err != nil {
		return err
	}
	for _, c := range n.childs {
		if err := c.walk(fn); err != nil {
			return err
		}
	}
	return nil
}
