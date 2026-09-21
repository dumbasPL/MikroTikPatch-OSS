// Package iso implements a deliberately small read-only ISO9660 reader with
// Rock Ridge (SUSP/RRIP) name support.  It offers just enough to walk the
// directory tree of a MikroTik RouterOS installation image and to read file
// contents, mapping the real long names carried by "NM" entries (for example
// calea-7.24.4.npk) onto the raw 8.3 names stored in the ISO9660 directory
// records (CALEA_7_.NPK;1).
//
// Only the features needed for that task are implemented: the primary volume
// descriptor, directory records, the system-use entries "SP", "ER", "CE" and
// "NM".  Joliet and multi-extent files are intentionally not supported.
package iso

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// sectorSize is the byte offset divisor used to locate the volume
	// descriptor set; the logical block size found in the PVD is used for
	// every extent afterwards.
	sectorSize = 2048
	pvdSector  = 16

	maxDirSize   = 64 << 20 // sanity limit for a directory extent
	maxDepth     = 32       // recursion guard for pathological images
	maxUseArea   = 1 << 16  // sanity limit for a Rock Ridge continuation area
	maxCEChain   = 4        // continuation-area indirection limit
	minBlockSize = 512
	maxBlockSize = 32768
)

// Image is an opened ISO9660 image.
type Image struct {
	r         io.ReaderAt
	size      int64
	blockSize uint32
	root      *Node

	// rr records that a Rock Ridge SUSP area was confirmed through an SP or
	// ER entry.  NM entries are structurally validated regardless, so images
	// that omit SP still get their long names.
	rr bool
}

// Node is a file or directory in the image.  Directories carry their entries
// in Children, in directory order.  Name is the Rock Ridge name when one is
// present, otherwise the ISO9660 identifier with the ";1" version stripped.
type Node struct {
	Name     string
	IsDir    bool
	Size     uint64
	Children []*Node

	// extent is the starting logical block of the file or directory data.
	extent uint32
}

// Open opens the ISO9660 image stored in r, which must offer random access
// from the beginning of the image.  size is the size of the image in bytes.
func Open(r io.ReaderAt, size int64) (*Image, error) {
	if r == nil {
		return nil, errors.New("iso: nil reader")
	}
	if size < (pvdSector+1)*sectorSize {
		return nil, fmt.Errorf("iso: image too small for a volume descriptor (%d bytes)", size)
	}
	im := &Image{r: r, size: size}

	var pvd [sectorSize]byte
	if err := im.readAt(pvd[:], pvdSector*sectorSize); err != nil {
		return nil, fmt.Errorf("iso: reading primary volume descriptor: %w", err)
	}
	if pvd[0] != 1 || string(pvd[1:6]) != "CD001" {
		return nil, errors.New("iso: sector 16 is not an ISO9660 primary volume descriptor")
	}
	bs := uint32(binary.LittleEndian.Uint16(pvd[128:130]))
	if bs < minBlockSize || bs > maxBlockSize {
		return nil, fmt.Errorf("iso: invalid logical block size %d", bs)
	}
	im.blockSize = bs

	root := pvd[156:]
	if len(root) < 34 || int(root[0]) < 34 {
		return nil, errors.New("iso: malformed root directory record")
	}
	im.root = &Node{
		Name:   "/",
		IsDir:  true,
		Size:   uint64(binary.LittleEndian.Uint32(root[10:14])),
		extent: binary.LittleEndian.Uint32(root[2:6]),
	}
	if err := im.readDir(im.root, 0, make(map[uint32]bool)); err != nil {
		return nil, err
	}
	return im, nil
}

// Root returns the root directory node.
func (im *Image) Root() *Node { return im.root }

// ReadFile reads a regular file named by a slash-separated path relative to
// the root.  Rock Ridge names are used when present.  It returns an error if
// the path does not name a regular file.
func (im *Image) ReadFile(path string) ([]byte, error) {
	n := im.root
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." {
			continue
		}
		if !n.IsDir {
			return nil, fmt.Errorf("iso: %q: %q is not a directory", path, n.Name)
		}
		child := n.child(part)
		if child == nil {
			return nil, fmt.Errorf("iso: %q: no such file or directory", path)
		}
		n = child
	}
	if n.IsDir {
		return nil, fmt.Errorf("iso: %q: is a directory", path)
	}
	if n.Size > uint64(im.size) {
		return nil, fmt.Errorf("iso: %q: implausible size %d", path, n.Size)
	}
	data := make([]byte, n.Size)
	if err := im.readAt(data, int64(n.extent)*int64(im.blockSize)); err != nil {
		return nil, fmt.Errorf("iso: reading %q: %w", path, err)
	}
	return data, nil
}

// child returns the entry with the given name, or nil.
func (n *Node) child(name string) *Node {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// readDir reads the directory data of n and fills n.Children, recursing into
// subdirectories.  seen holds the extents of directories already visited so
// that a malformed image cannot loop forever.
func (im *Image) readDir(n *Node, depth int, seen map[uint32]bool) error {
	if depth > maxDepth {
		return fmt.Errorf("iso: directory nesting exceeds %d levels", maxDepth)
	}
	if n.Size > maxDirSize {
		return fmt.Errorf("iso: directory %q is unreasonably large (%d bytes)", n.Name, n.Size)
	}
	data := make([]byte, n.Size)
	if err := im.readAt(data, int64(n.extent)*int64(im.blockSize)); err != nil {
		return fmt.Errorf("iso: reading directory %q: %w", n.Name, err)
	}
	seen[n.extent] = true

	for off := 0; off < len(data); {
		l := int(data[off])
		if l == 0 {
			// No more records in this logical block; skip to the next one.
			off = (off/int(im.blockSize) + 1) * int(im.blockSize)
			continue
		}
		if l < 33 || off+l > len(data) {
			return fmt.Errorf("iso: directory %q: malformed record at offset %d", n.Name, off)
		}
		rec := data[off : off+l]
		off += l

		idl := int(rec[32])
		if 33+idl > l {
			return fmt.Errorf("iso: directory %q: file identifier overruns record at offset %d", n.Name, off-l)
		}
		id := rec[33 : 33+idl]

		// Single-byte identifiers 0x00 and 0x01 mark "." and "..".
		if idl == 1 && (id[0] == 0x00 || id[0] == 0x01) {
			if id[0] == 0x00 {
				if _, _, err := im.systemUse(rec, idl); err != nil {
					return err
				}
			}
			continue
		}

		child := &Node{
			Name:   isoName(id),
			IsDir:  rec[25]&0x02 != 0,
			Size:   uint64(binary.LittleEndian.Uint32(rec[10:14])),
			extent: binary.LittleEndian.Uint32(rec[2:6]),
		}
		if name, ok, err := im.systemUse(rec, idl); err != nil {
			return err
		} else if ok {
			child.Name = name
		}
		n.Children = append(n.Children, child)

		if child.IsDir && !seen[child.extent] {
			if err := im.readDir(child, depth+1, seen); err != nil {
				return err
			}
		}
	}
	return nil
}

// systemUse extracts a Rock Ridge name from the system-use area of the
// directory record rec whose file identifier is idl bytes long.  It also
// confirms the presence of a SUSP area through the "SP" and "ER" entries.
func (im *Image) systemUse(rec []byte, idl int) (string, bool, error) {
	su := 33 + idl
	if idl%2 == 0 {
		// A padding byte precedes the system-use area when the identifier
		// length is even (this also covers the empty root identifier).
		su++
	}
	if su >= len(rec) {
		return "", false, nil
	}
	return im.parseUse(rec[su:], 0)
}

// parseUse walks one system-use area.  chain counts CE indirections.  The
// returned name is the concatenation of NM entries belonging to the first
// non-continued NM group in the area.
func (im *Image) parseUse(su []byte, chain int) (string, bool, error) {
	var (
		nm      []byte
		haveNM  bool
		ceName  string
		ceFound bool
	)
	for off := 0; off+4 <= len(su); {
		l := int(su[off+2])
		if l < 4 || off+l > len(su) {
			break
		}
		e := su[off : off+l]
		off += l
		if e[3] != 1 { // SUSP entry version
			continue
		}
		switch string(e[0:2]) {
		case "SP":
			if len(e) >= 7 && e[4] == 0xbe && e[5] == 0xef {
				im.rr = true
			}
		case "ER":
			if bytes.Contains(e[8:], []byte("RRIP")) ||
				bytes.Contains(e[8:], []byte("IEEE_P1282")) {
				im.rr = true
			}
		case "NM":
			if len(e) < 5 {
				continue
			}
			if e[4]&0x01 == 0 { // not a continuation: start a new name
				nm = nm[:0]
				haveNM = true
			}
			nm = append(nm, e[5:]...)
		case "CE":
			if chain >= maxCEChain {
				return "", false, fmt.Errorf("iso: rock ridge continuation areas nested too deeply")
			}
			if len(e) < 28 {
				continue
			}
			block := binary.LittleEndian.Uint32(e[4:8])
			coff := binary.LittleEndian.Uint32(e[12:16])
			clen := binary.LittleEndian.Uint32(e[20:24])
			if clen == 0 || clen > maxUseArea {
				return "", false, fmt.Errorf("iso: invalid rock ridge continuation length %d", clen)
			}
			buf := make([]byte, clen)
			if err := im.readAt(buf, int64(block)*int64(im.blockSize)+int64(coff)); err != nil {
				return "", false, fmt.Errorf("iso: reading rock ridge continuation area: %w", err)
			}
			name, ok, err := im.parseUse(buf, chain+1)
			if err != nil {
				return "", false, err
			}
			if ok && !ceFound {
				ceName, ceFound = name, true
			}
		}
	}
	if haveNM {
		if s := strings.TrimRight(string(nm), "\x00"); s != "" {
			return s, true, nil
		}
	}
	if ceFound {
		return ceName, true, nil
	}
	return "", false, nil
}

// isoName converts an ISO9660 file identifier to a name by dropping the
// ";1" version suffix.
func isoName(id []byte) string {
	s := string(id)
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = s[:i]
	}
	return s
}

// readAt reads len(p) bytes at off, refusing reads outside the image.
func (im *Image) readAt(p []byte, off int64) error {
	if off < 0 || off+int64(len(p)) > im.size {
		return io.ErrUnexpectedEOF
	}
	_, err := im.r.ReadAt(p, off)
	return err
}
