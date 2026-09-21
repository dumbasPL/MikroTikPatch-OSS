// Package squashfs implements a reader and a writer for the squashfs 4.0
// format as used by RouterOS system packages.  The reader parses the stock
// images (xz compression, fragments, extended inodes); the writer emits xz
// compressed images without fragments or xattrs, which is enough to repack the
// patched system tree.
package squashfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"mikrotikpatch/internal/lzma"
)

const (
	magic       = 0x73717368
	metaSize    = 8192
	invalidBlk  = ^uint64(0)
	invalidFrag = ^uint32(0)

	// Inode types.
	typeDir     = 1
	typeFile    = 2
	typeSymlink = 3
	typeLDir    = 8
	typeLFile   = 9
	typeLSym    = 10

	// Compression ids; only xz is supported.
	compressionXZ = 4
)

// NodeType classifies tree nodes.
type NodeType int

const (
	TypeDir NodeType = iota
	TypeFile
	TypeSymlink
)

// Node is a file, directory or symlink in the squashfs tree.
type Node struct {
	Name     string
	Mode     uint16 // permission bits only
	UID      uint32
	GID      uint32
	MTime    uint32
	Type     NodeType
	Data     []byte  // file content or symlink target
	Children []*Node // directory entries, sorted by name
}

// Walk calls fn for every node in the tree, depth-first, with the path
// relative to n (empty for n itself).
func (n *Node) Walk(fn func(path string, node *Node) error) error {
	return walk(n, "", fn)
}

func walk(n *Node, path string, fn func(string, *Node) error) error {
	if err := fn(path, n); err != nil {
		return err
	}
	for _, c := range n.Children {
		p := c.Name
		if path != "" {
			p = path + "/" + c.Name
		}
		if err := walk(c, p, fn); err != nil {
			return err
		}
	}
	return nil
}

// Find returns the node at the given slash-separated path (relative to n), or
// nil.
func (n *Node) Find(path string) *Node {
	if path == "" {
		return n
	}
	cur := n
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '/' {
			if i == start {
				return nil
			}
			name := path[start:i]
			var next *Node
			for _, c := range cur.Children {
				if c.Name == name {
					next = c
					break
				}
			}
			if next == nil {
				return nil
			}
			cur = next
			start = i + 1
		}
	}
	return cur
}

// SortChildren sorts every directory's children by name.
func (n *Node) SortChildren() {
	if n.Type != TypeDir {
		return
	}
	sortNodes(n.Children)
	for _, c := range n.Children {
		c.SortChildren()
	}
}

type superblock struct {
	inodes       uint32
	blockSize    uint32
	fragments    uint32
	compression  uint16
	blockLog     uint16
	flags        uint16
	noIDs        uint16
	versionMajor uint16
	versionMinor uint16
	rootInode    uint64
	bytesUsed    uint64
	idTableStart uint64
	xattrTable   uint64
	inodeTable   uint64
	dirTable     uint64
	fragTable    uint64
	lookupTable  uint64
}

type metaBlock struct {
	payload []byte
	next    uint64
}

type fragment struct {
	start uint64
	size  uint32
}

type reader struct {
	src       io.ReaderAt
	size      int64
	sb        superblock
	metaCache map[uint64]*metaBlock
	fragIndex []fragment
	fragDone  bool
	ids       []uint32
	idsDone   bool
}

// ReadAll parses the whole squashfs image and returns the root directory.
func ReadAll(src io.ReaderAt, size int64) (*Node, error) {
	r := &reader{src: src, size: size, metaCache: map[uint64]*metaBlock{}}
	hdr := make([]byte, 96)
	if _, err := src.ReadAt(hdr, 0); err != nil {
		return nil, fmt.Errorf("squashfs: read superblock: %w", err)
	}
	sb := &r.sb
	le := binary.LittleEndian
	if le.Uint32(hdr[0:]) != magic {
		return nil, errors.New("squashfs: bad magic")
	}
	sb.inodes = le.Uint32(hdr[4:])
	sb.blockSize = le.Uint32(hdr[12:])
	sb.fragments = le.Uint32(hdr[16:])
	sb.compression = le.Uint16(hdr[20:])
	sb.blockLog = le.Uint16(hdr[22:])
	sb.flags = le.Uint16(hdr[24:])
	sb.noIDs = le.Uint16(hdr[26:])
	sb.versionMajor = le.Uint16(hdr[28:])
	sb.versionMinor = le.Uint16(hdr[30:])
	sb.rootInode = le.Uint64(hdr[32:])
	sb.bytesUsed = le.Uint64(hdr[40:])
	sb.idTableStart = le.Uint64(hdr[48:])
	sb.xattrTable = le.Uint64(hdr[56:])
	sb.inodeTable = le.Uint64(hdr[64:])
	sb.dirTable = le.Uint64(hdr[72:])
	sb.fragTable = le.Uint64(hdr[80:])
	sb.lookupTable = le.Uint64(hdr[88:])
	if sb.versionMajor != 4 || sb.versionMinor != 0 {
		return nil, fmt.Errorf("squashfs: unsupported version %d.%d", sb.versionMajor, sb.versionMinor)
	}
	if sb.compression != compressionXZ {
		return nil, fmt.Errorf("squashfs: unsupported compression %d", sb.compression)
	}
	root, err := r.readInode(sb.rootInode, 0)
	if err != nil {
		return nil, err
	}
	if root.Type != TypeDir {
		return nil, errors.New("squashfs: root inode is not a directory")
	}
	root.Name = ""
	root.SortChildren()
	return root, nil
}

// readMeta reads length bytes starting at (block, offset), crossing metadata
// block boundaries as needed.  block is an absolute file offset.
func (r *reader) readMeta(block uint64, offset int, length int) ([]byte, error) {
	out := make([]byte, 0, length)
	for length > 0 {
		mb, err := r.metaBlockAt(block)
		if err != nil {
			return nil, err
		}
		if offset == len(mb.payload) {
			// Exactly at the end of a metadata block: continue in the next.
			block = mb.next
			offset = 0
			continue
		}
		if offset < 0 || offset > len(mb.payload) {
			return nil, fmt.Errorf("squashfs: metadata offset %d out of range (block %#x, len %d)", offset, block, len(mb.payload))
		}
		n := len(mb.payload) - offset
		if n > length {
			n = length
		}
		out = append(out, mb.payload[offset:offset+n]...)
		offset += n
		length -= n
		if length > 0 {
			block = mb.next
			offset = 0
		}
	}
	return out, nil
}

func (r *reader) metaBlockAt(block uint64) (*metaBlock, error) {
	if mb, ok := r.metaCache[block]; ok {
		return mb, nil
	}
	hdr := make([]byte, 2)
	if _, err := r.src.ReadAt(hdr, int64(block)); err != nil {
		return nil, fmt.Errorf("squashfs: read metadata header at %#x: %w", block, err)
	}
	v := binary.LittleEndian.Uint16(hdr)
	size := int(v & 0x7fff)
	raw := make([]byte, size)
	if _, err := r.src.ReadAt(raw, int64(block)+2); err != nil {
		return nil, fmt.Errorf("squashfs: read metadata block at %#x: %w", block, err)
	}
	var payload []byte
	if v&0x8000 != 0 {
		payload = raw
	} else {
		var err error
		payload, err = lzma.Decode(raw)
		if err != nil {
			return nil, fmt.Errorf("squashfs: decompress metadata block at %#x: %w", block, err)
		}
	}
	if len(payload) > metaSize {
		return nil, fmt.Errorf("squashfs: metadata block at %#x too large (%d)", block, len(payload))
	}
	mb := &metaBlock{payload: payload, next: block + 2 + uint64(size)}
	r.metaCache[block] = mb
	return mb, nil
}

// metaCursor is a sequential reader over metadata blocks.
type metaCursor struct {
	r     *reader
	block uint64
	off   int
}

func (c *metaCursor) read(n int) ([]byte, error) {
	out, err := c.r.readMeta(c.block, c.off, n)
	if err != nil {
		return nil, err
	}
	// Advance the cursor.
	remaining := n
	for remaining > 0 {
		mb, err := c.r.metaBlockAt(c.block)
		if err != nil {
			return nil, err
		}
		avail := len(mb.payload) - c.off
		if avail >= remaining {
			c.off += remaining
			remaining = 0
		} else {
			remaining -= avail
			c.block = mb.next
			c.off = 0
		}
	}
	return out, nil
}

type inodeInfo struct {
	typ         uint16
	mode        uint16
	uid         uint16
	gid         uint16
	mtime       uint32
	inodeNumber uint32

	// Directories.
	startBlock uint32
	fileSize   uint64
	offset     uint16
	parent     uint32

	// Regular files.
	frag      uint32
	fragOff   uint32
	blockList []uint32

	// Symlinks.
	target []byte
}

func (r *reader) readInode(ref uint64, depth int) (*Node, error) {
	if depth > 64 {
		return nil, errors.New("squashfs: directory nesting too deep")
	}
	block := r.sb.inodeTable + (ref >> 16)
	offset := int(ref & 0xffff)
	info, err := r.readInodeInfo(block, offset)
	if err != nil {
		return nil, err
	}
	node := &Node{
		Mode:  info.mode,
		UID:   r.id(info.uid),
		GID:   r.id(info.gid),
		MTime: info.mtime,
	}
	switch info.typ {
	case typeDir, typeLDir:
		node.Type = TypeDir
		if err := r.fillDirAt(node, info, depth); err != nil {
			return nil, err
		}
	case typeFile, typeLFile:
		node.Type = TypeFile
		data, err := r.readFileData(info)
		if err != nil {
			return nil, err
		}
		node.Data = data
	case typeSymlink, typeLSym:
		node.Type = TypeSymlink
		node.Data = info.target
	default:
		return nil, fmt.Errorf("squashfs: unsupported inode type %d", info.typ)
	}
	return node, nil
}

func (r *reader) readInodeInfo(block uint64, offset int) (*inodeInfo, error) {
	// Inode fields may span metadata block boundaries, so read them through a
	// sequential cursor (like the kernel's squashfs_read_metadata).
	cur := &metaCursor{r: r, block: block, off: offset}
	base, err := cur.read(16)
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	info := &inodeInfo{
		typ:         le.Uint16(base[0:]),
		mode:        le.Uint16(base[2:]),
		uid:         le.Uint16(base[4:]),
		gid:         le.Uint16(base[6:]),
		mtime:       le.Uint32(base[8:]),
		inodeNumber: le.Uint32(base[12:]),
	}
	switch info.typ {
	case typeDir:
		rest, err := cur.read(16)
		if err != nil {
			return nil, err
		}
		info.startBlock = le.Uint32(rest[0:])
		info.fileSize = uint64(le.Uint16(rest[8:]))
		info.offset = le.Uint16(rest[10:])
		info.parent = le.Uint32(rest[12:])
	case typeLDir:
		rest, err := cur.read(24)
		if err != nil {
			return nil, err
		}
		info.fileSize = uint64(le.Uint32(rest[4:]))
		info.startBlock = le.Uint32(rest[8:])
		info.parent = le.Uint32(rest[12:])
		info.offset = le.Uint16(rest[18:])
	case typeFile:
		rest, err := cur.read(16)
		if err != nil {
			return nil, err
		}
		info.startBlock = le.Uint32(rest[0:])
		info.frag = le.Uint32(rest[4:])
		info.fragOff = le.Uint32(rest[8:])
		info.fileSize = uint64(le.Uint32(rest[12:]))
		if err := r.readBlockList(cur, info); err != nil {
			return nil, err
		}
	case typeLFile:
		// squashfs_lreg_inode: start_block, file_size, sparse, nlink,
		// fragment, offset, xattr.
		rest, err := cur.read(40)
		if err != nil {
			return nil, err
		}
		info.startBlock = uint32(le.Uint64(rest[0:]))
		info.fileSize = le.Uint64(rest[8:])
		info.frag = le.Uint32(rest[28:])
		info.fragOff = le.Uint32(rest[32:])
		if err := r.readBlockList(cur, info); err != nil {
			return nil, err
		}
	case typeSymlink, typeLSym:
		rest, err := cur.read(8)
		if err != nil {
			return nil, err
		}
		size := int(le.Uint32(rest[4:]))
		if size < 0 || size > 65536 {
			return nil, fmt.Errorf("squashfs: implausible symlink size %d", size)
		}
		target, err := cur.read(size)
		if err != nil {
			return nil, err
		}
		info.target = target
	default:
		return nil, fmt.Errorf("squashfs: unsupported inode type %d", info.typ)
	}
	return info, nil
}

// readBlockList reads the file's block-size words through the cursor.
func (r *reader) readBlockList(cur *metaCursor, info *inodeInfo) error {
	var n int
	if info.frag == invalidFrag {
		n = int((info.fileSize + uint64(r.sb.blockSize) - 1) / uint64(r.sb.blockSize))
	} else {
		n = int(info.fileSize / uint64(r.sb.blockSize))
	}
	if n < 0 || n > 1<<20 {
		return fmt.Errorf("squashfs: implausible block count %d", n)
	}
	info.blockList = make([]uint32, n)
	for i := 0; i < n; i++ {
		v, err := cur.read(4)
		if err != nil {
			return err
		}
		info.blockList[i] = binary.LittleEndian.Uint32(v)
	}
	return nil
}

func (r *reader) fillDirAt(node *Node, info *inodeInfo, depth int) error {
	cursor := &metaCursor{r: r, block: r.sb.dirTable + uint64(info.startBlock), off: int(info.offset)}
	// mksquashfs stores directory sizes including the three pseudo bytes for
	// the "." and ".." entries the kernel synthesises; see
	// get_dir_index_using_offset() in fs/squashfs/dir.c.
	if info.fileSize < 3 {
		return fmt.Errorf("squashfs: implausible directory size %d", info.fileSize)
	}
	remaining := int(info.fileSize) - 3
	le := binary.LittleEndian
	for remaining > 0 {
		hdr, err := cursor.read(12)
		if err != nil {
			return err
		}
		remaining -= 12
		count := int(le.Uint32(hdr[0:])) + 1
		if count <= 0 || count > 256 {
			return fmt.Errorf("squashfs: bad directory header count %d", count)
		}
		startBlock := le.Uint32(hdr[4:])
		for i := 0; i < count; i++ {
			de, err := cursor.read(8)
			if err != nil {
				return err
			}
			remaining -= 8
			entryOffset := le.Uint16(de[0:])
			nameSize := int(le.Uint16(de[6:])) + 1
			name, err := cursor.read(nameSize)
			if err != nil {
				return err
			}
			remaining -= nameSize
			if remaining < 0 {
				return errors.New("squashfs: directory entry overruns inode size")
			}
			ref := uint64(startBlock)<<16 | uint64(entryOffset)
			child, err := r.readInode(ref, depth+1)
			if err != nil {
				return fmt.Errorf("squashfs: entry %q: %w", name, err)
			}
			child.Name = string(name)
			node.Children = append(node.Children, child)
		}
	}
	if remaining != 0 {
		return fmt.Errorf("squashfs: directory size mismatch (%d bytes left)", remaining)
	}
	return nil
}

func (r *reader) readFileData(info *inodeInfo) ([]byte, error) {
	out := make([]byte, 0, info.fileSize)
	pos := info.startBlock
	for _, bs := range info.blockList {
		expected := int(r.sb.blockSize)
		if remaining := int(info.fileSize) - len(out); remaining < expected {
			expected = remaining
		}
		stored := bs & 0xffffff
		uncompressed := bs&0x1000000 != 0
		if stored == 0 {
			// A zero-length block is a hole: the kernel zero-fills it.
			out = append(out, make([]byte, expected)...)
			continue
		}
		raw := make([]byte, stored)
		if _, err := r.src.ReadAt(raw, int64(pos)); err != nil {
			return nil, fmt.Errorf("squashfs: read data block at %#x: %w", pos, err)
		}
		pos += stored
		if uncompressed {
			out = append(out, raw...)
		} else {
			dec, err := lzma.Decode(raw)
			if err != nil {
				return nil, fmt.Errorf("squashfs: decompress data block at %#x: %w", pos, err)
			}
			out = append(out, dec...)
		}
	}
	tail := int(info.fileSize - uint64(len(out)))
	if info.frag != invalidFrag {
		if tail <= 0 {
			return nil, errors.New("squashfs: file with fragment has no tail")
		}
		entry, err := r.fragment(int(info.frag))
		if err != nil {
			return nil, err
		}
		raw := make([]byte, entry.size&0xffffff)
		if _, err := r.src.ReadAt(raw, int64(entry.start)); err != nil {
			return nil, fmt.Errorf("squashfs: read fragment at %#x: %w", entry.start, err)
		}
		var block []byte
		if entry.size&0x1000000 != 0 {
			block = raw
		} else {
			block, err = lzma.Decode(raw)
			if err != nil {
				return nil, fmt.Errorf("squashfs: decompress fragment at %#x: %w", entry.start, err)
			}
		}
		off := int(info.fragOff)
		if off+tail > len(block) {
			return nil, fmt.Errorf("squashfs: fragment tail out of range (frag %d, start %#x, size %#x, off %d, tail %d, block %d)",
				info.frag, entry.start, entry.size, off, tail, len(block))
		}
		out = append(out, block[off:off+tail]...)
	} else if tail != 0 {
		return nil, fmt.Errorf("squashfs: file truncated (%d bytes missing)", tail)
	}
	if uint64(len(out)) != info.fileSize {
		return nil, fmt.Errorf("squashfs: file size mismatch: got %d want %d", len(out), info.fileSize)
	}
	return out, nil
}

func (r *reader) fragment(i int) (fragment, error) {
	if !r.fragDone {
		if r.sb.fragTable == invalidBlk {
			r.fragDone = true
		} else {
			n := int((r.sb.fragments*16 + metaSize - 1) / metaSize)
			ptrs := make([]uint64, n)
			for k := 0; k < n; k++ {
				v, err := r.readRaw(r.sb.fragTable+uint64(k)*8, 8)
				if err != nil {
					return fragment{}, err
				}
				ptrs[k] = binary.LittleEndian.Uint64(v)
			}
			r.fragIndex = make([]fragment, r.sb.fragments)
			for k := 0; k < int(r.sb.fragments); k++ {
				blk := ptrs[k/(metaSize/16)]
				off := (k % (metaSize / 16)) * 16
				v, err := r.readMeta(blk, off, 16)
				if err != nil {
					return fragment{}, err
				}
				r.fragIndex[k] = fragment{
					start: binary.LittleEndian.Uint64(v[0:]),
					size:  binary.LittleEndian.Uint32(v[8:]),
				}
			}
			r.fragDone = true
		}
	}
	if i < 0 || i >= len(r.fragIndex) {
		return fragment{}, fmt.Errorf("squashfs: fragment index %d out of range", i)
	}
	return r.fragIndex[i], nil
}

func (r *reader) id(idx uint16) uint32 {
	if !r.idsDone {
		r.idsDone = true
		if r.sb.idTableStart != invalidBlk && r.sb.noIDs > 0 {
			n := int((uint32(r.sb.noIDs)*4 + metaSize - 1) / metaSize)
			ids := make([]uint32, 0, r.sb.noIDs)
			for k := 0; k < n; k++ {
				v, err := r.readRaw(r.sb.idTableStart+uint64(k)*8, 8)
				if err != nil {
					break
				}
				blk := binary.LittleEndian.Uint64(v)
				mb, err := r.metaBlockAt(blk)
				if err != nil {
					break
				}
				payload := mb.payload
				for i := 0; i+4 <= len(payload); i += 4 {
					ids = append(ids, binary.LittleEndian.Uint32(payload[i:]))
				}
			}
			r.ids = ids
		}
	}
	if int(idx) < len(r.ids) {
		return r.ids[idx]
	}
	return 0
}

func (r *reader) readRaw(off uint64, n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := r.src.ReadAt(buf, int64(off)); err != nil {
		return nil, fmt.Errorf("squashfs: read at %#x: %w", off, err)
	}
	return buf, nil
}

func sortNodes(nodes []*Node) {
	// Insertion sort keeps the code dependency-free and the lists are small.
	for i := 1; i < len(nodes); i++ {
		for j := i; j > 0 && nodes[j].Name < nodes[j-1].Name; j-- {
			nodes[j], nodes[j-1] = nodes[j-1], nodes[j]
		}
	}
}
