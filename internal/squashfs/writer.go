package squashfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"mikrotikpatch/internal/lzma"
)

// WriteOptions controls image creation.
type WriteOptions struct {
	// BlockSize is the data block size; must be a power of two.  Default 256k.
	BlockSize uint32
	// Preset is the liblzma preset used for data blocks.  Default
	// lzma.PresetDefault.
	Preset uint32
	// MTime is the filesystem creation timestamp; default now.
	MTime uint32
}

func (o *WriteOptions) fill() {
	if o.BlockSize == 0 {
		o.BlockSize = 256 * 1024
	}
	if o.Preset == 0 {
		o.Preset = lzma.PresetDefault
	}
	if o.MTime == 0 {
		o.MTime = uint32(time.Now().Unix())
	}
}

// Marshal builds a complete squashfs image for root and returns it.
func Marshal(root *Node, opts *WriteOptions) ([]byte, error) {
	if root.Type != TypeDir {
		return nil, errors.New("squashfs: root is not a directory")
	}
	o := WriteOptions{}
	if opts != nil {
		o = *opts
	}
	o.fill()
	if o.BlockSize&(o.BlockSize-1) != 0 {
		return nil, errors.New("squashfs: block size must be a power of two")
	}
	w := &writer{opts: o, dirContent: map[*wnode][]byte{}}
	if err := w.collect(root); err != nil {
		return nil, err
	}
	if err := w.build(); err != nil {
		return nil, err
	}
	return w.out.Bytes(), nil
}

// WriteTo writes the squashfs image for root to dst.
func WriteTo(dst io.Writer, root *Node, opts *WriteOptions) error {
	data, err := Marshal(root, opts)
	if err != nil {
		return err
	}
	_, err = dst.Write(data)
	return err
}

type wnode struct {
	n   *Node
	num uint32

	ref        uint64 // packed inode reference (relative to the inode table)
	start      uint64 // absolute offset of the first data block (files)
	blockSizes []uint32
	inodeSize  int

	// Directory placement (relative to the directory table).
	dirStart  uint64
	dirOffset uint16
	dirSize   uint16
}

type writer struct {
	opts       WriteOptions
	out        bytes.Buffer
	nodes      []*wnode // post-order: children before parents, root last
	root       *wnode
	parent     map[*Node]*wnode
	byNode     map[*Node]*wnode
	dirContent map[*wnode][]byte

	inodeTableStart uint64
	dirTableStart   uint64
}

// collect walks the tree depth-first, assigning inode numbers in post-order.
func (w *writer) collect(root *Node) error {
	w.parent = map[*Node]*wnode{}
	var visit func(n *Node) (*wnode, error)
	visit = func(n *Node) (*wnode, error) {
		if n.Type == TypeDir {
			sort.Slice(n.Children, func(i, j int) bool { return n.Children[i].Name < n.Children[j].Name })
		}
		wn := &wnode{n: n}
		for _, c := range n.Children {
			if _, err := visit(c); err != nil {
				return nil, err
			}
			w.parent[c] = wn
		}
		wn.num = uint32(len(w.nodes) + 1)
		w.nodes = append(w.nodes, wn)
		return wn, nil
	}
	var err error
	w.root, err = visit(root)
	return err
}

func (w *writer) build() error {
	le := binary.LittleEndian
	w.out.Write(make([]byte, 96))

	// Data blocks.  The compressed sizes are what make the 32-bit file
	// offsets known, so this has to happen before anything else is placed.
	for _, wn := range w.nodes {
		n := wn.n
		if n.Type != TypeFile || len(n.Data) == 0 {
			continue
		}
		wn.start = uint64(w.out.Len())
		if wn.start > 0xffffffff {
			return errors.New("squashfs: image too large for 32-bit data offsets")
		}
		data := n.Data
		for off := 0; off < len(data); off += int(w.opts.BlockSize) {
			end := off + int(w.opts.BlockSize)
			if end > len(data) {
				end = len(data)
			}
			chunk := data[off:end]
			comp, err := lzma.Encode(chunk, lzma.Options{Preset: w.opts.Preset, DictSize: w.opts.BlockSize, Check: lzma.CheckCRC32})
			if err != nil {
				return fmt.Errorf("squashfs: compress data block: %w", err)
			}
			if len(comp) < len(chunk) {
				w.out.Write(comp)
				wn.blockSizes = append(wn.blockSizes, uint32(len(comp)))
			} else {
				w.out.Write(chunk)
				wn.blockSizes = append(wn.blockSizes, uint32(len(chunk))|0x1000000)
			}
		}
	}

	// Round one: sizes and layout.  Metadata blocks are written uncompressed
	// (see metaWriter), so every block boundary is a pure function of the
	// payload sizes and the whole layout can be computed up front.
	for _, wn := range w.nodes {
		wn.inodeSize = w.inodeSize(wn)
		if wn.inodeSize > 1<<20 {
			return fmt.Errorf("squashfs: inode for %q is too large (%d bytes)", wn.n.Name, wn.inodeSize)
		}
	}
	lw := &layoutWriter{}
	for _, wn := range w.nodes {
		block, off := lw.pos()
		wn.ref = block<<16 | uint64(off)
		lw.append(wn.inodeSize)
	}
	inodeTableSize := lw.total()

	// Directory content can only be serialised once the inode references are
	// known (they are embedded in the entries), but its size does not depend
	// on the reference values.
	lw = &layoutWriter{}
	for _, wn := range w.nodes {
		if wn.n.Type != TypeDir {
			continue
		}
		content, err := w.dirBytes(wn)
		if err != nil {
			return err
		}
		if len(content)+3 > 0xffff {
			return fmt.Errorf("squashfs: directory %q too large (%d bytes); extended directories are not supported", wn.n.Name, len(content))
		}
		w.dirContent[wn] = content
		block, off := lw.pos()
		wn.dirStart = block
		wn.dirOffset = uint16(off)
		wn.dirSize = uint16(len(content) + 3)
		lw.append(len(content))
	}
	dirTableSize := lw.total()

	// Round two: emit the tables at the computed positions.
	w.inodeTableStart = uint64(w.out.Len())
	iw := newMetaWriter(&w.out)
	for _, wn := range w.nodes {
		block, off, err := iw.pos()
		if err != nil {
			return err
		}
		if got := (block-w.inodeTableStart)<<16 | uint64(off); got != wn.ref {
			return fmt.Errorf("squashfs: inode layout mismatch for %q: %#x != %#x", wn.n.Name, got, wn.ref)
		}
		if err := iw.writeAll(w.inodeBytes(wn)); err != nil {
			return err
		}
	}
	if err := iw.flush(); err != nil {
		return err
	}
	if got := uint64(w.out.Len()) - w.inodeTableStart; got != inodeTableSize {
		return fmt.Errorf("squashfs: inode table size mismatch: %d != %d", got, inodeTableSize)
	}

	w.dirTableStart = uint64(w.out.Len())
	dw := newMetaWriter(&w.out)
	for _, wn := range w.nodes {
		if wn.n.Type != TypeDir {
			continue
		}
		block, off, err := dw.pos()
		if err != nil {
			return err
		}
		if block-w.dirTableStart != wn.dirStart || uint16(off) != wn.dirOffset {
			return fmt.Errorf("squashfs: directory layout mismatch for %q: (%d,%d) != (%d,%d)", wn.n.Name, block-w.dirTableStart, off, wn.dirStart, wn.dirOffset)
		}
		if err := dw.writeAll(w.dirContent[wn]); err != nil {
			return err
		}
	}
	if err := dw.flush(); err != nil {
		return err
	}
	if got := uint64(w.out.Len()) - w.dirTableStart; got != dirTableSize {
		return fmt.Errorf("squashfs: directory table size mismatch: %d != %d", got, dirTableSize)
	}

	// ID table: one uncompressed metadata block holding the single id 0,
	// followed by the pointer array, which must end exactly at bytes_used.
	idBlockStart := uint64(w.out.Len())
	writeMetaBlock(&w.out, []byte{0, 0, 0, 0})
	idTableStart := uint64(w.out.Len())
	var ptr [8]byte
	le.PutUint64(ptr[:], idBlockStart)
	w.out.Write(ptr[:])
	bytesUsed := uint64(w.out.Len())

	// Pad the image to a 4 KiB boundary; the kernel rejects filesystems whose
	// bytes_used exceeds the (sector-rounded) device size.
	for w.out.Len()%4096 != 0 {
		w.out.WriteByte(0)
	}

	// Superblock.
	sb := w.out.Bytes()[:96]
	le.PutUint32(sb[0:], magic)
	le.PutUint32(sb[4:], uint32(len(w.nodes)))
	le.PutUint32(sb[8:], w.opts.MTime)
	le.PutUint32(sb[12:], w.opts.BlockSize)
	le.PutUint32(sb[16:], 0) // fragments
	le.PutUint16(sb[20:], compressionXZ)
	blockLog := uint16(0)
	for (1 << blockLog) < int(w.opts.BlockSize) {
		blockLog++
	}
	le.PutUint16(sb[22:], blockLog)
	le.PutUint16(sb[24:], 0x211) // UNCOMPRESSED_INODES | NO_FRAGMENTS | NO_XATTRS
	le.PutUint16(sb[26:], 1)     // no_ids
	le.PutUint16(sb[28:], 4)
	le.PutUint16(sb[30:], 0)
	le.PutUint64(sb[32:], w.root.ref)
	le.PutUint64(sb[40:], bytesUsed)
	le.PutUint64(sb[48:], idTableStart)
	le.PutUint64(sb[56:], invalidBlk) // xattr table
	le.PutUint64(sb[64:], w.inodeTableStart)
	le.PutUint64(sb[72:], w.dirTableStart)
	le.PutUint64(sb[80:], invalidBlk) // fragment table (no fragments)
	le.PutUint64(sb[88:], invalidBlk) // lookup table (no exports)
	return nil
}

func (w *writer) inodeSize(wn *wnode) int {
	switch wn.n.Type {
	case TypeDir:
		return 32
	case TypeSymlink:
		return 24 + len(wn.n.Data)
	default:
		blocks := 0
		if len(wn.n.Data) > 0 {
			blocks = (len(wn.n.Data) + int(w.opts.BlockSize) - 1) / int(w.opts.BlockSize)
		}
		return 32 + 4*blocks
	}
}

func (w *writer) inodeBytes(wn *wnode) []byte {
	le := binary.LittleEndian
	n := wn.n
	base := make([]byte, 16)
	switch n.Type {
	case TypeDir:
		le.PutUint16(base[0:], typeDir)
	case TypeFile:
		le.PutUint16(base[0:], typeFile)
	case TypeSymlink:
		le.PutUint16(base[0:], typeSymlink)
	}
	le.PutUint16(base[2:], n.Mode&0xfff)
	le.PutUint16(base[4:], 0) // uid index
	le.PutUint16(base[6:], 0) // gid index
	le.PutUint32(base[8:], n.MTime)
	le.PutUint32(base[12:], wn.num)

	switch n.Type {
	case TypeDir:
		out := make([]byte, 0, 32)
		out = append(out, base...)
		var rest [16]byte
		le.PutUint32(rest[0:], uint32(wn.dirStart))
		le.PutUint32(rest[4:], uint32(2+w.subdirCount(wn)))
		le.PutUint16(rest[8:], wn.dirSize)
		le.PutUint16(rest[10:], wn.dirOffset)
		parent := uint32(len(w.nodes) + 1)
		if p, ok := w.parent[n]; ok {
			parent = p.num
		}
		le.PutUint32(rest[12:], parent)
		return append(out, rest[:]...)
	case TypeFile:
		out := make([]byte, 0, 32+len(wn.blockSizes)*4)
		out = append(out, base...)
		var rest [16]byte
		le.PutUint32(rest[0:], uint32(wn.start))
		le.PutUint32(rest[4:], invalidFrag)
		le.PutUint32(rest[8:], 0)
		le.PutUint32(rest[12:], uint32(len(n.Data)))
		out = append(out, rest[:]...)
		for _, bs := range wn.blockSizes {
			var b [4]byte
			le.PutUint32(b[:], bs)
			out = append(out, b[:]...)
		}
		return out
	default: // symlink
		out := make([]byte, 0, 24+len(n.Data))
		out = append(out, base...)
		var rest [8]byte
		le.PutUint32(rest[0:], 1) // nlink
		le.PutUint32(rest[4:], uint32(len(n.Data)))
		out = append(out, rest[:]...)
		return append(out, n.Data...)
	}
}

func (w *writer) subdirCount(wn *wnode) int {
	c := 0
	for _, ch := range wn.n.Children {
		if ch.Type == TypeDir {
			c++
		}
	}
	return c
}

// dirBytes serialises a directory's entries.  Each header covers up to 256
// entries whose inode numbers are within an int16 of its base inode number.
func (w *writer) dirBytes(wn *wnode) ([]byte, error) {
	le := binary.LittleEndian
	var out bytes.Buffer
	children := wn.n.Children
	i := 0
	for i < len(children) {
		base := w.nodeOf(children[i]).num
		baseBlock := w.nodeOf(children[i]).ref >> 16
		run := 0
		for run < 256 && i+run < len(children) {
			cw := w.nodeOf(children[i+run])
			delta := int64(cw.num) - int64(base)
			if delta < -32768 || delta > 32767 || cw.ref>>16 != baseBlock {
				break
			}
			run++
		}
		if run == 0 {
			return nil, fmt.Errorf("squashfs: directory %q entry numbering is out of range", wn.n.Name)
		}
		var hdr [12]byte
		le.PutUint32(hdr[0:], uint32(run-1))
		child0 := w.nodeOf(children[i])
		le.PutUint32(hdr[4:], uint32(child0.ref>>16))
		le.PutUint32(hdr[8:], base)
		out.Write(hdr[:])
		for k := 0; k < run; k++ {
			cw := w.nodeOf(children[i+k])
			name := children[i+k].Name
			if len(name) == 0 || len(name) > 256 {
				return nil, fmt.Errorf("squashfs: invalid name length %d", len(name))
			}
			if cw.ref>>16 != child0.ref>>16 {
				return nil, fmt.Errorf("squashfs: directory %q: entries in one header must share a start block", wn.n.Name)
			}
			var de [8]byte
			le.PutUint16(de[0:], uint16(cw.ref&0xffff))
			le.PutUint16(de[2:], uint16(int64(cw.num)-int64(base)))
			le.PutUint16(de[4:], dirEntryType(children[i+k].Type))
			le.PutUint16(de[6:], uint16(len(name)-1))
			out.Write(de[:])
			out.WriteString(name)
		}
		i += run
	}
	return out.Bytes(), nil
}

func dirEntryType(t NodeType) uint16 {
	switch t {
	case TypeDir:
		return typeDir
	case TypeFile:
		return typeFile
	default:
		return typeSymlink
	}
}

func (w *writer) nodeOf(n *Node) *wnode {
	if w.byNode == nil {
		w.byNode = make(map[*Node]*wnode, len(w.nodes))
		for _, wn := range w.nodes {
			w.byNode[wn.n] = wn
		}
	}
	return w.byNode[n]
}

// layoutWriter mirrors metaWriter's block-splitting without writing bytes, so
// positions can be computed before the payloads exist.
type layoutWriter struct {
	blockBytes uint64
	pending    int
}

func (l *layoutWriter) pos() (uint64, int) {
	return l.blockBytes, l.pending
}

func (l *layoutWriter) append(n int) {
	for n > 0 {
		k := metaSize - l.pending
		if k > n {
			k = n
		}
		l.pending += k
		n -= k
		if l.pending == metaSize {
			l.blockBytes += 2 + uint64(l.pending)
			l.pending = 0
		}
	}
}

func (l *layoutWriter) total() uint64 {
	if l.blockBytes == 0 && l.pending == 0 {
		return 0
	}
	return l.blockBytes + 2 + uint64(l.pending)
}

// writeMetaBlock appends one metadata block with an uncompressed payload.
func writeMetaBlock(out *bytes.Buffer, payload []byte) {
	var hdr [2]byte
	binary.LittleEndian.PutUint16(hdr[:], uint16(len(payload))|0x8000)
	out.Write(hdr[:])
	out.Write(payload)
}

// metaWriter appends uncompressed metadata blocks (8 KiB payloads) to the
// output, tracking the absolute offsets callers need for references.  Keeping
// metadata uncompressed makes every block boundary a pure function of the
// payload sizes, which is what lets the layout be computed up front.
type metaWriter struct {
	out     *bytes.Buffer
	pending []byte
	base    uint64
}

func newMetaWriter(out *bytes.Buffer) *metaWriter {
	return &metaWriter{out: out}
}

// pos returns the (relative block offset, in-block offset) of the next byte.
func (m *metaWriter) pos() (uint64, int, error) {
	if len(m.pending) == 0 {
		m.base = uint64(m.out.Len())
	}
	return m.base, len(m.pending), nil
}

func (m *metaWriter) writeAll(p []byte) error {
	for len(p) > 0 {
		if len(m.pending) == 0 {
			m.base = uint64(m.out.Len())
		}
		n := metaSize - len(m.pending)
		if n > len(p) {
			n = len(p)
		}
		m.pending = append(m.pending, p[:n]...)
		p = p[n:]
		if len(m.pending) == metaSize {
			if err := m.flush(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *metaWriter) flush() error {
	if len(m.pending) == 0 {
		return nil
	}
	writeMetaBlock(m.out, m.pending)
	m.pending = m.pending[:0]
	return nil
}
