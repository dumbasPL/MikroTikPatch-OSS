package image

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// ext2/ext4 constants.  Both filesystems use ext4 features (extents and
// filetype directory entries); partition 1 uses 1 KiB blocks and partition 2
// uses 4 KiB blocks.
const (
	extMagic        = 0xEF53
	extInodeSize    = 128
	extFirstIno     = 11
	extExtentsFlag  = 0x80000
	extentsMagic    = 0xF30A
	extMaxExtents   = 4
	extMaxExtentLen = 32767

	extFeatureCompat   = 0
	extFeatureIncompat = 0x40 | 0x2 // EXTENTS | FILETYPE
	extFeatureROCompat = 0x1 | 0x2  // SPARSE_SUPER | LARGE_FILE

	extStateClean     = 1
	extErrorsContinue = 1
	extRevDynamic     = 1
)

// extent is one depth-0 ext4 extent.
type extent struct {
	logical uint32
	length  uint16
	start   uint32
}

// WriteExt4 formats partition 2 as ext4 with 4 KiB blocks and the volume
// label "RouterOS".
func (im *Image) WriteExt4(entries []Entry) error {
	return im.writeExt(entries, 4096, "RouterOS", ROSStart, ROSEnd)
}

// WriteExt2 formats partition 1 as ext2 with 1 KiB blocks and the volume
// label "RouterOS Boot".  The filesystem uses extents, so it is mounted by
// the ext4 driver.
func (im *Image) WriteExt2(entries []Entry) error {
	return im.writeExt(entries, 1024, "RouterOS Boot", BootStart, BootEnd)
}

// writeExt builds an ext filesystem for entries and writes it to a partition.
func (im *Image) writeExt(entries []Entry, blockSize int, label string, start, end uint64) error {
	root, err := buildTree(entries)
	if err != nil {
		return err
	}
	off, size := partitionRange(start, end)
	data, err := buildExt(root, blockSize, label, uint64(size))
	if err != nil {
		return err
	}
	return im.writeAt(off, data)
}

// extGroup describes one block group.
type extGroup struct {
	start      uint32 // first block of the group
	blocks     uint32 // number of blocks in the group
	bb, ib, it uint32 // block bitmap, inode bitmap, inode table
	freeBlocks uint32
	freeInodes uint32
	usedDirs   uint32
}

// extWriter holds the layout of an ext filesystem while it is being built.
type extWriter struct {
	blockSize int
	label     string

	blocks    uint32 // total blocks
	firstData uint32 // first data block (0 or 1)
	bpg       uint32 // blocks per group
	ipg       uint32 // inodes per group
	inodes    uint32 // total inodes
	itable    uint32 // inode table blocks per group
	gdtBlocks uint32 // group descriptor blocks

	groups []extGroup
	bbits  []byte // global block bitmap
	ibits  []byte // global inode bitmap
}

// buildExt lays out a complete ext filesystem for root and returns the
// partition contents.
func buildExt(root *node, blockSize int, label string, partSize uint64) ([]byte, error) {
	if blockSize != 1024 && blockSize != 4096 {
		return nil, fmt.Errorf("image: unsupported ext block size %d", blockSize)
	}
	w := &extWriter{blockSize: blockSize, label: label}
	w.blocks = uint32(partSize / uint64(blockSize))
	if uint64(w.blocks)*uint64(blockSize) != partSize {
		return nil, fmt.Errorf("image: ext partition size %d is not a multiple of %d", partSize, blockSize)
	}
	if blockSize == 1024 {
		w.firstData = 1
	}
	w.bpg = uint32(8 * blockSize)
	ngroups := (w.blocks - w.firstData + w.bpg - 1) / w.bpg

	// Inodes: roughly one per 16 KiB of space (like mkfs.ext4) but at least
	// enough for the tree, rounded up to whole inode blocks and to at least
	// eight inode blocks per group.
	count := uint32(0)
	if err := root.walk(func(*node) error { count++; return nil }); err != nil {
		return nil, err
	}
	ipb := uint32(blockSize / extInodeSize)
	total := uint32(partSize / 16384)
	if min := 2*count + 8; total < min {
		total = min
	}
	w.ipg = (total + ngroups - 1) / ngroups
	w.ipg = (w.ipg + ipb - 1) / ipb * ipb
	if min := ipb * 8; w.ipg < min {
		w.ipg = min
	}
	w.inodes = w.ipg * ngroups
	w.itable = (w.ipg*extInodeSize + uint32(blockSize) - 1) / uint32(blockSize)
	w.gdtBlocks = (ngroups*32 + uint32(blockSize) - 1) / uint32(blockSize)

	// Place each group's metadata inside the group it describes, which is
	// what the kernel's descriptor validation expects without FLEX_BG.
	w.groups = make([]extGroup, ngroups)
	var pos uint32
	for i := uint32(0); i < ngroups; i++ {
		g := &w.groups[i]
		g.start = w.firstData + i*w.bpg
		g.blocks = w.blocks - g.start
		if g.blocks > w.bpg {
			g.blocks = w.bpg
		}
		if i == 0 {
			pos = w.firstData + 1 + w.gdtBlocks
		} else {
			// Leave room for the backup superblock and group
			// descriptors: the kernel's system zone check expects
			// them at the start of the groups that have a backup.
			pos = g.start
			if groupHasSuper(i) {
				pos += 1 + w.gdtBlocks
			}
		}
		g.bb, g.ib, g.it = pos, pos+1, pos+2
		pos += 2 + w.itable
		if pos > g.start+g.blocks {
			return nil, fmt.Errorf("image: ext metadata does not fit in block group %d", i)
		}
		g.freeBlocks = g.blocks - (pos - g.start)
		g.freeInodes = w.ipg
	}
	dataStart := w.groups[ngroups-1].it + w.itable

	w.bbits = make([]byte, (w.blocks+7)/8)
	w.ibits = make([]byte, (w.inodes+7)/8)
	markBlock := func(b uint32) { w.bbits[b/8] |= 1 << (b % 8) }
	markInode := func(i uint32) { w.ibits[(i-1)/8] |= 1 << ((i - 1) % 8) }

	// Reserve the superblock, group descriptors, bitmaps and inode tables,
	// plus the ten reserved inodes.
	for i := range w.groups {
		g := &w.groups[i]
		for b := g.start; b < g.bb; b++ {
			markBlock(b)
		}
		markBlock(g.bb)
		markBlock(g.ib)
		for b := g.it; b < g.it+w.itable; b++ {
			markBlock(b)
		}
	}
	for i := uint32(1); i < extFirstIno; i++ {
		markInode(i)
	}
	w.groups[0].freeInodes -= extFirstIno - 1
	w.groups[0].usedDirs++ // root

	// Inode numbers: root is 2, everything else follows in pre-order.
	root.ino = 2
	nextIno := uint32(extFirstIno)
	if err := root.walk(func(n *node) error {
		if n == root {
			return nil
		}
		if nextIno > w.inodes {
			return errors.New("image: too many entries for the ext inode table")
		}
		n.ino = nextIno
		nextIno++
		markInode(n.ino)
		g := &w.groups[(n.ino-1)/w.ipg]
		g.freeInodes--
		if n.dir {
			g.usedDirs++
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Directory contents, now that child inode numbers are known.
	if err := root.walk(func(n *node) error {
		if !n.dir {
			return nil
		}
		data, err := extDirData(n, blockSize)
		if err != nil {
			return err
		}
		n.dirData = data
		return nil
	}); err != nil {
		return nil, err
	}

	// Allocate file and directory data blocks from a bump allocator that
	// starts after the metadata.
	next := dataStart
	if err := root.walk(func(n *node) error {
		size := uint32(len(n.data))
		if n.dir {
			size = uint32(len(n.dirData))
		}
		nblocks := (size + uint32(blockSize) - 1) / uint32(blockSize)
		if next+nblocks > w.blocks {
			return errors.New("image: ext partition is full")
		}
		for b := next; b < next+nblocks; b++ {
			n.blocks = append(n.blocks, b)
			markBlock(b)
			w.groups[(b-w.firstData)/w.bpg].freeBlocks--
		}
		n.extents = splitExtents(n.blocks)
		if len(n.extents) > extMaxExtents {
			return fmt.Errorf("image: %q needs more than %d extents", n.name, extMaxExtents)
		}
		next += nblocks
		return nil
	}); err != nil {
		return nil, err
	}

	// Serialise the filesystem.
	uuid := make([]byte, 16)
	if _, err := rand.Read(uuid); err != nil {
		return nil, err
	}
	buf := make([]byte, uint64(w.blocks)*uint64(blockSize))
	copy(buf[1024:2048], w.superblock(uuid))
	gdtOff := (w.firstData + 1) * uint32(blockSize)
	copy(buf[gdtOff:], w.groupDescriptors())
	for i := range w.groups {
		g := &w.groups[i]
		copy(buf[g.bb*uint32(blockSize):], w.blockBitmap(i))
		copy(buf[g.ib*uint32(blockSize):], w.inodeBitmap(i))
	}
	if err := root.walk(func(n *node) error {
		g := (n.ino - 1) / w.ipg
		idx := (n.ino - 1) % w.ipg
		off := w.groups[g].it*uint32(blockSize) + idx*extInodeSize
		copy(buf[off:off+extInodeSize], w.inodeBytes(n))
		return nil
	}); err != nil {
		return nil, err
	}
	if err := root.walk(func(n *node) error {
		src := n.data
		if n.dir {
			src = n.dirData
		}
		for i, b := range n.blocks {
			off := uint32(i) * uint32(blockSize)
			end := off + uint32(blockSize)
			if end > uint32(len(src)) {
				end = uint32(len(src))
			}
			copy(buf[b*uint32(blockSize):], src[off:end])
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return buf, nil
}

// extDirData builds a directory's contents: "." and ".." followed by the
// children, packed into whole blocks with 4-byte aligned record lengths.
func extDirData(n *node, blockSize int) ([]byte, error) {
	type dirent struct {
		ino  uint32
		name string
		typ  uint8
	}
	parent := n
	if n.parent != nil {
		parent = n.parent
	}
	ents := []dirent{{n.ino, ".", 2}, {parent.ino, "..", 2}}
	for _, c := range n.childs {
		typ := uint8(1) // regular file
		if c.dir {
			typ = 2
		}
		ents = append(ents, dirent{c.ino, c.name, typ})
	}

	var out, blk []byte
	last := 0
	flush := func() {
		if len(blk) == 0 {
			return
		}
		// The last entry of a block stretches to the end of the block.
		binary.LittleEndian.PutUint16(blk[last+4:], uint16(blockSize-last))
		blk = append(blk, make([]byte, blockSize-len(blk))...)
		out = append(out, blk...)
		blk = nil
	}
	for _, e := range ents {
		if len(e.name) > 255 {
			return nil, fmt.Errorf("image: name %q is too long", e.name)
		}
		need := (8 + len(e.name) + 3) &^ 3
		if need > blockSize {
			return nil, fmt.Errorf("image: name %q does not fit in a block", e.name)
		}
		if len(blk)+need > blockSize {
			flush()
		}
		last = len(blk)
		blk = append(blk, make([]byte, need)...)
		binary.LittleEndian.PutUint32(blk[last:], e.ino)
		binary.LittleEndian.PutUint16(blk[last+4:], uint16(need))
		blk[last+6] = byte(len(e.name))
		blk[last+7] = e.typ
		copy(blk[last+8:], e.name)
	}
	flush()
	return out, nil
}

// inodeBytes serialises one 128-byte inode.
func (w *extWriter) inodeBytes(n *node) []byte {
	b := make([]byte, extInodeSize)
	typ := uint16(modeFile)
	size := uint32(len(n.data))
	if n.dir {
		typ = modeDir
		size = uint32(len(n.dirData))
	}
	links := uint16(1)
	if n.dir {
		links = 2
		for _, c := range n.childs {
			if c.dir {
				links++
			}
		}
	}
	le := binary.LittleEndian
	le.PutUint16(b[0:], typ|n.mode)
	le.PutUint32(b[4:], size)
	le.PutUint16(b[26:], links)
	le.PutUint32(b[28:], uint32(len(n.blocks))*uint32(w.blockSize/sectorSize))
	le.PutUint32(b[32:], extExtentsFlag)
	putExtents(b[40:100], n.extents)
	return b
}

// putExtents writes a depth-0 extent header and the extents into the 60-byte
// i_block area of an inode.
func putExtents(b []byte, exts []extent) {
	le := binary.LittleEndian
	le.PutUint16(b[0:], extentsMagic)
	le.PutUint16(b[2:], uint16(len(exts)))
	le.PutUint16(b[4:], extMaxExtents)
	le.PutUint16(b[6:], 0) // depth
	for i, e := range exts {
		o := 12 + i*12
		le.PutUint32(b[o:], e.logical)
		le.PutUint16(b[o+4:], e.length)
		le.PutUint16(b[o+6:], uint16(uint64(e.start)>>32))
		le.PutUint32(b[o+8:], e.start)
	}
}

// splitExtents turns a run of blocks into depth-0 extents of at most
// extMaxExtentLen blocks each.
func splitExtents(blocks []uint32) []extent {
	var out []extent
	for i := 0; i < len(blocks); {
		j := i + 1
		for j < len(blocks) && blocks[j] == blocks[j-1]+1 && j-i < extMaxExtentLen {
			j++
		}
		out = append(out, extent{logical: uint32(i), length: uint16(j - i), start: blocks[i]})
		i = j
	}
	return out
}

// superblock serialises the 1024-byte superblock.
func (w *extWriter) superblock(uuid []byte) []byte {
	sb := make([]byte, 1024)
	le := binary.LittleEndian
	var freeBlocks, freeInodes uint32
	for _, g := range w.groups {
		freeBlocks += g.freeBlocks
		freeInodes += g.freeInodes
	}
	le.PutUint32(sb[0:], w.inodes)
	le.PutUint32(sb[4:], w.blocks)
	le.PutUint32(sb[8:], 0) // reserved blocks
	le.PutUint32(sb[12:], freeBlocks)
	le.PutUint32(sb[16:], freeInodes)
	le.PutUint32(sb[20:], w.firstData)
	le.PutUint32(sb[24:], logBlockSize(w.blockSize))
	le.PutUint32(sb[28:], logBlockSize(w.blockSize))
	le.PutUint32(sb[32:], w.bpg)
	le.PutUint32(sb[36:], w.bpg)
	le.PutUint32(sb[40:], w.ipg)
	// s_mtime, s_wtime, s_mnt_count are zero.
	le.PutUint16(sb[54:], 0xFFFF) // no mount count limit
	le.PutUint16(sb[56:], extMagic)
	le.PutUint16(sb[58:], extStateClean)
	le.PutUint16(sb[60:], extErrorsContinue)
	// s_minor_rev_level, s_lastcheck, s_checkinterval are zero.
	le.PutUint32(sb[76:], extRevDynamic)
	// s_def_resuid, s_def_resgid are zero.
	le.PutUint32(sb[84:], extFirstIno)
	le.PutUint16(sb[88:], extInodeSize)
	le.PutUint32(sb[92:], extFeatureCompat)
	le.PutUint32(sb[96:], extFeatureIncompat)
	le.PutUint32(sb[100:], extFeatureROCompat)
	copy(sb[104:120], uuid)
	copy(sb[120:136], w.label)
	return sb
}

// logBlockSize converts a block size to the superblock's log2 field.
func logBlockSize(blockSize int) uint32 {
	var n uint32
	for blockSize > 1024 {
		blockSize >>= 1
		n++
	}
	return n
}

// groupHasSuper reports whether a block group carries a superblock backup.
// With SPARSE_SUPER that is group 0, group 1 and the powers of 3, 5 and 7.
func groupHasSuper(group uint32) bool {
	if group == 0 || group == 1 {
		return true
	}
	for _, base := range []uint64{3, 5, 7} {
		for p := base; p <= uint64(group); p *= base {
			if p == uint64(group) {
				return true
			}
		}
	}
	return false
}

// groupDescriptors serialises the group descriptor table.
func (w *extWriter) groupDescriptors() []byte {
	gdt := make([]byte, w.gdtBlocks*uint32(w.blockSize))
	le := binary.LittleEndian
	for i, g := range w.groups {
		b := gdt[i*32:]
		le.PutUint32(b[0:], g.bb)
		le.PutUint32(b[4:], g.ib)
		le.PutUint32(b[8:], g.it)
		le.PutUint16(b[12:], uint16(g.freeBlocks))
		le.PutUint16(b[14:], uint16(g.freeInodes))
		le.PutUint16(b[16:], uint16(g.usedDirs))
		// bg_flags and bg_itable_unused stay zero: without the
		// uninit_bg/GDT_CSUM feature they are not meaningful.
	}
	return gdt
}

// blockBitmap serialises one group's block bitmap.  Bits beyond the last
// block of a partial group are marked allocated.
func (w *extWriter) blockBitmap(group int) []byte {
	g := &w.groups[group]
	b := make([]byte, w.blockSize)
	for j := uint32(0); j < g.blocks; j++ {
		if w.bbits[(g.start+j)/8]&(1<<((g.start+j)%8)) != 0 {
			b[j/8] |= 1 << (j % 8)
		}
	}
	for j := g.blocks; j < uint32(w.blockSize*8); j++ {
		b[j/8] |= 1 << (j % 8)
	}
	return b
}

// inodeBitmap serialises one group's inode bitmap.  Bits beyond the last
// inode of a group are marked allocated.
func (w *extWriter) inodeBitmap(group int) []byte {
	b := make([]byte, w.blockSize)
	base := uint32(group) * w.ipg
	valid := w.ipg
	if left := w.inodes - base; left < valid {
		valid = left
	}
	for j := uint32(0); j < valid; j++ {
		i := base + j
		if w.ibits[i/8]&(1<<(i%8)) != 0 {
			b[j/8] |= 1 << (j % 8)
		}
	}
	for j := valid; j < uint32(w.blockSize*8); j++ {
		b[j/8] |= 1 << (j % 8)
	}
	return b
}
