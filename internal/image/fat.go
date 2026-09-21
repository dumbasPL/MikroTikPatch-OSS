package image

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// FAT16 parameters of the boot partition, matching the official CHR images.
const (
	fatBPS         = 512
	fatSPC         = 4
	fatReserved    = 4
	fatNumFATs     = 2
	fatRootEntries = 512
	fatMedia       = 0xF8
	fatLabel       = "BOOT"
	fatOEM         = "mkfs.fat"
	fatFSType      = "FAT16   "

	fatAttrVolume  = 0x08
	fatAttrDir     = 0x10
	fatAttrArchive = 0x20
)

// fatBootCode is a minimal boot stub (cli; hlt; jmp $).  The boot sector is
// never executed on a UEFI system; it only exists so that the BPB lives in a
// plausible boot sector.
var fatBootCode = []byte{0xFA, 0xF4, 0xEB, 0xFD}

// WriteFAT16 formats partition 1 as FAT16 and writes entries to it.  Names
// must be representable as 8.3 names.
func (im *Image) WriteFAT16(entries []Entry) error {
	root, err := buildTree(entries)
	if err != nil {
		return err
	}
	data, err := buildFAT16(root)
	if err != nil {
		return err
	}
	off, _ := partitionRange(BootStart, BootEnd)
	return im.writeAt(off, data)
}

// buildFAT16 lays out a complete FAT16 filesystem for root.
func buildFAT16(root *node) ([]byte, error) {
	total := uint32(BootEnd - BootStart + 1)
	rootDirSectors := uint32(fatRootEntries*32) / fatBPS

	// Find the smallest FAT that covers the clusters it describes.
	var fatSectors, clusters uint32
	for fatSectors = 1; ; fatSectors++ {
		dataSectors := total - fatReserved - fatNumFATs*fatSectors - rootDirSectors
		if int32(dataSectors) <= 0 {
			return nil, errors.New("image: FAT16 partition too small")
		}
		clusters = dataSectors / fatSPC
		if clusters >= 4085 && clusters < 0xFFF5 && (clusters+2)*2 <= fatSectors*fatBPS {
			break
		}
		if fatSectors >= 256 {
			return nil, errors.New("image: cannot lay out a FAT16 filesystem")
		}
	}
	clusterBytes := uint32(fatSPC * fatBPS)

	// Convert names and allocate clusters depth-first, parents before
	// children, so that directory contents can refer to child clusters.
	next := uint32(2)
	err := root.walk(func(n *node) error {
		names := map[[11]byte]string{}
		for _, c := range n.childs {
			nm, err := fatName(c.name)
			if err != nil {
				return err
			}
			if prev, ok := names[nm]; ok {
				return fmt.Errorf("image: %q and %q are the same FAT 8.3 name", prev, c.name)
			}
			names[nm] = c.name
			c.fatName = nm

			var nclusters uint32
			if c.dir {
				nclusters = (uint32(len(c.childs))*32 + 2*32 + clusterBytes - 1) / clusterBytes
			} else {
				nclusters = (uint32(len(c.data)) + clusterBytes - 1) / clusterBytes
			}
			if next+nclusters > clusters+2 {
				return fmt.Errorf("image: FAT16 partition is full at %q", c.name)
			}
			for i := uint32(0); i < nclusters; i++ {
				c.clusters = append(c.clusters, next+i)
			}
			next += nclusters
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Build the two identical FATs.
	fat := make([]byte, fatSectors*fatBPS)
	binary.LittleEndian.PutUint16(fat[0:], 0xFFF8) // media byte 0xF8
	binary.LittleEndian.PutUint16(fat[2:], 0xFFFF)
	root.walk(func(n *node) error {
		for _, c := range n.childs {
			for i := range c.clusters {
				link := uint32(0xFFFF)
				if i+1 < len(c.clusters) {
					link = c.clusters[i+1]
				}
				binary.LittleEndian.PutUint16(fat[c.clusters[i]*2:], uint16(link))
			}
		}
		return nil
	})

	out := make([]byte, total*fatBPS)
	boot := out[:fatBPS]

	// Boot sector with the BPB.
	copy(boot[0:3], []byte{0xEB, 0x3C, 0x90})
	copy(boot[3:11], fatOEM)
	le := binary.LittleEndian
	le.PutUint16(boot[11:], fatBPS)
	boot[13] = fatSPC
	le.PutUint16(boot[14:], fatReserved)
	boot[16] = fatNumFATs
	le.PutUint16(boot[17:], fatRootEntries)
	le.PutUint16(boot[19:], uint16(total))
	boot[21] = fatMedia
	le.PutUint16(boot[22:], uint16(fatSectors))
	le.PutUint16(boot[24:], 32) // sectors per track
	le.PutUint16(boot[26:], 8)  // heads
	le.PutUint32(boot[28:], BootStart)
	boot[36] = 0x80 // drive number
	boot[38] = 0x29 // extended boot signature
	var volid [4]byte
	if _, err := rand.Read(volid[:]); err != nil {
		return nil, err
	}
	copy(boot[39:43], volid[:])
	copy(boot[43:54], pad11(fatLabel))
	copy(boot[54:62], fatFSType)
	copy(boot[62:], fatBootCode)
	boot[510] = 0x55
	boot[511] = 0xAA

	fatOff := uint32(fatReserved) * fatBPS
	copy(out[fatOff:], fat)
	copy(out[fatOff+fatSectors*fatBPS:], fat)

	// Root directory: the volume label followed by the tree.
	rootOff := fatOff + fatNumFATs*fatSectors*fatBPS
	rd := out[rootOff : rootOff+rootDirSectors*fatBPS]
	copy(rd[0:11], pad11(fatLabel))
	rd[11] = fatAttrVolume
	off := uint32(32)
	for _, c := range root.childs {
		if off+32 > uint32(len(rd)) {
			return nil, errors.New("image: too many entries in the FAT16 root directory")
		}
		fatDirEntry(rd[off:], c.fatName, fatAttr(c), firstCluster(c), uint32(len(c.data)))
		off += 32
	}

	// File and subdirectory data.
	dataOff := rootOff + rootDirSectors*fatBPS
	root.walk(func(n *node) error {
		for _, c := range n.childs {
			if len(c.clusters) == 0 {
				continue
			}
			dst := out[dataOff+(c.clusters[0]-2)*clusterBytes:]
			if c.dir {
				copy(dst, fatDirData(c))
			} else {
				copy(dst, c.data)
			}
		}
		return nil
	})
	return out, nil
}

// fatDirData lays out the contents of a subdirectory: the "." and ".."
// entries followed by its children.
func fatDirData(n *node) []byte {
	clusterBytes := uint32(fatSPC * fatBPS)
	out := make([]byte, uint32(len(n.clusters))*clusterBytes)
	var dot, dotdot [11]byte
	copy(dot[:], ".          ")
	copy(dotdot[:], "..         ")
	parent := n.parent
	if parent == nil {
		parent = n
	}
	fatDirEntry(out[0:], dot, fatAttrDir, firstCluster(n), 0)
	fatDirEntry(out[32:], dotdot, fatAttrDir, firstCluster(parent), 0)
	off := uint32(64)
	for _, c := range n.childs {
		fatDirEntry(out[off:], c.fatName, fatAttr(c), firstCluster(c), uint32(len(c.data)))
		off += 32
	}
	return out
}

// fatAttr returns the directory entry attributes of a node.
func fatAttr(n *node) byte {
	if n.dir {
		return fatAttrDir
	}
	return fatAttrArchive
}

// fatDirEntry writes one 32-byte directory entry.
func fatDirEntry(b []byte, name [11]byte, attr byte, cluster, size uint32) {
	copy(b[0:11], name[:])
	b[11] = attr
	binary.LittleEndian.PutUint16(b[20:], uint16(cluster>>16))
	binary.LittleEndian.PutUint16(b[26:], uint16(cluster))
	binary.LittleEndian.PutUint32(b[28:], size)
}

// firstCluster returns a node's first FAT cluster, or 0 (the root directory)
// when it has none.
func firstCluster(n *node) uint32 {
	if n == nil || len(n.clusters) == 0 {
		return 0
	}
	return n.clusters[0]
}

// fatName converts a file name to its 11-byte 8.3 representation.
func fatName(name string) ([11]byte, error) {
	var out [11]byte
	for i := range out {
		out[i] = ' '
	}
	base, ext := name, ""
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		base, ext = name[:i], name[i+1:]
	}
	if len(base) == 0 || len(base) > 8 || len(ext) > 3 {
		return out, fmt.Errorf("image: %q cannot be represented as a FAT 8.3 name", name)
	}
	for i := 0; i < len(base); i++ {
		c, ok := fatChar(base[i])
		if !ok {
			return out, fmt.Errorf("image: %q cannot be represented as a FAT 8.3 name", name)
		}
		out[i] = c
	}
	for i := 0; i < len(ext); i++ {
		c, ok := fatChar(ext[i])
		if !ok {
			return out, fmt.Errorf("image: %q cannot be represented as a FAT 8.3 name", name)
		}
		out[8+i] = c
	}
	return out, nil
}

// fatChar validates and upper-cases one character of a short FAT name.
func fatChar(c byte) (byte, bool) {
	switch {
	case c >= 'a' && c <= 'z':
		return c - 'a' + 'A', true
	case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return c, true
	}
	switch c {
	case '$', '%', '\'', '-', '_', '@', '~', '`', '!', '(', ')', '{', '}', '^', '#', '&':
		return c, true
	}
	return 0, false
}

// pad11 returns s as an 11-byte space-padded upper-case name.
func pad11(s string) []byte {
	b := make([]byte, 11)
	for i := range b {
		b[i] = ' '
	}
	copy(b, strings.ToUpper(s))
	return b
}
