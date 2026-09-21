package build

import (
	"encoding/binary"
	"fmt"
)

// ext2FileLayout parses partition 1 of a disk image and returns the block list
// (in filesystem blocks) of every regular file, keyed by its path relative to
// the filesystem root.  It understands the ext4 extent trees the image writer
// produces.
func ext2FileLayout(disk []byte, partStart uint64) (map[string][]uint64, error) {
	base := int64(partStart) * 512
	if base+2048 > int64(len(disk)) {
		return nil, fmt.Errorf("partition out of range")
	}
	part := disk[base:]
	sb := part[1024:]
	if binary.LittleEndian.Uint16(sb[56:]) != 0xEF53 {
		return nil, fmt.Errorf("not an ext2/ext4 filesystem")
	}
	logBlock := int(binary.LittleEndian.Uint32(sb[24:]))
	blockSize := 1024 << logBlock
	inodeSize := int(binary.LittleEndian.Uint16(sb[88:]))
	inodesPerGroup := uint64(binary.LittleEndian.Uint32(sb[40:]))
	gdtBlock := uint64(1)
	if blockSize == 1024 {
		gdtBlock = 2
	}
	readBlock := func(block uint64) ([]byte, error) {
		off := int64(block) * int64(blockSize)
		if off < 0 || off+int64(blockSize) > int64(len(part)) {
			return nil, fmt.Errorf("block %d out of range", block)
		}
		return part[off : off+int64(blockSize)], nil
	}
	readInode := func(num uint64) ([]byte, error) {
		if num == 0 {
			return nil, fmt.Errorf("null inode")
		}
		group := (num - 1) / inodesPerGroup
		index := (num - 1) % inodesPerGroup
		gdt, err := readBlock(gdtBlock)
		if err != nil {
			return nil, err
		}
		if int(group*32+12) > len(gdt) {
			return nil, fmt.Errorf("group descriptor %d out of range", group)
		}
		table := uint64(binary.LittleEndian.Uint32(gdt[group*32+8:]))
		byteOff := table*uint64(blockSize) + index*uint64(inodeSize)
		if byteOff+uint64(inodeSize) > uint64(len(part)) {
			return nil, fmt.Errorf("inode %d out of range", num)
		}
		return part[byteOff : byteOff+uint64(inodeSize)], nil
	}

	// walkExtents expands an on-disk extent tree.
	var walkExtents func(header []byte, depth int) []uint64
	walkExtents = func(header []byte, depth int) []uint64 {
		if len(header) < 12 {
			return nil
		}
		entries := int(binary.LittleEndian.Uint16(header[2:]))
		var out []uint64
		for i := 0; i < entries; i++ {
			pos := 12 + i*12
			if pos+12 > len(header) {
				break
			}
			if depth == 0 {
				eeLen := uint64(binary.LittleEndian.Uint16(header[pos+4:]))
				startHi := uint64(binary.LittleEndian.Uint16(header[pos+6:]))
				startLo := uint64(binary.LittleEndian.Uint32(header[pos+8:]))
				start := startHi<<32 | startLo
				n := eeLen
				if n > 32768 { // uninitialised extent
					n -= 32768
				}
				for b := uint64(0); b < n && b < 1<<20; b++ {
					out = append(out, start+b)
				}
			} else {
				child := uint64(binary.LittleEndian.Uint32(header[pos+4:]))
				hi := uint64(binary.LittleEndian.Uint16(header[pos+8:]))
				node := hi<<32 | child
				if data, err := readBlock(node); err == nil {
					out = append(out, walkExtents(data, depth-1)...)
				}
			}
		}
		return out
	}
	inodeBlocks := func(inode []byte) ([]uint64, error) {
		iBlock := inode[40:100]
		if binary.LittleEndian.Uint16(iBlock[0:]) != 0xF30A {
			return nil, fmt.Errorf("inode does not use extents")
		}
		depth := int(binary.LittleEndian.Uint16(iBlock[6:]))
		return walkExtents(iBlock, depth), nil
	}

	result := map[string][]uint64{}
	var visit func(name string, inodeNum uint64, depth int) error
	visit = func(name string, inodeNum uint64, depth int) error {
		if depth > 64 {
			return fmt.Errorf("directory nesting too deep")
		}
		inode, err := readInode(inodeNum)
		if err != nil {
			return err
		}
		mode := binary.LittleEndian.Uint16(inode[0:])
		blocks, err := inodeBlocks(inode)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		switch mode & 0xF000 {
		case 0x8000:
			result[name] = blocks
		case 0x4000:
			for _, block := range blocks {
				data, err := readBlock(block)
				if err != nil {
					return err
				}
				for off := 0; off+8 <= len(data); {
					recLen := int(binary.LittleEndian.Uint16(data[off+4:]))
					if recLen < 8 {
						break
					}
					childInode := uint64(binary.LittleEndian.Uint32(data[off:]))
					nameLen := int(data[off+6])
					if off+8+nameLen > len(data) {
						break
					}
					childName := string(data[off+8 : off+8+nameLen])
					if childInode != 0 && childName != "." && childName != ".." {
						p := childName
						if name != "" {
							p = name + "/" + childName
						}
						if err := visit(p, childInode, depth+1); err != nil {
							return err
						}
					}
					off += recLen
				}
			}
		}
		return nil
	}
	if err := visit("", 2, 0); err != nil {
		return nil, err
	}
	return result, nil
}
