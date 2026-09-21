// Package patch rewrites RouterOS binaries so they trust a custom key set: it
// patches the licence and NPK-signing public keys inside kernels, initramfs
// images and squashfs trees, and installs the keygen as /nova/bin/mode.
package patch

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// Logf reports progress; it can be replaced by the CLI.
var Logf = func(format string, args ...any) { fmt.Printf(format, args...) }

// ArmLoadImm builds the three ARMv7 instructions that load a 32-bit immediate
// into rd.
//
// The stock ARM binaries do not store the licence key word verbatim: they
// rebuild it from a table entry plus a hard-coded delta.  For a new key the
// delta does not fit, so the word is loaded directly instead.
//
// style "movt": MOVW/MOVT/NOP (32-bit key table, word = bytes 12..16).
// style "orr":  MOVW/ORR/ORR (packed key table, word 8).
func ArmLoadImm(rd uint32, value uint32, style string) [][]byte {
	lo := value & 0xffff
	movw := uint32(0xE3000000) | ((lo & 0xf000) << 4) | (rd << 12) | (lo & 0xfff)
	var words [3]uint32
	if style == "orr" {
		b2 := (value >> 16) & 0xff
		b3 := (value >> 24) & 0xff
		words[0] = movw
		words[1] = 0xE3800000 | (rd << 16) | (rd << 12) | (8 << 8) | b2
		words[2] = 0xE3800000 | (rd << 16) | (rd << 12) | (4 << 8) | b3
	} else {
		hi := (value >> 16) & 0xffff
		words[0] = movw
		words[1] = 0xE3400000 | ((hi & 0xf000) << 4) | (rd << 12) | (hi & 0xfff)
		words[2] = 0xE1A00000 // NOP
	}
	out := make([][]byte, 3)
	for i, w := range words {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, w)
		out[i] = b
	}
	return out
}

// ReplaceChunks replaces every occurrence of the old chunk sequence with the
// new one, allowing up to six bytes between consecutive chunks.  The gap bytes
// are preserved, and (like Python's greedy regex) the largest gap that still
// lets the remaining chunks match is used.
func ReplaceChunks(oldChunks, newChunks [][]byte, data []byte, name string) []byte {
	if len(oldChunks) == 0 || len(oldChunks) != len(newChunks) {
		return data
	}
	var out bytes.Buffer
	last := 0
	pos := 0
	for {
		start := bytes.Index(data[pos:], oldChunks[0])
		if start < 0 {
			break
		}
		start += pos
		end, gaps, ok := matchGreedy(data, start, oldChunks)
		if !ok {
			pos = start + 1
			continue
		}
		out.Write(data[last:start])
		for i := 0; i < len(newChunks)-1; i++ {
			out.Write(newChunks[i])
			out.Write(gaps[i])
		}
		out.Write(newChunks[len(newChunks)-1])
		Logf("%s public key patched %X...\n", name, oldChunks[0])
		last = end
		pos = end
	}
	out.Write(data[last:])
	return out.Bytes()
}

// matchGreedy finds the end of the chunk sequence starting at start, returning
// the gaps between chunks and whether a match exists.  Gaps are searched from
// largest to smallest to reproduce the greedy quantifier.
func matchGreedy(data []byte, start int, chunks [][]byte) (int, [][]byte, bool) {
	if len(chunks) == 1 {
		return start + len(chunks[0]), nil, true
	}
	after := start + len(chunks[0])
	rest := chunks[1:]
	maxGap := 6
	if limit := len(data) - after - len(rest[len(rest)-1]); limit < maxGap {
		maxGap = limit
	}
	if maxGap < 0 {
		return 0, nil, false
	}
	for gap := maxGap; gap >= 0; gap-- {
		idx := after + gap
		if idx+len(rest[0]) > len(data) {
			continue
		}
		if !bytes.Equal(data[idx:idx+len(rest[0])], rest[0]) {
			continue
		}
		end, gaps, ok := matchGreedy(data, idx, rest)
		if ok {
			all := make([][]byte, 0, len(chunks)-1)
			all = append(all, data[after:idx])
			all = append(all, gaps...)
			return end, all, true
		}
	}
	return 0, nil, false
}

// keyMap is the byte order of the packed key table.
var keyMap = []int{28, 19, 25, 16, 14, 3, 24, 15, 22, 8, 6, 17, 11, 7, 9, 23,
	18, 13, 10, 0, 26, 21, 2, 5, 20, 30, 31, 4, 27, 29, 1, 12}

// ReplaceKeyArch replaces every stored form of an old public key with the new
// one.  archEnv selects the ARM handling and is ARCH-style ("x86", "arm64");
// anything else gets the byte-level replacements only.
//
// ARM binaries additionally rebuild part of the licence key from hard-coded
// instructions, which are rewritten to load the new key directly.
func ReplaceKeyArch(old, new []byte, data []byte, name, archEnv string) []byte {
	oldChunks := chunk4(old)
	newChunks := chunk4(new)
	data = ReplaceChunks(oldChunks, newChunks, data, name)

	// The byte-packed key table stores the key bytes in a shuffled order.
	oldShuffled := make([][]byte, len(keyMap))
	newShuffled := make([][]byte, len(keyMap))
	for i, idx := range keyMap {
		oldShuffled[i] = []byte{old[idx]}
		newShuffled[i] = []byte{new[idx]}
	}
	data = ReplaceChunks(oldShuffled, newShuffled, data, name)

	arch := strings.ReplaceAll(archEnv, "-", "")
	if arch != "arm" && arch != "arm64" {
		return data
	}
	// Full-word key table: the stock word order differs from the byte order.
	oldBytes := concat(oldChunks[4], oldChunks[5], oldChunks[2], oldChunks[0], oldChunks[1], oldChunks[6], oldChunks[7])
	newBytes := concat(newChunks[4], newChunks[5], newChunks[2], newChunks[0], newChunks[1], newChunks[6], newChunks[7])
	if bytes.Contains(data, oldBytes) {
		Logf("%s public key patched %X...\n", name, old[:16])
		data = bytes.ReplaceAll(data, oldBytes, newBytes)
		oldCodes := [][]byte{
			mustHex("793583E2"), mustHex("FD3A83E2"), mustHex("193D83E2"),
		}
		newCodes := ArmLoadImm(3, binary.LittleEndian.Uint32(new[12:16]), "movt")
		data = ReplaceChunks(oldCodes, newCodes, data, name)
		return data
	}
	// Packed key table: the words are bit-packed and the stock code rebuilds
	// word 8 from a hard-coded delta.
	oldWords := packedWords(old)
	newWords := packedWords(new)
	oldJoined := joinExcept(oldWords, 8)
	newJoined := joinExcept(newWords, 8)
	if bytes.Contains(data, oldJoined) {
		Logf("%s public key patched %X...\n", name, old[:16])
		data = bytes.ReplaceAll(data, oldJoined, newJoined)
		oldCodes := [][]byte{
			mustHex("713783E2"), mustHex("223A83E2"), mustHex("8D3F83E2"),
		}
		newCodes := ArmLoadImm(3, binary.LittleEndian.Uint32(newWords[8]), "orr")
		data = ReplaceChunks(oldCodes, newCodes, data, name)
	}
	return data
}

func packedWords(key []byte) [][]byte {
	w := []uint32{
		uint32(key[2])<<16 | uint32(key[1])<<8 | uint32(key[0]) | (uint32(key[3]) << 24 & 0x03000000),
		uint32(key[3])>>2 | uint32(key[4])<<6 | uint32(key[5])<<14 | (uint32(key[6]) << 22 & 0x1C00000),
		uint32(key[6])>>3 | uint32(key[7])<<5 | uint32(key[8])<<13 | (uint32(key[9]) << 21 & 0x3E00000),
		uint32(key[9])>>5 | uint32(key[10])<<3 | uint32(key[11])<<11 | (uint32(key[12]) << 19 & 0x1F80000),
		uint32(key[12])>>6 | uint32(key[13])<<2 | uint32(key[14])<<10 | uint32(key[15])<<18,
		uint32(key[16]) | uint32(key[17])<<8 | uint32(key[18])<<16 | (uint32(key[19]) << 24 & 0x01000000),
		uint32(key[19])>>1 | uint32(key[20])<<7 | uint32(key[21])<<15 | (uint32(key[22]) << 23 & 0x03800000),
		uint32(key[22])>>3 | uint32(key[23])<<5 | uint32(key[24])<<13 | (uint32(key[25]) << 21 & 0x1E00000),
		uint32(key[25])>>4 | uint32(key[26])<<4 | uint32(key[27])<<12 | (uint32(key[28]) << 20 & 0x3F00000),
		uint32(key[28])>>6 | uint32(key[29])<<2 | uint32(key[30])<<10 | uint32(key[31])<<18,
	}
	out := make([][]byte, len(w))
	for i, v := range w {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, v)
		out[i] = b
	}
	return out
}

func chunk4(data []byte) [][]byte {
	out := make([][]byte, 0, (len(data)+3)/4)
	for i := 0; i < len(data); i += 4 {
		end := i + 4
		if end > len(data) {
			end = len(data)
		}
		out = append(out, data[i:end])
	}
	return out
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func joinExcept(words [][]byte, skip int) []byte {
	var out []byte
	for i, w := range words {
		if i == skip {
			continue
		}
		out = append(out, w...)
	}
	return out
}

func mustHex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		fmt.Sscanf(s[2*i:2*i+2], "%02x", &out[i])
	}
	return out
}

// ReplaceStrings replaces stock hosts and keys in data.
func ReplaceStrings(data []byte, replacements map[string]string, name string) []byte {
	for old, new := range replacements {
		if bytes.Contains(data, []byte(old)) {
			Logf("%s patched %s...\n", name, old[:min(7, len(old))])
			data = bytes.ReplaceAll(data, []byte(old), []byte(new))
		}
	}
	return data
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
