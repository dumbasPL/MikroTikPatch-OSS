// Package patch rewrites RouterOS binaries so they trust a custom key set: it
// patches the licence and NPK-signing public keys inside kernels, initramfs
// images and squashfs trees, and installs the keygen as /nova/bin/mode.
package patch

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// Logf reports progress; it can be replaced by the CLI.
var Logf = func(format string, args ...any) { fmt.Printf(format, args...) }

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

// unorderedKeySpan bounds the distance between the first and last chunk of one
// key.  The x86 binaries materialise the key as eight independent
// mov-immediate instructions; even the disp32 form (10 bytes each) leaves
// plenty of room in this window.
const unorderedKeySpan = 256

type chunkHit struct {
	offset int
	chunk  int
}

// ReplaceChunksUnordered replaces a set of chunks that occur close together in
// an arbitrary order.
//
// The x86 licence verifiers load the key as eight independent mov-immediate
// instructions.  The compiler may schedule those in any order, and RouterOS
// 7.25 does: chunks 5 and 6 are emitted swapped even though the resulting
// on-stack key is identical.  An ordered search therefore misses the key, so
// accept a window that holds every chunk exactly once.
func ReplaceChunksUnordered(oldChunks, newChunks [][]byte, data []byte, name string) []byte {
	if len(oldChunks) < 2 || len(oldChunks) != len(newChunks) {
		return data
	}
	var hits []chunkHit
	for i, chunk := range oldChunks {
		for pos := 0; ; {
			j := bytes.Index(data[pos:], chunk)
			if j < 0 {
				break
			}
			hits = append(hits, chunkHit{offset: pos + j, chunk: i})
			pos += j + 1
		}
	}
	if len(hits) < len(oldChunks) {
		return data
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].offset < hits[j].offset })

	replace := make(map[int]int) // chunk offset -> chunk index
	for start := 0; start+len(oldChunks) <= len(hits); start++ {
		window := hits[start : start+len(oldChunks)]
		if window[len(window)-1].offset+len(oldChunks[0])-window[0].offset > unorderedKeySpan {
			continue
		}
		seen := make([]bool, len(oldChunks))
		complete := true
		for _, h := range window {
			if seen[h.chunk] {
				complete = false
				break
			}
			seen[h.chunk] = true
		}
		if !complete {
			continue
		}
		for _, h := range window {
			replace[h.offset] = h.chunk
		}
		start += len(oldChunks) - 1
	}
	if len(replace) == 0 {
		return data
	}
	out := append([]byte(nil), data...)
	for offset, chunk := range replace {
		copy(out[offset:], newChunks[chunk])
	}
	Logf("%s public key patched %X...\n", name, oldChunks[0])
	return out
}

// armTableSpan bounds the span of a literal pool that stores the words of one
// ARM key representation.  Compilers keep the words contiguous; the slack
// tolerates alignment padding and a few interleaved constants.
const armTableSpan = 128

// armWordTable is one way RouterOS materialises the ARM public key: a literal
// pool with most of the words and, usually, an instruction sequence that
// derives the remaining word.
type armWordTable struct {
	oldWords [][]byte
	newWords [][]byte
	stored   []int // word indices present in the literal pool
	derived  int   // word index computed by instructions, or -1
}

// armPatch is one in-place replacement.
type armPatch struct {
	off  int
	data []byte
}

// replaceArmKey patches every ARM key table in data.  Both known encodings are
// tried: the full-word table used by the arm32 userspace (seven words stored,
// the fourth derived) and the bit-packed table (nine words stored, the ninth
// derived).  The stored words are matched as a set, in any order, and the
// table is only patched when the derived word can be rewritten too.
func replaceArmKey(old, new []byte, data []byte, name string) []byte {
	tables := []armWordTable{
		{oldWords: chunk4(old), newWords: chunk4(new),
			stored: []int{4, 5, 2, 0, 1, 6, 7}, derived: 3},
		{oldWords: packedWords(old), newWords: packedWords(new),
			stored: []int{0, 1, 2, 3, 4, 5, 6, 7, 9}, derived: 8},
	}
	for {
		patched := false
		for _, t := range tables {
			out, ok := replaceArmTable(data, t, name)
			if ok {
				data = out
				patched = true
				break
			}
		}
		if !patched {
			return data
		}
	}
}

// replaceArmTable patches one key table.  If the table happens to contain all
// eight (or ten) words, no instruction rewrite is needed.  Otherwise the
// stored words are patched and the derived word's instruction sequence is
// rewritten atomically: a table match with no usable derived-word patch does
// not change data at all.
func replaceArmTable(data []byte, t armWordTable, name string) ([]byte, bool) {
	all := append([]int(nil), t.stored...)
	if t.derived >= 0 {
		all = append(all, t.derived)
	}
	if out, ok := patchArmWordSet(data, t.oldWords, t.newWords, all, name); ok {
		return out, true
	}
	if t.derived < 0 {
		return data, false
	}

	chunks := make([][]byte, len(t.stored))
	for i, idx := range t.stored {
		chunks[i] = t.oldWords[idx]
	}
	offsets, ok := findChunkSet(data, chunks, armTableSpan)
	if !ok {
		return data, false
	}
	wordOffsets := make(map[int]int, len(t.stored))
	for i, idx := range t.stored {
		wordOffsets[idx] = offsets[i]
	}
	derivedPatches, ok := patchArmDerived(data, t.oldWords, t.newWords, t.derived, wordOffsets)
	if !ok {
		return data, false
	}

	out := append([]byte(nil), data...)
	for i, idx := range t.stored {
		copy(out[offsets[i]:], t.newWords[idx])
	}
	for _, p := range derivedPatches {
		copy(out[p.off:], p.data)
	}
	Logf("%s public key patched %X...\n", name, t.oldWords[0])
	return out, true
}

// patchArmWordSet finds a window holding every word in indices, in any order,
// and replaces each with the corresponding new word.
func patchArmWordSet(data []byte, oldWords, newWords [][]byte, indices []int, name string) ([]byte, bool) {
	chunks := make([][]byte, len(indices))
	for i, idx := range indices {
		chunks[i] = oldWords[idx]
	}
	offsets, ok := findChunkSet(data, chunks, armTableSpan)
	if !ok {
		return data, false
	}
	out := append([]byte(nil), data...)
	for i, idx := range indices {
		copy(out[offsets[i]:], newWords[idx])
	}
	Logf("%s public key patched %X...\n", name, oldWords[0])
	return out, true
}

// findChunkSet finds one window in data that contains all chunks exactly once,
// in any order, with the whole set spanning at most span bytes.  It anchors on
// the first chunk and searches the window around each of its occurrences.
func findChunkSet(data []byte, chunks [][]byte, span int) ([]int, bool) {
	if len(chunks) == 0 || span <= 0 {
		return nil, false
	}
	for pos := 0; ; {
		j := bytes.Index(data[pos:], chunks[0])
		if j < 0 {
			return nil, false
		}
		anchor := pos + j
		lo := anchor - span
		if lo < 0 {
			lo = 0
		}
		hi := anchor + span + len(chunks[0])
		if hi > len(data) {
			hi = len(data)
		}
		offsets := make([]int, len(chunks))
		offsets[0] = anchor
		complete := true
		for i := 1; i < len(chunks); i++ {
			k := bytes.Index(data[lo:hi], chunks[i])
			if k < 0 {
				complete = false
				break
			}
			offsets[i] = lo + k
		}
		if complete {
			first, last := offsets[0], offsets[0]
			for _, off := range offsets[1:] {
				if off < first {
					first = off
				}
				if off > last {
					last = off
				}
			}
			if last+4-first <= span {
				return offsets, true
			}
		}
		pos = anchor + 1
	}
}

// armInsn is one 32-bit ARM instruction with its file offset.
type armInsn struct {
	off  int
	word uint32
}

func armRor(v uint32, shift uint32) uint32 {
	shift &= 31
	if shift == 0 {
		return v
	}
	return v>>shift | v<<(32-shift)
}

// armAddSub decodes ADD/SUB <Rd>, <Rd>, #imm.  It only accepts the
// unconditional, flag-preserving form the compilers use for key arithmetic.
func armAddSub(w uint32) (reg int, imm uint32, sub, ok bool) {
	if w>>28 != 0xE || w&0x0E000000 != 0x02000000 || w&(1<<20) != 0 {
		return 0, 0, false, false
	}
	op := (w >> 21) & 0xf
	if op != 2 && op != 4 {
		return 0, 0, false, false
	}
	rd := int((w >> 12) & 0xf)
	if int((w>>16)&0xf) != rd {
		return 0, 0, false, false
	}
	return rd, armRor(w&0xff, 2*((w>>8)&0xf)), op == 2, true
}

func armMovw(w uint32) (reg int, imm uint16, ok bool) {
	if w>>28 != 0xE || w&0x0ff00000 != 0x03000000 {
		return 0, 0, false
	}
	return int((w >> 12) & 0xf), uint16((w>>16)&0xf)<<12 | uint16(w&0xfff), true
}

func armMovt(w uint32) (reg int, imm uint16, ok bool) {
	if w>>28 != 0xE || w&0x0ff00000 != 0x03400000 {
		return 0, 0, false
	}
	return int((w >> 12) & 0xf), uint16((w>>16)&0xf)<<12 | uint16(w&0xfff), true
}

// armLdrLiteral decodes LDR <Rd>, [pc, #imm].
func armLdrLiteral(w uint32, off int) (reg, target int, ok bool) {
	if w>>28 != 0xE || w&0x0f7f0000 != 0x051f0000 {
		return 0, 0, false
	}
	imm := int(w & 0xfff)
	if w&(1<<23) == 0 {
		imm = -imm
	}
	return int((w >> 12) & 0xf), off + 8 + imm, true
}

// armStrSp reports whether w is STR <Rd>, [sp, #imm].
func armStrSp(w uint32) (reg int, ok bool) {
	if w>>28 != 0xE || (w&0x0ff00000 != 0x05800000 && w&0x0ff00000 != 0x05000000) {
		return 0, false
	}
	if (w>>16)&0xf != 13 {
		return 0, false
	}
	return int((w >> 12) & 0xf), true
}

func armMovwInsn(reg int, imm uint16) []byte {
	w := uint32(0xE3000000) | uint32((imm>>12)&0xf)<<16 | uint32(reg)<<12 | uint32(imm&0xfff)
	return armWord(w)
}

func armMovtInsn(reg int, imm uint16) []byte {
	w := uint32(0xE3400000) | uint32((imm>>12)&0xf)<<16 | uint32(reg)<<12 | uint32(imm&0xfff)
	return armWord(w)
}

func armNop() []byte { return armWord(0xE1A00000) }

func armWord(w uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, w)
	return b
}

// patchArmDerived finds the instructions that compute the word missing from the
// literal pool and rewrites them to load newWords[derived] directly.  It
// accepts either a MOVW/MOVT pair or a chain of ADD/SUB immediates on one
// register that starts from one of the stored words.
func patchArmDerived(data []byte, oldWords, newWords [][]byte, derived int, wordOffsets map[int]int) ([]armPatch, bool) {
	oldWord := binary.LittleEndian.Uint32(oldWords[derived])
	newWord := binary.LittleEndian.Uint32(newWords[derived])

	minOff, maxOff := len(data), 0
	for _, off := range wordOffsets {
		if off < minOff {
			minOff = off
		}
		if off+4 > maxOff {
			maxOff = off + 4
		}
	}
	start := minOff - 512
	if start < 0 {
		start = 0
	}
	start &^= 3
	end := maxOff + 256
	if end > len(data) {
		end = len(data)
	}

	var insns []armInsn
	for off := start; off+4 <= end; off += 4 {
		// Do not decode the literal pool itself as instructions.
		if off >= minOff && off < maxOff {
			continue
		}
		insns = append(insns, armInsn{off: off, word: binary.LittleEndian.Uint32(data[off:])})
	}

	// A compiler that materialises the missing word with MOVW/MOVT needs no
	// arithmetic at all.
	for i := 0; i+1 < len(insns); i++ {
		reg, lo, ok := armMovw(insns[i].word)
		if !ok || uint32(lo) != oldWord&0xffff {
			continue
		}
		reg2, hi, ok := armMovt(insns[i+1].word)
		if !ok || reg2 != reg || uint32(hi) != oldWord>>16 {
			continue
		}
		return []armPatch{
			{insns[i].off, armMovwInsn(reg, uint16(newWord))},
			{insns[i+1].off, armMovtInsn(reg, uint16(newWord>>16))},
		}, true
	}

	type step struct {
		off int
		imm uint32
		sub bool
	}
	var chains [16][]step
	for _, in := range insns {
		if reg, imm, sub, ok := armAddSub(in.word); ok {
			chains[reg] = append(chains[reg], step{off: in.off, imm: imm, sub: sub})
		}
	}
	for reg := 0; reg < 16; reg++ {
		steps := chains[reg]
		for i := 0; i+1 < len(steps); i++ {
			var delta uint32
			for j := i; j < len(steps) && j < i+4; j++ {
				if steps[j].sub {
					delta -= steps[j].imm
				} else {
					delta += steps[j].imm
				}
				if j == i {
					continue
				}
				for base, baseOff := range wordOffsets {
					baseWord := binary.LittleEndian.Uint32(oldWords[base])
					if baseWord+delta != oldWord {
						continue
					}
					if !armChainMatches(insns, reg, baseOff, steps[i].off, steps[j].off) {
						continue
					}
					patches := []armPatch{
						{steps[i].off, armMovwInsn(reg, uint16(newWord))},
						{steps[i+1].off, armMovtInsn(reg, uint16(newWord>>16))},
					}
					for k := i + 2; k <= j; k++ {
						patches = append(patches, armPatch{steps[k].off, armNop()})
					}
					return patches, true
				}
			}
		}
	}
	return nil, false
}

// armChainMatches checks that the chain around chainStart/chainEnd starts from
// the stored word at baseOff and that its result is written to the stack right
// after the chain.  That ties the arithmetic to the key table instead of
// accepting any add sequence that happens to produce the old word.
func armChainMatches(insns []armInsn, reg, baseOff, chainStart, chainEnd int) bool {
	loaded := false
	for _, in := range insns {
		if in.off >= chainStart || in.off < chainStart-128 {
			continue
		}
		if r, target, ok := armLdrLiteral(in.word, in.off); ok && r == reg && target == baseOff {
			loaded = true
		}
	}
	if !loaded {
		return false
	}

	storeOff := -1
	for _, in := range insns {
		if in.off <= chainEnd || in.off > chainEnd+64 {
			continue
		}
		if r, ok := armStrSp(in.word); ok && r == reg {
			storeOff = in.off
			break
		}
	}
	if storeOff < 0 {
		return false
	}
	// The chain must contain every ADD/SUB to this register up to the store;
	// otherwise the last steps would still change the value we just loaded.
	for _, in := range insns {
		if in.off <= chainEnd || in.off >= storeOff {
			continue
		}
		if r, _, _, ok := armAddSub(in.word); ok && r == reg {
			return false
		}
	}
	return true
}

// keyMap is the byte order of the packed key table.
var keyMap = []int{28, 19, 25, 16, 14, 3, 24, 15, 22, 8, 6, 17, 11, 7, 9, 23,
	18, 13, 10, 0, 26, 21, 2, 5, 20, 30, 31, 4, 27, 29, 1, 12}

// ReplaceKeyArch replaces every stored form of an old public key with the new
// one.  archEnv selects the ARM handling and is ARCH-style ("x86", "arm64");
// anything else gets the byte-level replacements only.
//
// ARM binaries store most of the key in a literal pool and derive the
// remaining word with compiler-generated instructions.  replaceArmKey matches
// the stored words as a set and rewrites the derivation, so both the pool
// order and the instruction encoding may change between RouterOS builds.
func ReplaceKeyArch(old, new []byte, data []byte, name, archEnv string) []byte {
	oldChunks := chunk4(old)
	newChunks := chunk4(new)
	data = ReplaceChunks(oldChunks, newChunks, data, name)

	arch := strings.ReplaceAll(archEnv, "-", "")
	if arch != "arm" && arch != "arm64" {
		// x86 code may load the key words in a compiler-scheduled order.
		data = ReplaceChunksUnordered(oldChunks, newChunks, data, name)
	}

	// The byte-packed key table stores the key bytes in a shuffled order.
	oldShuffled := make([][]byte, len(keyMap))
	newShuffled := make([][]byte, len(keyMap))
	for i, idx := range keyMap {
		oldShuffled[i] = []byte{old[idx]}
		newShuffled[i] = []byte{new[idx]}
	}
	data = ReplaceChunks(oldShuffled, newShuffled, data, name)

	if arch != "arm" && arch != "arm64" {
		return data
	}
	return replaceArmKey(old, new, data, name)
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
