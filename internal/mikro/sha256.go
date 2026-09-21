// Package mikro implements the MikroTik crypto primitives used by the patch
// tooling: their SHA-256 variant (different round constants and initial hash
// values), EC-KCDSA over Curve25519 (licence key) and Ed25519 (NPK sign key).
package mikro

import (
	"encoding/binary"
	"math/bits"
)

// MTSHA256K are MikroTik's SHA-256 round constants.
var MTSHA256K = [64]uint32{
	0x0548D563, 0x98308EAB, 0x37AF7CCC, 0xDFBC4E3C,
	0xF125AAC9, 0xEC98ACB8, 0x8B540795, 0xD3E0EF0E,
	0x4904D6E5, 0x0DA84981, 0x9A1F8452, 0x00EB7EAA,
	0x96F8E3B3, 0xA6CDB655, 0xE7410F9E, 0x8EECB03D,
	0x9C6A7C25, 0xD77B072F, 0x6E8F650A, 0x124E3640,
	0x7E53785A, 0xE0150772, 0xC61EF4E0, 0xBC57E5E0,
	0xC0F9A285, 0xDB342856, 0x190834C7, 0xFBEB7D8E,
	0x251BED34, 0x0E9F2AAD, 0x256AB901, 0x0A5B7890,
	0x9F124F09, 0xD84A9151, 0x427AF67A, 0x8059C9AA,
	0x13EAB029, 0x3153CDF1, 0x262D405D, 0xA2105D87,
	0x9C745F15, 0xD1613847, 0x294CE135, 0x20FB0F3C,
	0x8424D8ED, 0x8F4201B6, 0x12CA1EA7, 0x2054B091,
	0x463D8288, 0xC83253C3, 0x33EA314A, 0x9696DC92,
	0xD041CE9A, 0xE5477160, 0xC7656BE8, 0x5179FE33,
	0x1F4726F1, 0x5F393AF0, 0x26E2D004, 0x6D020245,
	0x85FDF6D7, 0xB0237C56, 0xFF5FBD94, 0xA8B3F534,
}

// MTSHA256IV are MikroTik's SHA-256 initial hash values.
var MTSHA256IV = [8]uint32{
	0x5B653932, 0x7B145F8F, 0x71FFB291, 0x38EF925F,
	0x03E1AAF9, 0x4A2057CC, 0x4CAF4DD9, 0x643CC9EA,
}

// MTSHA256 hashes data with MikroTik's SHA-256 variant.
func MTSHA256(data []byte) []byte {
	h := MTSHA256IV
	state := h[:]

	length := uint64(len(data)) * 8
	padded := make([]byte, 0, len(data)+72)
	padded = append(padded, data...)
	padded = append(padded, 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	var lenbuf [8]byte
	binary.BigEndian.PutUint64(lenbuf[:], length)
	padded = append(padded, lenbuf[:]...)

	var w [64]uint32
	for off := 0; off < len(padded); off += 64 {
		for t := 0; t < 16; t++ {
			w[t] = binary.BigEndian.Uint32(padded[off+4*t:])
		}
		for t := 16; t < 64; t++ {
			s0 := bits.RotateLeft32(w[t-15], -7) ^ bits.RotateLeft32(w[t-15], -18) ^ (w[t-15] >> 3)
			s1 := bits.RotateLeft32(w[t-2], -17) ^ bits.RotateLeft32(w[t-2], -19) ^ (w[t-2] >> 10)
			w[t] = w[t-16] + s0 + w[t-7] + s1
		}
		a, b, c, d, e, f, g, hh := state[0], state[1], state[2], state[3],
			state[4], state[5], state[6], state[7]
		for t := 0; t < 64; t++ {
			s1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
			ch := (e & f) ^ (^e & g)
			t1 := hh + s1 + ch + MTSHA256K[t] + w[t]
			s0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
			maj := (a & b) ^ (a & c) ^ (b & c)
			t2 := s0 + maj
			hh, g, f, e, d, c, b, a = g, f, e, d+t1, c, b, a, t1+t2
		}
		state[0] += a
		state[1] += b
		state[2] += c
		state[3] += d
		state[4] += e
		state[5] += f
		state[6] += g
		state[7] += hh
	}
	out := make([]byte, 32)
	for i, v := range state {
		binary.BigEndian.PutUint32(out[4*i:], v)
	}
	return out
}
