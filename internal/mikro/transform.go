package mikro

import "encoding/binary"

func rotl32(n uint32, d uint) uint32 {
	if d == 0 {
		return n
	}
	return (n << d) | (n >> (32 - d))
}

func to32(v uint32) uint32 { return v }

// MTTransform maps a stored licence value (16 bytes, four big-endian words) to
// the licence value, exactly like keygen.py's mt_transform.
func MTTransform(s []byte) []byte {
	w := make([]uint32, 4)
	for i := 0; i < 4; i++ {
		w[i] = binary.BigEndian.Uint32(s[4*i:])
	}
	for i := 0; i < 16; i++ {
		k0 := MTSHA256K[i*4+0]
		k1 := MTSHA256K[i*4+1]
		k2 := MTSHA256K[i*4+2]
		k3 := MTSHA256K[i*4+3]
		w[(i+2)%4] = to32(w[(i+2)%4] - w[(i+0)%4] - k0)
		w[(i+3)%4] = to32((rotl32(w[(i+0)%4], uint(k0&0x0F)) ^ w[(i+3)%4]) + w[(i+0)%4])
		w[(i+1)%4] = to32(w[(i+1)%4] - w[(i+3)%4] - k1)
		w[(i+2)%4] = to32((rotl32(w[(i+1)%4], uint(k1&0x0F)) ^ w[(i+2)%4]) + w[(i+1)%4])
		w[(i+0)%4] = to32(w[(i+0)%4] - w[(i+2)%4] - k2)
		w[(i+1)%4] = to32((rotl32(w[(i+2)%4], uint(k2&0x0F)) ^ w[(i+1)%4]) + w[(i+2)%4])
		w[(i+3)%4] = to32(w[(i+3)%4] - w[(i+1)%4] - k3)
		w[(i+0)%4] = to32((rotl32(w[(i+3)%4], uint(k3&0x0F)) ^ w[(i+0)%4]) + w[(i+3)%4])
	}
	out := make([]byte, 16)
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(out[4*i:], w[i])
	}
	return out
}

// MTTransformRev maps a licence value back to the stored form, exactly like
// keygen.py's mt_transform_rev.
func MTTransformRev(s []byte) []byte {
	w := make([]uint32, 4)
	for i := 0; i < 4; i++ {
		w[i] = binary.BigEndian.Uint32(s[4*i:])
	}
	for i := 15; i >= 0; i-- {
		k0 := MTSHA256K[i*4+0]
		k1 := MTSHA256K[i*4+1]
		k2 := MTSHA256K[i*4+2]
		k3 := MTSHA256K[i*4+3]
		w[(i+0)%4] = to32(rotl32(w[(i+3)%4], uint(k3&0x0F)) ^ (w[(i+0)%4] - w[(i+3)%4]))
		w[(i+3)%4] = to32(w[(i+3)%4] + w[(i+1)%4] + k3)
		w[(i+1)%4] = to32(rotl32(w[(i+2)%4], uint(k2&0x0F)) ^ (w[(i+1)%4] - w[(i+2)%4]))
		w[(i+0)%4] = to32(w[(i+0)%4] + w[(i+2)%4] + k2)
		w[(i+2)%4] = to32(rotl32(w[(i+1)%4], uint(k1&0x0F)) ^ (w[(i+2)%4] - w[(i+1)%4]))
		w[(i+1)%4] = to32(w[(i+1)%4] + w[(i+3)%4] + k1)
		w[(i+3)%4] = to32(rotl32(w[(i+0)%4], uint(k0&0x0F)) ^ (w[(i+3)%4] - w[(i+0)%4]))
		w[(i+2)%4] = to32(w[(i+2)%4] + w[(i+0)%4] + k0)
	}
	out := make([]byte, 16)
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(out[4*i:], w[i])
	}
	return out
}
