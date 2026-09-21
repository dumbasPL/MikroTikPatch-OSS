package mikro

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// randScalar returns a uniform scalar in [1, n-1].
func randScalar() (*big.Int, error) {
	max := new(big.Int).Sub(CurveN, big.NewInt(1))
	k, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return k.Add(k, big.NewInt(1)), nil
}

// kcdsaDigest applies the MikroTik EC-KCDSA message digest transform:
// hash the data, XOR the first 16 witness bytes into bytes 8..23, clear the
// low bits of byte 0 and force the top bits of byte 31.  mask selects which
// bits of byte 31 are cleared; the package signer (mikro.py) keeps bit 7 while
// the keygen keeps only bits 5..0 (see the two callers).
func kcdsaDigest(data, witness []byte, highMask byte) *big.Int {
	h := MTSHA256(data)
	for i := 0; i < 16 && i < len(witness); i++ {
		h[8+i] ^= witness[i]
	}
	h[0] &= 0xF8
	h[31] = (h[31] & highMask) | 0x40
	return BigFromLE(h)
}

// KCDSASign creates the package-signing EC-KCDSA signature (witness || s) used
// for NPK signatures.  It mirrors mikro.py's mikro_kcdsa_sign, including the
// 0x7F byte-31 mask.
func KCDSASign(data, privateKey []byte) ([]byte, error) {
	d := BigFromLE(privateKey)
	publicPoint := CurveScalarBaseMult(d)
	inv := new(big.Int).ModInverse(d, CurveN)
	if inv == nil {
		return nil, errors.New("mikro: private key is not invertible modulo n")
	}
	for {
		k, err := randScalar()
		if err != nil {
			return nil, err
		}
		r := CurveScalarBaseMult(k)
		if r.Inf {
			continue
		}
		nonce := new(big.Int).Mod(r.X, CurveN)
		nonceHash := MTSHA256(LEBytes(nonce, 32))
		e := kcdsaDigest(data, nonceHash, 0x7F)
		s := new(big.Int).Sub(k, e)
		s.Mul(s, inv).Mod(s, CurveN)
		check := curveAdd(CurveScalarMult(s, publicPoint), CurveScalarMult(e, CurveG))
		if check != nil && !check.Inf && check.X.Cmp(nonce) == 0 {
			out := make([]byte, 0, 48)
			out = append(out, nonceHash[:16]...)
			out = append(out, LEBytes(s, 32)...)
			return out, nil
		}
	}
}

// KCDSAVerify verifies an NPK signature against the bare x-coordinate public
// key.  Curve25519 gives two candidate points for an x (y and -y); both are
// tried, matching mikro.py.
func KCDSAVerify(data, signature, publicKey []byte) bool {
	if len(signature) != 48 || len(publicKey) != 32 {
		return false
	}
	witness := signature[:16]
	s := BigFromLE(signature[16:])
	e := kcdsaDigest(data, witness, 0x7F)
	x := BigFromLE(publicKey)
	p := CurvePointFromX(x)
	if p == nil {
		return false
	}
	for _, cand := range []*Point{p, curveNeg(p)} {
		nonce := curveAdd(CurveScalarMult(s, cand), CurveScalarMult(e, CurveG))
		if nonce == nil || nonce.Inf {
			continue
		}
		h := MTSHA256(LEBytes(nonce.X, 32))
		if string(h[:len(witness)]) == string(witness) {
			return true
		}
	}
	return false
}

// KCDSASignKeygen creates the licence signature (witness || s) exactly like
// keygen.py's kcdsa_sign: byte-31 mask 0x3F and a retry when the nonce
// x-coordinate is not below n.
func KCDSASignKeygen(licval []byte, d *big.Int) ([]byte, error) {
	inv := new(big.Int).ModInverse(d, CurveN)
	if inv == nil {
		return nil, errors.New("mikro: private key is not invertible modulo n")
	}
	for i := 0; i < 1000; i++ {
		k, err := randScalar()
		if err != nil {
			return nil, err
		}
		r := CurveScalarMult(k, CurveGKeygen)
		if r.Inf || r.X.Cmp(CurveN) >= 0 {
			continue
		}
		witness := MTSHA256(LEBytes(r.X, 32))[:16]
		e := kcdsaDigest(licval, witness, 0x3F)
		s := new(big.Int).Sub(k, e)
		s.Mul(s, inv).Mod(s, CurveN)
		out := make([]byte, 0, 48)
		out = append(out, witness...)
		out = append(out, LEBytes(s, 32)...)
		return out, nil
	}
	return nil, errors.New("mikro: no suitable nonce")
}

// KCDSAVerifyKeygen is the lenient keygen verifier (either y root accepted).
func KCDSAVerifyKeygen(licval, signature, publicKey []byte) bool {
	if len(signature) != 48 || len(publicKey) != 32 {
		return false
	}
	witness := signature[:16]
	s := BigFromLE(signature[16:])
	e := kcdsaDigest(licval, witness, 0x3F)
	p := CurvePointFromX(BigFromLE(publicKey))
	if p == nil {
		return false
	}
	for _, cand := range []*Point{p, curveNeg(p)} {
		y := curveAdd(CurveScalarMult(s, cand), CurveScalarMult(e, CurveGKeygen))
		if y == nil || y.Inf {
			continue
		}
		h := MTSHA256(LEBytes(y.X, 32))
		if string(h[:16]) == string(witness) {
			return true
		}
	}
	return false
}

// DevicePublicPoint reconstructs the public point the way the device does:
// with keygen.py's sqrt root, normalised to an odd y.
func DevicePublicPoint(publicX *big.Int) *Point {
	return CurvePointFromXParity(publicX, true)
}

// KCDSAVerifyDevice is the strict verifier that mirrors keyman: only the
// device's odd-y point is accepted.
func KCDSAVerifyDevice(licval, signature, publicKey []byte) bool {
	if len(signature) != 48 || len(publicKey) != 32 {
		return false
	}
	point := DevicePublicPoint(BigFromLE(publicKey))
	if point == nil {
		return false
	}
	witness := signature[:16]
	s := BigFromLE(signature[16:])
	e := kcdsaDigest(licval, witness, 0x3F)
	y := curveAdd(CurveScalarMult(s, point), CurveScalarMult(e, CurveGKeygen))
	if y == nil || y.Inf {
		return false
	}
	h := MTSHA256(LEBytes(y.X, 32))
	return string(h[:16]) == string(witness)
}
