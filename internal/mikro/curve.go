package mikro

import (
	"math/big"
)

// Curve25519 constants (the Montgomery form used by MikroTik).
var (
	CurveP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	CurveN = func() *big.Int {
		n, _ := new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
		return n
	}()
	curveA = big.NewInt(486662)
)

// Point is an affine point on Curve25519; Inf marks the point at infinity.
type Point struct {
	X, Y *big.Int
	Inf  bool
}

// BigFromLE converts a little-endian byte slice to a non-negative integer.
func BigFromLE(b []byte) *big.Int {
	rev := make([]byte, len(b))
	for i := range b {
		rev[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(rev)
}

// LEBytes encodes v as a little-endian byte slice of the given size.
func LEBytes(v *big.Int, size int) []byte {
	out := make([]byte, size)
	b := v.Bytes() // big-endian, minimal
	for i := 0; i < len(b) && i < size; i++ {
		out[i] = b[len(b)-1-i]
	}
	return out
}

// SqrtModP returns a square root of v modulo CurveP, or nil when v is not a
// quadratic residue.  This is a direct port of keygen.py's _sqrt_mod, including
// its deterministic root selection (the generator ends up with an odd y), so
// the recovered key scalars match the Python tools.
func SqrtModP(vIn *big.Int) *big.Int {
	v := new(big.Int).Mod(vIn, CurveP)
	if v.Sign() == 0 {
		return big.NewInt(0)
	}
	// Euler's criterion.
	euler := new(big.Int).Rsh(CurveP, 1)
	if new(big.Int).Exp(v, euler, CurveP).Cmp(big.NewInt(1)) != 0 {
		return nil
	}
	q := new(big.Int).Sub(CurveP, big.NewInt(1))
	s := 0
	for q.Bit(0) == 0 {
		q.Rsh(q, 1)
		s++
	}
	z := big.NewInt(2)
	for {
		if new(big.Int).Exp(z, euler, CurveP).Cmp(new(big.Int).Sub(CurveP, big.NewInt(1))) == 0 {
			break
		}
		z.Add(z, big.NewInt(1))
	}
	m := s
	c := new(big.Int).Exp(z, q, CurveP)
	t := new(big.Int).Exp(v, q, CurveP)
	one := big.NewInt(1)
	// r = v^((q+1)/2)
	ex := new(big.Int).Add(q, one)
	ex.Rsh(ex, 1)
	r := new(big.Int).Exp(v, ex, CurveP)
	for t.Cmp(one) != 0 {
		i := 0
		t2 := new(big.Int).Set(t)
		for t2.Cmp(one) != 0 {
			t2.Mul(t2, t2).Mod(t2, CurveP)
			i++
		}
		// b = c^(2^(m-i-1))
		b := new(big.Int).Lsh(big.NewInt(1), uint(m-i-1))
		b.Exp(c, b, CurveP)
		c.Mul(b, b).Mod(c, CurveP)
		t.Mul(t, c).Mod(t, CurveP)
		r.Mul(r, b).Mod(r, CurveP)
		m = i
	}
	return r
}

// CurvePointFromX returns the point with the given x and the root selected by
// SqrtModP, or nil when x is not on the curve.
func CurvePointFromX(x *big.Int) *Point {
	y := SqrtModP(curveRHS(x))
	if y == nil {
		return nil
	}
	return &Point{X: new(big.Int).Mod(x, CurveP), Y: y}
}

// CurvePointFromXParity returns the point with the given x whose y has the
// requested parity, or nil when x is not on the curve.
func CurvePointFromXParity(x *big.Int, odd bool) *Point {
	p := CurvePointFromX(x)
	if p == nil {
		return nil
	}
	if (p.Y.Bit(0) == 1) != odd {
		p.Y = new(big.Int).Sub(CurveP, p.Y)
	}
	return p
}

func curveRHS(x *big.Int) *big.Int {
	// x^3 + A x^2 + x  (B = 1)
	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, CurveP)
	x3 := new(big.Int).Mul(x2, x)
	x3.Mod(x3, CurveP)
	r := new(big.Int).Mul(x2, curveA)
	r.Add(r, x3)
	r.Add(r, x)
	return r.Mod(r, CurveP)
}

func curveNeg(p *Point) *Point {
	if p.Inf {
		return p
	}
	return &Point{X: p.X, Y: new(big.Int).Sub(CurveP, p.Y)}
}

func curveAdd(p1, p2 *Point) *Point {
	if p1 == nil || p1.Inf {
		return p2
	}
	if p2 == nil || p2.Inf {
		return p1
	}
	if p1.X.Cmp(p2.X) == 0 {
		sum := new(big.Int).Add(p1.Y, p2.Y)
		if sum.Mod(sum, CurveP).Sign() == 0 {
			return &Point{Inf: true}
		}
	}
	var m *big.Int
	if p1.X.Cmp(p2.X) == 0 && p1.Y.Cmp(p2.Y) == 0 {
		// tangent: (3x^2 + 2Ax + 1) / (2y)
		num := new(big.Int).Mul(p1.X, p1.X)
		num.Mul(num, big.NewInt(3))
		ax := new(big.Int).Mul(p1.X, curveA)
		ax.Lsh(ax, 1)
		num.Add(num, ax)
		num.Add(num, big.NewInt(1))
		den := new(big.Int).Lsh(p1.Y, 1)
		inv := new(big.Int).ModInverse(den.Mod(den, CurveP), CurveP)
		if inv == nil {
			return &Point{Inf: true}
		}
		m = num.Mod(num, CurveP)
		m.Mul(m, inv).Mod(m, CurveP)
	} else {
		num := new(big.Int).Sub(p2.Y, p1.Y)
		den := new(big.Int).Sub(p2.X, p1.X)
		inv := new(big.Int).ModInverse(den.Mod(den, CurveP), CurveP)
		if inv == nil {
			return &Point{Inf: true}
		}
		m = num.Mod(num, CurveP)
		m.Mul(m, inv).Mod(m, CurveP)
	}
	// x3 = m^2 - A - x1 - x2
	x3 := new(big.Int).Mul(m, m)
	x3.Sub(x3, curveA)
	x3.Sub(x3, p1.X)
	x3.Sub(x3, p2.X)
	x3.Mod(x3, CurveP)
	// y3 = m (x1 - x3) - y1
	y3 := new(big.Int).Sub(p1.X, x3)
	y3.Mul(y3, m)
	y3.Sub(y3, p1.Y)
	y3.Mod(y3, CurveP)
	return &Point{X: x3, Y: y3}
}

// CurveScalarMult multiplies the point by a scalar (double-and-add).
func CurveScalarMult(k *big.Int, p *Point) *Point {
	result := &Point{Inf: true}
	kk := new(big.Int).Set(k)
	for kk.Sign() > 0 {
		if kk.Bit(0) == 1 {
			result = curveAdd(result, p)
		}
		p = curveAdd(p, p)
		kk.Rsh(kk, 1)
	}
	return result
}

// CurveGKeygen is the generator with the root keygen.py's sqrt picks (odd y).
var CurveGKeygen = func() *Point {
	p := CurvePointFromX(big.NewInt(9))
	if p == nil {
		panic("curve25519: generator x not on curve")
	}
	if p.Y.Bit(0) == 0 {
		p.Y = new(big.Int).Sub(CurveP, p.Y)
	}
	return p
}()

// CurveG is the generator with the even-y root (toyecc's convention).
var CurveG = func() *Point {
	p := CurvePointFromX(big.NewInt(9))
	if p == nil {
		panic("curve25519: generator x not on curve")
	}
	if p.Y.Bit(0) == 1 {
		p.Y = new(big.Int).Sub(CurveP, p.Y)
	}
	return p
}()

// CurveScalarBaseMult multiplies the even-y generator by k.
func CurveScalarBaseMult(k *big.Int) *Point {
	return CurveScalarMult(k, CurveG)
}
