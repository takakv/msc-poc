package algebra

import (
	"crypto/rand"
	"github.com/ing-bank/zkrp/crypto/p256"
	"math/big"
)

type CurveGroup struct {
	fieldOrder *big.Int
	curveOrder *big.Int
}

type Point struct {
	curve *CurveGroup
	val   *p256.P256
}

func (g *CurveGroup) P() *big.Int {
	return g.fieldOrder
}

func (g *CurveGroup) N() *big.Int {
	return g.curveOrder
}

func (g *CurveGroup) Generator() Element {
	return &Point{
		curve: g,
		val:   new(p256.P256).ScalarBaseMult(big.NewInt(1)),
	}
}

func (g *CurveGroup) Identity() Element {
	return &Point{
		curve: g,
		val:   new(p256.P256).SetInfinity(),
	}
}

func (g *CurveGroup) Random() Element {
	r, _ := rand.Int(rand.Reader, g.curveOrder)
	e := g.Identity()
	e.BaseScale(r)
	return e
}

func (g *CurveGroup) Element() Element {
	p := new(Point)
	p.curve = g
	p.val = new(p256.P256)
	return p
}

func (e *Point) check(a Element) *Point {
	ey, ok := a.(*Point)
	if !ok {
		panic("incompatible group element type")
	}
	return ey
}

func (e *Point) Add(a Element, b Element) Element {
	if a.Equal(b) {
		return e.BaseScale(big.NewInt(2))
	}
	ca := e.check(a)
	cb := e.check(b)
	e.val = new(p256.P256).Add(ca.val, cb.val)
	return e
}

func (e *Point) Subtract(a Element, b Element) Element {
	tmp := e.curve.Identity()
	tmp.Negate(b)
	e.Add(a, tmp)
	return e
}

func (e *Point) Negate(a Element) Element {
	ca := e.check(a)
	e.val = new(p256.P256).ScalarMult(ca.val, big.NewInt(-1))
	return e
}

func (e *Point) Equal(b Element) bool {
	cb := e.check(b)
	if e.val.X == nil || e.val.Y == nil || cb.val.X == nil || cb.val.Y == nil {
		return e.val.X == nil && e.val.Y == nil && cb.val.X == nil && cb.val.Y == nil
	}
	return e.val.X.Cmp(cb.val.X) == 0 && e.val.Y.Cmp(cb.val.Y) == 0
}

func (e *Point) Set(a Element) Element {
	ca := e.check(a)
	e.val = new(p256.P256).Add(new(p256.P256).SetInfinity(), ca.val)
	return e
}

func (e *Point) SetBytes(b []byte) Element {
	xBytes := b[:32]
	yBytes := b[32:]
	e.val = new(p256.P256).SetInfinity()
	e.val.X = new(big.Int).SetBytes(xBytes)
	e.val.Y = new(big.Int).SetBytes(yBytes)
	return e
}

func (e *Point) Scale(a Element, s *big.Int) Element {
	ca := e.check(a)
	e.val = new(p256.P256).ScalarMult(ca.val, s)
	return e
}

func (e *Point) BaseScale(s *big.Int) Element {
	e.val = new(p256.P256).ScalarBaseMult(s)
	return e
}

func (e *Point) GroupOrder() *big.Int {
	return e.curve.curveOrder
}

func (e *Point) FieldOrder() *big.Int {
	return e.curve.fieldOrder
}

func (e *Point) String() string {
	return e.val.String()
}

func (e *Point) IsIdentity() bool {
	if e.val.X == nil && e.val.Y == nil {
		return true
	}
	return e.val.X.Cmp(big.NewInt(0)) == 0 && e.val.Y.Cmp(big.NewInt(0)) == 0
}

func NewSecP256k1Group() Group {
	p, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	n, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

	G := new(CurveGroup)
	G.fieldOrder = p
	G.curveOrder = n
	return G
}
