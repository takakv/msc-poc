package group

import (
	"crypto/rand"
	"encoding/json"
	"github.com/ing-bank/zkrp/crypto/p256"
	"math/big"
)

type p256k1Group struct {
	fieldOrder *big.Int
	curveOrder *big.Int
	name       string
}

type p256k1Point struct {
	curve *p256k1Group
	val   *p256.P256
}

func (g *p256k1Group) Name() string {
	return g.name
}

func (g *p256k1Group) P() *big.Int {
	return g.fieldOrder
}

func (g *p256k1Group) N() *big.Int {
	return g.curveOrder
}

func (g *p256k1Group) Generator() Element {
	return &p256k1Point{
		curve: g,
		val:   new(p256.P256).ScalarBaseMult(big.NewInt(1)),
	}
}

func (g *p256k1Group) Identity() Element {
	return &p256k1Point{
		curve: g,
		val:   new(p256.P256).SetInfinity(),
	}
}

func (g *p256k1Group) Random() Element {
	r, _ := rand.Int(rand.Reader, g.curveOrder)
	e := g.Identity()
	e.BaseScale(r)
	return e
}

func (g *p256k1Group) Element() Element {
	p := new(p256k1Point)
	p.curve = g
	p.val = new(p256.P256)
	return p
}

func (e *p256k1Point) check(a Element) *p256k1Point {
	ey, ok := a.(*p256k1Point)
	if !ok {
		panic("incompatible group element type")
	}
	return ey
}

func (e *p256k1Point) Add(a Element, b Element) Element {
	ca := e.check(a)
	cb := e.check(b)
	e.val = new(p256.P256).Multiply(ca.val, cb.val)
	return e
}

func (e *p256k1Point) Subtract(a Element, b Element) Element {
	tmp := e.curve.Identity()
	tmp.Negate(b)
	e.Add(a, tmp)
	return e
}

func (e *p256k1Point) Negate(a Element) Element {
	ca := e.check(a)
	e.val = new(p256.P256).ScalarMult(ca.val, big.NewInt(-1))
	return e
}

func (e *p256k1Point) IsEqual(b Element) bool {
	cb := e.check(b)
	zero := big.NewInt(0)

	xIsEq := false
	yIsEq := false

	if e.val.X == nil || e.val.X.Cmp(zero) == 0 {
		xIsEq = cb.val.X == nil || cb.val.X.Cmp(zero) == 0
	} else if cb.val.X == nil || cb.val.X.Cmp(zero) == 0 {
		xIsEq = e.val.X == nil || e.val.X.Cmp(zero) == 0
	} else {
		xIsEq = e.val.X.Cmp(cb.val.X) == 0
	}

	if e.val.Y == nil || e.val.Y.Cmp(zero) == 0 {
		yIsEq = cb.val.Y == nil || cb.val.Y.Cmp(zero) == 0
	} else if cb.val.Y == nil || cb.val.Y.Cmp(zero) == 0 {
		yIsEq = e.val.Y == nil || e.val.Y.Cmp(zero) == 0
	} else {
		yIsEq = e.val.Y.Cmp(cb.val.Y) == 0
	}

	return xIsEq && yIsEq
}

func (e *p256k1Point) Set(a Element) Element {
	ca := e.check(a)
	e.val = new(p256.P256).Add(new(p256.P256).SetInfinity(), ca.val)
	return e
}

func (e *p256k1Point) SetBytes(b []byte) Element {
	xBytes := b[:32]
	yBytes := b[32:]
	e.val = new(p256.P256).SetInfinity()
	e.val.X = new(big.Int).SetBytes(xBytes)
	e.val.Y = new(big.Int).SetBytes(yBytes)
	return e
}

func (e *p256k1Point) Scale(a Element, s *big.Int) Element {
	ca := e.check(a)
	e.val = new(p256.P256).ScalarMult(ca.val, s)
	return e
}

func (e *p256k1Point) BaseScale(s *big.Int) Element {
	e.val = new(p256.P256).ScalarBaseMult(s)
	return e
}

func (e *p256k1Point) GroupOrder() *big.Int {
	return e.curve.curveOrder
}

func (e *p256k1Point) FieldOrder() *big.Int {
	return e.curve.fieldOrder
}

func (e *p256k1Point) MapToGroup(s string) (Element, error) {
	tmp, _ := p256.MapToGroup(s)
	tmpX := tmp.X.Bytes()
	tmpY := tmp.Y.Bytes()
	res := e.curve.Element().SetBytes(append(tmpX, tmpY...))
	return res, nil
}

func (e *p256k1Point) String() string {
	return e.val.String()
}

func (e *p256k1Point) IsIdentity() bool {
	if e.val.X == nil && e.val.Y == nil {
		return true
	}
	return e.val.X.Cmp(big.NewInt(0)) == 0 && e.val.Y.Cmp(big.NewInt(0)) == 0
}

func (e *p256k1Point) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.val)
}

func SecP256k1() Group {
	p, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	n, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

	G := new(p256k1Group)
	G.fieldOrder = p
	G.curveOrder = n
	G.name = "secp256k1"
	return G
}
