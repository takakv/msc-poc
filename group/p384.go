package group

import (
	"crypto/rand"
	"encoding/json"
	"github.com/cloudflare/circl/group"
	"math/big"
)

type p384Group struct {
	fieldOrder *big.Int
	curveOrder *big.Int
}

type p384Point struct {
	curve *p384Group
	group *group.Group
	val   group.Element
}

func (g *p384Group) P() *big.Int {
	return g.fieldOrder
}

func (g *p384Group) N() *big.Int {
	return g.curveOrder
}

func (g *p384Group) Generator() Element {
	return &p384Point{
		curve: g,
		val:   group.P384.Generator(),
	}
}

func (g *p384Group) Identity() Element {
	return &p384Point{
		curve: g,
		val:   group.P384.Identity(),
	}
}

func (g *p384Group) Random() Element {
	return &p384Point{
		curve: g,
		val:   group.P384.RandomElement(rand.Reader),
	}
}

func (g *p384Group) Element() Element {
	return &p384Point{
		curve: g,
		val:   group.P384.NewElement(),
	}
}

func (e *p384Point) check(a Element) *p384Point {
	ey, ok := a.(*p384Point)
	if !ok {
		panic("incompatible group element type")
	}
	return ey
}

func (e *p384Point) Add(a Element, b Element) Element {
	ca := e.check(a)
	cb := e.check(b)
	e.val = group.P384.NewElement().Add(ca.val, cb.val)
	return e
}

func (e *p384Point) Subtract(a Element, b Element) Element {
	tmp := e.curve.Identity()
	tmp.Negate(b)
	e.Add(a, tmp)
	return e
}

func (e *p384Point) Negate(a Element) Element {
	ca := e.check(a)
	e.val = group.P384.NewElement().Neg(ca.val)
	return e
}

func (e *p384Point) Equal(b Element) bool {
	cb := e.check(b)
	return e.val.IsEqual(cb.val)
}

func (e *p384Point) Set(x Element) Element {
	ca := e.check(x)
	e.val = group.P384.NewElement().Set(ca.val)
	return e
}

func (e *p384Point) SetBytes(b []byte) Element {
	e.val = group.P384.NewElement()
	e.val.UnmarshalBinary(b)
	return e
}

func (e *p384Point) Scale(x Element, s *big.Int) Element {
	ex := e.check(x)
	scalar := group.P384.NewScalar()
	e.val = group.P384.NewElement().Mul(ex.val, scalar.SetBigInt(s))
	return e
}

func (e *p384Point) BaseScale(s *big.Int) Element {
	scalar := group.P384.NewScalar()
	e.val = group.P384.NewElement().MulGen(scalar.SetBigInt(s))
	return e
}

func (e *p384Point) GroupOrder() *big.Int {
	return e.curve.curveOrder
}

func (e *p384Point) FieldOrder() *big.Int {
	return e.curve.fieldOrder
}

func (e *p384Point) MapToGroup(s string) (Element, error) {
	bs := ([]byte)(s)
	be := make([]byte, 0)
	e.val = group.P384.HashToElement(bs, be)
	return e, nil
}

func (e *p384Point) String() string {
	tmp, _ := e.val.MarshalBinary()
	return string(tmp)
}

func (e *p384Point) IsIdentity() bool {
	return e.val.IsIdentity()
}

func (e *p384Point) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.val)
}

func NewP384Group() Group {
	p, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16)
	n, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)

	G := new(p384Group)
	G.fieldOrder = p
	G.curveOrder = n
	return G
}
