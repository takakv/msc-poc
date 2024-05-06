package group

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/cloudflare/circl/group"
	"math/big"
)

type r255Group struct {
	fieldOrder *big.Int
	curveOrder *big.Int
	name       string
}

type r255Point struct {
	curve *r255Group
	group *group.Group
	val   group.Element
}

func (g *r255Group) Name() string {
	return g.name
}

func (g *r255Group) MarshalJSON() ([]byte, error) {
	return json.Marshal(&GroupId{g.name})
}

func (g *r255Group) P() *big.Int {
	return g.fieldOrder
}

func (g *r255Group) N() *big.Int {
	return g.curveOrder
}

func (g *r255Group) Generator() Element {
	return &r255Point{
		curve: g,
		val:   group.Ristretto255.Generator(),
	}
}

func (g *r255Group) Identity() Element {
	return &r255Point{
		curve: g,
		val:   group.Ristretto255.Identity(),
	}
}

func (g *r255Group) Random() Element {
	return &r255Point{
		curve: g,
		val:   group.Ristretto255.RandomElement(rand.Reader),
	}
}

func (g *r255Group) Element() Element {
	return &r255Point{
		curve: g,
		val:   group.Ristretto255.NewElement(),
	}
}

func (e *r255Point) check(a Element) *r255Point {
	ey, ok := a.(*r255Point)
	if !ok {
		panic("incompatible group element type")
	}
	return ey
}

func (e *r255Point) Add(a Element, b Element) Element {
	ca := e.check(a)
	cb := e.check(b)
	e.val = group.Ristretto255.NewElement().Add(ca.val, cb.val)
	return e
}

func (e *r255Point) Subtract(a Element, b Element) Element {
	tmp := e.curve.Identity()
	tmp.Negate(b)
	e.Add(a, tmp)
	return e
}

func (e *r255Point) Negate(a Element) Element {
	ca := e.check(a)
	e.val = group.Ristretto255.NewElement().Neg(ca.val)
	return e
}

func (e *r255Point) IsEqual(b Element) bool {
	cb := e.check(b)
	return e.val.IsEqual(cb.val)
}

func (e *r255Point) Set(x Element) Element {
	ca := e.check(x)
	e.val = group.Ristretto255.NewElement().Set(ca.val)
	return e
}

func (e *r255Point) SetBytes(b []byte) Element {
	e.val = group.Ristretto255.NewElement()
	e.val.UnmarshalBinary(b)
	return e
}

func (e *r255Point) Scale(x Element, s *big.Int) Element {
	ex := e.check(x)
	scalar := group.Ristretto255.NewScalar()
	e.val = group.Ristretto255.NewElement().Mul(ex.val, scalar.SetBigInt(s))
	return e
}

func (e *r255Point) BaseScale(s *big.Int) Element {
	scalar := group.Ristretto255.NewScalar()
	e.val = group.Ristretto255.NewElement().MulGen(scalar.SetBigInt(s))
	return e
}

func (e *r255Point) GroupOrder() *big.Int {
	return e.curve.curveOrder
}

func (e *r255Point) FieldOrder() *big.Int {
	return e.curve.fieldOrder
}

func (e *r255Point) MapToGroup(s string) (Element, error) {
	bs := ([]byte)(s)
	be := make([]byte, 0)
	e.val = group.Ristretto255.HashToElement(bs, be)
	return e, nil
}

func (e *r255Point) String() string {
	tmp, _ := e.val.MarshalBinary()
	return string(tmp)
}

func (e *r255Point) IsIdentity() bool {
	return e.val.IsIdentity()
}

func (e *r255Point) MarshalBinary() ([]byte, error) {
	return e.val.MarshalBinary()
}

func (e *r255Point) UnmarshalBinary(data []byte) error {
	err := e.val.UnmarshalBinary(data)
	return err
}

func (e *r255Point) MarshalJSON() ([]byte, error) {
	tmp, _ := e.val.MarshalBinary()
	xVal := big.NewInt(0)
	yVal := big.NewInt(0)

	// If the point is not 0.
	if tmp[0] != 0 {
		xBytes := tmp[1 : 32+1]
		yBytes := tmp[1+32:]
		if len(xBytes) != 32 || len(xBytes) != len(yBytes) {
			return nil, fmt.Errorf("error in underlying binary marshalling")
		}
		xVal.SetBytes(xBytes)
		yVal.SetBytes(yBytes)
	}

	point := ECPoint{
		X: xVal,
		Y: yVal,
	}

	return json.Marshal(&point)
}

func (e *r255Point) UnmarshalJSON(data []byte) error {
	point := ECPoint{}
	err := json.Unmarshal(data, &point)
	if err != nil {
		return err
	}

	// The special case encoding of the point at infinity.
	if point.X.Cmp(big.NewInt(0)) == 0 && point.Y.Cmp(big.NewInt(0)) == 0 {
		err = e.val.UnmarshalBinary([]byte{0})
		return err
	}

	byteLen := 32

	xBytes := point.X.Bytes()
	yBytes := point.Y.Bytes()

	tmp := make([]byte, 1+2*byteLen)
	tmp[0] = 4
	// Copy while maintaining leading zeroes.
	copy(tmp[1+byteLen-len(xBytes):byteLen+1], point.X.Bytes())
	copy(tmp[1+2*byteLen-len(yBytes):], point.Y.Bytes())
	err = e.val.UnmarshalBinary(tmp)
	return err
}

func Ristretto255() Group {
	p, _ := new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	n, _ := new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)

	G := new(r255Group)
	G.fieldOrder = p
	G.curveOrder = n
	G.name = "ristretto255"
	return G
}
