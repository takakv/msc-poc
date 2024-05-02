package group

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/cloudflare/circl/group"
	"math/big"
)

type p256Group struct {
	fieldOrder *big.Int
	curveOrder *big.Int
	name       string
}

type p256Point struct {
	curve *p256Group
	group *group.Group
	val   group.Element
}

func (g *p256Group) Name() string {
	return g.name
}

func (g *p256Group) MarshalJSON() ([]byte, error) {
	return json.Marshal(&GroupId{g.name})
}

func (g *p256Group) P() *big.Int {
	return g.fieldOrder
}

func (g *p256Group) N() *big.Int {
	return g.curveOrder
}

func (g *p256Group) Generator() Element {
	return &p256Point{
		curve: g,
		val:   group.P256.Generator(),
	}
}

func (g *p256Group) Identity() Element {
	return &p256Point{
		curve: g,
		val:   group.P256.Identity(),
	}
}

func (g *p256Group) Random() Element {
	return &p256Point{
		curve: g,
		val:   group.P256.RandomElement(rand.Reader),
	}
}

func (g *p256Group) Element() Element {
	return &p256Point{
		curve: g,
		val:   group.P256.NewElement(),
	}
}

func (e *p256Point) check(a Element) *p256Point {
	ey, ok := a.(*p256Point)
	if !ok {
		panic("incompatible group element type")
	}
	return ey
}

func (e *p256Point) Add(a Element, b Element) Element {
	ca := e.check(a)
	cb := e.check(b)
	e.val = group.P256.NewElement().Add(ca.val, cb.val)
	return e
}

func (e *p256Point) Subtract(a Element, b Element) Element {
	tmp := e.curve.Identity()
	tmp.Negate(b)
	e.Add(a, tmp)
	return e
}

func (e *p256Point) Negate(a Element) Element {
	ca := e.check(a)
	e.val = group.P256.NewElement().Neg(ca.val)
	return e
}

func (e *p256Point) IsEqual(b Element) bool {
	cb := e.check(b)
	return e.val.IsEqual(cb.val)
}

func (e *p256Point) Set(x Element) Element {
	ca := e.check(x)
	e.val = group.P256.NewElement().Set(ca.val)
	return e
}

func (e *p256Point) SetBytes(b []byte) Element {
	e.val = group.P256.NewElement()
	e.val.UnmarshalBinary(b)
	return e
}

func (e *p256Point) Scale(x Element, s *big.Int) Element {
	ex := e.check(x)
	scalar := group.P256.NewScalar()
	e.val = group.P256.NewElement().Mul(ex.val, scalar.SetBigInt(s))
	return e
}

func (e *p256Point) BaseScale(s *big.Int) Element {
	scalar := group.P256.NewScalar()
	e.val = group.P256.NewElement().MulGen(scalar.SetBigInt(s))
	return e
}

func (e *p256Point) GroupOrder() *big.Int {
	return e.curve.curveOrder
}

func (e *p256Point) FieldOrder() *big.Int {
	return e.curve.fieldOrder
}

func (e *p256Point) MapToGroup(s string) (Element, error) {
	bs := ([]byte)(s)
	be := make([]byte, 0)
	e.val = group.P256.HashToElement(bs, be)
	return e, nil
}

func (e *p256Point) String() string {
	tmp, _ := e.val.MarshalBinary()
	return string(tmp)
}

func (e *p256Point) IsIdentity() bool {
	return e.val.IsIdentity()
}

func (e *p256Point) MarshalBinary() ([]byte, error) {
	return e.val.MarshalBinary()
}

func (e *p256Point) UnmarshalBinary(data []byte) error {
	err := e.val.UnmarshalBinary(data)
	return err
}

func (e *p256Point) MarshalJSON() ([]byte, error) {
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

func (e *p256Point) UnmarshalJSON(data []byte) error {
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

func P256() Group {
	p, _ := new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
	n, _ := new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

	G := new(p256Group)
	G.fieldOrder = p
	G.curveOrder = n
	G.name = "P-256"
	return G
}
