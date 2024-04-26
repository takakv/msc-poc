package group

import (
	"crypto/rand"
	"math/big"
	"strings"
)

type ModPElement struct {
	group *ModPGroup
	val   *big.Int
}

type ModPGroup struct {
	gen        *big.Int
	fieldOrder *big.Int
	groupOrder *big.Int
	name       string
}

func (g *ModPGroup) Name() string {
	return g.name
}

func (g *ModPGroup) equals(h Group) bool {
	if g == h {
		return true
	}
	gh, ok := h.(*ModPGroup)
	if !ok {
		return false
	}
	return g.fieldOrder.Cmp(gh.fieldOrder) == 0 && g.gen.Cmp(gh.gen) == 0
}

func (g *ModPGroup) P() *big.Int {
	return g.fieldOrder
}

func (g *ModPGroup) N() *big.Int {
	return g.groupOrder
}

func (g *ModPGroup) Generator() Element {
	return &ModPElement{
		group: g,
		val:   new(big.Int).Set(g.gen),
	}
}

func (g *ModPGroup) Identity() Element {
	return &ModPElement{
		group: g,
		val:   big.NewInt(1),
	}
}

func (g *ModPGroup) Random() Element {
	r, _ := rand.Int(rand.Reader, g.groupOrder)
	e := g.Identity()
	e.BaseScale(r)
	return e
}

func (g *ModPGroup) Element() Element {
	e := new(ModPElement)
	e.group = g
	e.val = new(big.Int)
	return e
}

func (e *ModPElement) check(a Element) *ModPElement {
	ey, ok := a.(*ModPElement)
	if !ok {
		panic("incompatible group element type")
	}
	if !e.group.equals(ey.group) {
		panic("incompatible groups")
	}
	return ey
}

func (e *ModPElement) Add(a Element, b Element) Element {
	ex := e.check(a)
	ey := e.check(b)
	e.val.Mul(ex.val, ey.val)
	e.val.Mod(e.val, e.group.fieldOrder)
	return e
}

func (e *ModPElement) Subtract(a Element, b Element) Element {
	tmp := e.group.Identity()
	tmp.Negate(b)
	e.Add(a, tmp)
	return e
}

func (e *ModPElement) Negate(a Element) Element {
	ex := e.check(a)
	e.val.ModInverse(ex.val, e.group.fieldOrder)
	return e
}

func (e *ModPElement) Equal(b Element) bool {
	ey := e.check(b)
	return e.val.Cmp(ey.val) == 0
}

func (e *ModPElement) Set(a Element) Element {
	ex := e.check(a)
	e.val.Set(ex.val)
	return e
}

func (e *ModPElement) SetBytes(b []byte) Element {
	e.val.SetBytes(b)
	return e
}

func (e *ModPElement) Scale(a Element, s *big.Int) Element {
	ex := e.check(a)
	e.val.Exp(ex.val, s, e.group.fieldOrder)
	return e
}

func (e *ModPElement) BaseScale(s *big.Int) Element {
	e.val.Exp(e.group.gen, s, e.group.fieldOrder)
	return e
}

func (e *ModPElement) GroupOrder() *big.Int {
	return e.group.groupOrder
}

func (e *ModPElement) FieldOrder() *big.Int {
	return e.group.fieldOrder
}

func (e *ModPElement) String() string {
	return e.val.String()
}

func (e *ModPElement) IsIdentity() bool {
	return e.val.Cmp(big.NewInt(1)) == 0
}

func (e *ModPElement) MapToGroup(s string) (Element, error) {
	panic("not implemented")
}

func NewModPGroup(name string, fieldOrder, generator string) Group {
	repr := strings.Join(strings.Fields(fieldOrder), "")

	ffOrder, ok := new(big.Int).SetString(repr, 16)
	if !ok {
		panic("invalid group definition")
	}

	gen, ok := new(big.Int).SetString(generator, 16)
	if !ok {
		panic("invalid generator")
	}

	genOrder := new(big.Int).Set(ffOrder)
	genOrder.Sub(genOrder, big.NewInt(1))
	genOrder.Div(genOrder, big.NewInt(2))

	G := new(ModPGroup)
	G.fieldOrder = ffOrder
	G.groupOrder = genOrder
	G.gen = gen
	G.name = name
	return G
}
