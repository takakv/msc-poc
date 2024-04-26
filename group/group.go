package group

import (
	"math/big"
)

// Element represents an element of a prime-order group.
type Element interface {
	// Add sets the value of this element to A + B and returns it.
	Add(A, B Element) Element
	// Subtract sets the value of this element to A - B and returns it.
	Subtract(A, B Element) Element
	// Equal returns equality of this element with B.
	Equal(B Element) bool
	// Negate sets the value of the element to -A and returns it.
	Negate(A Element) Element
	// Set sets this element to A and returns it.
	Set(A Element) Element
	SetBytes(b []byte) Element

	Scale(E Element, s *big.Int) Element
	BaseScale(s *big.Int) Element

	GroupOrder() *big.Int
	FieldOrder() *big.Int

	String() string

	MapToGroup(s string) (Element, error)

	IsIdentity() bool
}

// Group represents a prime-order group over a prime-order field.
// The group can be either multiplicative or additive.
type Group interface {
	// Name returns the name of the group.
	Name() string

	// Element creates a new group element.
	Element() Element
	// Generator creates a group element set to the group's generator.
	Generator() Element
	// Identity creates a group element set to the group's identity element.
	Identity() Element

	// Random returns uniformly sampled element from the group by sampling a
	// random scalar r and returning rG.
	Random() Element

	// P is the prime-order of the field.
	P() *big.Int
	// N is the prime-order of the group.
	N() *big.Int
}
