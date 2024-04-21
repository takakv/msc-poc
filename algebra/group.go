package algebra

import "math/big"

// Element represents a group element.
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
}

// Group is an algebraic group.
type Group interface {
	// Generator returns G.
	Generator() Element
	// Identity returns E.
	//
	// To assign a value to an element, it is recommended to first initialize an
	// element using Identity() and then read the value into with
	// Element.Read() or Element.SetBytes().
	Identity() Element

	// Random returns uniformly sampled element from the group by sampling a
	// random scalar r and returning rG.
	Random() Element

	Element() Element
}
