package group

import (
	"encoding"
	"encoding/json"
	"math/big"
)

// Element represents an element of a prime-order group.
type Element interface {
	// Add sets the receiver to X + Y, and returns it.
	Add(X, Y Element) Element
	// Subtract sets the receiver to X - Y and returns it.
	Subtract(X, Y Element) Element
	// Negate sets the receiver to -X, and returns it.
	Negate(X Element) Element
	// Scale performs the group operation s times with X,
	// sets the receiver to the result, and returns it.
	Scale(X Element, s *big.Int) Element
	// BaseScale performs the group operation s times with the
	//group's generator, sets the receiver to the result, and returns it.
	BaseScale(s *big.Int) Element
	// Set the receiver to X, and returns it.
	Set(X Element) Element
	// SetBytes recovers a group element from a byte representation,
	// sets the receiver to this element, and returns it.
	SetBytes(b []byte) Element
	// MapToGroup hashes a message (s) and produces a group element
	// with uniform distribution whose discrete logarithm is not known.
	MapToGroup(s string) (Element, error)
	// IsEqual returns true if the receiver is equal to X.
	IsEqual(X Element) bool
	// IsIdentity returns true if the receiver is the group's
	// identity element.
	IsIdentity() bool
	// GroupOrder returns the number of elements in the group.
	GroupOrder() *big.Int
	// FieldOrder returns the number of elements in the field
	// over which the group is defined.
	FieldOrder() *big.Int
	// String returns a string representation of the element.
	String() string
	// BinaryMarshaler returns a byte representation of the element.
	encoding.BinaryMarshaler
	// BinaryUnmarshaler recovers an element from a byte representation
	// produced by encoding.BinaryMarshaler.
	encoding.BinaryUnmarshaler
	// Marshaler returns a JSON representation of the element.
	json.Marshaler
	// Unmarshaler recovers an element from a JSON representation
	// produced by json.Marshaler.
	json.Unmarshaler
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

	// P returns the prime-order of the field.
	P() *big.Int
	// N returns the prime-order of the group.
	N() *big.Int
}
