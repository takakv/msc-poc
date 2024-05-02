package group

import "math/big"

// ECPoint is needed for JSON marshalling EC points.
type ECPoint struct {
	X *big.Int `json:"x"`
	Y *big.Int `json:"y"`
}

// GroupId is needed for JSON marshalling groups.
type GroupId struct {
	Name string `json:"group"`
}
