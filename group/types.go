package group

import "math/big"

// ECPoint is needed for JSON marshalling.
type ECPoint struct {
	X *big.Int
	Y *big.Int
}
