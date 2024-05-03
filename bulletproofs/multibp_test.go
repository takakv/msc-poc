package bulletproofs

import (
	"math"
	"math/big"
	"testing"
)

func TestXYWithinRange(t *testing.T) {
	rangeEnd := int64(math.Pow(2, 32))
	x := new(big.Int).SetInt64(3)
	y := new(big.Int).SetInt64(15)

	vals := []*big.Int{x, y}

	params := setupRange(t, rangeEnd)
	if proveAndVerifyRanges(vals, params) != true {
		t.Errorf("x within range should verify successfully")
	}
}

func proveAndVerifyRanges(vals []*big.Int, params BulletProofSetupParams) bool {
	proof, _, _ := MultiProve(vals, params)
	ok, _ := proof.Verify()
	return ok
}
