/*
 * Copyright (C) 2019 ING BANK N.V.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
This file contains the implementation of the Bulletproofs scheme proposed in the paper:
Bulletproofs: Short Proofs for Confidential Transactions and More
Benedikt Bunz, Jonathan Bootle, Dan Boneh, Andrew Poelstra, Pieter Wuille and Greg Maxwell
Asiacrypt 2008
*/

package bulletproofs

import (
	"github.com/ing-bank/zkrp/crypto/p256"
)

var ORDER = p256.CURVE.N
var SEEDH = "BulletproofsDoesNotNeedTrustedSetupH"
var MAX_RANGE_END int64 = 4294967296 // 2**32
var MAX_RANGE_END_EXPONENT = 32      // 2**32

/*
func Setup(n uint8) BpParams {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	// Generate a random secret to compute point H.
	// To make the setup transparent, obtain H with a hash-to-point function.
	sec := suite.Scalar().Pick(suite.RandomStream())

	params := BpParams{}
	params.group = suite
	params.ORDER, _ = new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	params.G = suite.Point().Base()
	params.H = suite.Point().Mul(sec, nil)
	params.L = int(n)
	params.Gg = make([]kyber.Point, params.L)
	params.Hh = make([]kyber.Point, params.L)
	for i := 0; i < params.L; i++ {
		sec := suite.Scalar().Pick(suite.RandomStream())
		params.Gg[i] = suite.Point().Mul(sec, nil)
		sec = suite.Scalar().Pick(suite.RandomStream())
		params.Hh[i] = suite.Point().Mul(sec, nil)
	}
	return params
}
*/
