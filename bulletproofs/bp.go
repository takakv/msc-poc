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

package bulletproofs

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/takakv/msc-poc/group"
	"math"
	"math/big"

	"github.com/ing-bank/zkrp/util/bn"
	. "github.com/takakv/msc-poc/util"
)

/*
BulletProofSetupParams is the structure that stores the parameters for
the Zero Knowledge Proof system.
*/
type BulletProofSetupParams struct {
	// N is the bit-length of the range.
	N int64
	// G is the Elliptic Curve generator.
	G group.Element
	// H is a new generator, computed using MapToGroup function,
	// such that there is no discrete logarithm relation with G.
	H group.Element
	// Gg and Hh are sets of new generators obtained using MapToGroup.
	// They are used to compute Pedersen Vector Commitments.
	Gg []group.Element
	Hh []group.Element
	GP group.Group
}

/*
BulletProof is the structure that contains the elements that are necessary for
the verification of the Zero Knowledge Proof.
*/
type BulletProof struct {
	V                 group.Element
	A                 group.Element
	S                 group.Element
	T1                group.Element
	T2                group.Element
	Taux              *big.Int
	Mu                *big.Int
	Tprime            *big.Int
	InnerProductProof InnerProductProof
	Params            BulletProofSetupParams
}

/*
Setup is responsible for computing the common parameters.
Only works for ranges to 0 to 2^n, where n is a power of 2 and n <= 32
TODO: allow n > 32 (need uint64 for that).
*/
func Setup(b int64, SP group.Group) (BulletProofSetupParams, error) {
	if !IsPowerOfTwo(b) {
		return BulletProofSetupParams{}, errors.New("range end is not a power of 2")
	}

	params := BulletProofSetupParams{}
	params.GP = SP
	params.G = SP.Element().BaseScale(big.NewInt(1))
	params.H, _ = SP.Element().MapToGroup(SEEDH)
	params.N = int64(math.Log2(float64(b)))
	if !IsPowerOfTwo(params.N) {
		return BulletProofSetupParams{}, fmt.Errorf("range end is a power of 2, but it's exponent should also be. Exponent: %d", params.N)
	}
	if params.N > 32 {
		return BulletProofSetupParams{}, errors.New("range end can not be greater than 2**32")
	}
	params.Gg = make([]group.Element, params.N)
	params.Hh = make([]group.Element, params.N)
	for i := int64(0); i < params.N; i++ {
		params.Gg[i], _ = SP.Element().MapToGroup(SEEDH + "g" + fmt.Sprint(i))
		params.Hh[i], _ = SP.Element().MapToGroup(SEEDH + "h" + fmt.Sprint(i))
	}
	return params, nil
}

/*
Prove computes the ZK rangeproof. The documentation and comments are based on
eprint version of Bulletproofs papers:
https://eprint.iacr.org/2017/1066.pdf
*/
func Prove(secret *big.Int, params BulletProofSetupParams) (BulletProof, *big.Int, error) {
	var (
		proof BulletProof
	)
	// ////////////////////////////////////////////////////////////////////////////
	// First phase: page 19
	// ////////////////////////////////////////////////////////////////////////////

	// commitment to v and gamma
	gamma, _ := rand.Int(rand.Reader, params.GP.N())
	V, _ := CommitG1SP(secret, gamma, params.H, params.GP)

	// aL, aR and commitment: (A, alpha)
	aL, _ := Decompose(secret, 2, params.N)                                               // (41)
	aR, _ := computeAR(aL)                                                                // (42)
	alpha, _ := rand.Int(rand.Reader, params.GP.N())                                      // (43)
	A := commitVector(aL, aR, alpha, params.H, params.Gg, params.Hh, params.N, params.GP) // (44)

	// sL, sR and commitment: (S, rho)                                     // (45)
	sL := sampleRandomVector(params.N, params.GP)
	sR := sampleRandomVector(params.N, params.GP)
	rho, _ := rand.Int(rand.Reader, params.GP.N())                                         // (46)
	S := commitVectorBig(sL, sR, rho, params.H, params.Gg, params.Hh, params.N, params.GP) // (47)

	// Fiat-Shamir heuristic to compute challenges y and z, corresponds to    (49)
	y, z, _ := HashBP(A, S)

	// ////////////////////////////////////////////////////////////////////////////
	// Second phase: page 20
	// ////////////////////////////////////////////////////////////////////////////
	tau1, _ := rand.Int(rand.Reader, params.GP.N()) // (52)
	tau2, _ := rand.Int(rand.Reader, params.GP.N()) // (52)

	/*
	   The paper does not describe how to compute t1 and t2.
	*/
	// compute t1: < aL - z.1^n, y^n . sR > + < sL, y^n . (aR + z . 1^n) >
	vz, _ := VectorCopy(z, params.N)
	vy := powerOf(y, params.N, params.GP)

	// aL - z.1^n
	naL, _ := VectorConvertToBig(aL, params.N)
	aLmvz, _ := VectorSub(naL, vz, params.GP.N())

	// y^n .sR
	ynsR, _ := VectorMul(vy, sR, params.GP.N())

	// scalar prod: < aL - z.1^n, y^n . sR >
	sp1, _ := ScalarProduct(aLmvz, ynsR, params.GP)

	// scalar prod: < sL, y^n . (aR + z . 1^n) >
	naR, _ := VectorConvertToBig(aR, params.N)
	aRzn, _ := VectorAdd(naR, vz, params.GP.N())
	ynaRzn, _ := VectorMul(vy, aRzn, params.GP.N())

	// Add z^2.2^n to the result
	// z^2 . 2^n
	p2n := powerOf(new(big.Int).SetInt64(2), params.N, params.GP)
	zsquared := bn.Multiply(z, z)
	z22n, _ := VectorScalarMul(p2n, zsquared, params.GP.N())
	ynaRzn, _ = VectorAdd(ynaRzn, z22n, params.GP.N())
	sp2, _ := ScalarProduct(sL, ynaRzn, params.GP)

	// sp1 + sp2
	t1 := bn.Add(sp1, sp2)
	t1 = bn.Mod(t1, params.GP.N())

	// compute t2: < sL, y^n . sR >
	t2, _ := ScalarProduct(sL, ynsR, params.GP)
	t2 = bn.Mod(t2, params.GP.N())

	// compute T1
	T1, _ := CommitG1SP(t1, tau1, params.H, params.GP) // (53)

	// compute T2
	T2, _ := CommitG1SP(t2, tau2, params.H, params.GP) // (53)

	// Fiat-Shamir heuristic to compute 'random' challenge x
	x, _, _ := HashBP(T1, T2)

	// ////////////////////////////////////////////////////////////////////////////
	// Third phase                                                              //
	// ////////////////////////////////////////////////////////////////////////////

	// compute bl                                                          // (58)
	sLx, _ := VectorScalarMul(sL, x, params.GP.N())
	bl, _ := VectorAdd(aLmvz, sLx, params.GP.N())

	// compute br                                                          // (59)
	// y^n . ( aR + z.1^n + sR.x )
	sRx, _ := VectorScalarMul(sR, x, params.GP.N())
	aRzn, _ = VectorAdd(aRzn, sRx, params.GP.N())
	ynaRzn, _ = VectorMul(vy, aRzn, params.GP.N())
	// y^n . ( aR + z.1^n sR.x ) + z^2 . 2^n
	br, _ := VectorAdd(ynaRzn, z22n, params.GP.N())

	// Compute t` = < bl, br >                                             // (60)
	tprime, _ := ScalarProduct(bl, br, params.GP)

	// Compute taux = tau2 . x^2 + tau1 . x + z^2 . gamma                  // (61)
	taux := bn.Multiply(tau2, bn.Multiply(x, x))
	taux = bn.Add(taux, bn.Multiply(tau1, x))
	taux = bn.Add(taux, bn.Multiply(bn.Multiply(z, z), gamma))
	taux = bn.Mod(taux, params.GP.N())

	// Compute mu = alpha + rho.x                                          // (62)
	mu := bn.Multiply(rho, x)
	mu = bn.Add(mu, alpha)
	mu = bn.Mod(mu, params.GP.N())

	// Inner Product over (g, h', P.h^-mu, tprime)
	hprime := updateGenerators(params.Hh, y, params.N, params.GP)

	// SetupInnerProduct Inner Product (Section 4.2)
	ipp, setupErr := setupInnerProduct(params.Gg, hprime, params.N, params.GP)
	if setupErr != nil {
		return proof, gamma, setupErr
	}
	commit := commitInnerProduct(params.Gg, hprime, bl, br, params.GP)
	ipProof, _ := proveInnerProduct(bl, br, commit, tprime, ipp)

	proof.V = V
	proof.A = A
	proof.S = S
	proof.T1 = T1
	proof.T2 = T2
	proof.Taux = taux
	proof.Mu = mu
	proof.Tprime = tprime
	proof.InnerProductProof = ipProof
	proof.Params = params

	return proof, gamma, nil
}

/*
Verify returns true if and only if the proof is valid.
*/
func (proof *BulletProof) Verify() (bool, error) {
	params := proof.Params
	// Recover x, y, z using Fiat-Shamir heuristic
	x, _, _ := HashBP(proof.T1, proof.T2)
	y, z, _ := HashBP(proof.A, proof.S)

	// Switch generators                                                   // (64)
	hprime := updateGenerators(params.Hh, y, params.N, params.GP)

	// ////////////////////////////////////////////////////////////////////////////
	// Check that tprime  = t(x) = t0 + t1x + t2x^2  ----------  Condition (65) //
	// ////////////////////////////////////////////////////////////////////////////

	// Compute left hand side
	lhs, _ := CommitG1SP(proof.Tprime, proof.Taux, params.H, params.GP)

	// Compute right hand side
	z2 := bn.Multiply(z, z)
	z2 = bn.Mod(z2, params.GP.N())
	x2 := bn.Multiply(x, x)
	x2 = bn.Mod(x2, params.GP.N())

	// rhs := new(p256.P256).ScalarMult(proof.V, z2)
	rhs := params.GP.Element().Scale(proof.V, z2)

	delta := params.delta(y, z)

	// gdelta := new(p256.P256).ScalarBaseMult(delta)
	gdelta := params.GP.Element().BaseScale(delta)

	rhs.Add(rhs, gdelta)

	T1x := params.GP.Element().Scale(proof.T1, x)
	T2x2 := params.GP.Element().Scale(proof.T2, x2)

	rhs.Add(rhs, T1x)
	rhs.Add(rhs, T2x2)

	// Subtract lhs and rhs and compare with point at infinity
	rhs.Subtract(rhs, lhs)
	c65 := rhs.IsIdentity() // Condition (65), page 20, from eprint version

	// Compute P - lhs  #################### Condition (66) ######################

	// S^x
	// Sx := new(p256.P256).ScalarMult(proof.S, x)
	Sx := params.GP.Element().Scale(proof.S, x)
	// A.S^x
	// ASx := new(p256.P256).Add(proof.A, Sx)
	ASx := params.GP.Element().Add(proof.A, Sx)

	// g^-z
	mz := bn.Sub(params.GP.N(), z)
	vmz, _ := VectorCopy(mz, params.N)
	gpmz, _ := VectorExp(params.Gg, vmz, params.GP)

	// z.y^n
	vz, _ := VectorCopy(z, params.N)
	vy := powerOf(y, params.N, params.GP)
	zyn, _ := VectorMul(vy, vz, params.GP.N())

	p2n := powerOf(new(big.Int).SetInt64(2), params.N, params.GP)
	zsquared := bn.Multiply(z, z)
	z22n, _ := VectorScalarMul(p2n, zsquared, params.GP.N())

	// z.y^n + z^2.2^n
	zynz22n, _ := VectorAdd(zyn, z22n, params.GP.N())

	// lP := new(p256.P256)
	// lP.Add(ASx, gpmz)
	lP := params.GP.Element().Add(ASx, gpmz)

	// h'^(z.y^n + z^2.2^n)
	hprimeexp, _ := VectorExp(hprime, zynz22n, params.GP)

	lP.Add(lP, hprimeexp)

	// Compute P - rhs  #################### Condition (67) ######################

	// h^mu
	rP := params.GP.Element().Scale(params.H, proof.Mu)
	rP.Add(rP, proof.InnerProductProof.P)

	// Subtract lhs and rhs and compare with point at infinity
	rP.Subtract(rP, lP)
	c67 := rP.IsIdentity()

	// Verify Inner Product Proof ################################################
	ok, _ := proof.InnerProductProof.Verify()

	result := c65 && c67 && ok

	return result, nil
}

/*
sampleRandomVector generates a vector composed by random big numbers.
*/
func sampleRandomVector(N int64, SP group.Group) []*big.Int {
	s := make([]*big.Int, N)
	for i := int64(0); i < N; i++ {
		s[i], _ = rand.Int(rand.Reader, SP.N())
	}
	return s
}

/*
updateGenerators is responsible for computing generators in the following format:
[h_1, h_2^(y^-1), ..., h_n^(y^(-n+1))], where [h_1, h_2, ..., h_n] is the original
vector of generators. This method is used both by prover and verifier. After this
update we have that A is a vector commitments to (aL, aR . y^n). Also S is a vector
commitment to (sL, sR . y^n).
*/
func updateGenerators(Hh []group.Element, y *big.Int, N int64, SP group.Group) []group.Element {
	var (
		i int64
	)
	// Compute h'                                                          // (64)
	hprime := make([]group.Element, N)
	// Switch generators
	yinv := bn.ModInverse(y, SP.N())
	expy := yinv
	hprime[0] = Hh[0]
	i = 1
	for i < N {
		hprime[i] = SP.Element().Scale(Hh[i], expy)
		expy = bn.Multiply(expy, yinv)
		i = i + 1
	}
	return hprime
}

/*
aR = aL - 1^n
*/
func computeAR(x []int64) ([]int64, error) {
	result := make([]int64, len(x))
	for i := int64(0); i < int64(len(x)); i++ {
		if x[i] == 0 {
			result[i] = -1
		} else if x[i] == 1 {
			result[i] = 0
		} else {
			return nil, errors.New("input contains non-binary element")
		}
	}
	return result, nil
}

func commitVectorBig(aL, aR []*big.Int, alpha *big.Int, H group.Element, g, h []group.Element, n int64, SP group.Group) group.Element {
	// Compute h^alpha.vg^aL.vh^aR
	R := SP.Element().Scale(H, alpha)
	for i := int64(0); i < n; i++ {
		R.Add(R, SP.Element().Scale(g[i], aL[i]))
		R.Add(R, SP.Element().Scale(h[i], aR[i]))
	}
	return R
}

/*
commitVector computes a commitment to the bit of the secret.
*/
func commitVector(aL, aR []int64, alpha *big.Int, H group.Element, g, h []group.Element, n int64, SP group.Group) group.Element {
	// Compute h^alpha.vg^aL.vh^aR
	R := SP.Element().Scale(H, alpha)
	for i := int64(0); i < n; i++ {
		gaL := SP.Element().Scale(g[i], big.NewInt(aL[i]))
		haR := SP.Element().Scale(h[i], big.NewInt(aR[i]))
		R.Add(R, gaL)
		R.Add(R, haR)
	}
	return R
}

// delta(y,z) = (z-z^2) . < 1^n, y^n > - z^3 . < 1^n, 2^n >
func (params *BulletProofSetupParams) delta(y, z *big.Int) *big.Int {
	result := new(big.Int)

	// (z-z^2)
	z2 := new(big.Int).Mod(new(big.Int).Mul(z, z), params.GP.N())
	t1 := new(big.Int).Mod(new(big.Int).Sub(z, z2), params.GP.N())

	// < 1^n, y^n >
	v1, _ := VectorCopy(new(big.Int).SetInt64(1), params.N)
	vy := powerOf(y, params.N, params.GP)
	t2, _ := ScalarProduct(v1, vy, params.GP)

	// < 1^n, 2^n >
	p2n := powerOf(new(big.Int).SetInt64(2), params.N, params.GP)
	sp12, _ := ScalarProduct(v1, p2n, params.GP)

	// z3 . < 1^n, 2^n >
	z3 := bn.Multiply(z2, z)
	z3 = bn.Mod(z3, params.GP.N())
	t3 := new(big.Int).Mod(new(big.Int).Mul(z3, sp12), params.GP.N())

	result.Mod(t2.Mul(t2, t1), params.GP.N())
	result.Mod(result.Sub(result, t3), params.GP.N())

	return result
}
