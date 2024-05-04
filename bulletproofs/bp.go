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
	// Gg is a set of generators obtained using MapToGroup used to
	// compute Pedersen vector commitments.
	Gg []group.Element
	// Hh is a set of generators obtained using MapToGroup used to
	// compute Pedersen vector commitments.
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
Prove computes the Bulletproof range proof.
The documentation and comments are based on the ePrint version of Bulletproofs:
https://eprint.iacr.org/2017/1066.pdf
*/
func Prove(secret *big.Int, params BulletProofSetupParams) (BulletProof, *big.Int, error) {
	proof := BulletProof{}

	mod := params.GP.N()

	// ////////////////////////////////////////////////////////////////////////////
	// First phase: page 19                                                      //
	// ////////////////////////////////////////////////////////////////////////////

	// Sample randomness gamma and commit to v.
	gamma, _ := rand.Int(rand.Reader, mod)
	V := PedersenCommit(secret, gamma, params.H, params.GP)

	// aL, aR and commitment: (A, alpha)
	aL := Decompose(secret, 2, params.N)                                                  // (41)
	aR, _ := computeAR(aL)                                                                // (42)
	alpha, _ := rand.Int(rand.Reader, mod)                                                // (43)
	A := commitVector(aL, aR, alpha, params.H, params.Gg, params.Hh, params.N, params.GP) // (44)

	// sL, sR and commitment: (S, rho)
	sL := sampleRandomVector(params.N, params.GP)                                          // (45)
	sR := sampleRandomVector(params.N, params.GP)                                          // (45)
	rho, _ := rand.Int(rand.Reader, mod)                                                   // (46)
	S := commitVectorBig(sL, sR, rho, params.H, params.Gg, params.Hh, params.N, params.GP) // (47)

	proof.A = A // (48)
	proof.S = S // (48)

	// Fiat-Shamir heuristic to compute challenges y and z.
	y, z, _ := HashBP(A, S) // (49) & (50)

	// ////////////////////////////////////////////////////////////////////////////
	// Second phase: page 20                                                     //
	// ////////////////////////////////////////////////////////////////////////////

	tau1, _ := rand.Int(rand.Reader, mod) // (52)
	tau2, _ := rand.Int(rand.Reader, mod) // (52)

	// The paper does not describe how to compute t1 and t2.
	// The below approach is taken from Bünz's own reference code.

	// yPow = (y^0, y^1, ..., y^(n-1))
	// l0 = aL - z
	// l1 = sL
	// r0 = (yPow ∘ (aR + z)) + 2Pow . z^2
	// r1 = sR ∘ yPow
	// t1 = < l1, r0 > + < l0, r1 >
	// t2 = < l1, r1 >

	yPow := powerOf(y, params.N, params.GP)

	// 2Pow . z ^ 2
	powersOf2 := powerOf(big.NewInt(2), params.N, params.GP)
	zSquared := new(big.Int).Mul(z, z)
	powersOf2TimesZSquared, _ := VectorScalarMul(powersOf2, zSquared, mod)

	// Vectors of big integers are needed for some functions.
	aLb, _ := VectorConvertToBig(aL, params.N)
	aRb, _ := VectorConvertToBig(aR, params.N)

	// l(x) = (aL - z . 1Pow) + sL . x
	l0 := VectorAddConst(aLb, new(big.Int).Neg(z), mod)
	l1 := sL

	// aRzn = aR + z . 1Pow
	vecZ, _ := VectorCopy(z, params.N)
	aRzn, _ := VectorAdd(vecZ, aRb, mod)

	// r(x) = yPow ∘ (aR + z . 1Pow + sR . x) + z^2 . 2Pow
	r0, _ := VectorMul(yPow, aRzn, mod)
	r0, _ = VectorAdd(r0, powersOf2TimesZSquared, mod)
	r1, _ := VectorMul(yPow, sR, mod)

	t1left := VectorInnerProduct(l1, r0, mod)  // <l1, r0>
	t1right := VectorInnerProduct(l0, r1, mod) // <l0, r1>

	t1 := new(big.Int).Mod(new(big.Int).Add(t1left, t1right), mod)
	t2 := VectorInnerProduct(l1, r1, mod)

	T1 := PedersenCommit(t1, tau1, params.H, params.GP) // (53)
	T2 := PedersenCommit(t2, tau2, params.H, params.GP) // (53)

	proof.T1 = T1 // (54)
	proof.T2 = T2 // (54)

	// Fiat-Shamir heuristic to compute 'random' challenge x
	x, _, _ := HashBP(T1, T2) // (55) & (56)

	// ////////////////////////////////////////////////////////////////////////////
	// Third phase: page 20                                                      //
	// ////////////////////////////////////////////////////////////////////////////

	// l = l(x) = (aL - z . 1Pow) + sL . x // (58)
	sLx, _ := VectorScalarMul(sL, x, mod) // sL . x
	bl, _ := VectorAdd(l0, sLx, mod)      // l(x)

	// r = r(x) = yPow ∘ (aR + z . 1Pow + sR . x) + z^2 . 2Pow // (59)
	sRx, _ := VectorScalarMul(sR, x, mod)                // sR . x
	tmp, _ := VectorAdd(aRzn, sRx, mod)                  // (aR + z . 1Pow + sR . x)
	tmp, _ = VectorMul(yPow, tmp, mod)                   // yPow ∘ (aR + z . 1Pow + sR . x)
	br, _ := VectorAdd(tmp, powersOf2TimesZSquared, mod) // r(x)

	// th = <bl, br>
	th, _ := ScalarProduct(bl, br, params.GP) // (60)

	// tau_x = tau2 . x^2 + tau1 . x + z^2 . gamma // (61)
	tauX := new(big.Int).Mul(tau2, new(big.Int).Mul(x, x))
	tauX.Add(tauX, new(big.Int).Mul(tau1, x))
	tauX.Add(tauX, new(big.Int).Mul(zSquared, gamma))
	tauX.Mod(tauX, mod)

	// mu = alpha + rho . x // (62)
	mu := new(big.Int).Mul(rho, x)
	mu.Add(mu, alpha)
	mu.Mod(mu, mod)

	// ////////////////////////////////////////////////////////////////////////////
	// Logarithmic phase: Section 4.2                                            //
	// ////////////////////////////////////////////////////////////////////////////

	// h' = h^(y^(-n))
	hp := updateGenerators(params.Hh, y, params.N, params.GP)

	// Inner product over (g, h', P.h^-mu, t')
	ipp, setupErr := setupInnerProduct(params.Gg, hp, params.N, params.GP)
	if setupErr != nil {
		return proof, gamma, setupErr
	}
	commit := commitInnerProduct(params.Gg, hp, bl, br, params.GP)
	ipProof, _ := proveInnerProduct(bl, br, commit, th, ipp)

	proof.V = V
	proof.Taux = tauX
	proof.Mu = mu
	proof.Tprime = th
	proof.InnerProductProof = ipProof
	proof.Params = params

	return proof, gamma, nil
}

/*
Verify returns true if and only if the proof is valid.
*/
func (proof *BulletProof) Verify() (bool, error) {
	params := proof.Params
	mod := params.GP.N()

	// Recover x, y, z using Fiat-Shamir heuristic
	x, _, _ := HashBP(proof.T1, proof.T2)
	y, z, _ := HashBP(proof.A, proof.S)

	zSquared := new(big.Int).Mod(new(big.Int).Mul(z, z), mod)
	xSquared := new(big.Int).Mod(new(big.Int).Mul(x, x), mod)

	// Switch generators
	hp := updateGenerators(params.Hh, y, params.N, params.GP) // (64)

	// ////////////////////////////////////////////////////////////////////////////
	// Check that tprime  = t(x) = t0 + t1x + t2x^2  ----------  Condition (65) //
	// ////////////////////////////////////////////////////////////////////////////

	// Compute left hand side
	lhs := PedersenCommit(proof.Tprime, proof.Taux, params.H, params.GP)

	// Compute right hand side
	rhs := params.GP.Element().Scale(proof.V, zSquared)

	delta := params.delta(y, z)
	gDelta := params.GP.Element().BaseScale(delta)

	rhs.Add(rhs, gDelta)

	T1x := params.GP.Element().Scale(proof.T1, x)
	T2x2 := params.GP.Element().Scale(proof.T2, xSquared)

	rhs.Add(rhs, T1x)
	rhs.Add(rhs, T2x2)

	c65 := rhs.IsEqual(lhs) // (65)

	// Compute P - lhs  #################### Condition (66) ######################
	// P = A . S^x . g^(-z) . (h')^(z . yPow + z^2 . 2Pow)

	// S^x
	Sx := params.GP.Element().Scale(proof.S, x)
	// A.S^x
	ASx := params.GP.Element().Add(proof.A, Sx)

	// g^-z
	mz := new(big.Int).Sub(mod, z)
	vmz, _ := VectorCopy(mz, params.N)
	gpmz, _ := VectorExp(params.Gg, vmz, params.GP)

	// z.y^n
	vz, _ := VectorCopy(z, params.N)
	vy := powerOf(y, params.N, params.GP)
	zyn, _ := VectorMul(vy, vz, mod)

	p2n := powerOf(new(big.Int).SetInt64(2), params.N, params.GP)
	z22n, _ := VectorScalarMul(p2n, zSquared, mod)

	// z.y^n + z^2.2^n
	zynz22n, _ := VectorAdd(zyn, z22n, mod)

	lP := params.GP.Element().Add(ASx, gpmz)

	// h'^(z.y^n + z^2.2^n)
	hpExp, _ := VectorExp(hp, zynz22n, params.GP)

	lP.Add(lP, hpExp)

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
func sampleRandomVector(N int64, GP group.Group) []*big.Int {
	s := make([]*big.Int, N)
	for i := int64(0); i < N; i++ {
		s[i], _ = rand.Int(rand.Reader, GP.N())
	}
	return s
}

/*
updateGenerators is responsible for computing generators in the following format:
[h_1, h_2^(y^-1), ..., h_n^(y^(-n+1))], where [h_1, h_2, ..., h_n] is the original
vector of generators. This method is used both by prover and verifier. After this
update we have that A is a vector commitments to (aL, aR . y^n). Also, S is a vector
commitment to (sL, sR . y^n).
*/
func updateGenerators(Hh []group.Element, y *big.Int, N int64, GP group.Group) []group.Element {
	// Compute h' // (64)
	hp := make([]group.Element, N)

	// Switch generators
	yInv := new(big.Int).ModInverse(y, GP.N())
	yExp := yInv
	hp[0] = Hh[0]

	for i := int64(1); i < N; i++ {
		hp[i] = GP.Element().Scale(Hh[i], yExp)
		yExp = new(big.Int).Mul(yExp, yInv)
	}

	return hp
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

func commitVectorBig(aL, aR []*big.Int, alpha *big.Int, H group.Element,
	g, h []group.Element, n int64, GP group.Group) group.Element {
	// Compute h^alpha.vg^aL.vh^aR
	R := GP.Element().Scale(H, alpha)
	for i := int64(0); i < n; i++ {
		R.Add(R, GP.Element().Scale(g[i], aL[i]))
		R.Add(R, GP.Element().Scale(h[i], aR[i]))
	}
	return R
}

/*
commitVector computes a commitment to the bit of the secret.
*/
func commitVector(aL, aR []int64, alpha *big.Int, H group.Element,
	g, h []group.Element, n int64, GP group.Group) group.Element {
	// Compute h^alpha.vg^aL.vh^aR
	R := GP.Element().Scale(H, alpha)
	for i := int64(0); i < n; i++ {
		gaL := GP.Element().Scale(g[i], big.NewInt(aL[i]))
		haR := GP.Element().Scale(h[i], big.NewInt(aR[i]))
		R.Add(R, gaL)
		R.Add(R, haR)
	}
	return R
}

// delta(y,z) = (z - z^2) . < 1Pow, yPow > - z^3 . < 1Pow, 2Pow >
func (params *BulletProofSetupParams) delta(y, z *big.Int) *big.Int {
	mod := params.GP.N()
	result := new(big.Int)

	onePow, _ := VectorCopy(new(big.Int).SetInt64(1), params.N)
	twoPow := powerOf(big.NewInt(2), params.N, params.GP)
	yPow := powerOf(y, params.N, params.GP)

	zSquared := new(big.Int).Mod(new(big.Int).Mul(z, z), mod)
	zCubed := new(big.Int).Mod(new(big.Int).Mul(zSquared, z), mod)

	// (z-z^2)
	t1 := new(big.Int).Mod(new(big.Int).Sub(z, zSquared), mod)

	// < 1Pow, yPow >
	t2, _ := ScalarProduct(onePow, yPow, params.GP)

	// < 1Pow, 2Pow >
	sp12, _ := ScalarProduct(onePow, twoPow, params.GP)

	// z3 . < 1Pow, 2Pow >
	t3 := new(big.Int).Mod(new(big.Int).Mul(zCubed, sp12), mod)

	result.Mod(t2.Mul(t2, t1), mod)
	result.Mod(result.Sub(result, t3), mod)

	return result
}
