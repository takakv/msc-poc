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
	"fmt"
	"github.com/takakv/msc-poc/group"
	"math/big"

	. "github.com/takakv/msc-poc/util"
)

/*
BulletProof is the structure that contains the elements that are necessary for
the verification of the Zero Knowledge Proof.
*/
type MultiBulletProof struct {
	Vs                []group.Element
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
MultiProve computes the aggregated ZKRP for multiple values.
The documentation and comments are based on the ePrint version of the Bulletproofs paper:
https://eprint.iacr.org/2017/1066.pdf
*/
func MultiProve(secrets []*big.Int, params BulletProofSetupParams) (MultiBulletProof, []*big.Int, error) {
	proof := MultiBulletProof{}

	mod := params.GP.N()

	m := len(secrets)
	bitsPerValue := int(params.N) / m

	commitments := make([]group.Element, m)
	gammas := make([]*big.Int, m)
	aLConcat := make([]int64, params.N)
	aRConcat := make([]int64, params.N)

	// ////////////////////////////////////////////////////////////////////////////
	// First phase: page 19                                                      //
	// ////////////////////////////////////////////////////////////////////////////

	for j := range secrets {
		// Sample randomness gamma and commit to v.
		gamma, _ := rand.Int(rand.Reader, mod)
		commitments[j] = PedersenCommit(secrets[j], gamma, params.H, params.GP)
		gammas[j] = gamma

		// aL, aR
		aL := Decompose(secrets[j], 2, int64(bitsPerValue)) // (41)
		aR, _ := computeAR(aL)                              // (42)

		for i := range aR {
			aLConcat[bitsPerValue*j+i] = aL[i]
			aRConcat[bitsPerValue*j+i] = aR[i]
		}
	}

	// Commitment: (A, alpha)
	alpha, _ := rand.Int(rand.Reader, mod)                                                            // (43)
	A := commitVector(aRConcat, aRConcat, alpha, params.H, params.Gg, params.Hh, params.N, params.GP) // (44)

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
	powersOf2 := powerOf(big.NewInt(2), int64(bitsPerValue), params.GP)

	zPowersTimesTwoVec := make([]*big.Int, params.N)
	for j := 0; j < m; j++ {
		zp := new(big.Int).Exp(z, big.NewInt(2+int64(j)), mod)
		for i := 0; i < bitsPerValue; i++ {
			zPowersTimesTwoVec[j*bitsPerValue+i] = new(big.Int).Mod(new(big.Int).Mul(powersOf2[i], zp), mod)
		}
	}

	// Vectors of big integers are needed for some functions.
	aLb, _ := VectorConvertToBig(aLConcat, params.N)
	aRb, _ := VectorConvertToBig(aRConcat, params.N)

	// l(x) = (aL - z . 1Pow) + sL . x
	l0 := VectorAddConst(aLb, new(big.Int).Neg(z), mod)
	l1 := sL

	// aRzn = aR + z . 1Pow
	vecZ, _ := VectorCopy(z, params.N)
	aRzn, _ := VectorAdd(vecZ, aRb, mod)

	// r(x) = yPow ∘ (aR + z . 1Pow + sR . x) + z^2 . 2Pow
	r0, _ := VectorMul(yPow, aRzn, mod)
	r0, _ = VectorAdd(r0, zPowersTimesTwoVec, mod)
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
	sRx, _ := VectorScalarMul(sR, x, mod)            // sR . x
	tmp, _ := VectorAdd(aRzn, sRx, mod)              // (aR + z . 1Pow + sR . x)
	tmp, _ = VectorMul(yPow, tmp, mod)               // yPow ∘ (aR + z . 1Pow + sR . x)
	br, _ := VectorAdd(tmp, zPowersTimesTwoVec, mod) // r(x)

	// th = <bl, br>
	th, _ := ScalarProduct(bl, br, params.GP) // (60)

	// tau_x = tau2 . x^2 + tau1 . x + z^2 . gamma // (61)
	tauX := new(big.Int).Mul(tau2, new(big.Int).Mul(x, x))
	tauX.Add(tauX, new(big.Int).Mul(tau1, x))

	vecRandomnessTotal := big.NewInt(0)
	for j := 0; j < m; j++ {
		zp := new(big.Int).Exp(z, big.NewInt(2+int64(j)), mod)
		tmp1 := new(big.Int).Mul(gammas[j], zp)
		vecRandomnessTotal = new(big.Int).Mod(new(big.Int).Add(vecRandomnessTotal, tmp1), mod)
	}

	tauX.Add(tauX, vecRandomnessTotal)
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
		return proof, gammas, setupErr
	}
	commit := commitInnerProduct(params.Gg, hp, bl, br, params.GP)
	ipProof, _ := proveInnerProduct(bl, br, commit, th, ipp)

	proof.Vs = commitments
	proof.Taux = tauX
	proof.Mu = mu
	proof.Tprime = th
	proof.InnerProductProof = ipProof
	proof.Params = params

	return proof, gammas, nil
}

/*
Verify returns true if and only if the proof is valid.
*/
func (proof *MultiBulletProof) Verify() (bool, error) {
	params := proof.Params
	mod := params.GP.N()

	m := len(proof.Vs)
	bitsPerValue := int(params.N) / m

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
	powersOfz := powerOf(z, int64(m), params.GP)
	rhs := params.GP.Identity()
	for j := 0; j < m; j++ {
		tmp := params.GP.Element().Scale(proof.Vs[j], new(big.Int).Mul(zSquared, powersOfz[j]))
		rhs.Add(rhs, tmp)
	}

	delta := params.deltaMul(y, z, int64(m))
	gDelta := params.GP.Element().BaseScale(delta)

	rhs.Add(rhs, gDelta)

	T1x := params.GP.Element().Scale(proof.T1, x)
	T2x2 := params.GP.Element().Scale(proof.T2, xSquared)

	rhs.Add(rhs, T1x)
	rhs.Add(rhs, T2x2)

	c65 := rhs.IsEqual(lhs) // (65)
	fmt.Println("Check 65:", c65)

	// Compute P - lhs  #################### Condition (66) ######################
	// P = A . S^x . g^(-z) . (h')^(z . y^n + z^2 . 2^n)

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

	// (h')^(z . y^n)
	hpExp, _ := VectorExp(hp, zyn, params.GP)

	powersOfTwo := powerOf(new(big.Int).SetInt64(2), int64(bitsPerValue), params.GP)
	prod := params.GP.Identity()

	for j := 0; j < m; j++ {
		hpSlide := hp[j*bitsPerValue : (j+1)*bitsPerValue]
		zp := new(big.Int).Exp(z, big.NewInt(2+int64(j)), mod)
		exp := VectorAddConst(powersOfTwo, zp, mod)
		val, _ := VectorExp(hpSlide, exp, params.GP)
		prod.Add(prod, val)
	}

	tail := params.GP.Element().Add(hpExp, prod)
	lP := params.GP.Element().Add(ASx, gpmz)
	lP.Add(lP, tail)

	// Compute P - rhs  #################### Condition (67) ######################

	// h^mu
	rP := params.GP.Element().Scale(params.H, proof.Mu)
	rP.Add(rP, proof.InnerProductProof.P)

	// Subtract lhs and rhs and compare with point at infinity
	rP.Subtract(rP, lP)
	c67 := rP.IsIdentity()
	fmt.Println("Check 67:", c67)

	// Verify Inner Product Proof ################################################
	ok, _ := proof.InnerProductProof.Verify()
	fmt.Println("Check 68:", ok)

	result := c65 && c67 && ok

	return result, nil
}

// delta(y,z) = (z - z^2) . < 1Pow(nm), yPow(nm) > - sum_{j=0}^{m-1} (z^{j+3} . < 1Pow, 2Pow >)
func (params *BulletProofSetupParams) deltaMul(y, z *big.Int, m int64) *big.Int {
	mod := params.GP.N()
	result := new(big.Int)

	// Do a confusing swap: take nm <- n and n <- n/m.
	// This is because params.N is always the upper bit bound,
	// and so nm must not exceed it.
	nm := params.N / m

	onePow, _ := VectorCopy(new(big.Int).SetInt64(1), nm)
	twoPow := powerOf(big.NewInt(2), nm, params.GP)

	zSquared := new(big.Int).Mod(new(big.Int).Mul(z, z), mod)

	// (z-z^2)
	t1 := new(big.Int).Mod(new(big.Int).Sub(z, zSquared), mod)

	// < 11Pow(n/m), yPow(n/m) >
	onePowNM, _ := VectorCopy(new(big.Int).SetInt64(1), params.N)
	yPowNM := powerOf(y, params.N, params.GP)
	t2, _ := ScalarProduct(onePowNM, yPowNM, params.GP)

	// < 1Pow, 2Pow >
	sp12, _ := ScalarProduct(onePow, twoPow, params.GP)

	// sum_{j=0}^{m-1} z^{j+3} . < 1Pow, 2Pow >
	t3 := big.NewInt(0)
	for j := int64(0); j < m; j++ {
		zp := new(big.Int).Exp(z, big.NewInt(j+3), params.GP.N())
		tmp := new(big.Int).Mod(new(big.Int).Mul(zp, sp12), params.GP.N())
		t3.Mod(new(big.Int).Add(t3, tmp), params.GP.N())
	}

	result.Mod(t2.Mul(t2, t1), mod)
	result.Mod(result.Sub(result, t3), mod)

	return result
}
