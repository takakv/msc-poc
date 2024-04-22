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
	"github.com/takakv/msc-poc/algebra"
	"math"
	"math/big"

	"github.com/ing-bank/zkrp/crypto/p256"
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
	G algebra.Element
	// H is a new generator, computed using MapToGroup function,
	// such that there is no discrete logarithm relation with G.
	H algebra.Element
	// Gg and Hh are sets of new generators obtained using MapToGroup.
	// They are used to compute Pedersen Vector Commitments.
	Gg []algebra.Element
	Hh []algebra.Element
	// InnerProductParams is the setup parameters for the inner product proof.
	InnerProductParams InnerProductParamsSP
	SP                 algebra.Group
}

/*
BulletProof is the structure that contains the elements that are necessary for
the verification of the Zero Knowledge Proof.
*/
type BulletProof struct {
	V                 algebra.Element
	VEl               algebra.Element
	A                 algebra.Element
	S                 algebra.Element
	T1                algebra.Element
	T2                algebra.Element
	Taux              *big.Int
	Mu                *big.Int
	Tprime            *big.Int
	InnerProductProof InnerProductProofSP
	Commit            algebra.Element
	Params            BulletProofSetupParams
}

/*
Setup is responsible for computing the common parameters.
Only works for ranges to 0 to 2^n, where n is a power of 2 and n <= 32
TODO: allow n > 32 (need uint64 for that).
*/
func Setup(b int64, SP algebra.Group) (BulletProofSetupParams, error) {
	if !IsPowerOfTwo(b) {
		return BulletProofSetupParams{}, errors.New("range end is not a power of 2")
	}

	params := BulletProofSetupParams{}
	params.SP = SP
	params.G = SP.Element().BaseScale(big.NewInt(1))

	tmp, _ := p256.MapToGroup(SEEDH)
	tmpX := tmp.X.Bytes()
	tmpY := tmp.Y.Bytes()
	params.H = SP.Element().SetBytes(append(tmpX, tmpY...))

	params.N = int64(math.Log2(float64(b)))
	if !IsPowerOfTwo(params.N) {
		return BulletProofSetupParams{}, fmt.Errorf("range end is a power of 2, but it's exponent should also be. Exponent: %d", params.N)
	}
	if params.N > 32 {
		return BulletProofSetupParams{}, errors.New("range end can not be greater than 2**32")
	}
	params.Gg = make([]algebra.Element, params.N)
	params.Hh = make([]algebra.Element, params.N)
	for i := int64(0); i < params.N; i++ {
		tmp, _ = p256.MapToGroup(SEEDH + "g" + fmt.Sprint(i))
		tmpX = tmp.X.Bytes()
		tmpY = tmp.Y.Bytes()
		params.Gg[i] = SP.Element().SetBytes(append(tmpX, tmpY...))
		tmp, _ = p256.MapToGroup(SEEDH + "h" + fmt.Sprint(i))
		tmpX = tmp.X.Bytes()
		tmpY = tmp.Y.Bytes()
		params.Hh[i] = SP.Element().SetBytes(append(tmpX, tmpY...))
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
	gamma, _ := rand.Int(rand.Reader, ORDER)
	V, _ := CommitG1SP(secret, gamma, params.H, params.SP)

	// aL, aR and commitment: (A, alpha)
	aL, _ := Decompose(secret, 2, params.N)                                               // (41)
	aR, _ := computeAR(aL)                                                                // (42)
	alpha, _ := rand.Int(rand.Reader, ORDER)                                              // (43)
	A := commitVector(aL, aR, alpha, params.H, params.Gg, params.Hh, params.N, params.SP) // (44)

	// sL, sR and commitment: (S, rho)                                     // (45)
	sL := sampleRandomVector(params.N)
	sR := sampleRandomVector(params.N)
	rho, _ := rand.Int(rand.Reader, ORDER)                                                 // (46)
	S := commitVectorBig(sL, sR, rho, params.H, params.Gg, params.Hh, params.N, params.SP) // (47)

	// Fiat-Shamir heuristic to compute challenges y and z, corresponds to    (49)
	y, z, _ := HashBPSP(A, S)

	// ////////////////////////////////////////////////////////////////////////////
	// Second phase: page 20
	// ////////////////////////////////////////////////////////////////////////////
	tau1, _ := rand.Int(rand.Reader, ORDER) // (52)
	tau2, _ := rand.Int(rand.Reader, ORDER) // (52)

	/*
	   The paper does not describe how to compute t1 and t2.
	*/
	// compute t1: < aL - z.1^n, y^n . sR > + < sL, y^n . (aR + z . 1^n) >
	vz, _ := VectorCopy(z, params.N)
	vy := powerOf(y, params.N)

	// aL - z.1^n
	naL, _ := VectorConvertToBig(aL, params.N)
	aLmvz, _ := VectorSub(naL, vz)

	// y^n .sR
	ynsR, _ := VectorMul(vy, sR)

	// scalar prod: < aL - z.1^n, y^n . sR >
	sp1, _ := ScalarProduct(aLmvz, ynsR)

	// scalar prod: < sL, y^n . (aR + z . 1^n) >
	naR, _ := VectorConvertToBig(aR, params.N)
	aRzn, _ := VectorAdd(naR, vz)
	ynaRzn, _ := VectorMul(vy, aRzn)

	// Add z^2.2^n to the result
	// z^2 . 2^n
	p2n := powerOf(new(big.Int).SetInt64(2), params.N)
	zsquared := bn.Multiply(z, z)
	z22n, _ := VectorScalarMul(p2n, zsquared)
	ynaRzn, _ = VectorAdd(ynaRzn, z22n)
	sp2, _ := ScalarProduct(sL, ynaRzn)

	// sp1 + sp2
	t1 := bn.Add(sp1, sp2)
	t1 = bn.Mod(t1, ORDER)

	// compute t2: < sL, y^n . sR >
	t2, _ := ScalarProduct(sL, ynsR)
	t2 = bn.Mod(t2, ORDER)

	// compute T1
	T1, _ := CommitG1SP(t1, tau1, params.H, params.SP) // (53)

	// compute T2
	T2, _ := CommitG1SP(t2, tau2, params.H, params.SP) // (53)

	// Fiat-Shamir heuristic to compute 'random' challenge x
	x, _, _ := HashBPSP(T1, T2)

	// ////////////////////////////////////////////////////////////////////////////
	// Third phase                                                              //
	// ////////////////////////////////////////////////////////////////////////////

	// compute bl                                                          // (58)
	sLx, _ := VectorScalarMul(sL, x)
	bl, _ := VectorAdd(aLmvz, sLx)

	// compute br                                                          // (59)
	// y^n . ( aR + z.1^n + sR.x )
	sRx, _ := VectorScalarMul(sR, x)
	aRzn, _ = VectorAdd(aRzn, sRx)
	ynaRzn, _ = VectorMul(vy, aRzn)
	// y^n . ( aR + z.1^n sR.x ) + z^2 . 2^n
	br, _ := VectorAdd(ynaRzn, z22n)

	// Compute t` = < bl, br >                                             // (60)
	tprime, _ := ScalarProduct(bl, br)

	// Compute taux = tau2 . x^2 + tau1 . x + z^2 . gamma                  // (61)
	taux := bn.Multiply(tau2, bn.Multiply(x, x))
	taux = bn.Add(taux, bn.Multiply(tau1, x))
	taux = bn.Add(taux, bn.Multiply(bn.Multiply(z, z), gamma))
	taux = bn.Mod(taux, ORDER)

	// Compute mu = alpha + rho.x                                          // (62)
	mu := bn.Multiply(rho, x)
	mu = bn.Add(mu, alpha)
	mu = bn.Mod(mu, ORDER)

	// Inner Product over (g, h', P.h^-mu, tprime)
	hprime := updateGenerators(params.Hh, y, params.N, params.SP)

	// SetupInnerProduct Inner Product (Section 4.2)
	var setupErr error
	params.InnerProductParams, setupErr = setupInnerProductSP(params.H, params.Gg, hprime, tprime, params.N, params.SP)
	if setupErr != nil {
		return proof, gamma, setupErr
	}
	commit := commitInnerProductSP(params.Gg, hprime, bl, br, params.SP)
	proofip, _ := proveInnerProductSP(bl, br, commit, params.InnerProductParams)

	proof.V = V
	proof.A = A
	proof.S = S
	proof.T1 = T1
	proof.T2 = T2
	proof.Taux = taux
	proof.Mu = mu
	proof.Tprime = tprime
	proof.InnerProductProof = proofip
	proof.Commit = commit
	proof.Params = params

	return proof, gamma, nil
}

/*
Verify returns true if and only if the proof is valid.
*/
func (proof *BulletProof) Verify() (bool, error) {
	params := proof.Params
	// Recover x, y, z using Fiat-Shamir heuristic
	x, _, _ := HashBPSP(proof.T1, proof.T2)
	y, z, _ := HashBPSP(proof.A, proof.S)

	// Switch generators                                                   // (64)
	hprime := updateGenerators(params.Hh, y, params.N, params.SP)

	// ////////////////////////////////////////////////////////////////////////////
	// Check that tprime  = t(x) = t0 + t1x + t2x^2  ----------  Condition (65) //
	// ////////////////////////////////////////////////////////////////////////////

	// Compute left hand side
	lhs, _ := CommitG1SP(proof.Tprime, proof.Taux, params.H, params.SP)

	// Compute right hand side
	z2 := bn.Multiply(z, z)
	z2 = bn.Mod(z2, ORDER)
	x2 := bn.Multiply(x, x)
	x2 = bn.Mod(x2, ORDER)

	// rhs := new(p256.P256).ScalarMult(proof.V, z2)
	rhs := params.SP.Element().Scale(proof.V, z2)

	delta := params.delta(y, z)

	// gdelta := new(p256.P256).ScalarBaseMult(delta)
	gdelta := params.SP.Element().BaseScale(delta)

	// rhs.Multiply(rhs, gdelta)
	rhs = params.SP.Element().Add(rhs, gdelta)

	// T1x := new(p256.P256).ScalarMult(proof.T1, x)
	T1x := params.SP.Element().Scale(proof.T1, x)
	// T2x2 := new(p256.P256).ScalarMult(proof.T2, x2)
	T2x2 := params.SP.Element().Scale(proof.T2, x2)

	// rhs.Multiply(rhs, T1x)
	rhs = params.SP.Element().Add(rhs, T1x)
	// rhs.Multiply(rhs, T2x2)
	rhs = params.SP.Element().Add(rhs, T2x2)

	// Subtract lhs and rhs and compare with poitn at infinity
	// lhs.Neg(lhs)
	lhs = params.SP.Element().Negate(lhs)
	// rhs.Multiply(rhs, lhs)
	rhs = params.SP.Element().Add(rhs, lhs)
	// c65 := rhs.IsZero() // Condition (65), page 20, from eprint version
	c65 := rhs.IsIdentity()

	// Compute P - lhs  #################### Condition (66) ######################

	// S^x
	// Sx := new(p256.P256).ScalarMult(proof.S, x)
	Sx := params.SP.Element().Scale(proof.S, x)
	// A.S^x
	// ASx := new(p256.P256).Add(proof.A, Sx)
	ASx := params.SP.Element().Add(proof.A, Sx)

	// g^-z
	mz := bn.Sub(ORDER, z)
	vmz, _ := VectorCopy(mz, params.N)
	gpmz, _ := VectorExpSP(params.Gg, vmz, params.SP)

	// z.y^n
	vz, _ := VectorCopy(z, params.N)
	vy := powerOf(y, params.N)
	zyn, _ := VectorMul(vy, vz)

	p2n := powerOf(new(big.Int).SetInt64(2), params.N)
	zsquared := bn.Multiply(z, z)
	z22n, _ := VectorScalarMul(p2n, zsquared)

	// z.y^n + z^2.2^n
	zynz22n, _ := VectorAdd(zyn, z22n)

	// lP := new(p256.P256)
	// lP.Add(ASx, gpmz)
	lP := params.SP.Element().Add(ASx, gpmz)

	// h'^(z.y^n + z^2.2^n)
	hprimeexp, _ := VectorExpSP(hprime, zynz22n, params.SP)

	lP.Add(lP, hprimeexp)

	// Compute P - rhs  #################### Condition (67) ######################

	// h^mu
	// rP := new(p256.P256).ScalarMult(params.H, proof.Mu)
	rP := params.SP.Element().Scale(params.H, proof.Mu)
	// rP.Multiply(rP, proof.Commit)
	rP = params.SP.Element().Add(rP, proof.Commit)

	// Subtract lhs and rhs and compare with poitn at infinity
	// lP = lP.Neg(lP)
	lP = params.SP.Element().Negate(lP)
	// rP.Add(rP, lP)
	rP = params.SP.Element().Add(rP, lP)
	// c67 := rP.IsZero()
	c67 := rP.IsIdentity()

	// Verify Inner Product Proof ################################################
	ok, _ := proof.InnerProductProof.VerifySP()

	result := c65 && c67 && ok

	return result, nil
}

/*
SampleRandomVector generates a vector composed by random big numbers.
*/
func sampleRandomVector(N int64) []*big.Int {
	s := make([]*big.Int, N)
	for i := int64(0); i < N; i++ {
		s[i], _ = rand.Int(rand.Reader, ORDER)
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
func updateGenerators(Hh []algebra.Element, y *big.Int, N int64, SP algebra.Group) []algebra.Element {
	var (
		i int64
	)
	// Compute h'                                                          // (64)
	hprime := make([]algebra.Element, N)
	// Switch generators
	yinv := bn.ModInverse(y, ORDER)
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

func commitVectorBig(aL, aR []*big.Int, alpha *big.Int, H algebra.Element, g, h []algebra.Element, n int64, SP algebra.Group) algebra.Element {
	// Compute h^alpha.vg^aL.vh^aR
	R := SP.Element().Scale(H, alpha)
	for i := int64(0); i < n; i++ {
		R.Add(R, SP.Element().Scale(g[i], aL[i]))
		R.Add(R, SP.Element().Scale(h[i], aR[i]))
	}
	return R
}

/*
Commitvector computes a commitment to the bit of the secret.
*/
func commitVector(aL, aR []int64, alpha *big.Int, H algebra.Element, g, h []algebra.Element, n int64, SP algebra.Group) algebra.Element {
	// Compute h^alpha.vg^aL.vh^aR
	R := SP.Element().Scale(H, alpha)
	for i := int64(0); i < n; i++ {
		gaL := SP.Element().Scale(g[i], big.NewInt(aL[i]))
		haR := SP.Element().Scale(h[i], big.NewInt(aR[i]))
		R = SP.Element().Add(R, gaL)
		R = SP.Element().Add(R, haR)
	}
	return R
}

func (params *BulletProofSetupParams) delta(y, z *big.Int) *big.Int {
	var (
		result *big.Int
	)
	// delta(y,z) = (z-z^2) . < 1^n, y^n > - z^3 . < 1^n, 2^n >
	z2 := bn.Multiply(z, z)
	z2 = bn.Mod(z2, ORDER)
	z3 := bn.Multiply(z2, z)
	z3 = bn.Mod(z3, ORDER)

	// < 1^n, y^n >
	v1, _ := VectorCopy(new(big.Int).SetInt64(1), params.N)
	vy := powerOf(y, params.N)
	sp1y, _ := ScalarProduct(v1, vy)

	// < 1^n, 2^n >
	p2n := powerOf(new(big.Int).SetInt64(2), params.N)
	sp12, _ := ScalarProduct(v1, p2n)

	result = bn.Sub(z, z2)
	result = bn.Mod(result, ORDER)
	result = bn.Multiply(result, sp1y)
	result = bn.Mod(result, ORDER)
	result = bn.Sub(result, bn.Multiply(z3, sp12))
	result = bn.Mod(result, ORDER)

	return result
}
