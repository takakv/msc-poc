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
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/takakv/msc-poc/group"
	"math/big"

	"github.com/ing-bank/zkrp/util/bn"
	"github.com/ing-bank/zkrp/util/byteconversion"
)

var SEEDU = "BulletproofsDoesNotNeedTrustedSetupU"

/*
InnerProductParams contains elliptic curve generators used to compute Pedersen
commitments.
*/
type InnerProductParams struct {
	Gg []group.Element // Random generators
	Hh []group.Element // Random generators
	Uu group.Element   // Internal fixed element with unknown dlog
	SP group.Group
}

/*
InnerProductProof contains the elements used to verify the Inner Product Proof.
*/
type InnerProductProof struct {
	P      group.Element // Commitment
	Cc     *big.Int      // Inner product
	A      *big.Int
	B      *big.Int
	L      []group.Element
	R      []group.Element
	Params InnerProductParams
}

/*
setupInnerProduct is responsible for computing the inner product basic parameters
that are common to both the proveInnerProduct and Verify algorithms.
*/
func setupInnerProduct(g, h []group.Element, N int64, SP group.Group) (InnerProductParams, error) {
	var params InnerProductParams

	if N <= 0 {
		return params, errors.New("N must be greater than zero")
	}

	if g == nil {
		params.Gg = make([]group.Element, N)
		for i := range params.Gg {
			params.Gg[i], _ = SP.Element().MapToGroup(SEEDH + "g" + fmt.Sprint(i))
		}
	} else {
		params.Gg = g
	}
	if h == nil {
		params.Hh = make([]group.Element, N)
		for i := range params.Hh {
			params.Hh[i], _ = SP.Element().MapToGroup(SEEDH + "h" + fmt.Sprint(i))
		}
	} else {
		params.Hh = h
	}

	params.Uu, _ = SP.Element().MapToGroup(SEEDU)
	params.SP = SP

	return params, nil
}

// computePP computes P' as P' = P.u^(x.c) and returns P' and u^x
func computePP(P group.Element, c *big.Int, x *big.Int, params InnerProductParams) (group.Element, group.Element) {
	ux := params.SP.Element().Scale(params.Uu, x)
	uxc := params.SP.Element().Scale(ux, c)
	PP := params.SP.Element().Add(P, uxc)
	return PP, ux
}

/*
proveInnerProduct calculates the Zero Knowledge Proof for the Inner Product argument.
*/
func proveInnerProduct(a, b []*big.Int, P group.Element, c *big.Int, params InnerProductParams) (InnerProductProof, error) {
	var (
		proof InnerProductProof
		n, m  int64
		Ls    []group.Element
		Rs    []group.Element
	)

	n = int64(len(a))
	m = int64(len(b))

	if n != m {
		return proof, errors.New("size of first array argument must be equal to the second")
	}

	// Fiat-Shamir
	x, _ := hashIP(params.Gg, params.Hh, P, c) // (6) & (7)

	// P' = P.u^(x.c)
	PP, ux := computePP(P, c, x, params) // (8)

	// Execute Protocol 2 recursively
	proof = computeBipRecursive(a, b, params.Gg, params.Hh, ux, PP, n, Ls, Rs, params.SP) // 9

	proof.Params = params
	proof.P = P
	proof.Cc = c

	return proof, nil
}

/*
computeBipRecursive is the main recursive function that will be used to compute the inner product argument.
*/
func computeBipRecursive(a, b []*big.Int, g, h []group.Element, u, P group.Element, n int64, Ls, Rs []group.Element, SP group.Group) InnerProductProof {
	var (
		proof                            InnerProductProof
		cL, cR, x, xinv, x2, x2inv       *big.Int
		L, R, Lh, Rh, Pprime             group.Element
		gprime, hprime, gprime2, hprime2 []group.Element
		aprime, bprime, aprime2, bprime2 []*big.Int
	)

	if n == 1 {
		// recursion end
		proof.A = a[0]
		proof.B = b[0]
		proof.P = P
		proof.L = Ls
		proof.R = Rs
		return proof
	}

	// recursion

	nprime := n / 2 // (20)

	// Compute cL = < a[:n'], b[n':] >                                    // (21)
	cL, _ = ScalarProduct(a[:nprime], b[nprime:], SP)
	// Compute cR = < a[n':], b[:n'] >                                    // (22)
	cR, _ = ScalarProduct(a[nprime:], b[:nprime], SP)
	// Compute L = g[n':]^(a[:n']).h[:n']^(b[n':]).u^cL                   // (23)
	L, _ = VectorExp(g[nprime:], a[:nprime], SP)
	Lh, _ = VectorExp(h[:nprime], b[nprime:], SP)
	L.Add(L, Lh)
	L.Add(L, SP.Element().Scale(u, cL))

	// Compute R = g[:n']^(a[n':]).h[n':]^(b[:n']).u^cR                   // (24)
	R, _ = VectorExp(g[:nprime], a[nprime:], SP)
	Rh, _ = VectorExp(h[nprime:], b[:nprime], SP)
	R.Add(R, Rh)
	R.Add(R, SP.Element().Scale(u, cR))

	// Fiat-Shamir:                                                       // (26)
	x, _, _ = HashBP(L, R)
	xinv = bn.ModInverse(x, SP.N())

	// Compute g' = g[:n']^(x^-1) * g[n':]^(x)                            // (29)
	gprime = vectorScalarExp(g[:nprime], xinv, SP)
	gprime2 = vectorScalarExp(g[nprime:], x, SP)
	gprime, _ = VectorECAdd(gprime, gprime2, SP)
	// Compute h' = h[:n']^(x)    * h[n':]^(x^-1)                         // (30)
	hprime = vectorScalarExp(h[:nprime], x, SP)
	hprime2 = vectorScalarExp(h[nprime:], xinv, SP)
	hprime, _ = VectorECAdd(hprime, hprime2, SP)

	// Compute P' = L^(x^2).P.R^(x^-2)                                    // (31)
	x2 = bn.Mod(bn.Multiply(x, x), SP.N())
	x2inv = bn.ModInverse(x2, SP.N())
	Pprime = SP.Element().Scale(L, x2)
	Pprime.Add(Pprime, P)
	Pprime.Add(Pprime, SP.Element().Scale(R, x2inv))

	// Compute a' = a[:n'].x      + a[n':].x^(-1)                         // (33)
	aprime, _ = VectorScalarMul(a[:nprime], x, SP.N())
	aprime2, _ = VectorScalarMul(a[nprime:], xinv, SP.N())
	aprime, _ = VectorAdd(aprime, aprime2, SP.N())
	// Compute b' = b[:n'].x^(-1) + b[n':].x                              // (34)
	bprime, _ = VectorScalarMul(b[:nprime], xinv, SP.N())
	bprime2, _ = VectorScalarMul(b[nprime:], x, SP.N())
	bprime, _ = VectorAdd(bprime, bprime2, SP.N())

	Ls = append(Ls, L)
	Rs = append(Rs, R)
	// recursion computeBipRecursive(g',h',u,P'; a', b')                  // (35)
	proof = computeBipRecursive(aprime, bprime, gprime, hprime, u, Pprime, nprime, Ls, Rs, SP)

	return proof
}

/*
Verify is responsible for the verification of the Inner Product Proof.
*/
func (proof InnerProductProof) Verify() (bool, error) {

	logn := len(proof.L)
	var (
		x, xinv, x2, x2inv                   *big.Int
		ngprime, nhprime, ngprime2, nhprime2 []group.Element
	)

	gprime := proof.Params.Gg
	hprime := proof.Params.Hh

	// Fiat-Shamir
	x, _ = hashIP(gprime, hprime, proof.P, proof.Cc) // (6) & (7)

	Pprime, ux := computePP(proof.P, proof.Cc, x, proof.Params) // (8)

	nprime := len(gprime)
	for i := int64(0); i < int64(logn); i++ {
		nprime = nprime / 2                      // (20)
		x, _, _ = HashBP(proof.L[i], proof.R[i]) // (26)
		xinv = bn.ModInverse(x, proof.Params.SP.N())
		// Compute g' = g[:n']^(x^-1) * g[n':]^(x)                            // (29)
		ngprime = vectorScalarExp(gprime[:nprime], xinv, proof.Params.SP)
		ngprime2 = vectorScalarExp(gprime[nprime:], x, proof.Params.SP)
		gprime, _ = VectorECAdd(ngprime, ngprime2, proof.Params.SP)
		// Compute h' = h[:n']^(x)    * h[n':]^(x^-1)                         // (30)
		nhprime = vectorScalarExp(hprime[:nprime], x, proof.Params.SP)
		nhprime2 = vectorScalarExp(hprime[nprime:], xinv, proof.Params.SP)
		hprime, _ = VectorECAdd(nhprime, nhprime2, proof.Params.SP)
		// Compute P' = L^(x^2).P.R^(x^-2)                                    // (31)
		x2 = bn.Mod(bn.Multiply(x, x), proof.Params.SP.N())
		x2inv = bn.ModInverse(x2, proof.Params.SP.N())
		Pprime.Add(Pprime, proof.Params.SP.Element().Scale(proof.L[i], x2))
		Pprime.Add(Pprime, proof.Params.SP.Element().Scale(proof.R[i], x2inv))
	}

	// c == a*b and checks if P = g^a.h^b.u^c                                     // (16)
	ab := bn.Multiply(proof.A, proof.B)
	ab = bn.Mod(ab, proof.Params.SP.N())
	// Compute right hand side
	rhs := proof.Params.SP.Element().Scale(gprime[0], proof.A)
	hb := proof.Params.SP.Element().Scale(hprime[0], proof.B)
	rhs = proof.Params.SP.Element().Add(rhs, hb)
	rhs = proof.Params.SP.Element().Add(rhs, proof.Params.SP.Element().Scale(ux, ab))
	// Compute inverse of left hand side
	nP := proof.Params.SP.Element().Negate(Pprime)
	nP.Add(nP, rhs)
	// If both sides are equal then nP must be zero                               // (17)
	c := nP.IsIdentity()

	return c, nil
}

/*
hashIP is responsible for the computing a Zp element given elements from GT and G1.
*/
func hashIP(g, h []group.Element, P group.Element, c *big.Int) (*big.Int, error) {
	digest := sha256.New()
	digest.Write([]byte(P.String()))

	for i := 0; i < len(g); i++ {
		digest.Write([]byte(g[i].String()))
		digest.Write([]byte(h[i].String()))
	}

	digest.Write([]byte(c.String()))
	output := digest.Sum(nil)
	tmp := output[0:]
	result, err := byteconversion.FromByteArray(tmp)

	return result, err
}

/*
commitInnerProduct is responsible for calculating g^a.h^b.
*/
func commitInnerProduct(g, h []group.Element, a, b []*big.Int, SP group.Group) group.Element {
	ga, _ := VectorExp(g, a, SP)
	hb, _ := VectorExp(h, b, SP)
	return SP.Element().Add(ga, hb)
}

/*
vectorScalarExp computes a[i]^b for each i.
*/
func vectorScalarExp(a []group.Element, b *big.Int, SP group.Group) []group.Element {
	n := int64(len(a))
	result := make([]group.Element, n)
	for i := int64(0); i < n; i++ {
		result[i] = SP.Element().Scale(a[i], b)
	}
	return result
}
