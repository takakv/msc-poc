package voteproof

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/takakv/msc-poc/group"
	"math/big"
)

var BigTwo = big.NewInt(2)

// GroupParameters describes a group in a prime field.
type GroupParameters struct {
	G group.Element // Group generator.
	H group.Element // Generator whose logarithm to the base G is not known.
	N *big.Int      // Group size.
	F *big.Int      // Field size.
	I group.Group   // Group implementation.
}

// AlgebraicParameters describes both groups of the vote correctness proof system.
type AlgebraicParameters struct {
	GFF GroupParameters // ElGamal group.
	GEC GroupParameters // Bulletproofs group.
}

// ProofParams holds the parameters of the vote correctness proof system.
type ProofParams struct {
	Bx                  uint8  // Length of the secret.
	Bc                  uint16 // Length of the challenge.
	Bg                  uint16 // Length of the order of the smaller group.
	Bb                  int    // Abort parameter.
	RangeLo             uint16 // Inclusive lower bound of the range.
	RangeHi             uint16 // Inclusive upper bound of the range.
	AlgebraicParameters        // Group descriptions.
}

// VerCommitments holds the commitments needed to verify the correctness proof.
type VerCommitments struct {
	Y   group.Element // First component of an ElGamal ciphertext.
	Xp  group.Element // Second component of an ElGamal ciphertext.
	Xq1 group.Element // Pedersen commitment to a secret.
	Xq2 group.Element // Pedersen commitment to a secret.
}

// SigmaCommit represents the initial commitments of the protocol.
type SigmaCommit struct {
	W   group.Element
	Kp  group.Element
	Kq1 group.Element
	Kq2 group.Element
}

// SigmaChallenge represents the random challenge.
type SigmaChallenge struct {
	Challenge *big.Int
}

// SigmaResponse represents the response of the protocol.
type SigmaResponse struct {
	Z   *big.Int
	Sp  *big.Int
	Sq1 *big.Int
	Sq2 *big.Int
}

// SigmaProof contains the elements involved in the sigma protocol.
// The proof is not complete without the commitments and Bulletproofs.
type SigmaProof struct {
	SigmaCommit    // 1st move data.
	SigmaChallenge // 2nd move data.
	SigmaResponse  // 3rd move data.
	Params         ProofParams
}

// Setup sets the common parameters for the vote correctness proof system.
func Setup(lenSecret uint8, lenChallenge uint16, groupOrderLog uint16,
	rangeLo uint16, rangeHi uint16, AP AlgebraicParameters) (ProofParams, error) {
	params := ProofParams{}
	params.Bx = lenSecret
	params.Bc = lenChallenge
	params.Bg = groupOrderLog
	params.Bb = int(groupOrderLog) - 1 - int(lenSecret) - int(lenChallenge)
	params.RangeLo = rangeLo
	params.RangeHi = rangeHi
	params.GFF = AP.GFF
	params.GEC = AP.GEC

	if params.Bb < 1 {
		return params, errors.New("inconsistent parameter choice")
	}

	return params, nil
}

func pedersenCommit(m *big.Int, r *big.Int, gp GroupParameters) group.Element {
	bind := gp.I.Element().BaseScale(m)
	blind := gp.I.Element().Scale(gp.H, r)
	return gp.I.Element().Add(bind, blind)
}

func sigmaPedersenCheck(z, s, c *big.Int, k, x group.Element, gp GroupParameters) bool {
	left := pedersenCommit(z, s, gp)
	right := gp.I.Element().Scale(x, c)
	right = gp.I.Element().Add(right, k)
	return left.IsEqual(right)
}

func getFSChallenge(w group.Element, Kp group.Element, Kq1, Kq2 group.Element, pow2bound uint16) *big.Int {
	hasher := sha256.New()

	var buffer bytes.Buffer
	buffer.WriteString(w.String())
	buffer.WriteString(Kp.String())
	buffer.WriteString(Kq1.String())
	buffer.WriteString(Kq2.String())
	hasher.Write(buffer.Bytes())

	challenge := hasher.Sum(nil)[:pow2bound/8]
	return new(big.Int).SetBytes(challenge)
}

func Prove(secret *big.Int, rp *big.Int, rq1, rq2 *big.Int, params ProofParams) SigmaProof {
	bxbc := big.NewInt(int64(uint16(params.Bx) + params.Bc))
	// Inclusive lower bound
	zLowerBound := new(big.Int).Exp(BigTwo, bxbc, nil)
	// Exclusive upper bound
	zUpperBound := new(big.Int).Exp(BigTwo, new(big.Int).Add(bxbc, big.NewInt(int64(params.Bb))), nil)

	// Abort loop
	for {
		// Setup
		k, _ := rand.Int(rand.Reader, zUpperBound)
		kp := new(big.Int).Mod(k, params.GFF.N) // k mod p for efficiency
		kq := new(big.Int).Mod(k, params.GFF.N) // k mod q for efficiency

		tp, _ := rand.Int(rand.Reader, params.GFF.N)
		tq1, _ := rand.Int(rand.Reader, params.GEC.N)
		tq2, _ := rand.Int(rand.Reader, params.GEC.N)

		// Commitment
		w := params.GFF.I.Element().BaseScale(tp)
		Kp := pedersenCommit(kp, tp, params.GFF)
		Kq1 := pedersenCommit(kq, tq1, params.GEC)
		Kq2 := pedersenCommit(kq, tq2, params.GEC)

		// Challenge
		challenge := getFSChallenge(w, Kp, Kq1, Kq2, params.Bc)
		z := new(big.Int).Add(k, new(big.Int).Mul(challenge, secret))
		if z.Cmp(zLowerBound) == -1 || z.Cmp(zUpperBound) != -1 {
			fmt.Println("Aborted")
			continue
		}

		// Response
		sp := new(big.Int).Mod(new(big.Int).Add(tp, new(big.Int).Mul(challenge, rp)), params.GFF.N)
		sq1 := new(big.Int).Mod(new(big.Int).Add(tq1, new(big.Int).Mul(challenge, rq1)), params.GEC.N)
		sq2 := new(big.Int).Mod(new(big.Int).Add(tq2, new(big.Int).Mul(challenge, rq2)), params.GEC.N)

		var proof SigmaProof
		proof.W = w
		proof.Kp = Kp
		proof.Kq1 = Kq1
		proof.Kq2 = Kq2
		proof.Challenge = challenge
		proof.Z = z
		proof.Sp = sp
		proof.Sq1 = sq1
		proof.Sq2 = sq2
		proof.Params = params

		return proof
	}
}

// Verify verifies the transcript of the proof of secret equality across groups.
// NB! The range proof(s) that assert "smallness" of the secret must be verified
// prior to verifying the transcript. Verify does not verify the range proof(s).
func (proof *SigmaProof) Verify(comm VerCommitments) bool {
	bxbc := big.NewInt(int64(uint16(proof.Params.Bx) + proof.Params.Bc))
	// Inclusive lower bound
	zLowerBound := new(big.Int).Exp(BigTwo, bxbc, nil)
	// Exclusive upper bound
	zUpperBound := new(big.Int).Exp(BigTwo, new(big.Int).Add(bxbc, big.NewInt(int64(proof.Params.Bb))), nil)

	// Verify whether z lies within the safe (no-leak) range.
	if proof.Z.Cmp(zLowerBound) == -1 || proof.Z.Cmp(zUpperBound) != -1 {
		return false
	}

	// Verify challenge correctness.
	challenge := getFSChallenge(proof.W, proof.Kp, proof.Kq1, proof.Kq2, proof.Params.Bc)
	if challenge.Cmp(proof.Challenge) != 0 {
		return false
	}

	// Verify ElGamal ciphertext c1.
	l := proof.Params.GFF.I.Element().BaseScale(proof.Sp)
	r := proof.Params.GFF.I.Element().Scale(comm.Y, proof.Challenge)
	r = proof.Params.GFF.I.Element().Add(r, proof.W)
	if !l.IsEqual(r) {
		return false
	}

	// Verify ElGamal ciphertext c2.
	if !sigmaPedersenCheck(proof.Z, proof.Sp, proof.Challenge, proof.Kp,
		comm.Xp, proof.Params.GFF) {
		return false
	}

	// Verify range proof commitments (range proofs themselves must have already been verified).
	if !sigmaPedersenCheck(proof.Z, proof.Sq1, proof.Challenge, proof.Kq1,
		comm.Xq1, proof.Params.GEC) {
		return false
	}

	if !sigmaPedersenCheck(proof.Z, proof.Sq2, proof.Challenge, proof.Kq2,
		comm.Xq2, proof.Params.GEC) {
		return false
	}

	return true
}
