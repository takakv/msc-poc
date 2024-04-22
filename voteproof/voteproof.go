package voteproof

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"github.com/takakv/msc-poc/algebra"
	"math/big"
)

// GroupParameters describes a group in a prime field.
type GroupParameters struct {
	G algebra.Element // Group generator.
	H algebra.Element // Generator whose logarithm to the base G is not known.
	N *big.Int        // Group size.
	F *big.Int        // Field size.
	I algebra.Group   // Group implementation.
}

// AlgebraicParameters describes both groups of the vote correctness proof system.
type AlgebraicParameters struct {
	GFF GroupParameters // ElGamal group.
	GEC GroupParameters // Bulletproofs group.
}

// ProofParams holds the parameters of the vote correctness proof system.
type ProofParams struct {
	bx                  uint8  // Length of the secret.
	bc                  uint16 // Length of the challenge.
	bf                  uint16 // Length of the field.
	RangeLo             uint16 // Inclusive lower bound of the range.
	RangeHi             uint16 // Inclusive upper bound of the range.
	AlgebraicParameters        // Group descriptions.
}

// VerCommitments holds the commitments needed to verify the correctness proof.
type VerCommitments struct {
	Y   algebra.Element // First component of an ElGamal ciphertext.
	Xp  algebra.Element // Second component of en ElGamal ciphertext.
	Xq1 algebra.Element // Pedersen commitment to a secret.
	Xq2 algebra.Element // Pedersen commitment to a secret.
}

// SigmaCommit represents the initial commitments of the protocol.
type SigmaCommit struct {
	W   algebra.Element
	Kp  algebra.Element
	Kq1 algebra.Element
	Kq2 algebra.Element
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
func Setup(lenSecret uint8, lenChallenge uint16, fieldSize uint16,
	rangeLo uint16, rangeHi uint16,
	AP AlgebraicParameters) ProofParams {
	params := ProofParams{}
	params.bx = lenSecret
	params.bc = lenChallenge
	params.bf = fieldSize
	params.RangeLo = rangeLo
	params.RangeHi = rangeHi
	params.GFF = AP.GFF
	params.GEC = AP.GEC
	return params
}

func PedersenCommit(m *big.Int, r *big.Int, gp GroupParameters) algebra.Element {
	bind := gp.I.Element().BaseScale(m)
	blind := gp.I.Element().Scale(gp.H, r)
	return gp.I.Element().Add(bind, blind)
}

func SigmaPedersenCheck(z, s, c *big.Int, k, x algebra.Element, gp GroupParameters) bool {
	left := PedersenCommit(z, s, gp)
	right := gp.I.Element().Scale(x, c)
	right = gp.I.Element().Add(right, k)
	return left.Equal(right)
}

func HashProof(w algebra.Element, Kp algebra.Element, Kq1, Kq2 algebra.Element) *big.Int {
	hasher := sha256.New()

	var buffer bytes.Buffer
	buffer.WriteString(w.String())
	buffer.WriteString(Kp.String())
	buffer.WriteString(Kq1.String())
	buffer.WriteString(Kq2.String())
	hasher.Write(buffer.Bytes())

	challenge := hasher.Sum(nil)[:31] // TODO: implement correct rejection sampling.
	return new(big.Int).SetBytes(challenge)
}

func Prove(secret *big.Int, rp *big.Int, rq1, rq2 *big.Int, params ProofParams) SigmaProof {
	k, _ := rand.Int(rand.Reader, params.GEC.N)
	kp := new(big.Int).Mod(k, params.GFF.N)
	kq := new(big.Int).Mod(k, params.GFF.N)

	tp, _ := rand.Int(rand.Reader, params.GFF.N)
	tq1, _ := rand.Int(rand.Reader, params.GEC.N)
	tq2, _ := rand.Int(rand.Reader, params.GEC.N)

	w := params.GFF.I.Element().BaseScale(tp)
	Kp := PedersenCommit(kp, tp, params.GFF)
	Kq1 := PedersenCommit(kq, tq1, params.GEC)
	Kq2 := PedersenCommit(kq, tq2, params.GEC)

	challenge := HashProof(w, Kp, Kq1, Kq2)
	if challenge.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(params.bc)), nil)) != -1 {
		panic("challenge too large")
	}

	z := new(big.Int).Add(k, new(big.Int).Mul(challenge, secret))
	// TODO: implement aborts

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

func (proof *SigmaProof) Verify(comm VerCommitments) bool {
	challenge := HashProof(proof.W, proof.Kp, proof.Kq1, proof.Kq2)
	if challenge.Cmp(proof.Challenge) != 0 {
		return false
	}

	l := proof.Params.GFF.I.Element().BaseScale(proof.Sp)
	r := proof.Params.GFF.I.Element().Scale(comm.Y, proof.Challenge)
	r = proof.Params.GFF.I.Element().Add(r, proof.W)
	if !l.Equal(r) {
		return false
	}

	if !SigmaPedersenCheck(proof.Z, proof.Sp, proof.Challenge, proof.Kp,
		comm.Xp, proof.Params.GFF) {
		return false
	}

	if !SigmaPedersenCheck(proof.Z, proof.Sq1, proof.Challenge, proof.Kq1,
		comm.Xq1, proof.Params.GEC) {
		return false
	}

	if !SigmaPedersenCheck(proof.Z, proof.Sq2, proof.Challenge, proof.Kq2,
		comm.Xq2, proof.Params.GEC) {
		return false
	}

	// TODO: add abort condition acceptance check

	return true
}
