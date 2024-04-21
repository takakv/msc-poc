package voteproof

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"github.com/0xdecaf/zkrp/crypto/p256"
	"math/big"
)

// FFGroupParameters holds the public parameters of a group.
type FFGroupParameters struct {
	G *big.Int // Base generator.
	H *big.Int // Generator whose logarithm to the base G is not known.
	N *big.Int // Group size.
	F *big.Int // Field size.
}

// ECGroupParameters holds the public parameters of an EC group.
type ECGroupParameters struct {
	G *p256.P256 // Base point.
	H *p256.P256 // Point whose logarithm to the base G is not known.
	N *big.Int   // Group size.
}

// AlgebraicParameters holds the parameters of the various groups
// used in the vote correctness proof system.
type AlgebraicParameters struct {
	GFF FFGroupParameters // ElGamal group.
	GEC ECGroupParameters // Bulletproofs group.
}

// ProofParams holds the parameters of the vote correctness proof system.
type ProofParams struct {
	bx      uint8               // Length of the secret.
	bc      uint16              // Length of the challenge.
	bf      uint16              // Length of the field.
	RangeLo uint16              // Inclusive lower bound of the range.
	RangeHi uint16              // Inclusive upper bound of the range.
	AP      AlgebraicParameters // ElGamalParameters of the two distinct groups.
}

// VerCommitments holds the commitments needed to verify the correctness proof.
type VerCommitments struct {
	Y   *big.Int
	Xp  *big.Int
	Xq1 *p256.P256
	Xq2 *p256.P256
}

// SigmaProof contains the elements involved in the sigma protocol.
// The proof is not complete without the commitments and Bulletproofs.
type SigmaProof struct {
	W         *big.Int
	Kp        *big.Int
	Kq1       *p256.P256
	Kq2       *p256.P256
	Challenge *big.Int
	Z         *big.Int
	Sp        *big.Int
	Sq1       *big.Int
	Sq2       *big.Int
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
	params.AP = AP
	return params
}

func PedersenCommitFF(m *big.Int, r *big.Int, gp FFGroupParameters) *big.Int {
	bind := new(big.Int).Exp(gp.G, m, gp.F)
	blind := new(big.Int).Exp(gp.H, r, gp.F)
	return new(big.Int).Mod(new(big.Int).Mul(bind, blind), gp.F)
}

func PedersenCommitEC(m, r *big.Int, gp ECGroupParameters) *p256.P256 {
	bind := new(p256.P256).ScalarBaseMult(m)
	blind := new(p256.P256).ScalarMult(gp.H, r)
	return new(p256.P256).Add(bind, blind)
}

func HashProof(w *big.Int, Kp *big.Int, Kq1, Kq2 *p256.P256) *big.Int {
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
	// fmt.Println("x:", secret)
	// fmt.Println("r_p:", rp)
	// fmt.Println("r_q:", rq1)
	// fmt.Println("r_q':", rq2)

	k, _ := rand.Int(rand.Reader, params.AP.GEC.N)
	kp := new(big.Int).Mod(k, params.AP.GFF.N)
	kq := new(big.Int).Mod(k, params.AP.GFF.N)

	tp, _ := rand.Int(rand.Reader, params.AP.GFF.N)
	tq1, _ := rand.Int(rand.Reader, params.AP.GEC.N)
	tq2, _ := rand.Int(rand.Reader, params.AP.GEC.N)
	// fmt.Println("k:", k)
	// fmt.Println("tp:", tp)
	// fmt.Println("tq1:", tq1)
	// fmt.Println("tq2:", tq2)

	w := new(big.Int).Exp(params.AP.GFF.G, tp, params.AP.GFF.F)
	Kp := PedersenCommitFF(kp, tp, params.AP.GFF)
	Kq1 := PedersenCommitEC(kq, tq1, params.AP.GEC)
	Kq2 := PedersenCommitEC(kq, tq2, params.AP.GEC)

	challenge := HashProof(w, Kp, Kq1, Kq2)
	if challenge.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(params.bc)), nil)) != -1 {
		panic("challenge too large")
	}

	z := new(big.Int).Add(k, new(big.Int).Mul(challenge, secret))
	// TODO: implement aborts

	sp := new(big.Int).Mod(new(big.Int).Add(tp, new(big.Int).Mul(challenge, rp)), params.AP.GFF.N)
	sq1 := new(big.Int).Mod(new(big.Int).Add(tq1, new(big.Int).Mul(challenge, rq1)), params.AP.GEC.N)
	sq2 := new(big.Int).Mod(new(big.Int).Add(tq2, new(big.Int).Mul(challenge, rq2)), params.AP.GEC.N)

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

	return proof
}

func Verify(comm VerCommitments, proof SigmaProof, params ProofParams) bool {
	l := new(big.Int).Exp(params.AP.GFF.G, proof.Sp, params.AP.GFF.F)
	r := new(big.Int).Exp(comm.Y, proof.Challenge, params.AP.GFF.F)
	r = new(big.Int).Mod(new(big.Int).Mul(proof.W, r), params.AP.GFF.F)
	if l.Cmp(r) != 0 {
		return false
	}

	left := PedersenCommitFF(proof.Z, proof.Sp, params.AP.GFF)
	right := new(big.Int).Mul(proof.Kp, new(big.Int).Exp(comm.Xp, proof.Challenge, params.AP.GFF.F))
	right = new(big.Int).Mod(right, params.AP.GFF.F)
	if left.Cmp(right) != 0 {
		return false
	}

	left1 := PedersenCommitEC(proof.Z, proof.Sq1, params.AP.GEC)
	right1 := new(p256.P256).Add(proof.Kq1, new(p256.P256).ScalarMult(comm.Xq1, proof.Challenge))
	if left1.X.Cmp(right1.X) != 0 || left1.Y.Cmp(right1.Y) != 0 {
		return false
	}

	left2 := PedersenCommitEC(proof.Z, proof.Sq2, params.AP.GEC)
	right2 := new(p256.P256).Add(proof.Kq2, new(p256.P256).ScalarMult(comm.Xq2, proof.Challenge))
	if left2.X.Cmp(right2.X) != 0 || left2.Y.Cmp(right2.Y) != 0 {
		return false
	}

	// TODO: add abort condition acceptance check

	return true
}
