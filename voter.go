package main

import (
	"crypto/rand"
	"fmt"
	"github.com/takakv/msc-poc/bulletproofs"
	"github.com/takakv/msc-poc/voteproof"
	"math/big"
	"time"
)

// BallotData contains elements that assert the correctness of a vote.
type BallotData struct {
	ballot    ElGamalCiphertext        // The ElGamal ciphertext, i.e. the encrypted ballot.
	bpLower   bulletproofs.BulletProof // Bulletproof for the lower bound.
	bpUpper   bulletproofs.BulletProof // Bulletproof for the upper bound.
	voteProof voteproof.SigmaProof     // Proof of vote correctness.

}

func castVote(pp PublicParameters) BallotData {
	rBig, _ := rand.Int(rand.Reader, big.NewInt(int64(pp.candidateMax-pp.candidateMin)))

	var choice = uint16(rBig.Uint64()) + pp.candidateMin
	fmt.Println("Chosen candidate:", choice)

	ciphertext, rp := encryptVote(choice, pp.EGPK, pp.FFGroupParams.I)
	// fmt.Println("ciphertext:", ciphertext)

	start := time.Now()

	// Prove the lower bound.
	bp1, rq1, _ := bulletproofs.Prove(big.NewInt(int64(choice-pp.candidateMin)), pp.BPParams)
	// Prove the upper bound.
	bp2, rq2, _ := bulletproofs.Prove(big.NewInt(int64(pp.candidateMax-choice)), pp.BPParams)
	rq2inv := new(big.Int).Sub(pp.ECGroupParams.N, rq2)
	// Prove that Bulletproofs correspond to the ciphertext.
	rangeProof := voteproof.Prove(big.NewInt(int64(choice)), rp, rq1, rq2inv, pp.RPParams)

	duration := time.Since(start)
	fmt.Println("Prove time:", duration)

	// Convert Bulletproof commitments to 'abstract' elements.
	tmpX := bp1.V.X.Bytes()
	tmpY := bp1.V.Y.Bytes()
	bp1.VEl = pp.RPParams.GEC.I.Element().SetBytes(append(tmpX, tmpY...))
	tmpX = bp2.V.X.Bytes()
	tmpY = bp2.V.Y.Bytes()
	bp2.VEl = pp.RPParams.GEC.I.Element().SetBytes(append(tmpX, tmpY...))

	var bd BallotData
	bd.ballot = ciphertext
	bd.bpLower = bp1
	bd.bpUpper = bp2
	bd.voteProof = rangeProof

	return bd
}
