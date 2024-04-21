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

func castVote(minCandidate, maxCandidate uint16,
	pk ElGamalPublicKey,
	bpParams bulletproofs.BulletProofSetupParams,
	rpParams voteproof.ProofParams) BallotData {
	rBig, _ := rand.Int(rand.Reader, big.NewInt(int64(maxCandidate-minCandidate)))

	var choice = uint16(rBig.Uint64()) + minCandidate
	fmt.Println("Chosen candidate:", choice)

	ciphertext, rp := encryptVote(choice, pk)
	// fmt.Println("ciphertext:", ciphertext)

	start := time.Now()

	// Prove the lower bound.
	bp1, rq1, _ := bulletproofs.Prove(big.NewInt(int64(choice-minCandidate)), bpParams)
	// Prove the upper bound.
	bp2, rq2, _ := bulletproofs.Prove(big.NewInt(int64(maxCandidate-choice)), bpParams)
	rq2inv := new(big.Int).Sub(rpParams.AP.GEC.N, rq2)
	// Prove that Bulletproofs correspond to the ciphertext.
	rangeProof := voteproof.Prove(big.NewInt(int64(choice)), rp, rq1, rq2inv, rpParams)

	duration := time.Since(start)
	fmt.Println("Prove time:", duration)

	var bd BallotData
	bd.ballot = ciphertext
	bd.bpLower = bp1
	bd.bpUpper = bp2
	bd.voteProof = rangeProof

	return bd
}
