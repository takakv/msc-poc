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
	Ballot    ElGamalCiphertext        `json:"ballot"`    // The ElGamal ciphertext, i.e. the encrypted ballot.
	BpLower   bulletproofs.BulletProof `json:"lbProof"`   // Bulletproof for the lower bound.
	BpUpper   bulletproofs.BulletProof `json:"ubProof"`   // Bulletproof for the upper bound.
	VoteProof voteproof.SigmaProof     `json:"voteProof"` // Proof of vote correctness.
}

func castVote(pp PublicParameters) BallotData {
	rBig, _ := rand.Int(rand.Reader, big.NewInt(int64(pp.candidateMax-pp.candidateMin)))

	var choice = uint16(rBig.Uint64()) + pp.candidateMin
	fmt.Println("Chosen candidate:", choice)

	ciphertext, rp := encryptVote(choice, pp.EGPK, pp.FFGroupParams.I)

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

	bd := BallotData{
		Ballot:    ciphertext,
		BpLower:   bp1,
		BpUpper:   bp2,
		VoteProof: rangeProof,
	}

	return bd
}
