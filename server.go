package main

import (
	"fmt"
	"github.com/0xdecaf/zkrp/crypto/p256"
	"github.com/takakv/msc-poc/voteproof"
	"math/big"
	"time"
)

func verifyVote(proofs BallotData, rpParams voteproof.ProofParams) bool {
	startBP := time.Now()
	// Verify vote lower bound.
	ok1, _ := proofs.bpLower.Verify()
	if !ok1 {
		return false
	}

	// Verify vote upper bound.
	ok2, _ := proofs.bpUpper.Verify()
	if !ok2 {
		return false
	}
	durationBP := time.Since(startBP)

	startRP := time.Now()
	// Shift back lower bound.
	loShift := new(p256.P256).ScalarBaseMult(big.NewInt(int64(rpParams.RangeLo)))
	Cq1 := (*p256.P256)(proofs.bpLower.V)
	Xq1 := new(p256.P256).Add(loShift, Cq1)

	// Shift back upper bound.
	upShift := new(p256.P256).ScalarBaseMult(big.NewInt(int64(rpParams.RangeHi)))
	Cq2 := (*p256.P256)(proofs.bpUpper.V)
	Xq2 := new(p256.P256).Add(upShift, new(p256.P256).ScalarMult(Cq2, big.NewInt(-1)))

	var commitments voteproof.VerCommitments
	commitments.Y = proofs.ballot.U
	commitments.Xp = proofs.ballot.V
	commitments.Xq1 = Xq1
	commitments.Xq2 = Xq2

	result := proofs.voteProof.Verify(commitments)
	durationRP := time.Since(startRP)

	fmt.Println("Verify time BP:", durationBP)
	fmt.Println("Verify time RP:", durationRP)

	durationTotal := durationBP + durationRP
	fmt.Println("Verify time total:", durationTotal)

	return result
}
