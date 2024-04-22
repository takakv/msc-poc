package main

import (
	"fmt"
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
	loShift := rpParams.GEC.I.Element().BaseScale(big.NewInt(int64(rpParams.RangeLo)))
	Xq1 := rpParams.GEC.I.Element().Add(loShift, proofs.bpLower.VEl)

	// Shift back upper bound.
	upShift := rpParams.GEC.I.Element().BaseScale(big.NewInt(int64(rpParams.RangeHi)))
	inv := rpParams.GEC.I.Element().Scale(proofs.bpUpper.VEl, big.NewInt(-1))
	Xq2 := rpParams.GEC.I.Element().Add(upShift, inv)

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
