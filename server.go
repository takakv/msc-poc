package main

import (
	"fmt"
	"github.com/takakv/msc-poc/voteproof"
	"math/big"
	"time"
)

func verifyVote(proofs BallotData, rpParams voteproof.ProofParams) bool {
	startBP := time.Now()
	// Verify the vote lower bound.
	ok1, _ := proofs.bpLower.Verify()
	if !ok1 {
		return false
	}

	// Verify the vote upper bound.
	ok2, _ := proofs.bpUpper.Verify()
	if !ok2 {
		return false
	}
	durationBP := time.Since(startBP)

	startRP := time.Now()
	// Shift back lower bound.
	loShift := rpParams.GEC.I.Element().BaseScale(big.NewInt(int64(rpParams.RangeLo)))
	Xq1 := rpParams.GEC.I.Element().Add(loShift, proofs.bpLower.V)

	// Shift back upper bound.
	upShift := rpParams.GEC.I.Element().BaseScale(big.NewInt(int64(rpParams.RangeHi)))
	inv := rpParams.GEC.I.Element().Scale(proofs.bpUpper.V, big.NewInt(-1))
	Xq2 := rpParams.GEC.I.Element().Add(upShift, inv)

	commitments := voteproof.VerCommitments{
		Y:   proofs.ballot.U, // First component of the ElGamal ciphertext
		Xp:  proofs.ballot.V, // Second component of the ElGamal ciphertext
		Xq1: Xq1,             // Lower bound shifted back to the secret
		Xq2: Xq2,             // Upper bound shifted back to the secret
	}

	// Verify the consistency of the shifted commitments with the ElGamal ciphertext.
	result := proofs.voteProof.Verify(commitments)
	durationRP := time.Since(startRP)

	fmt.Println("Verify time BP:", durationBP)
	fmt.Println("Verify time RP:", durationRP)

	durationTotal := durationBP + durationRP
	fmt.Println("Verify time total:", durationTotal)

	return result
}
