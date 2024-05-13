package main

import (
	"github.com/takakv/msc-poc/voteproof"
	"math/big"
	"time"
)

func verifyVote(proofs BallotData, rpParams voteproof.ProofParams) (bool, []time.Duration) {
	verificationTimes := make([]time.Duration, 2)

	startBP := time.Now()
	// Verify the vote lower bound.
	ok1, _ := proofs.BpLower.Verify()
	if !ok1 {
		return false, nil
	}

	// Verify the vote upper bound.
	ok2, _ := proofs.BpUpper.Verify()
	if !ok2 {
		return false, nil
	}
	durationBP := time.Since(startBP)

	startRP := time.Now()
	// Shift back lower bound.
	loShift := rpParams.GEC.I.Element().BaseScale(big.NewInt(int64(rpParams.RangeLo)))
	Xq1 := rpParams.GEC.I.Element().Add(loShift, proofs.BpLower.V)

	// Shift back upper bound.
	upShift := rpParams.GEC.I.Element().BaseScale(big.NewInt(int64(rpParams.RangeHi)))
	inv := rpParams.GEC.I.Element().Scale(proofs.BpUpper.V, big.NewInt(-1))
	Xq2 := rpParams.GEC.I.Element().Add(upShift, inv)

	commitments := voteproof.VerCommitments{
		Y:   proofs.Ballot.U, // First component of the ElGamal ciphertext
		Xp:  proofs.Ballot.V, // Second component of the ElGamal ciphertext
		Xq1: Xq1,             // Lower bound shifted back to the secret
		Xq2: Xq2,             // Upper bound shifted back to the secret
	}

	// Verify the consistency of the shifted commitments with the ElGamal ciphertext.
	result := proofs.VoteProof.Verify(commitments)
	durationRP := time.Since(startRP)

	// fmt.Println("Verify time BP:", durationBP)
	// fmt.Println("Verify time RP:", durationRP)

	// durationTotal := durationBP + durationRP
	// fmt.Println("Verify time total:", durationTotal)
	verificationTimes[0] = durationBP
	verificationTimes[1] = durationRP

	return result, verificationTimes
}
