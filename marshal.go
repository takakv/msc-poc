package main

import (
	"encoding/json"
	"github.com/takakv/msc-poc/bulletproofs"
	"github.com/takakv/msc-poc/group"
	"github.com/takakv/msc-poc/voteproof"
)

type elGamalCiphertextJSON struct {
	U json.RawMessage `json:"u"`
	V json.RawMessage `json:"v"`
}

type ballotDataJSON struct {
	Ballot    json.RawMessage `json:"ballot"`
	BpLower   json.RawMessage `json:"lbProof"`
	BpUpper   json.RawMessage `json:"ubProof"`
	VoteProof json.RawMessage `json:"voteProof"`
}

func BallotUnmarshalJSON(b []byte, g group.Group) (ElGamalCiphertext, error) {
	tmp := elGamalCiphertextJSON{}
	err := json.Unmarshal(b, &tmp)
	if err != nil {
		return ElGamalCiphertext{}, err
	}

	ballot := ElGamalCiphertext{
		U: g.Element(),
		V: g.Element(),
	}

	_ = ballot.U.UnmarshalJSON(tmp.U)
	_ = ballot.V.UnmarshalJSON(tmp.V)
	return ballot, nil
}

func BallotDataUnmarshalJSON(b []byte, pp PublicParameters) (BallotData, error) {
	tmp := ballotDataJSON{}
	err := json.Unmarshal(b, &tmp)

	ballot, err := BallotUnmarshalJSON(tmp.Ballot, pp.RPParams.GFF.I)
	if err != nil {
		return BallotData{}, err
	}

	bpLower, err := bulletproofs.BulletProofUnmarshalJSON(tmp.BpLower, pp.BPParams)
	if err != nil {
		return BallotData{}, err
	}

	bpUpper, err := bulletproofs.BulletProofUnmarshalJSON(tmp.BpUpper, pp.BPParams)
	if err != nil {
		return BallotData{}, err
	}

	voteProof, err := voteproof.ProofUnmarshalJSON(tmp.VoteProof, pp.RPParams.GFF.I, pp.RPParams.GEC.I)
	if err != nil {
		return BallotData{}, err
	}

	bd := BallotData{
		Ballot:    ballot,
		BpLower:   bpLower,
		BpUpper:   bpUpper,
		VoteProof: voteProof,
	}

	return bd, nil
}
