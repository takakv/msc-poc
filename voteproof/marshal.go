package voteproof

import (
	"encoding/json"
	"github.com/takakv/msc-poc/group"
	"math/big"
)

type groupParametersJSON struct {
	G json.RawMessage
	H json.RawMessage
	N *big.Int
	F *big.Int
	I json.RawMessage
}

type algebraicParametersJSON struct {
	GFF groupParametersJSON
	GEC groupParametersJSON
}

type proofParamsJSON struct {
	Bx      uint8
	Bc      uint16
	Bg      uint16
	Bb      int
	RangeLo uint16
	RangeHi uint16
	algebraicParametersJSON
}

type sigmaCommitJSON struct {
	W   json.RawMessage
	Kp  json.RawMessage
	Kq1 json.RawMessage
	Kq2 json.RawMessage
}

type sigmaProofJSON struct {
	sigmaCommitJSON
	SigmaChallenge
	SigmaResponse
	Params proofParamsJSON
}

func ProofUnmarshalJSON(b []byte, gFF, gEC group.Group) (SigmaProof, error) {
	tmp := sigmaProofJSON{}
	err := json.Unmarshal(b, &tmp)
	if err != nil {
		return SigmaProof{}, err
	}

	var ap AlgebraicParameters
	ap.GFF.G = gFF.Element()
	ap.GFF.H = gFF.Element()
	ap.GFF.N = tmp.Params.GFF.N
	ap.GFF.F = tmp.Params.GFF.F
	ap.GFF.I = gFF
	ap.GEC.G = gEC.Element()
	ap.GEC.H = gEC.Element()
	ap.GEC.N = tmp.Params.GEC.N
	ap.GEC.F = tmp.Params.GEC.F
	ap.GEC.I = gEC

	_ = ap.GFF.G.UnmarshalJSON(tmp.Params.GFF.G)
	_ = ap.GFF.H.UnmarshalJSON(tmp.Params.GFF.H)
	_ = ap.GEC.G.UnmarshalJSON(tmp.Params.GEC.G)
	_ = ap.GEC.H.UnmarshalJSON(tmp.Params.GEC.H)

	var pp ProofParams
	pp.Bx = tmp.Params.Bx
	pp.Bc = tmp.Params.Bc
	pp.Bg = tmp.Params.Bg
	pp.Bb = tmp.Params.Bb
	pp.RangeLo = tmp.Params.RangeLo
	pp.RangeHi = tmp.Params.RangeHi
	pp.GFF = ap.GFF
	pp.GEC = ap.GEC

	var proof SigmaProof
	proof.W = gFF.Element()
	proof.Kp = gFF.Element()
	proof.Kq1 = gEC.Element()
	proof.Kq2 = gEC.Element()
	proof.Challenge = tmp.Challenge
	proof.Z = tmp.Z
	proof.Sp = tmp.Sp
	proof.Sq1 = tmp.Sq1
	proof.Sq2 = tmp.Sq2
	proof.Params = pp

	_ = proof.W.UnmarshalJSON(tmp.W)
	_ = proof.Kp.UnmarshalJSON(tmp.Kp)
	_ = proof.Kq1.UnmarshalJSON(tmp.Kq1)
	_ = proof.Kq2.UnmarshalJSON(tmp.Kq2)
	return proof, nil
}
