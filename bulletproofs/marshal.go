package bulletproofs

import (
	"encoding/json"
	"github.com/takakv/msc-poc/group"
	"math/big"
)

type innerProductParamsJSON struct {
	Uu json.RawMessage
	Gg []json.RawMessage
	Hh []json.RawMessage
	SP json.RawMessage
}

type innerProductProofJSON struct {
	N      int64
	Ls     []json.RawMessage
	Rs     []json.RawMessage
	U      json.RawMessage
	P      json.RawMessage
	Cc     *big.Int
	Gg     json.RawMessage
	Hh     json.RawMessage
	A      *big.Int
	B      *big.Int
	Params innerProductParamsJSON
}

type bulletProofJSON struct {
	V                 json.RawMessage
	A                 json.RawMessage
	S                 json.RawMessage
	T1                json.RawMessage
	T2                json.RawMessage
	Taux              *big.Int
	Mu                *big.Int
	Tprime            *big.Int
	InnerProductProof innerProductProofJSON
	Commit            json.RawMessage
	Params            json.RawMessage
}

func ipParamsFromRawMessage(j innerProductParamsJSON, g group.Group) InnerProductParams {
	params := InnerProductParams{
		Uu: g.Element(),
		Gg: make([]group.Element, len(j.Gg)),
		Hh: make([]group.Element, len(j.Hh)),
		SP: g,
	}

	_ = params.Uu.UnmarshalJSON(j.Uu)
	for i := range j.Gg {
		params.Gg[i] = g.Element()
		params.Hh[i] = g.Element()
		_ = params.Gg[i].UnmarshalJSON(j.Gg[i])
		_ = params.Hh[i].UnmarshalJSON(j.Hh[i])
	}

	return params
}

func ipProofFromRawMessage(j innerProductProofJSON, g group.Group) InnerProductProof {
	proof := InnerProductProof{
		N:      j.N,
		Ls:     make([]group.Element, len(j.Ls)),
		Rs:     make([]group.Element, len(j.Rs)),
		U:      g.Element(),
		P:      g.Element(),
		Cc:     j.Cc,
		Gg:     g.Element(),
		Hh:     g.Element(),
		A:      j.A,
		B:      j.B,
		Params: ipParamsFromRawMessage(j.Params, g),
	}

	for i := range proof.Ls {
		proof.Ls[i] = g.Element()
		proof.Rs[i] = g.Element()
		_ = proof.Ls[i].UnmarshalJSON(j.Ls[i])
		_ = proof.Rs[i].UnmarshalJSON(j.Rs[i])
	}
	_ = proof.U.UnmarshalJSON(j.U)
	_ = proof.P.UnmarshalJSON(j.P)
	_ = proof.Gg.UnmarshalJSON(j.Gg)
	_ = proof.Hh.UnmarshalJSON(j.Hh)

	return proof
}

func BulletProofUnmarshalJSON(b []byte, params BulletProofSetupParams) (BulletProof, error) {
	var tmp bulletProofJSON
	err := json.Unmarshal(b, &tmp)
	if err != nil {
		return BulletProof{}, err
	}

	decodedProof := BulletProof{
		V:                 params.SP.Element(),
		A:                 params.SP.Element(),
		S:                 params.SP.Element(),
		T1:                params.SP.Element(),
		T2:                params.SP.Element(),
		Taux:              tmp.Taux,
		Mu:                tmp.Mu,
		Tprime:            tmp.Tprime,
		InnerProductProof: ipProofFromRawMessage(tmp.InnerProductProof, params.SP),
		Commit:            params.SP.Element(),
		Params:            params,
	}

	_ = decodedProof.V.UnmarshalJSON(tmp.V)
	_ = decodedProof.A.UnmarshalJSON(tmp.A)
	_ = decodedProof.S.UnmarshalJSON(tmp.S)
	_ = decodedProof.T1.UnmarshalJSON(tmp.T1)
	_ = decodedProof.T2.UnmarshalJSON(tmp.T2)
	_ = decodedProof.Commit.UnmarshalJSON(tmp.Commit)

	return decodedProof, nil
}
