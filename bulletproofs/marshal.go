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
	GP json.RawMessage
}

type innerProductProofJSON struct {
	P      json.RawMessage
	Cc     *big.Int
	A      *big.Int `json:"a"`
	B      *big.Int `json:"b"`
	L      []json.RawMessage
	R      []json.RawMessage
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
		GP: g,
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
		L:      make([]group.Element, len(j.L)),
		R:      make([]group.Element, len(j.R)),
		P:      g.Element(),
		Cc:     j.Cc,
		A:      j.A,
		B:      j.B,
		Params: ipParamsFromRawMessage(j.Params, g),
	}

	for i := range proof.L {
		proof.L[i] = g.Element()
		proof.R[i] = g.Element()
		_ = proof.L[i].UnmarshalJSON(j.L[i])
		_ = proof.R[i].UnmarshalJSON(j.R[i])
	}
	_ = proof.P.UnmarshalJSON(j.P)

	return proof
}

func BulletProofUnmarshalJSON(b []byte, params BulletProofSetupParams) (BulletProof, error) {
	var tmp bulletProofJSON
	err := json.Unmarshal(b, &tmp)
	if err != nil {
		return BulletProof{}, err
	}

	decodedProof := BulletProof{
		V:                 params.GP.Element(),
		A:                 params.GP.Element(),
		S:                 params.GP.Element(),
		T1:                params.GP.Element(),
		T2:                params.GP.Element(),
		Taux:              tmp.Taux,
		Mu:                tmp.Mu,
		Tprime:            tmp.Tprime,
		InnerProductProof: ipProofFromRawMessage(tmp.InnerProductProof, params.GP),
		Commit:            params.GP.Element(),
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
