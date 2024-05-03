package main

import (
	"encoding/json"
	"github.com/takakv/msc-poc/group"
)

type elGamalCiphertextJSON struct {
	U json.RawMessage `json:"u"`
	V json.RawMessage `json:"v"`
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
