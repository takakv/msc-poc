package main

import (
	"crypto/rand"
	"github.com/takakv/msc-poc/group"
	"math/big"
)

type ElGamalCiphertext struct {
	U group.Element // *big.Int
	V group.Element // *big.Int
}

func encryptVote(choice uint16, egPK group.Element, FFG group.Group) (ElGamalCiphertext, *big.Int) {
	var tmp big.Int

	rnd, _ := rand.Int(rand.Reader, tmp.Sub(egPK.GroupOrder(), big.NewInt(1)))
	rnd.Add(rnd, big.NewInt(1))

	cBig := big.NewInt(int64(choice))
	liftedMessage := FFG.Element().BaseScale(cBig)
	mask := FFG.Element().Scale(egPK, rnd)

	var ciphertext ElGamalCiphertext
	ciphertext.U = FFG.Element().BaseScale(rnd)
	ciphertext.V = FFG.Element().Add(liftedMessage, mask)
	return ciphertext, rnd
}
