package main

import (
	"crypto/rand"
	"github.com/takakv/msc-poc/algebra"
	"math/big"
)

type ElGamalParameters struct {
	P *big.Int // Group order.
	Q *big.Int // Subgroup order.
	G *big.Int // Generator of multiplicative subgroup.
}

type ElGamalPrivateKey struct {
	X *big.Int // Private key
}

type ElGamalPublicKey struct {
	ElGamalParameters          // Group parameters
	Y                 *big.Int // Public key
}

type ElGamalCiphertext struct {
	U algebra.Element // *big.Int
	V algebra.Element // *big.Int
}

func encryptVote(choice uint16, EGPK algebra.Element, FFG algebra.Group) (ElGamalCiphertext, *big.Int) {
	var tmp big.Int

	rnd, _ := rand.Int(rand.Reader, tmp.Sub(EGPK.GroupOrder(), bigOne))
	rnd.Add(rnd, bigOne)

	cBig := big.NewInt(int64(choice))
	// liftedMessage := new(big.Int).Exp(pk.G, cBig, pk.P)
	// mask := new(big.Int).Exp(pk.Y, rnd, pk.P)
	liftedMessage := FFG.Element().BaseScale(cBig)
	mask := FFG.Element().Scale(EGPK, rnd)

	var ciphertext ElGamalCiphertext
	// ciphertext.U = new(big.Int).Exp(pk.G, rnd, pk.P)
	// ciphertext.V = new(big.Int).Mod(tmp.Mul(liftedMessage, mask), pk.P)
	ciphertext.U = FFG.Element().BaseScale(rnd)
	ciphertext.V = FFG.Element().Add(liftedMessage, mask)
	return ciphertext, rnd
}
