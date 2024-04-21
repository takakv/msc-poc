package main

import (
	"crypto/rand"
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
	U *big.Int
	V *big.Int
}

func encryptVote(choice uint16, pk ElGamalPublicKey) (ElGamalCiphertext, *big.Int) {
	var tmp big.Int

	rnd, _ := rand.Int(rand.Reader, tmp.Sub(pk.Q, bigOne))
	rnd.Add(rnd, bigOne)

	cBig := big.NewInt(int64(choice))
	liftedMessage := new(big.Int).Exp(pk.G, cBig, pk.P)
	mask := new(big.Int).Exp(pk.Y, rnd, pk.P)

	var ciphertext ElGamalCiphertext
	ciphertext.U = new(big.Int).Exp(pk.G, rnd, pk.P)
	ciphertext.V = new(big.Int).Mod(tmp.Mul(liftedMessage, mask), pk.P)
	return ciphertext, rnd
}
