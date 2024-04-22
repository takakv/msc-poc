package main

import (
	"fmt"
	"github.com/0xdecaf/zkrp/crypto/p256"
	"github.com/takakv/msc-poc/algebra"
	"github.com/takakv/msc-poc/bulletproofs"
	"github.com/takakv/msc-poc/voteproof"
)
import "math/big"

type PublicParameters struct {
	// Parameters of the Finite Field ElGamal group.
	FFGroupParams voteproof.GroupParameters
	// Parameters of the Elliptic Curve Bulletproofs group.
	ECGroupParams voteproof.GroupParameters
	// ElGamal public key.
	EGPK algebra.Element
	// Lowest candidate number.
	candidateMin uint16
	// Highest candidate number.
	candidateMax uint16
	// Public parameters of Bulletproofs.
	BPParams bulletproofs.BulletProofSetupParams
	// Public parameters of the range proof protocol.
	RPParams voteproof.ProofParams
}

func setup() PublicParameters {
	// While the choice length is configurable in theory, it is fixed
	// at 16 in the current code (the used types will not fit more).
	// For Estonian elections, this parameter should be suitable for the
	// foreseeable future.
	const choiceLength uint8 = 16

	// In practice, since the proof is made non-interactive with FS, the
	// challenge should be 256 bits long for 128 bits of collision resistance.
	const challengeLength uint16 = 256

	// The first candidate number is fixed at 101.
	const candidateStart uint16 = 101
	// The last candidate number varies depending on the election. The largest
	// number of candidates so far in any Estonian election has been 15322.
	const candidateEnd uint16 = 1000

	RFC3526ModPGroup3072 := algebra.NewModPGroup(
		"RFC3526ModPGroup3072",
		`FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
		29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
		EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
		E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
		EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
		C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
		83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
		670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
		E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
		DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
		15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
		ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
		ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
		F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
		BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
		43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
		`, "2")

	SecP256k1Group := algebra.NewSecP256k1Group()

	// W.l.o.g. this secret is not known to any one party.
	elGamalPrivateKey := big.NewInt(13)

	bpParams, _ := bulletproofs.Setup(65536)

	var fieldGroupParams voteproof.GroupParameters
	fieldGroupParams.I = RFC3526ModPGroup3072
	fieldGroupParams.F = fieldGroupParams.I.P()
	fieldGroupParams.N = fieldGroupParams.I.N()
	fieldGroupParams.G = fieldGroupParams.I.Generator()
	fieldGroupParams.H = fieldGroupParams.I.Element().BaseScale(elGamalPrivateKey)

	tmp1 := (*p256.P256)(bpParams.H).X.Bytes()
	tmp2 := (*p256.P256)(bpParams.H).Y.Bytes()

	var curveGroupParams voteproof.GroupParameters
	curveGroupParams.I = SecP256k1Group
	curveGroupParams.F = fieldGroupParams.I.P()
	curveGroupParams.N = curveGroupParams.I.N()
	curveGroupParams.G = curveGroupParams.I.Generator()
	curveGroupParams.H = curveGroupParams.I.Element().SetBytes(append(tmp1, tmp2...))

	var algebraicParams voteproof.AlgebraicParameters
	algebraicParams.GFF = fieldGroupParams
	algebraicParams.GEC = curveGroupParams

	rpParams := voteproof.Setup(choiceLength, challengeLength, 253,
		candidateStart, candidateEnd, algebraicParams)

	var pp PublicParameters
	pp.FFGroupParams = fieldGroupParams
	pp.ECGroupParams = curveGroupParams
	pp.EGPK = pp.FFGroupParams.H
	pp.candidateMin = candidateStart
	pp.candidateMax = candidateEnd
	pp.BPParams = bpParams
	pp.RPParams = rpParams

	return pp
}

func main() {
	pp := setup()

	fmt.Println("Vote casting")
	vote := castVote(pp)

	fmt.Println()
	fmt.Println("Vote verification")
	verify := verifyVote(vote, pp.RPParams)

	fmt.Println()
	fmt.Println("Vote is correctly formed:", verify)
}
