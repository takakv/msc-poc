package main

import (
	"fmt"
	"github.com/takakv/msc-poc/bulletproofs"
	"github.com/takakv/msc-poc/group"
	"github.com/takakv/msc-poc/voteproof"
	"strings"
	"time"
)
import "math/big"

type PublicParameters struct {
	// Parameters of the Finite Field ElGamal group.
	FFGroupParams voteproof.GroupParameters
	// Parameters of the Elliptic Curve Bulletproofs group.
	ECGroupParams voteproof.GroupParameters
	// ElGamal public key.
	EGPK group.Element
	// Lowest candidate number.
	candidateMin uint16
	// Highest candidate number.
	candidateMax uint16
	// Public parameters of Bulletproofs.
	BPParams bulletproofs.BulletProofSetupParams
	// Public parameters of the range proof protocol.
	RPParams voteproof.ProofParams
}

func setup(curveGroup group.Group) (PublicParameters, error) {
	// While the choice length is configurable in theory, it is fixed
	// at 16 in the current code (the used types will not fit more).
	// For Estonian elections, this parameter should be suitable for the
	// foreseeable future.
	const choiceLength uint8 = 16

	// In practice, since the proof is made non-interactive with FS, the
	// challenge should be 256 bits long for 128 bits of collision resistance.
	const challengeLength uint16 = 224

	// The first candidate number is fixed at 101.
	const candidateStart uint16 = 101
	// The last candidate number varies depending on the election. The largest
	// number of candidates so far in any Estonian election has been 15322.
	// However, this does not reflect the highest candidate number available in
	// any single electoral district. The largest number of candidates unified
	// across an electoral district has been 1885.
	const candidateEnd uint16 = 2000

	RFC3526ModPGroup3072 := group.NewModPGroup(
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

	// W.l.o.g. this secret is not known to any one party.
	elGamalPrivateKey := big.NewInt(13)

	bpParams, err := bulletproofs.Setup(65536, curveGroup)
	if err != nil {
		return PublicParameters{}, err
	}

	var fieldGroupParams voteproof.GroupParameters
	fieldGroupParams.I = RFC3526ModPGroup3072
	fieldGroupParams.F = fieldGroupParams.I.P()
	fieldGroupParams.N = fieldGroupParams.I.N()
	fieldGroupParams.G = fieldGroupParams.I.Generator()
	fieldGroupParams.H = fieldGroupParams.I.Element().BaseScale(elGamalPrivateKey)

	var curveGroupParams voteproof.GroupParameters
	curveGroupParams.I = curveGroup
	curveGroupParams.F = fieldGroupParams.I.P()
	curveGroupParams.N = curveGroupParams.I.N()
	curveGroupParams.G = curveGroupParams.I.Generator()
	curveGroupParams.H = bpParams.H

	var algebraicParams voteproof.AlgebraicParameters
	algebraicParams.GFF = fieldGroupParams
	algebraicParams.GEC = curveGroupParams

	rpParams, err := voteproof.Setup(choiceLength, challengeLength, uint16(curveGroupParams.N.BitLen()),
		candidateStart, candidateEnd, algebraicParams)
	if err != nil {
		return PublicParameters{}, err
	}

	var pp PublicParameters
	pp.FFGroupParams = fieldGroupParams
	pp.ECGroupParams = curveGroupParams
	pp.EGPK = pp.FFGroupParams.H
	pp.candidateMin = candidateStart
	pp.candidateMax = candidateEnd
	pp.BPParams = bpParams
	pp.RPParams = rpParams

	return pp, nil
}

func main() {
	P256k1Group := group.SecP256k1()
	P256Group := group.P256()
	P384Group := group.P384()
	R255Group := group.Ristretto255()

	groups := []group.Group{P256k1Group, R255Group, P256Group, P384Group}

	sepLen := 60
	iterCount := 1000

	for i, g := range groups {
		if i != 0 {
			fmt.Print("\n")
		}
		fmt.Println(strings.Repeat("=", sepLen))
		fmt.Println("Generating public parameters for group:", g.Name())
		pp, err := setup(g)
		if err != nil {
			fmt.Println("Skipping execution for", g.Name(), "due to", err)
			continue
		}

		success := true
		var castTotal time.Duration = 0
		var bpVerTotal time.Duration = 0
		var rpVerTotal time.Duration = 0

		for j := 0; j < iterCount; j++ {

			vote, elapsed := castVote(pp)
			castTotal += elapsed

			verify, times := verifyVote(vote, pp.RPParams)

			bpVerTotal += times[0]
			rpVerTotal += times[1]
			success = success && verify
		}

		fmt.Println(strings.Repeat("-", sepLen))
		fmt.Println("Vote casting")

		fmt.Println("Prove time:", castTotal/time.Duration(iterCount))

		fmt.Println(strings.Repeat("-", sepLen))
		fmt.Println("Vote verification")

		bpAvg := bpVerTotal / time.Duration(iterCount)
		rpAvg := rpVerTotal / time.Duration(iterCount)

		fmt.Println("Verify time BP:", bpAvg)
		fmt.Println("Verify time RP:", rpAvg)
		fmt.Println("Verify time total:", bpAvg+rpAvg)

		fmt.Println(strings.Repeat("-", sepLen))
		fmt.Println("Votes were correctly formed:", success)
		fmt.Println(strings.Repeat("=", sepLen))
	}
}
