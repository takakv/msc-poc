package main

import (
	"fmt"
	"github.com/0xdecaf/zkrp/crypto/p256"
	"github.com/takakv/msc-poc/algebra"
	"github.com/takakv/msc-poc/bulletproofs"
	"github.com/takakv/msc-poc/voteproof"
)
import "math/big"

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
	bigTwo  = big.NewInt(2)
)

type PublicParameters struct {
	FFGroupParams voteproof.FFGroupParameters
	ECGroupParams voteproof.ECGroupParameters
	PublicKey     ElGamalPublicKey
	BPParams      bulletproofs.BulletProofSetupParams
	RPParams      voteproof.ProofParams
	candidateMin  uint16
	candidateMax  uint16
	FFG           algebra.Group
	EGPK          algebra.Element
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

	print(RFC3526ModPGroup3072)

	// Safe prime oder of the field used for ElGamal encryption.
	ffOrder, _ := new(big.Int).SetString("5809605995369958062791915965639201402176612226902900533702900882779736177890990861472094774477339581147373410185646378328043729800750470098210924487866935059164371588168047540943981644516632755067501626434556398193186628990071248660819361205119793693985433297036118232914410171876807536457391277857011849897410207519105333355801121109356897459426271845471397952675959440793493071628394122780510124618488232602464649876850458861245784240929258426287699705312584509625419513463605155428017165714465363094021609290561084025893662561222573202082865797821865270991145082200656978177192827024538990239969175546190770645685893438011714430426409338676314743571154537142031573004276428701433036381801705308659830751190352946025482059931306571004727362479688415574702596946457770284148435989129632853918392117997472632693078113129886487399347796982772784615865232621289656944284216824611318709764535152507354116344703769998514148343807", 10)
	// Sophie-Germain prime order of the group of quadratic residues needed for semantic security.
	voteGroupOrder := new(big.Int).Div(new(big.Int).Sub(ffOrder, bigOne), bigTwo)
	voteGroupGenerator := big.NewInt(2)

	var egParams ElGamalParameters
	egParams.P = ffOrder
	egParams.Q = voteGroupOrder
	egParams.G = voteGroupGenerator

	// W.l.o.g. this secret is not known to any one party.
	var egPriv ElGamalPrivateKey
	egPriv.X = big.NewInt(13)

	var egPub ElGamalPublicKey
	egPub.ElGamalParameters = egParams
	egPub.Y = new(big.Int).Exp(egParams.G, egPriv.X, egParams.P)

	bpParams, _ := bulletproofs.Setup(65536)

	// Prime order of the group of elliptic curve points.
	curveOrder, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

	var fieldGroupParams voteproof.FFGroupParameters
	fieldGroupParams.FFG = RFC3526ModPGroup3072
	fieldGroupParams.F = egPub.P
	fieldGroupParams.N = egPub.Q
	fieldGroupParams.G = egPub.G
	fieldGroupParams.H = fieldGroupParams.FFG.Generator().BaseScale(egPriv.X)

	var curveGroupParams voteproof.ECGroupParameters
	curveGroupParams.N = curveOrder
	curveGroupParams.G = (*p256.P256)(bpParams.G)
	curveGroupParams.H = (*p256.P256)(bpParams.H)

	var algebraicParams voteproof.AlgebraicParameters
	algebraicParams.GFF = fieldGroupParams
	algebraicParams.GEC = curveGroupParams

	rpParams := voteproof.Setup(choiceLength, challengeLength, 253,
		candidateStart, candidateEnd, algebraicParams)

	var pp PublicParameters
	pp.FFGroupParams = fieldGroupParams
	pp.ECGroupParams = curveGroupParams
	pp.BPParams = bpParams
	pp.RPParams = rpParams
	pp.candidateMin = candidateStart
	pp.candidateMax = candidateEnd
	pp.FFG = RFC3526ModPGroup3072
	pp.EGPK = pp.FFG.Generator().BaseScale(egPriv.X)

	return pp
}

func main() {
	pp := setup()

	fmt.Println("Vote casting")
	vote := castVote(pp.candidateMin, pp.candidateMax,
		pp.BPParams, pp.RPParams, pp.EGPK, pp.FFG)

	fmt.Println()
	fmt.Println("Vote verification")
	verify := verifyVote(vote, pp.RPParams)

	fmt.Println()
	fmt.Println("Vote is correctly formed:", verify)
}
