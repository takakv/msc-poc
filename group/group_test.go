package group

import (
	"fmt"
	"math/big"
	"testing"
)

var RFC3526ModPGroup3072 = NewModPGroup(
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

var SecP256k1Group = SecP256k1()
var P384Group = P384()
var P256Group = P256()

var allGroups = []Group{
	RFC3526ModPGroup3072,
	// SecP256k1Group,
	P256Group,
	P384Group,
}

func TestGroup(t *testing.T) {
	const testTimes = 1 << 7
	for _, g := range allGroups {
		n := g.Name()
		// t.Run(n+"/Add", func(tt *testing.T) { testAdd(tt, testTimes, g) })
		t.Run(n+"/Neg", func(tt *testing.T) { testNeg(tt, testTimes, g) })
		// t.Run(n+"/Mul", func(tt *testing.T) { testMul(tt, testTimes, g) })
		// t.Run(n+"/MulGen", func(tt *testing.T) { testMulGen(tt, testTimes, g) })
		// t.Run(n+"/CMov", func(tt *testing.T) { testCMov(tt, testTimes, g) })
		// t.Run(n+"/CSelect", func(tt *testing.T) { testCSelect(tt, testTimes, g) })
		t.Run(n+"/Order", func(tt *testing.T) { testOrder(tt, testTimes, g) })
		t.Run(n+"/Set", func(tt *testing.T) { testSet(tt, g) })
		t.Run(n+"/MarshalBinary", func(tt *testing.T) { testMarshalBinary(tt, testTimes, g) })
		t.Run(n+"/MarshalJSON", func(tt *testing.T) { testMarshalJSON(tt, testTimes, g) })
		// t.Run(n+"/Scalar", func(tt *testing.T) { testScalar(tt, testTimes, g) })
	}
}

func testNeg(t *testing.T, testTimes int, g Group) {
	Q := g.Element()
	for i := 0; i < testTimes; i++ {
		P := g.Random()
		Q.Set(P)
		Q.Subtract(Q, P)
		got := Q.IsIdentity()
		want := true
		if got != want {
			t.Error("testNeg | Got:", got, "Wanted:", want)
		}
	}
}

func testOrder(t *testing.T, testTimes int, g Group) {
	I := g.Identity()
	Q := g.Element()
	minusOne := big.NewInt(-1)
	for i := 0; i < testTimes; i++ {
		P := g.Random()

		Q.Scale(P, minusOne)
		got := Q.Add(Q, P)
		want := I
		if !got.IsEqual(want) {
			t.Error("testOrder | Got:", got, "Wanted:", want)
		}
	}
}

func testSet(t *testing.T, g Group) {
	P := g.Random()
	Q := g.Element()
	Q.Set(P)
	if !Q.IsEqual(P) {
		t.Error("testSet | Got:", false, "Wanted:", true)
	}
}

func testMarshalBinary(t *testing.T, testTimes int, g Group) {
	I := g.Identity()
	got, err := I.MarshalBinary()
	if err != nil {
		t.Error("testMarshalBinary | I:", I)
	}

	II := g.Element()
	err = II.UnmarshalBinary(got)
	if err != nil || !I.IsEqual(II) {
		t.Error("testMarshalBinary | I:", I, "II:", II)
	}

	gotEl := g.Element()
	for i := 0; i < testTimes; i++ {
		x := g.Random()
		enc, err := x.MarshalBinary()
		if err != nil {
			t.Error(err)
		}

		err = gotEl.UnmarshalBinary(enc)
		if !x.IsEqual(gotEl) {
			t.Error("testMarshalBinary | Got:", gotEl, "Wanted:", x)
		}
	}
}

func testMarshalJSON(t *testing.T, testTimes int, g Group) {
	I := g.Identity()
	got, err := I.MarshalJSON()
	if err != nil {
		t.Error("testMarshalJSON | I:", I)
	}

	II := g.Element()
	err = II.UnmarshalJSON(got)
	if err != nil || !I.IsEqual(II) {
		fmt.Println(err)
		t.Error("testMarshalJSON | I:", I, "II:", II)
	}

	gotEl := g.Element()
	for i := 0; i < testTimes; i++ {
		x := g.Random()
		enc, err := x.MarshalJSON()
		if err != nil {
			t.Error(err)
		}

		fmt.Println(string(enc))

		err = gotEl.UnmarshalJSON(enc)
		if err != nil {
			t.Error(err)
			continue
		}

		if !x.IsEqual(gotEl) {
			t.Error("testMarshalJSON | Got:", gotEl, "Wanted:", x)
		}
	}
}

func TestNewElements(t *testing.T) {
	els := []struct {
		name string
		el   func(Group) Element
	}{
		{"identity", func(g Group) Element { return g.Identity() }},
		{"generator", func(g Group) Element { return g.Generator() }},
		{"random", func(g Group) Element { return g.Random() }},
	}

	g := SecP256k1Group // RFC3526ModPGroup3072
	for _, e := range els {
		t.Run(fmt.Sprintf("%s-%s", "ModPGroup", e.name), func(t *testing.T) {
			x := e.el(g)
			if x == nil {
				t.Error("new element")
			}
		})
	}
}

func TestMath(t *testing.T) {
	g := SecP256k1Group // RFC3526ModPGroup3072

	a := g.Element().BaseScale(big.NewInt(2))
	b := g.Element().Add(g.Generator(), g.Generator())
	ok := a.IsEqual(b)
	if ok != true {
		t.Error("doubling error")
	}

	a = g.Element().Add(a, g.Generator())
	b = g.Element().BaseScale(big.NewInt(3))
	ok = a.IsEqual(b)
	if ok != true {
		t.Error("error in adding or scaling")
	}

	e := g.Identity()
	r1 := g.Random()
	r2 := g.Random()
	e.Add(r1, r2)
	e.Subtract(e, r2)
	ok = e.IsEqual(r1)
	if ok != true {
		t.Error("error in subtracting")
	}
}
