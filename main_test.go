package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/takakv/msc-poc/group"
	"os"
	"testing"
)

func generateAndMarshal(pp PublicParameters) {
	vote := castVote(pp)

	jsonData, _ := json.Marshal(vote)
	fmt.Println(string(jsonData))

	verify := verifyVote(vote, pp.RPParams)
	if !verify {
		fmt.Println("failed to verify generated data")
	}
}

func unmarshalAndVerify(b []byte, pp PublicParameters) error {
	dataset, err := BallotDataUnmarshalJSON(b, pp)
	if err != nil {
		return err
	}

	verify := verifyVote(dataset, pp.RPParams)
	if !verify {
		return errors.New("failed to verify data")
	}

	return nil
}

func TestTestData(t *testing.T) {
	p256data, err := os.ReadFile("./testdata/P256rp.json")
	if err != nil {
		t.Fatal(err)
	}

	p384data, err := os.ReadFile("./testdata/P384rp.json")
	if err != nil {
		t.Fatal(err)
	}

	P256Group := group.P256()
	P384Group := group.P384()

	groups := []group.Group{P256Group, P384Group}
	data := [][]byte{p256data, p384data}

	for i, g := range groups {
		pp, err := setup(g)
		if err != nil {
			t.Error(err)
		}

		err = unmarshalAndVerify(data[i], pp)
		if err != nil {
			t.Error(err)
		}
	}
}
