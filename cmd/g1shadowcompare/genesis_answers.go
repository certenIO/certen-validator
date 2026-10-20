package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// genesisAnswers are recorded answers of a Directory to the genesis question - the receipt from the pinned incarnation's genesis root chain anchor
// to a certified root chain anchor, at that anchor's RootChainIndex - in the file format cmd/proofv2linkprobe writes (the `links` member of
// pkg/consensus/testdata/g1_live_anchored/links.json).
//
// Every evidence 2.1 document needs its genesis link (RB9-F6, F-VE-2 option b). A fixture captured before that carries none, and its bytes are
// frozen; the comparator can be GIVEN the recorded answer to the question the document leaves open (-genesis-answers), and says in the result that
// the link came from there. A document without the link and without a recorded answer is not completed by anything: it ends
// certify_link_missing{genesis}, a verification failure by name.
type genesisAnswers struct {
	path  string
	links []genesisAnswer
}

type genesisAnswer struct {
	Prev    string `json:"prev"`
	Height  uint64 `json:"height"`
	Receipt string `json:"receipt"`
}

func loadGenesisAnswers(path string) (*genesisAnswers, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("-genesis-answers: %w", err)
	}
	var f struct {
		Links []genesisAnswer `json:"links"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("-genesis-answers %s: %w", path, err)
	}
	return &genesisAnswers{path: path, links: f.Links}, nil
}

// linkFor is the recorded answer to the genesis question of ev: the receipt asked from genesis at the RootChainIndex of the last run of its
// certification. The receipt is only attached; the verifier judges it (its start, its end and its path).
func (a *genesisAnswers) linkFor(ev *proofv2.Evidence, genesis [32]byte) (string, bool) {
	if a == nil || len(ev.Certify) == 0 {
		return "", false
	}
	height, _, err := proofv2.RunAnchor(ev.Certify[len(ev.Certify)-1])
	if err != nil {
		return "", false
	}
	prev := hex.EncodeToString(genesis[:])
	for _, l := range a.links {
		if l.Prev == prev && l.Height == height && l.Receipt != "" {
			return l.Receipt, true
		}
	}
	return "", false
}
