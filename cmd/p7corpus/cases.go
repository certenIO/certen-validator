package main

// The corpus, as this program understands it.
//
// The shapes come from scripts/phase7_corpus/corpus.json, which provision.py
// writes from what it actually observed on chain rather than from what it
// intended to build. This file reads that file; it does not restate it. The one
// thing stated here is which page each named key is expected to sit on, because
// that is the claim the key check tests and a claim has to be written down
// somewhere to be testable.

import (
	"encoding/json"
	"fmt"
	"sort"
)

// caseSpec is the union of the fields provision.py emits across the cases. Each
// case fills in the ones its shape has; the rest stay zero.
type caseSpec struct {
	Case          string   `json:"case"`
	Shape         string   `json:"shape"`
	Status        string   `json:"status"`
	ADI           string   `json:"adi"`
	Page          string   `json:"page"`
	SigningPage   string   `json:"signing_page"`
	Chain         []string `json:"chain"`
	Cycle         []string `json:"cycle"`
	Depth         int      `json:"depth"`
	Threshold     int      `json:"threshold"`
	DelegateBook  string   `json:"delegate_book"`
	Principal     string   `json:"principal"`
	PrincipalPage string   `json:"principal_page"`
	Delegate      string   `json:"delegate"`
	KeyNames      []string `json:"key_names"`
}

func parseCases(raw map[string]json.RawMessage) (map[string]caseSpec, error) {
	out := make(map[string]caseSpec, len(raw))
	for name, msg := range raw {
		var cs caseSpec
		if err := json.Unmarshal(msg, &cs); err != nil {
			return nil, fmt.Errorf("case %s: %w", name, err)
		}
		out[name] = cs
	}
	return out, nil
}

func sortedCaseNames(cases map[string]caseSpec) []string {
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// corpusKeyPages says, for each named key, the page it must appear on.
//
// These are assertions, not lookups: the key check fails if the chain disagrees,
// which is the only way to catch a seed that derives differently in Go than it
// did in the Python that minted it.
func corpusKeyPages(raw map[string]json.RawMessage) map[string]string {
	cases, err := parseCases(raw)
	if err != nil {
		fatal("parse corpus manifest: %v", err)
	}

	want := map[string]string{}
	for _, name := range sortedCaseNames(cases) {
		cs := cases[name]
		switch name {
		case "B":
			// All three keys sit on the single 2-of-3 page.
			for _, k := range cs.KeyNames {
				want[k] = cs.Page
			}
		case "C", "E", "G":
			// delegation_chain() creates every book in the chain with the SAME
			// key, so the one key is on the innermost signing page.
			want[cs.KeyNames[0]] = cs.SigningPage
		case "D":
			// d1 and d2 are direct entries on the 2-of-3 page; dd1 is the key of
			// the delegate book, so it lives on that book's first page.
			want["d1"] = cs.Page
			want["d2"] = cs.Page
			want["dd1"] = cs.DelegateBook + "/1"
		case "H":
			want[cs.KeyNames[0]] = cs.Cycle[0] + "/1"
		case "F":
			want["f1"] = cs.PrincipalPage
			want["f2"] = cs.DelegateBook + "/1"
		case "K":
			want[cs.KeyNames[0]] = cs.Page
		}
	}
	return want
}

// caseAPrincipal is the 1-of-1 ADI every one of the 400 production proofs used.
// It is not in corpus.json because provision.py did not create it; it is in the
// corpus because it is the shape that must not regress.
const caseAPrincipal = "acc://certen-kermit-12.acme"
