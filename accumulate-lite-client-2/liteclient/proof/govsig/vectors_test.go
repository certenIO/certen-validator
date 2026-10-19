// Copyright 2026 Certen Protocol

package govsig_test

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
)

const vectorDir = "testdata/sigtypes"

// Every shared conformance vector reaches the verdict it states under Accumulate's own Verify, and the manifest pins the
// files by hash. The TypeScript verifier runs byte-identical copies of the same files.
func TestSigtypeVectorsAreJudgedAsStated(t *testing.T) {
	vs, m, err := sigfixture.LoadVectors(vectorDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != m.Count || len(vs) < 100 {
		t.Fatalf("%d vectors loaded, the manifest pins %d", len(vs), m.Count)
	}
	for _, v := range vs {
		if err := sigfixture.Check(v); err != nil {
			t.Error(err)
		}
	}
}

// The vectors cover what Phase B item 7 names, for every accepted type.
func TestSigtypeVectorCoverage(t *testing.T) {
	vs, m, err := sigfixture.LoadVectors(vectorDir)
	if err != nil {
		t.Fatal(err)
	}
	if m.Sources[sigfixture.SourceKermit] != 4 || m.Sources[sigfixture.SourceLocal] == 0 {
		t.Fatalf("sources %v: the Kermit-delivered btc and ecdsaSha256 (and the judgments on them) must be present and labelled", m.Sources)
	}
	have := map[string]bool{}
	for _, v := range vs {
		have[v.ID] = true
	}
	for _, ty := range govsig.AcceptedKeyTypes() {
		for _, want := range []string{"valid/direct", "valid/delegated-1", "valid/delegated-2", "adversarial/wrong-transaction",
			"adversarial/flipped-bit", "adversarial/wrong-key-on-page"} {
			if id := ty.String() + "/" + want; !have[id] {
				t.Errorf("missing vector %s", id)
			}
		}
	}
	for _, id := range []string{"btc/kermit/case-k", "ecdsaSha256/kermit/northfield-inspection", "ed25519/adversarial/s-plus-l",
		"ecdsaSha256/adversarial/brainpool-key", "rsaSha256/adversarial/pkix-key", "typedData/adversarial/different-transaction",
		"typedData/adversarial/chain-id-1", "ed25519/valid/delegated-20", "ed25519/adversarial/delegated-21", "eth/adversarial/der-after-baikonur",
		"eth/valid/v1-der-before-activation", "non-key/authority", "non-key/delegated-authority", "ed25519/valid/reject-vote",
		"ecdsaSha256/valid/high-s", "btc/valid/lax-der-trailing-bytes", "label-swap/ed25519-bytes-as-ecdsaSha256", "label-swap/ecdsa-bytes-as-ed25519",
		"ecdsaSha256/gate/before-activation", "typedData/gate/before-activation", "rsaSha256/gate/no-location"} {
		if !have[id] {
			t.Errorf("missing vector %s", id)
		}
	}
	// every Kermit-delivered signature is a type Accumulate defines as a key signature
	for _, v := range vs {
		if v.Source != sigfixture.SourceKermit {
			continue
		}
		if _, class := govsig.Classify(v.Type); class != govsig.ClassKey {
			t.Errorf("%s: a Kermit-delivered vector of type %s", v.ID, v.Type)
		}
	}
}

// A vector file edited by a byte is refused by the manifest.
func TestSigtypeManifestPinsTheFiles(t *testing.T) {
	_, m, err := sigfixture.LoadVectors(vectorDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := sigfixture.ManifestHash(m.Files); got != m.Hash {
		t.Fatalf("manifest hash %s, files hash to %s", m.Hash, got)
	}
	tampered := append([]sigfixture.ManifestFile(nil), m.Files...)
	tampered[0].SHA256 = strings.Repeat("0", 64)
	if sigfixture.ManifestHash(tampered) == m.Hash {
		t.Fatal("changing a file hash must change the manifest hash")
	}
}
