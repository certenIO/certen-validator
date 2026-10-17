// Copyright 2026 Certen Protocol

package govsig_test

import (
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
)

// manifest.json (hash 032b15bd...) pins the first 154 vectors and is never edited; the suites that pin it keep passing.
// manifest2.json adds kermit2.json - signatures Kermit delivered for live CERTEN intents written by cmd/sigtypelive
// (RB8 phase D) - and is what the Kermit-delivered live set is judged under.
const (
	manifestV1Hash = "032b15bd27254856c05ca104d1aa16e73eb0fcb8b1136abf98bbe0ab5f80579c"
	manifestV2     = "manifest2.json"
)

// Every vector under manifest2.json, the Kermit-delivered live ones included, reaches the verdict it states under
// Accumulate's own Verify, and both manifests pin their files by hash.
func TestSigtypeLiveVectorsAreJudgedAsStated(t *testing.T) {
	vs, m, err := sigfixture.LoadVectorsFrom(vectorDir, manifestV2)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != m.Count || len(vs) < 154+10 {
		t.Fatalf("%d vectors loaded under manifest2, it pins %d (the 154 earlier ones plus the live set)", len(vs), m.Count)
	}
	for _, v := range vs {
		if err := sigfixture.Check(v); err != nil {
			t.Error(err)
		}
	}
}

// manifest2 extends manifest: the old manifest and its hash are byte-for-byte what the earlier suites pin, and manifest2
// lists the same three files with the same hashes before its own.
func TestSigtypeManifestV2ExtendsV1(t *testing.T) {
	_, m1, err := sigfixture.LoadVectors(vectorDir)
	if err != nil {
		t.Fatal(err)
	}
	if m1.Hash != manifestV1Hash {
		t.Fatalf("manifest.json's hash is %s, it is pinned at %s and must never change", m1.Hash, manifestV1Hash)
	}
	_, m2, err := sigfixture.LoadVectorsFrom(vectorDir, manifestV2)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Format == m1.Format || m2.Hash == m1.Hash {
		t.Fatalf("manifest2 must carry its own format tag and hash (%s %s)", m2.Format, m2.Hash)
	}
	if len(m2.Files) != len(m1.Files)+1 {
		t.Fatalf("manifest2 pins %d files, want manifest's %d plus kermit2.json", len(m2.Files), len(m1.Files))
	}
	for i, f := range m1.Files {
		if m2.Files[i] != f {
			t.Errorf("manifest2 file %d is %+v, manifest.json pins %+v", i, m2.Files[i], f)
		}
	}
	if last := m2.Files[len(m2.Files)-1]; last.Name != "kermit2.json" {
		t.Errorf("manifest2's last file is %s, want kermit2.json", last.Name)
	}
	if m2.Sources[sigfixture.SourceKermit] <= m1.Sources[sigfixture.SourceKermit] {
		t.Errorf("manifest2 counts %d Kermit-delivered vectors, manifest.json already counts %d", m2.Sources[sigfixture.SourceKermit], m1.Sources[sigfixture.SourceKermit])
	}
}

// The live set has, for every key-signature type Accumulate accepts and for a delegated ecdsaSha256, one signature Kermit
// delivered that is accepted - with its binary encoding, the JSON the network served, the transaction and the block it was
// recorded in - and a wrong-page sibling that is refused.
func TestSigtypeLiveVectorsCoverEveryAcceptedTypeAndDelegation(t *testing.T) {
	vs, _, err := sigfixture.LoadVectorsFrom(vectorDir, manifestV2)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]sigfixture.Vector{}
	for _, v := range vs {
		byID[v.ID] = v
	}
	live := []string{"delegated-ecdsaSha256"}
	for _, ty := range govsig.AcceptedKeyTypes() {
		live = append(live, ty.String())
	}
	for _, name := range live {
		v, ok := byID[name+"/kermit2/live"]
		if !ok {
			t.Errorf("no live vector for %s", name)
			continue
		}
		if v.Source != sigfixture.SourceKermit || v.Kind != "valid" || v.Expect.Verdict != "accepted" {
			t.Errorf("%s: source %q kind %q verdict %q, want a Kermit-delivered valid vector", v.ID, v.Source, v.Kind, v.Expect.Verdict)
		}
		if len(v.SignatureJSON) == 0 || v.Transaction == "" || v.Where == nil || v.Where.Block <= 0 || v.Page == nil || len(v.Page.Entries) == 0 {
			t.Errorf("%s: a live vector carries the served JSON, the transaction, the recording block and the signer page", v.ID)
		}
		w, ok := byID[name+"/kermit2/wrong-page"]
		if !ok || w.Expect.Verdict != "refused:key_not_on_page" {
			t.Errorf("%s: missing the wrong-page sibling, or it is not refused as key_not_on_page", name)
		}
		if name == "delegated-ecdsaSha256" && (len(v.Expect.Delegators) != 1 || v.Type != "ecdsaSha256") {
			t.Errorf("%s: the delegated case must be an ecdsaSha256 key behind one delegating page, got type %s delegators %v", v.ID, v.Type, v.Expect.Delegators)
		}
	}
}
