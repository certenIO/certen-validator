// Copyright 2026 Certen Protocol

package govvote

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The fixtures are the evidence the CLI emitted, live on Kermit, for two transactions, beside the vote it computed:
//
//	evidence_delegated_case_c.json   acc://certen-p7c.acme/data f25a6dfd... - book/1 decides through a delegate
//	                                 page of book2, so the evidence carries a delegated vote and two page histories
//	evidence_phasec_98e40472.json    acc://rb4-phase-c-09282125.acme/data 98e40472... - the RB4 Phase C intent
type fixture struct {
	Evidence      *Evidence       `json:"evidence"`
	Authorization json.RawMessage `json:"authorization"`
}

var evidenceFixtures = []string{"evidence_delegated_case_c.json", "evidence_phasec_98e40472.json"}

func loadFixture(t *testing.T, name string) fixture {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Evidence == nil || len(f.Authorization) == 0 {
		t.Fatalf("%s carries no evidence or no vote", name)
	}
	return f
}

func sameVote(t *testing.T, got *AccountVote, want json.RawMessage) bool {
	t.Helper()
	g, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var w interface{}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatal(err)
	}
	wb, _ := json.Marshal(w)
	var gv interface{}
	_ = json.Unmarshal(g, &gv)
	gb, _ := json.Marshal(gv)
	return string(gb) == string(wb)
}

// The evidence the CLI emitted verifies offline and reaches exactly the vote the CLI computed.
func TestEvidenceLiveReproducesTheVote(t *testing.T) {
	for _, name := range evidenceFixtures {
		t.Run(name, func(t *testing.T) {
			f := loadFixture(t, name)
			vote, err := VerifyEvidence(context.Background(), f.Evidence)
			if err != nil {
				t.Fatalf("the live evidence does not verify: %v", err)
			}
			if !vote.Satisfied {
				t.Fatalf("the live vote is not satisfied")
			}
			if !sameVote(t, vote, f.Authorization) {
				t.Fatalf("the evidence reaches a different vote than the CLI computed")
			}
		})
	}
}

func flipHex(h string, at int) string {
	b, _ := hex.DecodeString(h)
	if at < 0 {
		at += len(b)
	}
	b[at] ^= 0x01
	return hex.EncodeToString(b)
}

// Every item the vote read is bound: altering any of them is refused by name, never re-evaluated into a vote.
func TestEvidenceTamperIsRefused(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(ev *Evidence)
	}{
		{"version", func(ev *Evidence) { ev.Version = "certen:govvote-evidence:v0" }},
		{"governed transaction swapped for a page's", func(ev *Evidence) { ev.Transaction = ev.Pages[0].Genesis.Transaction }},
		{"signature bytes", func(ev *Evidence) { ev.Signatures[0].Signature = flipHex(ev.Signatures[0].Signature, -1) }},
		{"signature key hash", func(ev *Evidence) { ev.Signatures[0].Fact.KeyHash = strings.Repeat("ab", 32) }},
		{"signature signer version", func(ev *Evidence) { ev.Signatures[0].Fact.Version++ }},
		{"signature signer", func(ev *Evidence) { ev.Signatures[0].Fact.Signer = "acc://other.acme/book/1" }},
		{"signature vote", func(ev *Evidence) { ev.Signatures[0].Fact.Vote = protocol.VoteTypeReject }},
		{"signature path", func(ev *Evidence) { ev.Signatures[0].Fact.Path = []string{"acc://other.acme/book/1"} }},
		{"signature block", func(ev *Evidence) { ev.Signatures[0].Fact.Block-- }},
		{"signature receipt anchor", func(ev *Evidence) { ev.Signatures[0].Receipt.Anchor = strings.Repeat("00", 32) }},
		{"signature receipt block", func(ev *Evidence) { ev.Signatures[0].Receipt.LocalBlock++ }},
		{"recorded vote origin", func(ev *Evidence) { ev.Votes[0].Fact.Origin = "acc://other.acme/book/1" }},
		{"recorded vote value", func(ev *Evidence) { ev.Votes[0].Fact.Vote = protocol.VoteTypeReject }},
		{"recorded vote authority", func(ev *Evidence) { ev.Votes[0].Fact.Authority = "acc://other.acme/book" }},
		{"recorded vote block", func(ev *Evidence) { ev.Votes[0].Fact.Block++ }},
		{"recorded vote bytes", func(ev *Evidence) { ev.Votes[0].Signature = ev.Signatures[0].Signature }},
		{"page entry dropped", func(ev *Evidence) { ev.Pages[0].Events = ev.Pages[0].Events[1:] }},
		{"page entries swapped", func(ev *Evidence) {
			e := ev.Pages[0].Events
			e[0].Transaction, e[1].Transaction = e[1].Transaction, e[0].Transaction
		}},
		{"page entry transaction", func(ev *Evidence) {
			ev.Pages[0].Events[0].Transaction = ev.Pages[0].Genesis.Transaction
		}},
		{"page entry block", func(ev *Evidence) { ev.Pages[0].Events[0].LocalBlock++ }},
		{"page entry index", func(ev *Evidence) { ev.Pages[0].Events[0].Index = 7 }},
		{"page entry receipt path", func(ev *Evidence) {
			r := &ev.Pages[0].Events[0].Receipt
			r.Entries[0].Hash = flipHex(r.Entries[0].Hash, 0)
		}},
		{"genesis transaction", func(ev *Evidence) { ev.Pages[0].Genesis.Transaction = ev.Pages[0].Events[0].Transaction }},
		{"genesis index", func(ev *Evidence) { ev.Pages[0].Genesis.Index = 1 }},
		{"page chain length", func(ev *Evidence) { ev.Pages[0].Entries++ }},
		{"history missing", func(ev *Evidence) { ev.Pages = ev.Pages[:0] }},
	}
	for _, name := range evidenceFixtures {
		for _, c := range cases {
			t.Run(name+"/"+c.name, func(t *testing.T) {
				f := loadFixture(t, name)
				if len(f.Evidence.Pages[0].Events) < 2 {
					t.Fatalf("the fixture's first page has %d events; the tamper cases need two",
						len(f.Evidence.Pages[0].Events))
				}
				c.tamper(f.Evidence)
				vote, err := VerifyEvidence(context.Background(), f.Evidence)
				if err == nil {
					t.Fatalf("tampered evidence verified: satisfied=%v", vote.Satisfied)
				}
				t.Logf("refused: %v", err)
			})
		}
	}
}

// The delegated vote case C decides by is bound as tightly as a signature.
func TestEvidenceDelegatedVoteTamperIsRefused(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(ev *Evidence)
	}{
		{"arrival page", func(ev *Evidence) { ev.Arrivals[0].Fact.Page = "acc://certen-p7c.acme/book2/1" }},
		{"arrival path", func(ev *Evidence) { ev.Arrivals[0].Fact.Path = []string{"acc://other.acme/book/1"} }},
		{"arrival origin", func(ev *Evidence) { ev.Arrivals[0].Fact.Origin = "acc://certen-p7c.acme/book/1" }},
		{"arrival authority", func(ev *Evidence) { ev.Arrivals[0].Fact.Authority = "acc://certen-p7c.acme/book" }},
		{"arrival vote", func(ev *Evidence) { ev.Arrivals[0].Fact.Vote = protocol.VoteTypeReject }},
		{"arrival block", func(ev *Evidence) { ev.Arrivals[0].Fact.Block++ }},
		{"arrival bytes", func(ev *Evidence) { ev.Arrivals[0].Signature = ev.Votes[0].Signature }},
		{"delegate page history missing", func(ev *Evidence) {
			var keep []PageHistory
			for _, p := range ev.Pages {
				if !strings.Contains(p.Page, "book2") {
					keep = append(keep, p)
				}
			}
			ev.Pages = keep
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := loadFixture(t, "evidence_delegated_case_c.json")
			if len(f.Evidence.Arrivals) != 1 {
				t.Fatalf("case C carries %d delegated votes, want 1", len(f.Evidence.Arrivals))
			}
			c.tamper(f.Evidence)
			if vote, err := VerifyEvidence(context.Background(), f.Evidence); err == nil {
				t.Fatalf("tampered evidence verified: satisfied=%v", vote.Satisfied)
			} else {
				t.Logf("refused: %v", err)
			}
		})
	}
}

// Leaving a fact OUT is not detectable from the evidence alone - completeness rests on what the chain was read to
// hold (the known limit recorded in RUNLOG_RB4). What it cannot do is reach the same vote: the verifier compares the
// re-derived vote with the stored decision, so an omission that could matter is caught there.
func TestEvidenceOmissionChangesTheVote(t *testing.T) {
	for _, c := range []struct {
		name string
		file string
		drop func(ev *Evidence)
	}{
		{"signature", "evidence_phasec_98e40472.json", func(ev *Evidence) { ev.Signatures = nil }},
		{"recorded vote", "evidence_phasec_98e40472.json", func(ev *Evidence) { ev.Votes = nil }},
		{"delegated vote", "evidence_delegated_case_c.json", func(ev *Evidence) { ev.Arrivals = nil }},
		// The authority set is carried as G1 established it; re-deriving it offline from the account's own history
		// is RB4-F66 E2b. Changed here, it reaches another vote.
		{"authority set", "evidence_phasec_98e40472.json", func(ev *Evidence) {
			ev.Authorities = append(ev.Authorities, AccountAuthority{URL: "acc://other.acme/book"})
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := loadFixture(t, c.file)
			c.drop(f.Evidence)
			vote, err := VerifyEvidence(context.Background(), f.Evidence)
			if err == nil && sameVote(t, vote, f.Authorization) {
				t.Fatalf("dropping the %s still reaches the recorded vote", c.name)
			}
			if err != nil {
				t.Logf("refused: %v", err)
			} else {
				t.Logf("reaches a different vote (satisfied=%v)", vote.Satisfied)
			}
		})
	}
}

// ---- the initiator, from the initiating signature alone ----

func signedBy(t *testing.T, signer string) *protocol.ED25519Signature {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.ED25519Signature{PublicKey: pub, Signer: mustURL(t, signer), SignerVersion: 1, Timestamp: 1}
}

func initiatedTxn(t *testing.T, sig protocol.Signature) *protocol.Transaction {
	t.Helper()
	txn := &protocol.Transaction{Body: &protocol.UpdateKey{NewKeyHash: keyHash("next")}}
	txn.Header.Principal = mustURL(t, "acc://i.acme/book/1")
	copy(txn.Header.Initiator[:], sig.Metadata().Hash())
	return txn
}

func TestInitiatorOfKeySignature(t *testing.T) {
	sig := signedBy(t, "acc://i.acme/book/1")
	txn := initiatedTxn(t, sig)
	init, err := InitiatorOf(txn, sig)
	if err != nil {
		t.Fatal(err)
	}
	if init.Payer.String() != "acc://i.acme/book/1" {
		t.Fatalf("payer %v", init.Payer)
	}
	want := sha256.Sum256(sig.PublicKey)
	if hex.EncodeToString(init.KeyHash) != hex.EncodeToString(want[:]) {
		t.Fatalf("key hash %x, want %x", init.KeyHash, want)
	}
}

func TestInitiatorOfRefusesASignatureTheHeaderDoesNotCommitTo(t *testing.T) {
	sig := signedBy(t, "acc://i.acme/book/1")
	txn := initiatedTxn(t, sig)
	other := signedBy(t, "acc://i.acme/book/1")
	if _, err := InitiatorOf(txn, other); err == nil {
		t.Fatal("a signature the header does not commit to was accepted as the initiator")
	}
	if _, err := InitiatorOf(txn, nil); err == nil {
		t.Fatal("no signature was accepted as the initiator")
	}
}

func TestInitiatorOfLiteTokenAddressPaysAsItsIdentity(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	lid, err := protocol.LiteTokenAddress(pub, protocol.ACME, protocol.SignatureTypeED25519)
	if err != nil {
		t.Fatal(err)
	}
	sig := &protocol.ED25519Signature{PublicKey: pub, Signer: lid, SignerVersion: 1, Timestamp: 1}
	init, err := InitiatorOf(initiatedTxn(t, sig), sig)
	if err != nil {
		t.Fatal(err)
	}
	if !init.Payer.Equal(lid.RootIdentity()) {
		t.Fatalf("payer %v, want the lite identity %v", init.Payer, lid.RootIdentity())
	}
}

func TestInitiatorOfDelegatedSignatureCarriesNoKey(t *testing.T) {
	inner := signedBy(t, "acc://d.acme/book/1")
	sig := &protocol.DelegatedSignature{Signature: inner, Delegator: mustURL(t, "acc://i.acme/book/1")}
	init, err := InitiatorOf(initiatedTxn(t, sig), sig)
	if err != nil {
		t.Fatal(err)
	}
	if init.Payer.String() != "acc://d.acme/book/1" || init.KeyHash != nil {
		t.Fatalf("payer %v key %x; want the delegate page and no key", init.Payer, init.KeyHash)
	}
}

// ---- the genesis page, from the genesis transaction alone ----

func TestGenesisPageRefusesAGenesisOfAnotherPage(t *testing.T) {
	txn := &protocol.Transaction{Body: &protocol.CreateKeyBook{Url: mustURL(t, "acc://g.acme/book"),
		PublicKeyHash: keyHash("k")}}
	txn.Header.Principal = mustURL(t, "acc://g.acme")
	kp, err := GenesisPage("acc://g.acme/book/1", txn)
	if err != nil {
		t.Fatal(err)
	}
	if kp.Version != 1 || kp.AcceptThreshold != 0 || len(kp.Keys) != 1 {
		t.Fatalf("createKeyBook page: v%d threshold %d keys %d", kp.Version, kp.AcceptThreshold, len(kp.Keys))
	}
	for _, page := range []string{"acc://g.acme/book/2", "acc://g.acme/other/1"} {
		if _, err := GenesisPage(page, txn); err == nil {
			t.Fatalf("createKeyBook of acc://g.acme/book accepted as the genesis of %s", page)
		}
	}
	notGenesis := &protocol.Transaction{Body: &protocol.UpdateKey{NewKeyHash: keyHash("n")}}
	notGenesis.Header.Principal = mustURL(t, "acc://g.acme/book/1")
	if _, err := GenesisPage("acc://g.acme/book/1", notGenesis); err == nil {
		t.Fatal("an updateKey accepted as a page's genesis")
	}
}

func TestGenesisPageCreateKeyPage(t *testing.T) {
	txn := &protocol.Transaction{Body: &protocol.CreateKeyPage{Keys: []*protocol.KeySpecParams{
		{KeyHash: keyHash("a")}, {Delegate: mustURL(t, "acc://d.acme/book")}}}}
	txn.Header.Principal = mustURL(t, "acc://g.acme/book")
	kp, err := GenesisPage("acc://g.acme/book/2", txn)
	if err != nil {
		t.Fatal(err)
	}
	if kp.AcceptThreshold != 1 || len(kp.Keys) != 2 {
		t.Fatalf("createKeyPage page: threshold %d keys %d", kp.AcceptThreshold, len(kp.Keys))
	}
	txn.Header.Principal = mustURL(t, "acc://g.acme/other")
	if _, err := GenesisPage("acc://g.acme/book/2", txn); err == nil {
		t.Fatal("createKeyPage on another book accepted as the page's genesis")
	}
}
