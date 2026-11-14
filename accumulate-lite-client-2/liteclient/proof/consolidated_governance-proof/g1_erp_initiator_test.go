// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// DAX-1G (G-83, DAX-G3): the erp-initiator pattern (decision 0042 of the transaction-controls lab) through the PRODUCTION G1
// evidence builder, replayed from the exact exchanges recorded off Kermit (testdata/g1_erp_initiator, recorded by
// g1_record_erp_test.go): the principal is the customer's /data, the transaction is initiated by a page of a SEPARATE identity
// that is no authority of anything (`<customer>-erp`), and the customer's own authority page votes afterwards.
//
// The intent declares the erp page as its signer (the api-bridge builds required_key_page from the signer key page the gateway
// passes, and the gateway passes the submitter identity's page: g7's own blob 0 reads required_key_book
// acc://dax1-probe-g7-erp.acme/book, required_key_page acc://dax1-probe-g7-erp.acme/book/1), so G1 is asked about the erp page.

type erpInitiatorFixture struct {
	name        string
	description string
	account     string
	txHash      string
	keyPage     string
	// initiatorPage is the page of the initiator identity (the declared signer); authorityPage the page of the principal's own book that voted.
	initiatorPage string
	authorityPage string
	// The partitions the network's routing table sends the principal and the declared page to (as read on 2026-11-14).
	principalPartition string
	pagePartition      string
	// How the ordering of each of the two signatures before execution was established (g1_timing_basis.go): the erp page signs first, the
	// principal's authority page after.
	erpBasis       string
	authorityBasis string
}

var erpInitiatorFixtures = []erpInitiatorFixture{
	{
		name: "erp_initiator_g7",
		description: "Kermit dax1-probe-g7 (DAX-1 probe g7, 2026-11-11): a single-leg intent on acc://dax1-probe-g7.acme/data whose blob 0 declares " +
			"required_key_book acc://dax1-probe-g7-erp.acme/book and required_key_page acc://dax1-probe-g7-erp.acme/book/1; the erp page " +
			"signs first (ed25519) and pays, the identity's own page 1 (an authority of the principal) signs after",
		account:       "acc://dax1-probe-g7.acme/data",
		txHash:        "488396f128eab23618e3a0a08a30373d33b4c467a0c0d6d06d84aeffed002936",
		keyPage:       "acc://dax1-probe-g7-erp.acme/book/1",
		initiatorPage: "acc://dax1-probe-g7-erp.acme/book/1",
		authorityPage: "acc://dax1-probe-g7.acme/book/1",
		// The principal and the erp page both route to bvn1 (the routing table: g1_frame_report_test.go, evidence/frame-report-live.txt), so
		// EXEC_MBI and the page's blocks count one chain: this proof never had a frame to get wrong.
		principalPartition: "bvn1", pagePartition: "bvn1",
		// One clock: the erp page stands for the principal (as in every proof before G-85), its own signature is compared with EXEC_MBI and the
		// authority page, another identity, is conservatively declared cross-partition.
		erpBasis: TimingBasisLocalOrdering, authorityBasis: TimingBasisExecutionInclusion,
	},
	{
		name: "erp_initiator_r6a",
		description: "Kermit dax1-r6a (DAX-1 round 6, 2026-11-13, G-83 live probe, refused by the validators with `did not exist at block 16972068: its genesis " +
			"is at block 16981650`, G-85): a single-leg intent on acc://dax1-r6a.acme/data (bvn3) whose blob 0 declares required_key_book " +
			"acc://dax1-r6a-erp.acme/book and required_key_page acc://dax1-r6a-erp.acme/book/1 (bvn2, another partition); the erp page signs first " +
			"(ed25519) and pays, the identity's own page 1 (an authority of the principal) signs after",
		account:       "acc://dax1-r6a.acme/data",
		txHash:        "e965cf4ccb51a6f55eb5327ec9fb2c56a591de8c992778694cf6bb0cd9ca8ca3",
		keyPage:       "acc://dax1-r6a-erp.acme/book/1",
		initiatorPage: "acc://dax1-r6a-erp.acme/book/1",
		authorityPage: "acc://dax1-r6a.acme/book/1",
		// The erp page is on ANOTHER partition than the principal: its blocks (genesis 16981650) and the principal's EXEC_MBI (16972068) are
		// counters of two different chains.
		principalPartition: "bvn3", pagePartition: "bvn2",
		// Two clocks: EXEC_MBI is the principal's, so the authority page (the principal's identity) is compared with it and the erp page is not.
		erpBasis: TimingBasisExecutionInclusion, authorityBasis: TimingBasisLocalOrdering,
	},
}

// erpNetwork is Kermit's network-status answer as recorded (testdata/g1_erp_initiator/network_status_kermit.json, the exact bytes): the routing
// table the production proof reads from the live endpoint (G1Layer.networkInfo) to learn which partition an account is on.
func erpNetwork(t *testing.T) *govsig.Network {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "g1_erp_initiator", "network_status_kermit.json"))
	if err != nil {
		t.Fatalf("recorded network-status: %v", err)
	}
	n, err := govsig.ParseNetworkStatus(raw)
	if err != nil {
		t.Fatalf("recorded network-status: %v", err)
	}
	return n
}

// replayErpLayer is a G1 layer over the fixture's recorded exchanges, with the recorded routing table in place of the live read.
func replayErpLayer(t *testing.T, fx erpInitiatorFixture) (*G1Layer, *replayClient) {
	t.Helper()
	capture := loadErpCapture(t, fx)
	rc := newReplayClient(t, capture)
	am, err := NewArtifactManager(t.TempDir())
	if err != nil {
		t.Fatalf("artifact manager: %v", err)
	}
	g1 := NewG1Layer(rc, am, "")
	g1.network = erpNetwork(t)
	return g1, rc
}

func loadErpCapture(t *testing.T, fx erpInitiatorFixture) *recordedCapture {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "g1_erp_initiator", fx.name+".json.gz"))
	if err != nil {
		t.Fatalf("recorded capture %s: %v", fx.name, err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	var capture recordedCapture
	if err := json.Unmarshal(raw, &capture); err != nil {
		t.Fatalf("recorded capture %s is not JSON: %v", fx.name, err)
	}
	if len(capture.Exchanges) == 0 || capture.TxHash != fx.txHash || capture.Account != fx.account || capture.KeyPage != fx.keyPage {
		t.Fatalf("capture %s is for %s %s %s, not the fixture's", fx.name, capture.Account, capture.TxHash, capture.KeyPage)
	}
	return &capture
}

func proveErpReplayed(t *testing.T, fx erpInitiatorFixture) (*G1Result, *replayClient) {
	t.Helper()
	g1, rc := replayErpLayer(t, fx)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, err := g1.ProveG1(ctx, G1Request{
		G0Request: G0Request{Account: fx.account, TxHash: fx.txHash, Chain: "main"}, KeyPage: fx.keyPage})
	if err != nil {
		t.Fatalf("G1 over the live erp-initiated transaction must hold: %v", err)
	}
	rc.requireNoUnrecorded(t)
	return res, rc
}

// The vote evidence the production builder emits for the fixture, as the intent certificate carries it (govvote.Evidence, JSON). The
// golden is read by the validators' binding tests (pkg/intentcert, the module this one cannot import): the chain of evidence is
// capture -> this builder -> golden -> GoverningFactsFromVoteEvidence. Written by TestWriteG1ErpInitiatorVoteEvidenceGolden
// (build tag g1record) from the REPLAY, so it needs no network.
func erpVoteEvidenceGoldenPath(fx erpInitiatorFixture) string {
	return filepath.Join("testdata", "g1_erp_initiator", fx.name+".vote_evidence.json")
}

func marshalVoteEvidence(t *testing.T, res *G1Result) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(res.VoteEvidence); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// G1 is asked about the erp page; its signature routes collect the erp page's signature set (the initiating signature) and the
// principal's authority pages' sets (the vote's key signature), so the intent's own vote evidence holds BOTH: DAX-G3 settled for
// the facts half of the binding (the binding's own reader is run over the golden in pkg/intentcert).
func TestG1ErpInitiator_VoteEvidenceHoldsTheInitiatingSignature(t *testing.T) {
	for _, fx := range erpInitiatorFixtures {
		t.Run(fx.name, func(t *testing.T) {
			res, _ := proveErpReplayed(t, fx)
			st := res.SignatureRouteStatus
			if st == nil || !st.RoutesAgreed || st.Degraded {
				t.Fatalf("both routes must run, agree and not degrade: %+v", st)
			}
			ev := res.VoteEvidence
			if ev == nil {
				t.Fatal("the proof carries no vote evidence")
			}
			raw, err := hex.DecodeString(ev.Transaction)
			if err != nil {
				t.Fatal(err)
			}
			txn := new(protocol.Transaction)
			if err := txn.UnmarshalBinary(raw); err != nil {
				t.Fatal(err)
			}
			// Which signatures the route collected, by signer; and which of them initiated the transaction.
			signers := map[string]int{}
			initiating := map[string]int{}
			for _, s := range ev.Signatures {
				signers[normalizeAccURL(s.Fact.Signer)]++
				b, err := hex.DecodeString(s.Signature)
				if err != nil {
					t.Fatal(err)
				}
				sig, err := protocol.UnmarshalSignature(b)
				if err != nil {
					t.Fatal(err)
				}
				if did, _ := protocol.SignatureDidInitiate(sig, txn.Header.Initiator[:], nil); did {
					initiating[normalizeAccURL(s.Fact.Signer)]++
				}
			}
			t.Logf("vote evidence signatures by signer: %v; initiating: %v", signers, initiating)
			if signers[normalizeAccURL(fx.initiatorPage)] == 0 {
				t.Fatalf("the vote evidence holds no signature of the initiating page %s (signers %v)", fx.initiatorPage, signers)
			}
			if signers[normalizeAccURL(fx.authorityPage)] == 0 {
				t.Fatalf("the vote evidence holds no signature of the authority page %s (signers %v)", fx.authorityPage, signers)
			}
			if len(initiating) != 1 || initiating[normalizeAccURL(fx.initiatorPage)] != 1 {
				t.Fatalf("the signatures that initiated the transaction are %v, want exactly one, on %s", initiating, fx.initiatorPage)
			}
			golden, err := os.ReadFile(erpVoteEvidenceGoldenPath(fx))
			if err != nil {
				t.Fatalf("the vote evidence golden: %v", err)
			}
			if got := marshalVoteEvidence(t, res); !bytes.Equal(got, golden) {
				t.Fatalf("the vote evidence the builder emits differs from the golden %s (%d bytes, golden %d): regenerate it with -tags g1record -run TestWriteG1ErpInitiatorVoteEvidenceGolden and review the change", erpVoteEvidenceGoldenPath(fx), len(got), len(golden))
			}
		})
	}
}
