// Copyright 2026 Certen Protocol

package consensus

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
	govproof "github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// budgetBuilder returns a function that builds the certificate of one live anchored fixture into a block whose Timestamp is padded by pad bytes
// (a free string the certificate never reads, so it moves the encoded block by exactly pad bytes and nothing else).
func budgetBuilder(t *testing.T) func(pad int) (*ValidatorBlock, error) {
	t.Helper()
	links := loadAnchoredLiveLinks(t)
	raw, err := os.ReadFile("../proof/testdata/incarnation/kermit.json")
	if err != nil {
		t.Fatal(err)
	}
	var inc govproof.IncarnationEvidence
	if err := json.Unmarshal(raw, &inc); err != nil {
		t.Fatal(err)
	}
	ir, err := inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	dir := "testdata/g1_live"
	var m struct {
		Archive string `json:"archive"`
		Cases   []struct {
			Name string `json:"name"`
			File string `json:"file"`
		} `json:"cases"`
	}
	mb, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatal(err)
	}
	f := new(anchoredLiveFixture)
	if err := json.Unmarshal(gunzipFile(t, filepath.Join(dir, m.Cases[0].File)), f); err != nil {
		t.Fatal(err)
	}
	f.Archive = gunzipFile(t, filepath.Join(dir, m.Archive))
	fx := &intentFixtureV3{intentFixture: f.intentFixture, ProofV2: f.ProofV2, Archive: f.Archive}
	ar, err := proofv2.UnmarshalArchive(f.Archive)
	if err != nil {
		t.Fatal(err)
	}
	anchored, err := proofv2.AnchorEvidence(context.Background(), v3Evidence(t, fx), ar, ir.Inputs, links)
	if err != nil {
		t.Fatal(err)
	}
	rf, reg := intentRegistry(t)
	spine := v3Spine(t, fx)
	activation := &ledger.G1ActivationRecord{Version: 1, Height: 100, ID: "g1-activation:rb9-f5-budget"}
	return func(pad int) (*ValidatorBlock, error) {
		vb := v3Block(t, fx, "validator-1")
		vb.Timestamp = strings.Repeat("t", pad)
		err := BuildIntentCertificate(vb, intentChain, reg, rf.keys[0], f.KeyPage, f.KeyBook, fx.record(t), f.VoteEvidence, f.ChainedProof, spine, activation, anchored)
		return vb, err
	}
}

func broadcastBytes(t *testing.T, vb *ValidatorBlock) int {
	t.Helper()
	b, err := json.Marshal(vb)
	if err != nil {
		t.Fatal(err)
	}
	return len(b)
}

// The pre-sign check is a decision on the bytes that will be broadcast: the three roots and the signature are counted at their final length (they
// are filled after the check), so a block whose broadcast encoding is exactly the limit passes and its broadcast bytes are inside the limit, a
// block one byte over is certificate_budget{size,limit} with the size it will have on the wire, and a refusal leaves no certificate on the block.
// Before the fix the roots (about 215 bytes with the 83 of gov_root_v3's key) were not counted, so a block up to 215 bytes over was signed and
// refused at broadcast.
func TestBudgetBuildIntentCertificateBoundaryIsTheBroadcastBytes(t *testing.T) {
	build := budgetBuilder(t)
	const p0 = 16
	base, err := build(p0)
	if err != nil {
		t.Fatalf("a small block: %v", err)
	}
	s0 := broadcastBytes(t, base)
	if s0 >= proofv2.ConsensusTxLimit {
		t.Fatalf("the calibration block is %d bytes, already over the limit", s0)
	}
	padFor := func(wire int) int { return p0 + wire - s0 }

	for _, under := range []int{-1, 0} {
		want := proofv2.ConsensusTxLimit + under
		vb, err := build(padFor(want))
		if err != nil {
			t.Fatalf("limit%+d: a block whose broadcast bytes are %d is refused: %v", under, want, err)
		}
		if got := broadcastBytes(t, vb); got != want || got > proofv2.ConsensusTxLimit {
			t.Fatalf("limit%+d: the broadcast bytes are %d, want %d (<= %d)", under, got, want, proofv2.ConsensusTxLimit)
		}
	}
	for _, over := range []int{1, 83, 215, 216} {
		want := proofv2.ConsensusTxLimit + over
		vb, err := build(padFor(want))
		var cs *proofv2.CertifyState
		if !errors.As(err, &cs) || cs.Code != proofv2.StateCertificateBudget || len(cs.Fields) != 2 {
			t.Fatalf("limit+%d: a block whose broadcast bytes would be %d: %v, want certificate_budget{size,limit}", over, want, err)
		}
		if cs.Fields[0] != strconv.Itoa(want) || cs.Fields[1] != strconv.Itoa(proofv2.ConsensusTxLimit) {
			t.Fatalf("limit+%d: the refusal says size=%s limit=%s, want size=%d (the broadcast bytes) limit=%d", over, cs.Fields[0], cs.Fields[1], want, proofv2.ConsensusTxLimit)
		}
		if vb.IntentCertificate != nil {
			t.Fatalf("limit+%d: a refused block keeps its intent certificate", over)
		}
	}
}
