// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB10-B: a layer-6 document's member.replayGuard is decoded strictly, by the S6 format's own decoder
// (ethproof.DecodeReplayGuardEvidence): an unknown or duplicate key, a wrong type or another version refuses the document
// by name, on every path that reads layer 6 (the stored row, proofverify's outcome file), never silently dropped.
func TestTheL6ReplayGuardIsDecodedStrictly(t *testing.T) {
	m := newS6Member(t)
	m.ev.ReplayGuard = m.proven()
	ev := s6OutcomeDoc(t, m)
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}

	var back OutcomeEvidence
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("a well-formed layer 6 refused: %v", err)
	}
	again, _ := json.Marshal(&back)
	if !bytes.Equal(again, raw) || back.replayGuardStanding() != replayGuardProven {
		t.Fatal("a well-formed layer 6 does not round-trip to a proven replay guard")
	}
	var none OutcomeEvidence
	m.ev.ReplayGuard = nil
	plain, _ := json.Marshal(s6OutcomeDoc(t, m))
	if err := json.Unmarshal(plain, &none); err != nil || none.Member.ReplayGuard != nil {
		t.Fatalf("a layer 6 without a replay guard: %v %v", err, none.Member.ReplayGuard)
	}

	const open = `"replayGuard":{`
	if !bytes.Contains(raw, []byte(open)) {
		t.Fatalf("the document has no %s", open)
	}
	for _, c := range []struct {
		name, from, to, reason string
	}{
		{"an unknown key", open, open + `"extra":1,`, ethproof.ReasonUnknownField},
		{"an unknown key in the proof", `"proof":{`, `"proof":{"extra":1,`, ethproof.ReasonUnknownField},
		{"a duplicate key", open, open + `"version":"certen:s6-replay:v1",`, ethproof.ReasonMalformedJSON},
		{"a wrongly typed version", open + `"version":"certen:s6-replay:v1"`, open + `"version":1`, ethproof.ReasonWrongType},
		{"another version", open + `"version":"certen:s6-replay:v1"`, open + `"version":"certen:s6-replay:v2"`, ethproof.ReasonVersion},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad := bytes.Replace(raw, []byte(c.from), []byte(c.to), 1)
			if bytes.Equal(bad, raw) {
				t.Fatalf("the mutation %q did not apply", c.from)
			}
			var got OutcomeEvidence
			err := json.Unmarshal(bad, &got)
			if !errors.Is(err, ErrOutcomeEvidence) || !strings.Contains(err.Error(), "member.replayGuard") || !strings.Contains(err.Error(), c.reason) {
				t.Fatalf("want the document refused naming member.replayGuard and %s, got %v", c.reason, err)
			}
		})
	}
}

func s6OutcomeDoc(t *testing.T, m *s6Member) *OutcomeEvidence {
	t.Helper()
	rg := m.ev.ReplayGuard
	if err := m.verify(); err != nil {
		t.Fatal(err)
	}
	member := m.ev
	member.ReplayGuard = rg
	return &OutcomeEvidence{Version: OutcomeEvidenceVersion, ChainID: m.chainID,
		Anchor: OutcomeAnchorEvidence{BundleID: common.Hash(m.anchor.bundleID).Hex()}, Member: member}
}
