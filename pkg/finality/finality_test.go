// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// ---- helpers ----

type fakeVerifier struct {
	chain uint64
	kind  string
	max   Level
	level Level
	err   error
}

func (f fakeVerifier) Chain() uint64   { return f.chain }
func (f fakeVerifier) Kind() string    { return f.kind }
func (f fakeVerifier) MaxLevel() Level { return f.max }
func (f fakeVerifier) Verify(Settlement, Evidence, *Pins) (Level, error) {
	return f.level, f.err
}

func subject() Subject {
	var s Subject
	s.BlockNumber = 47368146
	for i := range s.BlockHash {
		s.BlockHash[i], s.TxHash[i] = 0x11, 0x22
	}
	return s
}

func settlementOn(chain uint64) Settlement { return Settlement{Chain: chain, Subject: subject()} }

func mustEvidence(t *testing.T, kind, body string) Evidence {
	t.Helper()
	return NewEvidence(kind, settlementOn(84532), []byte(body))
}

func code(t *testing.T, err error) string {
	t.Helper()
	n, ok := AsNamed(err)
	if !ok {
		t.Fatalf("not a named state: %v", err)
	}
	return n.Code()
}

// buildChain makes a valid three-addendum chain on chain 84532 over kinds that the test registry knows.
func buildChain(t *testing.T, original [32]byte) []Addendum {
	t.Helper()
	var chain []Addendum
	var prev *Addendum
	for _, step := range []struct {
		level Level
		kind  string
	}{{LevelIncluded, "t.incl/v1"}, {LevelL1Posted, "t.l1/v1"}, {LevelFinalized, "t.fin/v1"}} {
		a, err := NewAddendum(original, "proof-1", prev, 84532, step.level, mustEvidence(t, step.kind, "body-"+step.kind))
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, a)
		prev = &chain[len(chain)-1]
	}
	return chain
}

// ---- the encoding is specification: goldens computed independently (testdata/addendum_v1_golden_generator.py) ----

func TestAddendumEncodingMatchesTheIndependentGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/addendum_v1.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Domain         string            `json:"domain"`
		OriginalDigest string            `json:"originalDigest"`
		Addenda        []json.RawMessage `json:"addenda"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if g.Domain != Domain {
		t.Fatalf("domain %q, golden %q", Domain, g.Domain)
	}
	od, _ := hex.DecodeString(g.OriginalDigest)
	var original [32]byte
	copy(original[:], od)

	// 1. the golden parses and its chain verifies
	var golden []Addendum
	for _, r := range g.Addenda {
		var a Addendum
		if err := json.Unmarshal(r, &a); err != nil {
			t.Fatal(err)
		}
		golden = append(golden, a)
	}
	if err := VerifyChain(original, golden); err != nil {
		t.Fatalf("the golden chain does not verify: %v", err)
	}

	// 2. building the same chain from the same inputs reproduces every byte of it
	kinds := map[Level]string{LevelIncluded: "included.eth-mpt/v1", LevelL1Posted: "golden.l1/v1", LevelFinalized: "golden.final/v1"}
	var built []Addendum
	var prev *Addendum
	for _, level := range Levels {
		ev := NewEvidence(kinds[level], settlementOn(84532), []byte("golden-body-"+string(rune('0'+int(level)))))
		a, err := NewAddendum(original, "golden-proof-1", prev, 84532, level, ev)
		if err != nil {
			t.Fatal(err)
		}
		built = append(built, a)
		prev = &built[len(built)-1]
	}
	for i := range built {
		gb, _ := json.Marshal(golden[i])
		bb, _ := json.Marshal(built[i])
		if !bytes.Equal(gb, bb) {
			t.Fatalf("addendum %d: built\n%s\ngolden\n%s", i+1, bb, gb)
		}
	}
}

// ---- tamper: every field of every addendum ----

func TestAddendumChainTamperIsRefusedForEachField(t *testing.T) {
	var original [32]byte
	original[0] = 0xAB
	flip := func(b [32]byte) [32]byte { b[7] ^= 0x01; return b }

	cases := []struct {
		name  string
		check string
		edit  func(c []Addendum) []Addendum
	}{
		{"seq", "seq", func(c []Addendum) []Addendum { c[1].Seq = 5; return c }},
		{"proofId", "proof_id", func(c []Addendum) []Addendum { c[1].ProofID = "other-proof"; return c }},
		{"level up", "own_hash", func(c []Addendum) []Addendum { c[0].Level = LevelFinalized; return c }},
		{"level invalid", "level_invalid", func(c []Addendum) []Addendum { c[1].Level = 9; return c }},
		{"chain", "chain", func(c []Addendum) []Addendum { c[2].Chain = 421614; return c }},
		{"kind", "own_hash", func(c []Addendum) []Addendum { c[1].Kind = "t.other/v1"; return c }},
		{"evidence", "own_hash", func(c []Addendum) []Addendum { c[1].Evidence[len(c[1].Evidence)-1] ^= 1; return c }},
		{"prevHash", "prev_hash", func(c []Addendum) []Addendum { c[1].PrevHash = flip(c[1].PrevHash); return c }},
		{"first prevHash not zero", "prev_hash", func(c []Addendum) []Addendum { c[0].PrevHash[0] = 1; return c }},
		{"ownHash", "own_hash", func(c []Addendum) []Addendum { c[2].OwnHash = flip(c[2].OwnHash); return c }},
		{"drop middle", "seq", func(c []Addendum) []Addendum { return []Addendum{c[0], c[2]} }},
		{"duplicate", "seq", func(c []Addendum) []Addendum { return []Addendum{c[0], c[0], c[1]} }},
		{"reorder", "seq", func(c []Addendum) []Addendum { return []Addendum{c[1], c[0], c[2]} }},
		{"started at seq 2", "seq", func(c []Addendum) []Addendum { return c[1:] }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain := buildChain(t, original)
			err := VerifyChain(original, tc.edit(chain))
			if err == nil {
				t.Fatal("a tampered chain verified")
			}
			n, _ := AsNamed(err)
			if n == nil || n.Code() != CodeChainBroken || n.Fields()["check"] != tc.check {
				t.Fatalf("want %s check=%s, got %v", CodeChainBroken, tc.check, err)
			}
		})
	}

	t.Run("original digest", func(t *testing.T) {
		chain := buildChain(t, original)
		if err := VerifyChain(flip(original), chain); err == nil || code(t, err) != CodeChainBroken {
			t.Fatalf("a chain verified against another proof's digest: %v", err)
		}
	})

	t.Run("re-hashed forgery that lowers a level is not monotone", func(t *testing.T) {
		chain := buildChain(t, original)
		// an attacker who recomputes every hash still cannot make levels go down or stand still
		chain[1].Level = LevelIncluded
		chain[1].OwnHash = chain[1].ComputeHash(original)
		chain[2].PrevHash = chain[1].OwnHash
		chain[2].OwnHash = chain[2].ComputeHash(original)
		err := VerifyChain(original, chain)
		if err == nil || code(t, err) != CodeChainBroken {
			t.Fatalf("non-monotone chain accepted: %v", err)
		}
		if n, _ := AsNamed(err); n.Fields()["check"] != "level_not_monotone" {
			t.Fatalf("check %q", n.Fields()["check"])
		}
	})

	t.Run("re-hashed forgery that swaps the subject", func(t *testing.T) {
		chain := buildChain(t, original)
		ev, _ := DecodeEvidence(chain[1].Evidence)
		ev.Subject.TxHash[0] ^= 0xFF
		enc, _ := ev.Encode()
		chain[1].Evidence = enc
		chain[1].OwnHash = chain[1].ComputeHash(original)
		chain[2].PrevHash = chain[1].OwnHash
		chain[2].OwnHash = chain[2].ComputeHash(original)
		err := VerifyChain(original, chain)
		if err == nil {
			t.Fatal("a chain whose addenda are about different settlements verified")
		}
		if n, _ := AsNamed(err); n.Fields()["check"] != "subject" {
			t.Fatalf("check %q: %v", n.Fields()["check"], err)
		}
	})

	t.Run("valid chain and empty chain verify", func(t *testing.T) {
		if err := VerifyChain(original, buildChain(t, original)); err != nil {
			t.Fatal(err)
		}
		if err := VerifyChain(original, nil); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("NewAddendum refuses what VerifyChain would", func(t *testing.T) {
		chain := buildChain(t, original)
		if _, err := NewAddendum(original, "proof-1", &chain[2], 84532, LevelFinalized, mustEvidence(t, "t.fin/v1", "x")); err == nil {
			t.Fatal("appended a level that does not exceed the previous")
		}
		if _, err := NewAddendum(original, "proof-1", &chain[0], 421614, LevelL1Posted, mustEvidence(t, "t.l1/v1", "x")); err == nil {
			t.Fatal("appended on another chain")
		}
	})
}

func TestAddendumJSONIsStrict(t *testing.T) {
	chain := buildChain(t, [32]byte{1})
	raw, err := json.Marshal(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	var back Addendum
	if err := json.Unmarshal(raw, &back); err != nil || back.OwnHash != chain[0].OwnHash || back.Level != LevelIncluded {
		t.Fatalf("round trip: %v %+v", err, back)
	}
	for name, edit := range map[string]func(string) string{
		"unknown field": func(s string) string { return strings.Replace(s, `"seq"`, `"extra":1,"seq"`, 1) },
		"level":         func(s string) string { return strings.Replace(s, `"included"`, `"almost"`, 1) },
		"short hash":    func(s string) string { return strings.Replace(s, `"ownHash":"`, `"ownHash":"00`, 1) },
		"evidence hex":  func(s string) string { return strings.Replace(s, `"evidence":"`, `"evidence":"zz`, 1) },
	} {
		var a Addendum
		err := json.Unmarshal([]byte(edit(string(raw))), &a)
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if n, ok := AsNamed(err); !ok || n.Code() != CodeAddendumMalformed {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// ---- evidence container ----

func TestEvidenceContainerIsStrictAndCanonical(t *testing.T) {
	ev := mustEvidence(t, "t.incl/v1", "body")
	enc, err := ev.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeEvidence(enc)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := back.Encode()
	if !bytes.Equal(enc, again) {
		t.Fatal("decode then encode is not the identity")
	}
	bad := map[string][]byte{
		"empty":     nil,
		"truncated": enc[:len(enc)-1],
		"trailing":  append(append([]byte(nil), enc...), 0),
		"version":   append([]byte{0, 0, 0, 2}, enc[4:]...),
	}
	for name, b := range bad {
		if _, err := DecodeEvidence(b); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, uerr := DecodeEvidence(append([]byte{0, 0, 0, 2}, enc[4:]...)); uerr == nil || code(t, uerr) != CodeEvidenceUnrecognised {
		t.Fatalf("an unknown version is not finality_evidence_unrecognised: %v", uerr)
	}
	if _, err := (Evidence{Version: EvidenceVersion, Kind: "Bad Kind"}).Encode(); err == nil {
		t.Fatal("a malformed kind encoded")
	}
}

// ---- the level is never beyond the evidence ----

func TestLevelNeverExceedsEvidence(t *testing.T) {
	reg := NewRegistry()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// a verifier that over-reports (returns finalized for a kind that can only prove included) is caught by the dispatcher
	must(reg.RegisterVerifier(fakeVerifier{chain: 84532, kind: "t.liar/v1", max: LevelIncluded, level: LevelFinalized}))
	// a verifier that reports a level the chain does not offer (Adiri has no l1_posted)
	must(reg.RegisterVerifier(fakeVerifier{chain: ChainAdiri, kind: "t.l1/v1", max: LevelL1Posted, level: LevelL1Posted}))
	// honest ones
	must(reg.RegisterVerifier(fakeVerifier{chain: 84532, kind: "t.fin/v1", max: LevelFinalized, level: LevelFinalized}))
	must(reg.RegisterVerifier(fakeVerifier{chain: 84532, kind: "t.weak/v1", max: LevelFinalized, level: LevelIncluded}))

	if lvl, err := reg.Verify(84532, settlementOn(84532), mustEvidence(t, "t.liar/v1", "x"), nil); err == nil || lvl != LevelNone || code(t, err) != CodeLevelExceedsEvidence {
		t.Fatalf("over-reporting verifier: level %v err %v", lvl, err)
	}
	ev := NewEvidence("t.l1/v1", settlementOn(ChainAdiri), nil)
	if lvl, err := reg.Verify(ChainAdiri, settlementOn(ChainAdiri), ev, nil); err == nil || lvl != LevelNone || code(t, err) != CodeLevelNotOffered {
		t.Fatalf("level the chain does not offer: level %v err %v", lvl, err)
	}
	if lvl, err := reg.Verify(84532, settlementOn(84532), mustEvidence(t, "t.fin/v1", "x"), nil); err != nil || lvl != LevelFinalized {
		t.Fatalf("honest: %v %v", lvl, err)
	}

	// an addendum that claims more than its evidence proves is refused, and so is one that claims less
	original := [32]byte{9}
	a, err := NewAddendum(original, "p", nil, 84532, LevelFinalized, mustEvidence(t, "t.weak/v1", "x"))
	must(err)
	if _, err := reg.VerifyAddendum(a, nil); err == nil || code(t, err) != CodeLevelExceedsEvidence {
		t.Fatalf("finalized claimed over included evidence: %v", err)
	}
	a, err = NewAddendum(original, "p", nil, 84532, LevelIncluded, mustEvidence(t, "t.fin/v1", "x"))
	must(err)
	if _, err := reg.VerifyAddendum(a, nil); err == nil || code(t, err) != CodeLevelMismatch {
		t.Fatalf("included claimed over finalized evidence: %v", err)
	}
	a, err = NewAddendum(original, "p", nil, 84532, LevelIncluded, mustEvidence(t, "t.weak/v1", "x"))
	must(err)
	if lvl, err := reg.VerifyAddendum(a, nil); err != nil || lvl != LevelIncluded {
		t.Fatalf("matching claim: %v %v", lvl, err)
	}
}

func TestUnknownKindAndUnsupportedChainAreNamedStates(t *testing.T) {
	reg := NewRegistry()
	_, err := reg.Verify(84532, settlementOn(84532), mustEvidence(t, "no.such/v9", "x"), nil)
	n, ok := AsNamed(err)
	if !ok || n.Code() != CodeKindUnknown || n.Fields()["kind"] != "no.such/v9" || n.Fields()["chain"] != "84532" {
		t.Fatalf("unknown kind: %v", err)
	}
	_, err = reg.Verify(1, settlementOn(1), mustEvidence(t, KindIncluded, "x"), nil)
	if code(t, err) != CodeChainUnsupported {
		t.Fatalf("unsupported chain: %v", err)
	}
	// the evidence is about another settlement than the one asked about
	other := settlementOn(84532)
	other.TxHash[0] ^= 1
	_, err = reg.Verify(84532, other, mustEvidence(t, KindIncluded, "x"), nil)
	if n, _ := AsNamed(err); n == nil || n.Code() != CodeSubjectMismatch || n.Fields()["field"] != "txHash" {
		t.Fatalf("subject mismatch: %v", err)
	}
	// a verifier's plain error is wrapped as a named state, never passed through bare
	must := reg.RegisterVerifier(fakeVerifier{chain: 84532, kind: "t.plain/v1", max: LevelIncluded, err: context.Canceled})
	if must != nil {
		t.Fatal(must)
	}
	if _, err := reg.Verify(84532, settlementOn(84532), mustEvidence(t, "t.plain/v1", "x"), nil); code(t, err) != CodeVerifierFailed {
		t.Fatalf("plain verifier error: %v", err)
	}
	// a second verifier for the same chain and kind is refused
	if err := reg.RegisterVerifier(IncludedVerifier{ChainID: 84532}); err == nil {
		t.Fatal("a duplicate verifier was registered")
	}
}

func TestPendingAndNotApplicableAreTypedNonLevels(t *testing.T) {
	reg := NewRegistry()
	for _, chain := range []uint64{ChainSepolia, ChainBaseSepolia, ChainArbitrumSepolia, ChainAdiri} {
		p, err := reg.Profile(chain)
		if err != nil {
			t.Fatalf("chain %d: %v", chain, err)
		}
		if p.Top() != LevelFinalized || !p.Offers(LevelIncluded) {
			t.Fatalf("chain %d profile %+v", chain, p)
		}
	}
	adiri, _ := reg.Profile(ChainAdiri)
	na, ok := adiri.NotApplicableFor(LevelL1Posted)
	if !ok || na.Code() != CodeNotApplicable || !strings.Contains(na.Reason, "no L1 settlement") {
		t.Fatalf("adiri l1_posted: %+v", na)
	}
	if _, ok := adiri.NotApplicableFor(LevelFinalized); ok {
		t.Fatal("finalized is not-applicable on adiri")
	}
	if adiri.Next(LevelIncluded) != LevelFinalized {
		t.Fatal("adiri's level after included is not finalized")
	}
	base, _ := reg.Profile(ChainBaseSepolia)
	if base.Next(LevelIncluded) != LevelL1Posted || base.Next(LevelFinalized) != LevelNone {
		t.Fatal("base level sequence")
	}
	p := &Pending{Chain: ChainSepolia, LevelReached: LevelIncluded, NextLevel: LevelFinalized, Reason: "finality_pending", Judged: map[string]string{"slot": "123"}}
	if f := p.Fields(); f["level_reached"] != "included" || f["next_level"] != "finalized" || f["slot"] != "123" || p.Code() != CodePending {
		t.Fatalf("pending fields %v", f)
	}
	// neither is a Level: they are errors, so no caller can read one as a level
	var _ error = p
	var _ error = na
	if LevelNone.Valid() || Level(4).Valid() || LevelFinalized.String() != "finalized" {
		t.Fatal("level validity")
	}
}
