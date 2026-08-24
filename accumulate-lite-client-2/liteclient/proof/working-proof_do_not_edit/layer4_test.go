// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// Real transactions on Kermit, taken from certen_proofs.proof_artifacts.
// Two BVNs are covered so the leg builder is not exercised on one partition
// only.
var l4Cases = []struct {
	name    string
	account string
	txHash  string
	bvn     string
}{
	{"bvn1", "acc://carp-buyer-62431.acme/data", "51b0ba6abf413762fd3db7bcb12a2c56ee2806fcd8405640537f92b791aedcf0", "bvn1"},
	{"bvn3", "acc://certen-panel-carp-v7.acme/data", "37e28c94ce760872db514b22ffb483dbfc288204b94b22ad1d9c1c022357c750", "bvn3"},
}

// buildL1toL4 builds a full proof object from live data.
func buildL1toL4(t *testing.T, account, txHash, bvn string) *ChainedProof {
	t.Helper()
	c := liveClient(t)
	ctx := context.Background()

	l1, err := (&Layer1Builder{Client: c}).Build(ctx, account, txHash)
	if err != nil {
		t.Fatalf("L1: %v", err)
	}
	l2, err := (&Layer2Builder{Client: c}).Build(ctx, bvn, l1)
	if err != nil {
		t.Fatalf("L2: %v", err)
	}
	l3, err := (&Layer3Builder{Client: c}).Build(ctx, l2)
	if err != nil {
		t.Fatalf("L3: %v", err)
	}
	l4b := &Layer4Builder{Client: c}
	l4bvn, err := l4b.BuildBVNLeg(ctx, bvn, l1, l2)
	if err != nil {
		t.Fatalf("L4-BVN: %v", err)
	}
	l4dn, err := l4b.BuildDNLeg(ctx, bvn, l2, l3)
	if err != nil {
		t.Fatalf("L4-DN: %v", err)
	}
	return &ChainedProof{
		Input:     ProofInput{Account: account, TxHash: txHash, BVN: bvn},
		Layer1:    l1,
		Layer2:    l2,
		Layer3:    l3,
		Layer4BVN: l4bvn,
		Layer4DN:  l4dn,
	}
}

// Gate 2 — both legs populate against live Kermit and verify with no network.
func TestPhase2_Layer4BuildsAndVerifiesOffline(t *testing.T) {
	for _, tc := range l4Cases {
		t.Run(tc.name, func(t *testing.T) {
			p := buildL1toL4(t, tc.account, tc.txHash, tc.bvn)

			// Round-trip through JSON: the offline verifier must work from the
			// serialised proof alone, which is what a third party receives.
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			var q ChainedProof
			if err := json.Unmarshal(raw, &q); err != nil {
				t.Fatal(err)
			}

			if err := q.Layer4BVN.VerifyOffline(); err != nil {
				t.Fatalf("L4-BVN offline verify: %v", err)
			}
			if err := q.Layer4DN.VerifyOffline(); err != nil {
				t.Fatalf("L4-DN offline verify: %v", err)
			}

			// Cross-layer binds (V6, V7).
			if !strings.EqualFold(q.Layer4BVN.StateTreeAnchor, q.Layer2.BVNStateTreeAnchor) {
				t.Fatalf("V6: L4-BVN stateTreeAnchor %s != L2 %s",
					q.Layer4BVN.StateTreeAnchor, q.Layer2.BVNStateTreeAnchor)
			}
			if !strings.EqualFold(q.Layer4DN.StateTreeAnchor, q.Layer3.DNStateTreeAnchor) {
				t.Fatalf("V7: L4-DN stateTreeAnchor %s != L3 %s",
					q.Layer4DN.StateTreeAnchor, q.Layer3.DNStateTreeAnchor)
			}

			// Partitions must be the two distinct signing sets.
			if q.Layer4DN.Partition != "Directory" {
				t.Fatalf("L4-DN partition = %q, want Directory", q.Layer4DN.Partition)
			}
			if strings.EqualFold(q.Layer4BVN.Partition, "Directory") {
				t.Fatalf("L4-BVN partition must not be Directory")
			}

			t.Logf("L4-BVN %s: %d sigs, threshold %d, anchor %s[%d]",
				q.Layer4BVN.Partition, len(q.Layer4BVN.Signatures), q.Layer4BVN.Threshold,
				q.Layer4BVN.AnchorPool, q.Layer4BVN.AnchorIndex)
			t.Logf("L4-DN  %s: %d sigs, threshold %d, anchor %s[%d]",
				q.Layer4DN.Partition, len(q.Layer4DN.Signatures), q.Layer4DN.Threshold,
				q.Layer4DN.AnchorPool, q.Layer4DN.AnchorIndex)
		})
	}
}

// deepCopyLeg clones a leg through JSON so mutations cannot alias the original.
func deepCopyLeg(t *testing.T, l *Layer4) *Layer4 {
	t.Helper()
	raw, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	out := new(Layer4)
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatal(err)
	}
	return out
}

func flipHexByte(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) == 0 {
		return s
	}
	b[0] ^= 0x01
	return hex.EncodeToString(b)
}

// Phase 2.5 — the eight required negative tests, run against BOTH legs.
//
// A negative test that PASSES verification is a critical defect: it means a
// proof can succeed with less evidence than the spec requires.
func TestPhase2_Layer4NegativeMutations(t *testing.T) {
	tc := l4Cases[0]
	p := buildL1toL4(t, tc.account, tc.txHash, tc.bvn)

	mutations := []struct {
		name  string
		apply func(t *testing.T, l *Layer4) bool // false => not applicable to this leg
	}{
		{"1. flip one byte of a signature", func(t *testing.T, l *Layer4) bool {
			l.Signatures[0].Signature = flipHexByte(l.Signatures[0].Signature)
			return true
		}},
		{"2. drop signatures below threshold", func(t *testing.T, l *Layer4) bool {
			if uint64(len(l.Signatures)) <= l.Threshold {
				// Cannot drop below threshold without emptying; empty is also
				// rejected, and that is the same fail-closed outcome.
				l.Signatures = nil
				return true
			}
			l.Signatures = l.Signatures[:l.Threshold-1]
			return true
		}},
		{"3. substitute a pubkey not in the validator set", func(t *testing.T, l *Layer4) bool {
			l.Signatures[0].PublicKey = flipHexByte(l.Signatures[0].PublicKey)
			return true
		}},
		{"4. substitute a validator not active on that partition", func(t *testing.T, l *Layer4) bool {
			// Remove this partition from every validator's active list except
			// keep them in the set, so the key is known but not active here.
			for i := range l.ValidatorSet {
				var keep []string
				for _, part := range l.ValidatorSet[i].ActiveOn {
					if !strings.EqualFold(part, l.Partition) {
						keep = append(keep, part)
					}
				}
				l.ValidatorSet[i].ActiveOn = keep
			}
			return true
		}},
		{"5. duplicate one signer to reach the count", func(t *testing.T, l *Layer4) bool {
			if l.Threshold < 2 {
				return false // needs a threshold above one to be meaningful
			}
			first := l.Signatures[0]
			l.Signatures = []AnchorSignature{first}
			for uint64(len(l.Signatures)) < l.Threshold {
				l.Signatures = append(l.Signatures, first)
			}
			return true
		}},
		{"6. alter StateTreeAnchor", func(t *testing.T, l *Layer4) bool {
			l.StateTreeAnchor = flipHexByte(l.StateTreeAnchor)
			return true
		}},
		{"7. alter AnchorTxHash", func(t *testing.T, l *Layer4) bool {
			l.AnchorTxHash = flipHexByte(l.AnchorTxHash)
			return true
		}},
		{"8a. alter Timestamp", func(t *testing.T, l *Layer4) bool {
			l.Signatures[0].Timestamp++
			return true
		}},
		{"8b. alter SignerVersion", func(t *testing.T, l *Layer4) bool {
			l.Signatures[0].SignerVersion++
			return true
		}},
		// Beyond the runbook's eight: the binding the design doc omitted.
		{"9. swap in another partition's signed message", func(t *testing.T, l *Layer4) bool {
			other := p.Layer4DN
			if l.Partition == "Directory" {
				other = p.Layer4BVN
			}
			l.SequencedMessage = other.SequencedMessage
			return true
		}},
		{"10. alter SignedHash", func(t *testing.T, l *Layer4) bool {
			l.SignedHash = flipHexByte(l.SignedHash)
			return true
		}},
		{"11. raise Threshold above what the network requires", func(t *testing.T, l *Layer4) bool {
			l.Threshold++
			return true
		}},
		{"12. lower Threshold below what the network requires", func(t *testing.T, l *Layer4) bool {
			if l.Threshold == 0 {
				return false
			}
			l.Threshold--
			return true
		}},
		{"13. weaken AcceptThreshold to admit fewer signers", func(t *testing.T, l *Layer4) bool {
			l.AcceptThreshold = Rational{Numerator: 0, Denominator: 3}
			return true
		}},
		{"14. corrupt a validator publicKeyHash", func(t *testing.T, l *Layer4) bool {
			l.ValidatorSet[0].PublicKeyHash = flipHexByte(l.ValidatorSet[0].PublicKeyHash)
			return true
		}},
		{"15. drop the sequenced message entirely", func(t *testing.T, l *Layer4) bool {
			l.SequencedMessage = ""
			return true
		}},
		{"16. alter the sequence number", func(t *testing.T, l *Layer4) bool {
			l.SequenceNumber++
			return true
		}},
		{"17. alter the minor block index", func(t *testing.T, l *Layer4) bool {
			l.MinorBlockIndex++
			return true
		}},
	}

	legs := map[string]*Layer4{"L4-BVN": p.Layer4BVN, "L4-DN": p.Layer4DN}

	for legName, leg := range legs {
		// Sanity: the unmutated leg must verify, or the negatives prove nothing.
		if err := leg.VerifyOffline(); err != nil {
			t.Fatalf("%s: baseline leg does not verify: %v", legName, err)
		}
		for _, m := range mutations {
			t.Run(legName+" / "+m.name, func(t *testing.T) {
				mutated := deepCopyLeg(t, leg)
				if !m.apply(t, mutated) {
					t.Skipf("not applicable to %s (threshold %d)", legName, leg.Threshold)
				}
				err := mutated.VerifyOffline()
				if err == nil {
					t.Fatalf("CRITICAL DEFECT: mutation %q on %s was ACCEPTED — fail-open", m.name, legName)
				}
				t.Logf("rejected: %v", err)
			})
		}
	}
}

// A nil leg must never read as a passing leg.
func TestPhase2_NilLegIsRejected(t *testing.T) {
	var l *Layer4
	if err := l.VerifyOffline(); err == nil {
		t.Fatal("CRITICAL DEFECT: a nil L4 leg verified")
	}
	if err := (&Layer4{}).VerifyOffline(); err == nil {
		t.Fatal("CRITICAL DEFECT: an empty L4 leg verified")
	}
}

// The threshold must track the network, not a hardcoded fraction.
func TestPhase2_ThresholdMatchesAccumulateRational(t *testing.T) {
	cases := []struct {
		num, den uint64
		active   int
		want     uint64
	}{
		{2, 3, 3, 2}, // Kermit Directory today
		{2, 3, 1, 1}, // a single-validator BVN
		{2, 3, 4, 3},
		{2, 3, 100, 67},
		{1, 1, 5, 5},
	}
	for _, c := range cases {
		got, err := Rational{Numerator: c.num, Denominator: c.den}.Threshold(c.active)
		if err != nil {
			t.Fatalf("%d/%d over %d: %v", c.num, c.den, c.active, err)
		}
		if got != c.want {
			t.Fatalf("%d/%d over %d = %d, want %d", c.num, c.den, c.active, got, c.want)
		}
	}
	for _, bad := range []Rational{{0, 3}, {2, 0}, {4, 3}} {
		if _, err := bad.Threshold(3); err == nil {
			t.Fatalf("degenerate rational %d/%d was accepted", bad.Numerator, bad.Denominator)
		}
	}
}
