// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// deadDialer refuses every outbound connection. Installing it makes any
// accidental network access during verification an immediate, loud failure
// rather than something that quietly succeeds on a developer's machine.
type deadDialer struct{ t *testing.T }

func (d deadDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.t.Error("CRITICAL DEFECT: verification attempted a network connection")
	return nil, fmt.Errorf("network disabled for this test")
}

// V20 / Phase 6 criterion 2 — the whole proof verifies with network access
// disabled, from the serialised object alone.
//
// The old verifier hard-failed here: "proof-grade verification requires comet
// clients (BVN+DN); missing one or both". The governance spec requires the
// opposite - section 4: a governance proof MUST be verifiable offline.
func TestOffline_StoredProofsVerifyWithNetworkDisabled(t *testing.T) {
	// Cut the network for the duration of this test.
	origDefault := http.DefaultTransport
	origClient := http.DefaultClient
	dead := &http.Transport{
		DialContext:           deadDialer{t}.DialContext,
		ResponseHeaderTimeout: time.Millisecond,
	}
	http.DefaultTransport = dead
	http.DefaultClient = &http.Client{Transport: dead}
	t.Cleanup(func() {
		http.DefaultTransport = origDefault
		http.DefaultClient = origClient
	})

	files, err := filepath.Glob(filepath.Join("testdata", "proof_*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no stored proofs in testdata; regenerate them with probe/dump")
	}

	pv := NewProofVerifier(false)
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var p ChainedProof
			if err := json.Unmarshal(raw, &p); err != nil {
				t.Fatalf("decode %s: %v", f, err)
			}
			if err := pv.Verify(context.Background(), &p); err != nil {
				t.Fatalf("offline verification of %s failed: %v", f, err)
			}
			t.Logf("verified offline: L1..L3 receipts recomputed; L4-%s %d sigs / threshold %d; L4-%s %d sigs / threshold %d",
				p.Layer4BVN.Partition, len(p.Layer4BVN.Signatures), p.Layer4BVN.Threshold,
				p.Layer4DN.Partition, len(p.Layer4DN.Signatures), p.Layer4DN.Threshold)
		})
	}
}

// The stored proofs are also the regression net for L1-L3: if a refactor
// changes any L1-L3 field, these fixtures stop verifying.
func TestOffline_StoredProofsRejectTampering(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "proof_bvn1.json"))
	if err != nil {
		t.Skip("fixture missing")
	}
	pv := NewProofVerifier(false)
	ctx := context.Background()

	tamper := []struct {
		name string
		mut  func(p *ChainedProof)
	}{
		{"L1 receipt entry", func(p *ChainedProof) {
			p.Layer1.Receipt.Entries[0].Hash = flipHexByte(p.Layer1.Receipt.Entries[0].Hash)
		}},
		{"L1 receipt sibling side", func(p *ChainedProof) {
			p.Layer1.Receipt.Entries[0].Right = !p.Layer1.Receipt.Entries[0].Right
		}},
		{"L2 bpt receipt", func(p *ChainedProof) {
			p.Layer2.BptReceipt.Anchor = flipHexByte(p.Layer2.BptReceipt.Anchor)
		}},
		{"L3 root receipt", func(p *ChainedProof) {
			p.Layer3.RootReceipt.Entries[0].Hash = flipHexByte(p.Layer3.RootReceipt.Entries[0].Hash)
		}},
		{"L2 stateTreeAnchor (breaks the L4-BVN bind)", func(p *ChainedProof) {
			p.Layer2.BVNStateTreeAnchor = flipHexByte(p.Layer2.BVNStateTreeAnchor)
		}},
		{"L3 stateTreeAnchor (breaks the L4-DN bind)", func(p *ChainedProof) {
			p.Layer3.DNStateTreeAnchor = flipHexByte(p.Layer3.DNStateTreeAnchor)
		}},
		{"DN consensus height ordering", func(p *ChainedProof) {
			p.Layer3.DNConsensusHeight++
		}},
		{"DN_FINAL_MBI below DN_MBI", func(p *ChainedProof) {
			p.Layer3.DNSelfAnchorRecordedAtMinorBlockIndex = p.Layer2.DNMinorBlockIndex - 1
		}},
		{"swap the two L4 legs", func(p *ChainedProof) {
			p.Layer4BVN, p.Layer4DN = p.Layer4DN, p.Layer4BVN
		}},
		{"leaf no longer equals input txHash", func(p *ChainedProof) {
			p.Layer1.Leaf = flipHexByte(p.Layer1.Leaf)
		}},
	}

	for _, tc := range tamper {
		t.Run(tc.name, func(t *testing.T) {
			var p ChainedProof
			if err := json.Unmarshal(raw, &p); err != nil {
				t.Fatal(err)
			}
			if err := pv.Verify(ctx, &p); err != nil {
				t.Fatalf("baseline fixture does not verify: %v", err)
			}
			tc.mut(&p)
			if err := pv.Verify(ctx, &p); err == nil {
				t.Fatalf("CRITICAL DEFECT: tampering %q was ACCEPTED", tc.name)
			} else {
				t.Logf("rejected: %v", err)
			}
		})
	}
}
