// Copyright 2026 Certen Protocol
//
// What the anchor a proof settled under COMMITTED, carried in layer 5 so a verifier can re-derive the anchor's bundle id
// and the message CERTEN's quorum signed - and, on a V8.2 anchor, check that the Accumulate validator set the proof's
// L4 was verified against is the one the anchor committed (RB5 Phase G).
package execution

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/accumulateset"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// AnchorCommitment is everything a batch anchor derived its bundle id from and its quorum signed, beyond the batch root
// (Layer5.BatchRoot). AccumulateSetRoot and Incarnation are present exactly on a V8.2 anchor.
type AnchorCommitment struct {
	Version               string `json:"version"` // v8_1 | v8_2
	BundleID              string `json:"bundleId"`
	LeafCount             uint64 `json:"leafCount"`
	BatchOperationID      string `json:"batchOperationId"`
	AccumulateBlockHeight uint64 `json:"accumulateBlockHeight"`
	CertenSetRoot         string `json:"certenSetRoot"`
	MessageHash           string `json:"messageHash"`
	AccumulateSetRoot     string `json:"accumulateSetRoot,omitempty"`
	Incarnation           string `json:"incarnation,omitempty"`
}

// Verify re-derives the bundle id and the signed message from the commitment and the batch root, offline.
func (c *AnchorCommitment) Verify(chainID int64, batchRoot string) error {
	if c == nil {
		return fmt.Errorf("layer5.commitment: absent")
	}
	root, err := commitmentHex32(batchRoot, "layer5.batchRoot")
	if err != nil {
		return err
	}
	bundle, err := commitmentHex32(c.BundleID, "layer5.commitment.bundleId")
	if err != nil {
		return err
	}
	opID, err := commitmentHex32(c.BatchOperationID, "layer5.commitment.batchOperationId")
	if err != nil {
		return err
	}
	setRoot, err := commitmentHex32(c.CertenSetRoot, "layer5.commitment.certenSetRoot")
	if err != nil {
		return err
	}
	msg, err := commitmentHex32(c.MessageHash, "layer5.commitment.messageHash")
	if err != nil {
		return err
	}
	if c.LeafCount == 0 {
		return fmt.Errorf("layer5.commitment: a batch of zero members")
	}
	var wantBundle, wantMsg [32]byte
	switch c.Version {
	case string(contracts.BatchAnchorV8_2):
		acc, err := commitmentHex32(c.AccumulateSetRoot, "layer5.commitment.accumulateSetRoot")
		if err != nil {
			return err
		}
		inc, err := commitmentHex32(c.Incarnation, "layer5.commitment.incarnation")
		if err != nil {
			return err
		}
		if acc == ([32]byte{}) || inc == ([32]byte{}) {
			return fmt.Errorf("layer5.commitment: a V8.2 anchor with a zero Accumulate set root or incarnation")
		}
		wantBundle = contracts.DeriveV8_2BatchBundleID(chainID, root, c.LeafCount, opID, c.AccumulateBlockHeight, acc, inc)
		wantMsg = contracts.ComputeEvmMessageHashV8_2_Pre(chainID, bundle, root, opID, setRoot, acc, inc)
	case string(contracts.BatchAnchorV8_1):
		if c.AccumulateSetRoot != "" || c.Incarnation != "" {
			return fmt.Errorf("layer5.commitment: a V8.1 anchor stating an Accumulate commitment it never made")
		}
		wantBundle = contracts.DeriveV8_1BatchBundleID(chainID, root, c.LeafCount, opID, c.AccumulateBlockHeight)
		wantMsg = contracts.ComputeEvmMessageHashV6_1_Pre(chainID, bundle, root, opID, setRoot)
	default:
		return fmt.Errorf("layer5.commitment: anchor generation %q is not v8_1 or v8_2", c.Version)
	}
	if wantBundle != bundle {
		return fmt.Errorf("layer5.commitment: the anchor's arguments derive bundle %x…, it names %x…", wantBundle[:8], bundle[:8])
	}
	if wantMsg != msg {
		return fmt.Errorf("layer5.commitment: the quorum's message recomputes to %x…, it names %x…", wantMsg[:8], msg[:8])
	}
	return nil
}

// AccumulateCommitmentState names what a proof's anchor establishes about the Accumulate validator set its L4 used.
type AccumulateCommitmentState string

const (
	// AccumulateSetCommittedVerified: the anchor (V8.2) committed exactly the set the proof's L4 Directory leg was
	// verified against, under the incarnation the verifier pinned. The set is committed on-chain and cannot be
	// substituted; whether it descends from the incarnation's genesis set is RB6's validation, not this.
	AccumulateSetCommittedVerified AccumulateCommitmentState = "committed_verified"
	// AccumulateSetCommittedUnpinned: as above, but the verifier holds no pinned incarnation, so which Accumulate chain
	// it is about rests on the anchor alone.
	AccumulateSetCommittedUnpinned AccumulateCommitmentState = "committed_incarnation_unpinned"
	// AccumulateSetNotCommittedV8_1: the proof settled under a V8.1 anchor, which committed no Accumulate validator set.
	AccumulateSetNotCommittedV8_1 AccumulateCommitmentState = "anchor_v8_1_set_not_committed"
	// AccumulateCommitmentNotRecorded: the proof's layer 5 carries no anchor commitment (written before it existed).
	AccumulateCommitmentNotRecorded AccumulateCommitmentState = "commitment_not_recorded"
)

// ErrAccumulateSetNotCommitted wraps every proven disagreement between a proof and what its anchor committed.
var ErrAccumulateSetNotCommitted = errors.New("the proof's Accumulate validator set is not the one its anchor committed")

// CheckAccumulateCommitment compares the set the proof's L4 Directory leg was verified against with what the anchor
// committed, under the anchor's incarnation, and the incarnation with the verifier's pin. A named state for what is
// not established; an error only when something is PROVEN not to hold.
func CheckAccumulateCommitment(l5 *Layer5, dn *chained_proof.Layer4, pinned *[32]byte) (AccumulateCommitmentState, error) {
	if l5 == nil || l5.Commitment == nil {
		return AccumulateCommitmentNotRecorded, nil
	}
	c := l5.Commitment
	switch c.Version {
	case string(contracts.BatchAnchorV8_1):
		return AccumulateSetNotCommittedV8_1, nil
	case string(contracts.BatchAnchorV8_2):
	default:
		return "", fmt.Errorf("%w: anchor generation %q", ErrAccumulateSetNotCommitted, c.Version)
	}
	committed, err := commitmentHex32(c.AccumulateSetRoot, "layer5.commitment.accumulateSetRoot")
	if err != nil {
		return "", err
	}
	inc, err := commitmentHex32(c.Incarnation, "layer5.commitment.incarnation")
	if err != nil {
		return "", err
	}
	expanded, err := accumulateset.CommittedAccumulateSetRoot(dn, inc)
	if err != nil {
		return "", fmt.Errorf("%w: the proof's Directory leg does not reduce to a set: %v", ErrAccumulateSetNotCommitted, err)
	}
	if expanded != committed {
		return "", fmt.Errorf("%w: the proof's L4 was verified against set %x…, the anchor committed %x…",
			ErrAccumulateSetNotCommitted, expanded[:8], committed[:8])
	}
	if pinned == nil {
		return AccumulateSetCommittedUnpinned, nil
	}
	if *pinned != inc {
		return "", fmt.Errorf("%w: the anchor committed incarnation %x…, the verifier pinned %x… - a proof about another "+
			"Accumulate chain", ErrAccumulateSetNotCommitted, inc[:8], pinned[:8])
	}
	return AccumulateSetCommittedVerified, nil
}

func commitmentHex32(s, label string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x"))
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("%s: %q is not 32 bytes of hex", label, s)
	}
	copy(out[:], b)
	return out, nil
}
