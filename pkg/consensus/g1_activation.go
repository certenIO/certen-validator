package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/certen/independant-validator/pkg/ledger"
)

// The cross-partition G1 activation as consensus state (rules v15, RB9-C, docs/proof/G1_CROSS_PARTITION.md D7).
//
// # WHY A TRANSACTION
//
// Proof v2 evidence 2.1 changes what govRoot commits (govRoot v4, certen:g1:v4): every page of the governing set at its
// own partition and block, with its roles and the proven vote records. A v3 certificate judged with 2.0 evidence and a
// v4 certificate judged with 2.1 evidence cannot both be accepted at one height by some validators and not others, so the
// switch is a committed fact every node reads identically - never a date, never a node's configuration. Like the v14
// anchor set it is authorised by the admin quorum in force (AdminSetAt) over the chain id, recorded append-only at the
// block that accepted it (H), and read by height.
//
// # WHAT MAKES IT SAFE
//
//   - The admin quorum in force for the block authorises it, by distinct keys, over the kind, the chain and the version,
//     under a length-prefixed encoding nothing else shares.
//   - It carries no payload but the version, which is always 1: one activation per chain. A second is refused by name, so
//     the activation cannot be replayed, moved or undone, and "in force at h" is exactly "an activation was accepted at a
//     height below h".
//
// # THE V15 ACTIVATION
//
// Before the first accepted activation the v15 binary decides every block exactly as v14 does, and a certificate that
// carries evidence 2.1 is refused by name (ErrIntentProofV21NotInForce). From the height after it (H+1), every v3
// intent certificate must carry 2.1 (a 2.0 one is refused, ErrIntentProofV21Missing) and is judged under govRoot v4.
// Activation does not need all intents to be 2.1-capable beforehand: until the 2.1 evidence of an intent is built a
// proposer cannot certify it, which holds the intent (retried), never certifies it under weaker evidence.

// G1ActivationKind identifies a cross-partition activation transaction on the wire.
const G1ActivationKind = "certen.g1.crosspartition.activate/v1"

// codeG1ActivationRefused is the result code of a refused activation transaction. 16 and 17 are the anchor set's; 18 is
// the next free.
const codeG1ActivationRefused uint32 = 18

// ErrG1ActivationRefused names every refusal of an activation transaction.
var ErrG1ActivationRefused = errors.New("cross-partition activation refused")

// G1ActivationTx activates evidence 2.1 for every block above the block that accepts it.
type G1ActivationTx struct {
	Kind    string `json:"kind"`
	ChainID string `json:"chain_id"`
	Version uint64 `json:"version"`
	// Signatures are the admin signatures over SigningBytes.
	Signatures []PolicySignature `json:"signatures,omitempty"`
}

// SigningBytes is what the admins sign: sha256 over the kind, the chain and the version, every field length-prefixed.
func (t *G1ActivationTx) SigningBytes() []byte {
	sum := sha256.Sum256(lengthPrefixed(G1ActivationKind, t.ChainID, strconv.FormatUint(t.Version, 10)))
	return sum[:]
}

// ActivationID is what an accepted activation contributes to the app hash and records.
func (t *G1ActivationTx) ActivationID() string {
	return "g1-activation:" + hex.EncodeToString(t.SigningBytes())
}

// DecodeG1Activation returns the transaction if these bytes are one. The discriminator is the explicit kind; bytes of the
// kind that do not decode are still the kind, refused by CheckShape, never judged as a ValidatorBlock.
func DecodeG1Activation(tx []byte) (*G1ActivationTx, bool) {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(tx, &probe); err != nil || probe.Kind != G1ActivationKind {
		return nil, false
	}
	var t G1ActivationTx
	if err := json.Unmarshal(tx, &t); err != nil {
		return &G1ActivationTx{Kind: G1ActivationKind}, true
	}
	return &t, true
}

// CheckShape is the stateless part of verification, used by CheckTx as a mempool filter: everything except the chain,
// whether one is already recorded and the admin quorum.
func (t *G1ActivationTx) CheckShape() error {
	if t.Kind != G1ActivationKind {
		return fmt.Errorf("kind %q is not %q", t.Kind, G1ActivationKind)
	}
	if strings.TrimSpace(t.ChainID) == "" {
		return fmt.Errorf("a cross-partition activation names its chain")
	}
	if t.Version != 1 {
		return fmt.Errorf("a cross-partition activation is version 1: the chain activates once, and %d is not that version", t.Version)
	}
	return nil
}

// G1ActivationAt is the activation in force for a block at height h: the activation accepted below h. Nil when there is
// none - the chain has not reached the v15 activation, or h is at or below the block that accepted it.
func G1ActivationAt(log *ledger.G1ActivationLog, h int64) *ledger.G1ActivationRecord {
	if log == nil {
		return nil
	}
	for i := range log.Activations {
		if log.Activations[i].Height < h {
			return &log.Activations[i]
		}
	}
	return nil
}

// VerifyG1Activation judges an activation transaction for a block at height h against committed state - the policy,
// whose admin set in force at h (AdminSetAt) must authorise it, and the activations accepted before it - and returns the
// record it sets.
func VerifyG1Activation(t *G1ActivationTx, chainID string, policy *ledger.EntitlementPolicyState, log *ledger.G1ActivationLog,
	h int64) (*ledger.G1ActivationRecord, error) {
	policy = withAdminSetAt(policy, h)
	if err := t.CheckShape(); err != nil {
		return nil, err
	}
	if t.ChainID != chainID {
		return nil, fmt.Errorf("the activation is for chain %q, this is %q", t.ChainID, chainID)
	}
	if log != nil && len(log.Activations) > 0 {
		return nil, fmt.Errorf("the chain activated cross-partition evidence at height %d: an activation cannot be replayed, "+
			"moved or undone", log.Activations[0].Height)
	}
	if err := verifyAdminQuorum(t.SigningBytes(), t.Signatures, policy, "cross-partition activation", "no activation can be set"); err != nil {
		return nil, err
	}
	return &ledger.G1ActivationRecord{Version: t.Version, Height: h, ID: t.ActivationID()}, nil
}

// G1CrossPartitionRequired is whether a ValidatorBlock judged with activation in force (G1ActivationAt for its height)
// must carry evidence 2.1. It depends only on committed state, so every validator switches at the same block.
func G1CrossPartitionRequired(activation *ledger.G1ActivationRecord) bool {
	return activation != nil
}
