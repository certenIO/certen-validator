// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// Building a recorded outcome's offline evidence from the chain (RB5-F15)
// =============================================================================
//
// Built once an outcome's record is final, from the same agreed reads the outcome was derived from (RB5-F53): every
// header is the agreed header at its height, and every proof is checked against that header's roots before it is
// kept, whichever provider served the bytes. The evidence is then verified by the reader's own offline check
// (OutcomeEvidence.VerifyOffline) before it is returned - the write path never stores what the read path refuses.

// OutcomeEvidenceReader is what building an outcome's evidence reads of a chain, beyond OutcomeChain.
type OutcomeEvidenceReader interface {
	// Anchor is the CertenAnchorV8_2 the chain's outcomes are of.
	Anchor() common.Address
	// TransactionInclusion proves a FINAL transaction and its receipt into its block: the agreed header (canonical at
	// its height, at or below the finalized block) and both trie proofs against its roots.
	TransactionInclusion(ctx context.Context, tx common.Hash) (*ChainInclusionEvidence, *types.Header, error)
	// StateProofsAt proves each slot at the header's state root.
	StateProofsAt(ctx context.Context, header *types.Header, slots []ExpectedStateSlot) ([]*StateProof, error)
	// QuorumRegistryAt is the anchor's validator registry at the header: every validator (address, power, BLS key) and
	// its threshold.
	QuorumRegistryAt(ctx context.Context, header *types.Header) (*OutcomeQuorumRegistry, error)
}

// OutcomeQuorumRegistry is an anchor's validator registry as read.
type OutcomeQuorumRegistry struct {
	Validators           []OutcomeQuorumValidator
	ThresholdNumerator   uint64
	ThresholdDenominator uint64
}

// OutcomeEvidenceSource is everything building evidence reads.
type OutcomeEvidenceSource interface {
	OutcomeEvidenceReader
	HeaderAt(ctx context.Context, number uint64) (*types.Header, error)
}

// OutcomeEvidenceInput is a recorded outcome to build the evidence of.
type OutcomeEvidenceInput struct {
	Registry common.Address
	Anchor   common.Address
	// Tree is the anchor's batch tree with each member's leaf inputs, committed calls and effects, account and deadline;
	// Leaves its outcome leaves in tree order.
	Tree   *OutcomeTree
	Leaves []OutcomeLeaf
	// View is the anchor and registry at a recent agreed block: the CERTEN set root and the validator registry are read
	// there, and must reproduce the message the record covers.
	View   *OutcomeAnchorView
	Record *RecordedOutcomeTx
	// AggregateSignature and AggregatePublicKey are the BLS aggregate, when this validator holds it ("" otherwise).
	AggregateSignature string
	AggregatePublicKey string
}

// BuildRecordEvidence builds, and verifies offline, the evidence of a recorded outcome that every member's evidence
// shares: the anchor's commitment as the chain holds it (view.Anchor), the record transaction proven into its block, and
// the quorum - the anchor's registry, which must derive the set root the message covers, and the proof submitted.
func BuildRecordEvidence(ctx context.Context, c OutcomeEvidenceSource, chainID int64, registry, anchor common.Address,
	view *OutcomeAnchorView, rec *RecordedOutcomeTx, aggSig, aggPub string) (*OutcomeEvidence, error) {
	if c == nil || rec == nil || view == nil || view.At == nil || view.Anchor == nil {
		return nil, fmt.Errorf("%w: building evidence needs the chain, the record and an agreed view of the anchor", ErrOutcome)
	}
	a := view.Anchor
	if !a.Valid || a.Version != contracts.BatchAnchorV8_2 || a.AccumulateBlockHeight == nil || !a.AccumulateBlockHeight.IsUint64() {
		return nil, fmt.Errorf("%w: anchor 0x%x is not a valid V8.2 batch anchor", ErrOutcome, rec.BundleID[:8])
	}
	msg := contracts.ComputeEvmMessageHashV8_2_Outcome(chainID, rec.BundleID, rec.Root, view.CurrentSetRoot, a.AccumulateSetRoot, a.Incarnation)
	if msg != rec.MessageHash {
		return nil, fmt.Errorf("%w: the record signed message 0x%x, which the anchor's current CERTEN set root 0x%x does not reproduce; "+
			"the set it was certified by is not readable now", ErrOutcome, rec.MessageHash[:8], view.CurrentSetRoot[:8])
	}
	h := func(b [32]byte) string { return "0x" + hex.EncodeToString(b[:]) }
	ev := &OutcomeEvidence{
		Version: OutcomeEvidenceVersion, ChainID: chainID, Registry: strings.ToLower(registry.Hex()),
		Anchor: OutcomeAnchorEvidence{Address: strings.ToLower(anchor.Hex()), BundleID: h(rec.BundleID), BatchRoot: h(a.MerkleRoot),
			LeafCount: view.LeafCount, BatchOperationID: h(a.OperationID), AccumulateBlockHeight: a.AccumulateBlockHeight.Uint64(),
			AccumulateSetRoot: h(a.AccumulateSetRoot), Incarnation: h(a.Incarnation), CertenSetRoot: h(view.CurrentSetRoot)},
	}

	incl, hdr, err := c.TransactionInclusion(ctx, rec.Tx)
	if err != nil {
		return nil, fmt.Errorf("the record transaction %s: %w", rec.Tx.Hex(), err)
	}
	if hdr.Number.Uint64() != rec.Block {
		return nil, fmt.Errorf("%w: the record transaction %s is in block %d, the registry records block %d", ErrOutcome, rec.Tx.Hex(),
			hdr.Number.Uint64(), rec.Block)
	}
	ev.Record = OutcomeRecordEvidence{OutcomeRoot: h(rec.Root), MessageHash: h(msg), Recorder: strings.ToLower(rec.Recorder.Hex()),
		Tx: strings.ToLower(rec.Tx.Hex()), BlockNumber: rec.Block, BlockHash: strings.ToLower(hdr.Hash().Hex()), Inclusion: *incl}

	reg, err := c.QuorumRegistryAt(ctx, view.At)
	if err != nil {
		return nil, fmt.Errorf("the anchor's validator registry: %w", err)
	}
	q := OutcomeQuorumEvidence{Scheme: OutcomeQuorumScheme, ThresholdNumerator: reg.ThresholdNumerator,
		ThresholdDenominator: reg.ThresholdDenominator, Validators: append([]OutcomeQuorumValidator(nil), reg.Validators...),
		ZKProof: append(hexutil.Bytes(nil), rec.Proof.AggregateSignature...), AggregateSignature: aggSig, AggregatePublicKey: aggPub}
	SortQuorumValidators(q.Validators)
	if rec.Proof.SignedVotingPower == nil || rec.Proof.TotalVotingPower == nil {
		return nil, fmt.Errorf("%w: the record's proof states no voting power", ErrOutcome)
	}
	q.SignedVotingPower, q.TotalVotingPower = rec.Proof.SignedVotingPower.String(), rec.Proof.TotalVotingPower.String()
	for i, addr := range rec.Proof.ValidatorAddresses {
		if i >= len(rec.Proof.VotingPowers) || rec.Proof.VotingPowers[i] == nil {
			return nil, fmt.Errorf("%w: the record's proof states signer %d without its power", ErrOutcome, i)
		}
		q.Signers = append(q.Signers, strings.ToLower(addr.Hex()))
		q.SignerPowers = append(q.SignerPowers, rec.Proof.VotingPowers[i].String())
	}
	ev.Quorum = q
	if _, err := ev.VerifyRecordOffline(); err != nil {
		return nil, fmt.Errorf("the record's evidence does not verify offline, so it is not kept: %w", err)
	}
	return ev, nil
}

// BuildOutcomeEvidence builds, and verifies offline, every member's evidence of a recorded outcome.
func BuildOutcomeEvidence(ctx context.Context, c OutcomeEvidenceSource, in OutcomeEvidenceInput) ([]*OutcomeEvidence, error) {
	t, rec, view := in.Tree, in.Record, in.View
	if c == nil || t == nil || rec == nil || view == nil || view.At == nil || view.Anchor == nil {
		return nil, fmt.Errorf("%w: building evidence needs the chain, the tree, the record and an agreed view", ErrOutcome)
	}
	if len(in.Leaves) != len(t.Members) || len(t.Members) == 0 {
		return nil, fmt.Errorf("%w: %d outcome leaves for %d members", ErrOutcome, len(in.Leaves), len(t.Members))
	}
	if rec.BundleID != t.BundleID {
		return nil, fmt.Errorf("%w: a record of anchor 0x%x for the tree of 0x%x", ErrOutcome, rec.BundleID[:8], t.BundleID[:8])
	}
	if err := checkAnchorIsTree(view, t); err != nil {
		return nil, err
	}
	root, err := OutcomeRoot(in.Leaves, uint64(len(t.Members)))
	if err != nil {
		return nil, err
	}
	if root != rec.Root {
		return nil, fmt.Errorf("%w: the leaves form outcome root 0x%x, the record names 0x%x", ErrOutcomeContradiction, root[:8], rec.Root[:8])
	}
	base, err := BuildRecordEvidence(ctx, c, t.ChainID, in.Registry, in.Anchor, view, rec, in.AggregateSignature, in.AggregatePublicKey)
	if err != nil {
		return nil, err
	}

	// The branches: the outcome tree and the batch tree, both in tree order.
	outcomeHashes := make([][32]byte, len(in.Leaves))
	batchLeaves := make([][32]byte, len(t.Members))
	for i, l := range in.Leaves {
		if outcomeHashes[i], err = l.Hash(); err != nil {
			return nil, err
		}
		batchLeaves[i] = t.Members[i].Leaf
	}

	out := make([]*OutcomeEvidence, 0, len(t.Members))
	for i, m := range t.Members {
		ev := *base
		leaf := in.Leaves[i]
		if leaf.LeafIndex != m.LeafIndex || leaf.BatchLeaf != m.Leaf || leaf.OperationID != m.OperationID {
			return nil, fmt.Errorf("%w: outcome leaf %d is not of member %d", ErrOutcome, leaf.LeafIndex, i)
		}
		ob, err := MerkleBranch(outcomeHashes, i)
		if err != nil {
			return nil, err
		}
		bb, err := MerkleBranch(batchLeaves, i)
		if err != nil {
			return nil, err
		}
		ev.Member, err = buildMemberEvidence(ctx, c, m, leaf, ob, bb)
		if err != nil {
			return nil, fmt.Errorf("member %d (operation 0x%x): %w", i, m.OperationID[:8], err)
		}
		if _, err := ev.VerifyOffline(); err != nil {
			return nil, fmt.Errorf("member %d's evidence does not verify offline, so it is not kept: %w", i, err)
		}
		out = append(out, &ev)
	}
	return out, nil
}

func hexBranch(b [][32]byte) []string {
	out := make([]string, 0, len(b))
	for _, x := range b {
		out = append(out, "0x"+hex.EncodeToString(x[:]))
	}
	return out
}

func buildMemberEvidence(ctx context.Context, c OutcomeEvidenceSource, m OutcomeTreeMember, leaf OutcomeLeaf, outcomeBranch,
	batchBranch [][32]byte) (OutcomeMemberEvidence, error) {
	h := func(b [32]byte) string { return "0x" + hex.EncodeToString(b[:]) }
	ev := OutcomeMemberEvidence{
		Leaf: OutcomeLeafEvidence{LeafIndex: leaf.LeafIndex, BatchLeaf: h(leaf.BatchLeaf), OperationID: h(leaf.OperationID),
			Status: uint8(leaf.Status), Tx: h(leaf.Tx), BlockNumber: leaf.BlockNumber, BlockHash: h(leaf.BlockHash),
			ReceiptsRoot: h(leaf.ReceiptsRoot), EffectsHash: h(leaf.EffectsHash)},
		OutcomeBranch: hexBranch(outcomeBranch), BatchBranch: hexBranch(batchBranch),
		Account: strings.ToLower(m.Account.Hex()), ADIURL: m.ADIURL, AuthorityBook: h(m.AuthorityBook), AuthorityPage: m.AuthorityPage,
		Legs: m.Legs, Deadline: m.Deadline, FinalityMargin: int64(nonSettlementFinality.Seconds()),
	}
	switch leaf.Status {
	case OutcomeExecuted, OutcomeEffectsNotProven, OutcomeConsumedElsewhere:
		incl, hdr, err := c.TransactionInclusion(ctx, common.Hash(leaf.Tx))
		if err != nil {
			return ev, err
		}
		if hdr.Hash() != common.Hash(leaf.BlockHash) {
			return ev, fmt.Errorf("%w: %s is in block %s, the leaf names 0x%x", ErrOutcomeContradiction, common.Hash(leaf.Tx).Hex(),
				hdr.Hash().Hex(), leaf.BlockHash)
		}
		ev.Transaction = incl
		if leaf.Status != OutcomeConsumedElsewhere {
			var slots []ExpectedStateSlot
			for _, l := range m.Legs {
				slots = append(slots, l.State...)
			}
			if len(slots) > 0 {
				if ev.StateProofs, err = c.StateProofsAt(ctx, hdr, slots); err != nil {
					return ev, err
				}
			}
		}
	case OutcomeNotSettled:
		claim, err := c.HeaderAt(ctx, leaf.BlockNumber)
		if err != nil {
			return ev, err
		}
		if claim.Hash() != common.Hash(leaf.BlockHash) {
			return ev, fmt.Errorf("%w: the claim block %d is %s, the leaf names 0x%x", ErrOutcomeContradiction, leaf.BlockNumber,
				claim.Hash().Hex(), leaf.BlockHash)
		}
		parent, err := c.HeaderAt(ctx, leaf.BlockNumber-1)
		if err != nil {
			return ev, err
		}
		if ev.ClaimHeader, err = rlp.EncodeToBytes(claim); err != nil {
			return ev, err
		}
		if ev.ClaimParentHeader, err = rlp.EncodeToBytes(parent); err != nil {
			return ev, err
		}
		if leaf.Tx != ([32]byte{}) {
			incl, _, err := c.TransactionInclusion(ctx, common.Hash(leaf.Tx))
			if err != nil {
				return ev, fmt.Errorf("its last attempt: %w", err)
			}
			ev.Transaction = incl
		}
	default:
		return ev, fmt.Errorf("%w: status %d", ErrOutcome, leaf.Status)
	}
	return ev, nil
}

// =============================================================================
// The agreed chain's evidence reads
// =============================================================================

// TransactionInclusion: see OutcomeEvidenceReader.
func (c *AgreedOutcomeChain) TransactionInclusion(ctx context.Context, tx common.Hash) (*ChainInclusionEvidence, *types.Header, error) {
	if err := c.requireFinal(ctx, tx); err != nil {
		return nil, nil, err
	}
	r, err := c.reader.TransactionReceipt(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	hdr, err := c.HeaderAt(ctx, r.BlockNumber.Uint64())
	if err != nil {
		return nil, nil, err
	}
	if hdr.Hash() != r.BlockHash {
		return nil, nil, outcomeNotYet("%s's receipt names block %s, the agreed block at %d is %s", tx.Hex(), r.BlockHash.Hex(),
			r.BlockNumber.Uint64(), hdr.Hash().Hex())
	}
	txp, rcp, err := c.observer.inclusionProofsFromRaw(ctx, hdr, r.TransactionIndex)
	if err != nil {
		return nil, nil, readErr(fmt.Errorf("inclusion proofs of %s in block %d: %w", tx.Hex(), hdr.Number.Uint64(), err))
	}
	raw, err := rlp.EncodeToBytes(hdr)
	if err != nil {
		return nil, nil, err
	}
	out := &ChainInclusionEvidence{Header: raw, Index: uint64(r.TransactionIndex), Transaction: txp.LeafValue, Receipt: rcp.LeafValue}
	for _, n := range txp.ProofNodes {
		out.TransactionProof = append(out.TransactionProof, n)
	}
	for _, n := range rcp.ProofNodes {
		out.ReceiptProof = append(out.ReceiptProof, n)
	}
	return out, hdr, nil
}

// StateProofsAt: see OutcomeEvidenceReader. Every slot needs a proof that verifies against the agreed header's state
// root, whichever provider served it.
func (c *AgreedOutcomeChain) StateProofsAt(ctx context.Context, header *types.Header, slots []ExpectedStateSlot) ([]*StateProof, error) {
	proofs := c.observer.fetchStateProofs(ctx, header.Number, slots)
	var out []*StateProof
	for i, s := range slots {
		var found *StateProof
		for _, p := range proofs {
			if p != nil && p.Account == s.Account && p.Slot == s.Slot && p.Verify(header.Root) {
				found = p
				break
			}
		}
		if found == nil {
			return nil, readErr(fmt.Errorf("committed slot %d (%s[%s]) has no state proof verifying at block %d's state root",
				i, s.Account.Hex(), s.Slot.Hex(), header.Number.Uint64()))
		}
		out = append(out, found)
	}
	return out, nil
}

// outcomeQuorumABI is the part of CertenAnchorV8_2 the validator registry is read through.
var outcomeQuorumABI = mustParseABI(`[
  {"type":"function","name":"getValidatorCount","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
  {"type":"function","name":"validatorList","inputs":[{"name":"","type":"uint256"}],"outputs":[{"name":"","type":"address"}],"stateMutability":"view"},
  {"type":"function","name":"validators","inputs":[{"name":"","type":"address"}],"outputs":[{"name":"registered","type":"bool"},{"name":"votingPower","type":"uint256"},{"name":"blsPublicKey","type":"bytes"},{"name":"registeredAt","type":"uint256"}],"stateMutability":"view"},
  {"type":"function","name":"blsThresholdNumerator","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
  {"type":"function","name":"blsThresholdDenominator","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
  {"type":"function","name":"totalVotingPower","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
  {"type":"function","name":"pubkeyBindingEnforced","inputs":[],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"},
  {"type":"function","name":"authorizedPubkeyCommitments","inputs":[{"name":"","type":"bytes32"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"}
]`)

// QuorumRegistryAt: see OutcomeEvidenceReader.
func (c *AgreedOutcomeChain) QuorumRegistryAt(ctx context.Context, header *types.Header) (*OutcomeQuorumRegistry, error) {
	return readQuorumRegistry(func(method string, args ...interface{}) ([]interface{}, error) {
		return c.call(ctx, outcomeQuorumABI, c.anchor, header.Hash(), method, args...)
	})
}

// readQuorumRegistry reads every validator of the anchor's list, and its threshold, through call.
func readQuorumRegistry(call func(method string, args ...interface{}) ([]interface{}, error)) (*OutcomeQuorumRegistry, error) {
	word := func(method string, args ...interface{}) (*big.Int, error) {
		out, err := call(method, args...)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", method, err)
		}
		n, ok := out[0].(*big.Int)
		if !ok || !n.IsUint64() {
			return nil, fmt.Errorf("%s returned %v", method, out[0])
		}
		return n, nil
	}
	count, err := word("getValidatorCount")
	if err != nil {
		return nil, err
	}
	num, err := word("blsThresholdNumerator")
	if err != nil {
		return nil, err
	}
	den, err := word("blsThresholdDenominator")
	if err != nil {
		return nil, err
	}
	total, err := word("totalVotingPower")
	if err != nil {
		return nil, err
	}
	reg := &OutcomeQuorumRegistry{ThresholdNumerator: num.Uint64(), ThresholdDenominator: den.Uint64()}
	sum := new(big.Int)
	for i := uint64(0); i < count.Uint64(); i++ {
		out, err := call("validatorList", new(big.Int).SetUint64(i))
		if err != nil {
			return nil, fmt.Errorf("validatorList(%d): %w", i, err)
		}
		addr, ok := out[0].(common.Address)
		if !ok {
			return nil, fmt.Errorf("validatorList(%d) returned %T", i, out[0])
		}
		info, err := call("validators", addr)
		if err != nil {
			return nil, fmt.Errorf("validators(%s): %w", addr.Hex(), err)
		}
		registered, _ := info[0].(bool)
		power, _ := info[1].(*big.Int)
		key, _ := info[2].([]byte)
		if !registered || power == nil || power.Sign() <= 0 || len(key) == 0 {
			return nil, fmt.Errorf("validatorList(%d) = %s is not a registered validator with power and a BLS key", i, addr.Hex())
		}
		sum.Add(sum, power)
		reg.Validators = append(reg.Validators, OutcomeQuorumValidator{Address: strings.ToLower(addr.Hex()), VotingPower: power.String(),
			BLSPublicKey: "0x" + hex.EncodeToString(key)})
	}
	if sum.Cmp(total) != 0 {
		return nil, fmt.Errorf("the listed validators' powers sum to %s, the anchor's totalVotingPower is %s", sum, total)
	}
	return reg, nil
}
