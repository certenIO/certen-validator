// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// THE authorization of a captured batch (RB12-INDEX-B, the Arbitrum analog of baseposted/authorize.go). One rule, one function, and every
// reader of batch records asks it: the capture (Capturer.proveAt, when it stores the proof of a batch), the reference reader (arbposted
// Builder.locate over the window candidates), the indexed reader (arbposted IndexReader) and the index writer.
//
// What "posted by the SequencerInbox's authorized batch poster" can mean here, established from the contracts and the verifier:
//
//   - A SequencerBatchDelivered event can only be emitted by the SequencerInbox after its own poster check (isBatchPoster[msg.sender] in
//     addSequencerL2BatchFromOrigin / addSequencerL2BatchFromBlobs) or by forceInclusion (data location NoData, which carries no batch
//     data). The set of posters is contract state that no pin of the verifier names; the verifier's authority is the Bridge: a batch
//     exists for it exactly when Bridge.sequencerInboxAccs[N] holds keccak256(beforeAcc || dataHash || delayedAcc) (verify.go, annex A6.3),
//     and only the SequencerInbox, after its poster check, can write that slot.
//   - So a captured record is the poster's batch exactly when the Bridge accumulator it names is the one the chain holds: its own afterAcc
//     equals the value a captured, VERIFIED proof shows at slot sequencerInboxAccs[N] (account and storage proofs checked under the state
//     root of a header row whose hash is its key). A record the chain does not hold - an event a provider invented, the orphan twin of a
//     reorged batch (the same N under two L1 blocks), a record with a zero accumulator - is foreign.
//
// Three verdicts, never a fourth: a record no verified proof can judge yet is UNPROVEN and is kept (the verifier of the leg decides, and a
// batch without a captured proof is the named l1_proof_window_unavailable), a record a verified proof confirms is PROVEN, a record a
// verified proof contradicts is FOREIGN and no reader may serve it. Proofs taken at a block BELOW the batch's own L1 block are not
// evidence about it (the slot is still empty there) and are ignored.

// Authorization is the verdict of AuthorizeBatch.
type Authorization uint8

const (
	// AuthUnproven: no captured, verified proof of the accumulator at or after the batch's block can judge the record.
	AuthUnproven Authorization = iota
	// AuthProven: a verified proof shows Bridge.sequencerInboxAccs[N] == the record's afterAcc.
	AuthProven
	// AuthForeign: a verified proof shows another value (or an empty slot) and none shows the record's afterAcc.
	AuthForeign
)

func (a Authorization) String() string {
	switch a {
	case AuthProven:
		return "proven"
	case AuthForeign:
		return "foreign"
	}
	return "unproven"
}

// ProofView is a captured batch-accumulator proof with the state root of its proof block: the root comes from the header row stored at the
// proof row's own key, whose keccak256 is the key's hash, so it is the root of the block the key names.
type ProofView struct {
	Rec       ProofRecord
	Block     uint64
	StateRoot [32]byte
}

// AuthorizeBatch judges rec against the proofs. bridge and accSlot are the pinned Bridge address and the storage slot of its
// sequencerInboxAccs array (arb_sepolia.bridge, arb_sepolia.layout.acc_array_slot).
func AuthorizeBatch(rec BatchRecord, bridge [20]byte, accSlot uint64, views []ProofView) Authorization {
	proven, foreign := false, false
	slot := ArraySlot(accSlot, rec.N)
	for _, v := range views {
		p := v.Rec
		if p.Kind != ProofBatchAcc || p.Index != rec.N || v.Block < rec.L1Block {
			continue
		}
		acct, err := ethproof.VerifyAccount(common.Hash(v.StateRoot), common.Address(bridge), p.Nodes)
		if err != nil || acct == nil || !acct.Exists {
			continue
		}
		word, err := ethproof.VerifySlot(acct.StorageRoot, common.Hash(slot), p.Nodes)
		if err != nil {
			continue
		}
		switch {
		case word == (common.Hash{}):
			foreign = true // the chain holds no batch N at this block, which is at or after the record's own block
		case [32]byte(word) == rec.AfterAcc:
			proven = true
		default:
			foreign = true
		}
	}
	switch {
	case proven:
		return AuthProven
	case foreign:
		return AuthForeign
	}
	return AuthUnproven
}

// LoadProofViews returns the captured accumulator proofs of batch n stored at or after fromBlock, each with the state root of its proof
// block. A proof whose header row is absent, does not hash to the key, or names another height is left out (it judges nothing). Rows are
// reserved against the hold ctx carries.
func LoadProofViews(ctx context.Context, s CaptureStore, chain, n, fromBlock uint64) ([]ProofView, error) {
	keys, err := s.ListByRange(ctx, chain, fromBlock, finality.MaxCaptureBlock, ItemProof(n))
	if err != nil {
		return nil, err
	}
	var out []ProofView
	for _, k := range keys {
		if k.Item != ItemProof(n) {
			continue
		}
		b, ok, err := s.Get(ctx, k)
		if err != nil || !ok {
			return nil, fmt.Errorf("capture: row %s unreadable: %v", k, err)
		}
		if err := finality.ReserveRow(ctx, len(b)); err != nil {
			return nil, err
		}
		p, err := DecodeProofRecord(b)
		if err != nil {
			return nil, fmt.Errorf("capture: row %s: %w", k, err)
		}
		hk := k
		hk.Item = ItemHeader
		hb, ok, err := s.Get(ctx, hk)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if err := finality.ReserveRow(ctx, len(hb)); err != nil {
			return nil, err
		}
		if crypto.Keccak256Hash(hb) != common.Hash(k.L1Hash) {
			continue
		}
		hf, err := finality.ReadHeader(hb)
		if err != nil || hf.Number != k.L1Block {
			continue
		}
		out = append(out, ProofView{Rec: p, Block: k.L1Block, StateRoot: hf.StateRoot})
	}
	return out, nil
}
