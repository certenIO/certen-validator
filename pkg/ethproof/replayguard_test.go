// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/certen/independant-validator/pkg/ethproof"
)

func TestReplayGuard_ValidAtTheSettlementBlock(t *testing.T) {
	w := newWorld(t, worldOpts{after: 0})
	chk, err := w.proof.Verify(w.settlement)
	if err != nil {
		t.Fatal(err)
	}
	if chk.State != ethproof.ReplayProven || !chk.BeforeVerified || chk.BeforeUnavailable != nil || len(chk.Established) != 2 {
		t.Fatalf("%+v", chk)
	}
	if chk.ProvenAt.Number != testN || chk.SettlementBlock.Number != testN || chk.CodeHash == (common.Hash{}) {
		t.Fatalf("%+v", chk)
	}
}

func TestReplayGuard_ValidAfterAHeaderChain(t *testing.T) {
	w := newWorld(t, worldOpts{after: 3})
	chk, err := w.proof.Verify(w.settlement)
	if err != nil {
		t.Fatal(err)
	}
	if chk.ProvenAt.Number != testN+3 || !chk.BeforeVerified {
		t.Fatalf("%+v", chk)
	}
	// The batch entry point is a settlement call of the same generation.
	wb := newWorld(t, worldOpts{after: 1, selector: v73Batch})
	if _, err := wb.proof.Verify(wb.settlement); err != nil {
		t.Fatalf("batch settlement: %v", err)
	}
	// The evidence wrapper verifies the same.
	ev := &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, Proof: w.proof}
	if _, err := ev.Verify(w.settlement); err != nil {
		t.Fatal(err)
	}
	// And survives its JSON.
	enc, _ := json.Marshal(ev)
	var back ethproof.ReplayGuardEvidence
	if err := json.Unmarshal(enc, &back); err != nil {
		t.Fatal(err)
	}
	if _, err := back.Verify(w.settlement); err != nil {
		t.Fatalf("after a JSON round trip: %v", err)
	}
}

func TestReplayGuard_TheContractMayNotExistYetAtTheParent(t *testing.T) {
	w := newWorld(t, worldOpts{after: 0, noBeforeAcc: true})
	if !w.proof.Before.Proof.AccountAbsent {
		t.Fatal("the Before proof must be an exclusion proof")
	}
	chk, err := w.proof.Verify(w.settlement)
	if err != nil || !chk.BeforeVerified {
		t.Fatalf("an absent account at the parent is a slot of 0: %v %+v", err, chk)
	}
}

func TestReplayGuard_BeforeUnavailableIsDisclosedNotFailed(t *testing.T) {
	w := newWorld(t, worldOpts{after: 1})
	p := w.clone()
	p.Before = nil
	p.BeforeUnavailable = &ethproof.ReplayBeforeUnavailable{Reason: "no provider served block 4999",
		Providers: []ethproof.ReplayProviderFailure{{Host: "rpc.telcoin.network", Error: "distance to target block exceeds maximum proof window"}}}
	chk, err := p.Verify(w.settlement)
	if err != nil {
		t.Fatal(err)
	}
	if chk.BeforeVerified || chk.BeforeUnavailable == nil || chk.BeforeUnavailable.Providers[0].Host != "rpc.telcoin.network" || len(chk.Established) != 1 {
		t.Fatalf("%+v", chk)
	}
	// Neither a Before proof nor the disclosure: refused, never silently omitted.
	p2 := w.clone()
	p2.Before = nil
	_, err = p2.Verify(w.settlement)
	refusedAs(t, "Before neither proven nor disclosed", err, ethproof.ReplayUnproven, ethproof.ReasonBeforeUndisclosed)
	// Both: refused.
	p3 := w.clone()
	p3.BeforeUnavailable = p.BeforeUnavailable
	_, err = p3.Verify(w.settlement)
	refusedAs(t, "Before and its disclosure both carried", err, ethproof.ReplayUnproven, ethproof.ReasonBeforeUndisclosed)
	// A disclosure with no reason is no disclosure.
	p4 := w.clone()
	p4.Before = nil
	p4.BeforeUnavailable = &ethproof.ReplayBeforeUnavailable{}
	_, err = p4.Verify(w.settlement)
	refusedAs(t, "a reasonless disclosure", err, ethproof.ReplayUnproven, ethproof.ReasonBeforeUndisclosed)
}

// A status-1 receipt cannot follow a state in which the leaf was already consumed: a Before proof of 1 is a contradiction.
func TestReplayGuard_BeforeSaysOneIsRefuted(t *testing.T) {
	w := newWorld(t, worldOpts{after: 0})
	p := w.clone()
	p.Before.Proof = w.after.prove(w.contract, w.slot) // the consumed state, served as the parent's
	// The parent header must root that state for the proof to verify at all; rebuild it so the only fault is the value.
	parent := *w.parent
	parent.Root = w.after.root
	hdrN := *w.headerN
	hdrN.ParentHash = parent.Hash()
	p.Before.ParentHeader = rawHeader(t, &parent)
	// Re-prove the settlement in the block that names this parent.
	txEnc, _ := w.tx.MarshalBinary()
	rcEnc, _ := w.receipt.MarshalBinary()
	blk := &ethproof.Block{Header: &hdrN, Txs: [][]byte{txEnc}, Receipts: [][]byte{rcEnc}}
	s, err := blk.Prove(w.tx.Hash(), 0)
	if err != nil {
		t.Fatal(err)
	}
	p.SettlementBlock = ethproof.BlockRef{Number: testN, Hash: hdrN.Hash()}
	p.ProvenAt = p.SettlementBlock
	_, err = p.Verify(s)
	refusedAs(t, "slot already 1 at the parent", err, ethproof.ReplayRefuted, ethproof.ReasonSlotSetAtParent)
}

func TestReplayGuard_AfterValueZeroIsRefuted(t *testing.T) {
	w := newWorld(t, worldOpts{after: 0})
	p := w.clone()
	p.After = w.before.prove(w.contract, w.slot) // the unconsumed state
	// Proven against the settlement block's root it does not verify; against a header that roots the unconsumed state it
	// proves 0: build the block so that the proof is VALID and says 0.
	hdrN := *w.headerN
	hdrN.Root = w.before.root
	txEnc, _ := w.tx.MarshalBinary()
	rcEnc, _ := w.receipt.MarshalBinary()
	blk := &ethproof.Block{Header: &hdrN, Txs: [][]byte{txEnc}, Receipts: [][]byte{rcEnc}}
	s, err := blk.Prove(w.tx.Hash(), 0)
	if err != nil {
		t.Fatal(err)
	}
	p.SettlementBlock = ethproof.BlockRef{Number: testN, Hash: hdrN.Hash()}
	p.ProvenAt = p.SettlementBlock
	_, err = p.Verify(s)
	refusedAs(t, "After proves the slot unset", err, ethproof.ReplayRefuted, ethproof.ReasonSlotUnsetAtBlock)
}

func TestReplayGuard_WrongMappingKey(t *testing.T) {
	w := newWorld(t, worldOpts{after: 0})
	wrong := common.HexToHash("0x3039") // a leaf that IS consumed in the state, but is not this receipt's
	p := w.clone()
	p.Slot.Key = wrong
	p.Slot.Slot = ethproof.ReplaySlotFor(wrong, 4)
	p.After = w.after.prove(w.contract, p.Slot.Slot)
	p.Before.Proof = w.before.prove(w.contract, p.Slot.Slot)
	_, err := p.Verify(w.settlement)
	refusedAs(t, "a consumed slot of another leaf", err, ethproof.ReplayUnproven, ethproof.ReasonSlotMismatch)

	// The right key with a slot taken from another key, or another base.
	p2 := w.clone()
	p2.Slot.Slot = ethproof.ReplaySlotFor(wrong, 4)
	_, err = p2.Verify(w.settlement)
	refusedAs(t, "the slot is not derived from the key", err, ethproof.ReplayUnproven, ethproof.ReasonSlotMismatch)
	p3 := w.clone()
	p3.Slot.Base = 5
	p3.Slot.Slot = ethproof.ReplaySlotFor(w.leaf, 5)
	_, err = p3.Verify(w.settlement)
	refusedAs(t, "another base than the pinned layout's", err, ethproof.ReplayUnproven, ethproof.ReasonSlotMismatch)
	p4 := w.clone()
	p4.Slot.Derivation = "keccak256(abi.encode(base, key))"
	_, err = p4.Verify(w.settlement)
	refusedAs(t, "another derivation", err, ethproof.ReplayUnproven, ethproof.ReasonSlotMismatch)
}

func TestReplayGuard_ProofAgainstAnotherBlocksRoot(t *testing.T) {
	w := newWorld(t, worldOpts{after: 2})
	// After proven in the state of an unrelated block.
	other := buildState(t, account{addr: testOther}, account{addr: testContract, code: testCode, storage: map[common.Hash]*big.Int{w.slot: big.NewInt(1), common.BigToHash(big.NewInt(77)): big.NewInt(5)}})
	p := w.clone()
	p.After = other.prove(w.contract, w.slot)
	_, err := p.Verify(w.settlement)
	refusedAs(t, "After from another state root", err, ethproof.ReplayUnproven, ethproof.ReasonProofDoesNotVerify)

	// The settlement block's root, claimed for a later block of the chain.
	p2 := w.clone()
	p2.After = w.after.prove(w.contract, w.slot)
	// every header of the chain roots the same state here, so make the last one root another.
	last := *w.chain[len(w.chain)-1]
	last.Root = other.root
	p2.Headers[len(p2.Headers)-1] = rawHeader(t, &last)
	p2.ProvenAt = ethproof.BlockRef{Number: last.Number.Uint64(), Hash: last.Hash()}
	_, err = p2.Verify(w.settlement)
	refusedAs(t, "After proven against the root of another block", err, ethproof.ReplayUnproven, ethproof.ReasonProofDoesNotVerify)

	// Before proven against the wrong parent state root.
	p3 := w.clone()
	p3.Before.Proof = other.prove(w.contract, w.slot)
	_, err = p3.Verify(w.settlement)
	refusedAs(t, "Before from another state root", err, ethproof.ReplayUnproven, ethproof.ReasonProofDoesNotVerify)
}

func TestReplayGuard_EventFromAnotherContract(t *testing.T) {
	// The account emits nothing; another contract emits a LeafConsumed with the leaf.
	attacker := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	w := newWorld(t, worldOpts{after: 0, eventFrom: &attacker})
	_, err := w.proof.Verify(w.settlement)
	refusedAs(t, "LeafConsumed emitted by another contract", err, ethproof.ReplayEventMissing, ethproof.ReasonNoEvent)

	// The proof names the emitter as its contract while the transaction targets the account (S5).
	w2 := newWorld(t, worldOpts{after: 0, eventFrom: &attacker})
	p := w2.clone()
	p.Contract = attacker
	_, err = p.Verify(w2.settlement)
	refusedAs(t, "the emitter is not the transaction's target", err, ethproof.ReplayUnproven, ethproof.ReasonContractMismatch)

	// A transaction that targets a contract other than the proof's.
	w3 := newWorld(t, worldOpts{after: 0, to: &attacker})
	_, err = w3.proof.Verify(w3.settlement)
	refusedAs(t, "the transaction targets another contract", err, ethproof.ReplayUnproven, ethproof.ReasonContractMismatch)
}

func TestReplayGuard_HeaderChainMustLinkToTheSettlementBlock(t *testing.T) {
	w := newWorld(t, worldOpts{after: 3})
	// A chain whose first header does not name the settlement block.
	p := w.clone()
	bad := *w.chain[0]
	bad.ParentHash = common.HexToHash("0xbad")
	p.Headers[0] = rawHeader(t, &bad)
	_, err := p.Verify(w.settlement)
	refusedAs(t, "the chain does not link to the settlement block", err, ethproof.ReplayUnproven, ethproof.ReasonHeaderChainBroken)

	// A gap: the second header is dropped.
	p2 := w.clone()
	p2.Headers = append([]hexutil.Bytes{p2.Headers[0]}, p2.Headers[2:]...)
	_, err = p2.Verify(w.settlement)
	refusedAs(t, "a gap in the chain", err, ethproof.ReplayUnproven, ethproof.ReasonHeaderChainBroken)

	// The proof says it is proven at a block the chain does not end at.
	p3 := w.clone()
	p3.ProvenAt = ethproof.BlockRef{Number: testN + 1, Hash: w.chain[0].Hash()}
	_, err = p3.Verify(w.settlement)
	refusedAs(t, "ProvenAt is not the end of the chain", err, ethproof.ReplayUnproven, ethproof.ReasonHeaderChainBroken)

	// The proof is about another settlement block.
	p4 := w.clone()
	p4.SettlementBlock.Hash = common.HexToHash("0x01")
	_, err = p4.Verify(w.settlement)
	refusedAs(t, "the proof is of another block", err, ethproof.ReplayUnproven, ethproof.ReasonBlockMismatch)

	// The Before parent header is not the block's parent.
	p5 := w.clone()
	p5.Before.ParentHeader = rawHeader(t, w.chain[0])
	_, err = p5.Verify(w.settlement)
	refusedAs(t, "the parent header is not the block's parent", err, ethproof.ReplayUnproven, ethproof.ReasonParentHeaderUnproven)
	p6 := w.clone()
	other := *w.parent
	other.Time++
	p6.Before.ParentHeader = rawHeader(t, &other)
	_, err = p6.Verify(w.settlement)
	refusedAs(t, "a header that merely resembles the parent", err, ethproof.ReplayUnproven, ethproof.ReasonParentHeaderUnproven)
}

func TestReplayGuard_ChainLongerThanTheBound(t *testing.T) {
	w := newWorld(t, worldOpts{after: ethproof.MaxReplayHeaderChain})
	if _, err := w.proof.Verify(w.settlement); err != nil {
		t.Fatalf("a chain of exactly %d headers is within the bound: %v", ethproof.MaxReplayHeaderChain, err)
	}
	w2 := newWorld(t, worldOpts{after: ethproof.MaxReplayHeaderChain + 1})
	_, err := w2.proof.Verify(w2.settlement)
	refusedAs(t, "a chain longer than the bound", err, ethproof.ReplayUnproven, ethproof.ReasonHeaderChainTooLong)
}

func TestReplayGuard_TheSettlementMustHaveExecuted(t *testing.T) {
	w := newWorld(t, worldOpts{after: 0, reverted: true})
	_, err := w.proof.Verify(w.settlement)
	refusedAs(t, "a status-0 receipt", err, ethproof.ReplayUnproven, ethproof.ReasonSettlementNotExecuted)
}

func TestReplayGuard_OnlyThePinnedGenerationIsProven(t *testing.T) {
	// A settlement call of no pinned generation (another selector): never proven against a pinned layout, never omitted.
	w := newWorld(t, worldOpts{after: 0, selector: []byte{0xde, 0xad, 0xbe, 0xef}})
	_, err := w.proof.Verify(w.settlement)
	refusedAs(t, "a calldata selector of no pinned generation", err, ethproof.ReplayUnproven, ethproof.ReasonAccountGeneration)
	w2 := newWorld(t, worldOpts{after: 0})
	p := w2.clone()
	p.Generation = "CertenAccountV7_1" // V7_2 and V7_3 are pinned (RB10-F3); a generation without a pinned layout is refused
	_, err = p.Verify(w2.settlement)
	refusedAs(t, "an unpinned generation", err, ethproof.ReplayUnproven, ethproof.ReasonAccountGeneration)
}

func TestReplayGuard_DeclaredFieldsAreCheckedAgainstTheProof(t *testing.T) {
	w := newWorld(t, worldOpts{after: 1})
	p := w.clone()
	p.After.Value = common.BigToHash(big.NewInt(0))
	_, err := p.Verify(w.settlement)
	refusedAs(t, "a declared value that is not the proven one", err, ethproof.ReplayUnproven, ethproof.ReasonProofDoesNotVerify)
	p2 := w.clone()
	p2.After.CodeHash = common.HexToHash("0x01")
	_, err = p2.Verify(w.settlement)
	refusedAs(t, "a declared code hash that is not the proven one", err, ethproof.ReplayUnproven, ethproof.ReasonProofDoesNotVerify)
	p3 := w.clone()
	p3.After.AccountAbsent = true
	_, err = p3.Verify(w.settlement)
	refusedAs(t, "a present account declared absent", err, ethproof.ReplayUnproven, ethproof.ReasonProofDoesNotVerify)
	p4 := w.clone()
	p4.Version = "certen:s6-replay:v0"
	_, err = p4.Verify(w.settlement)
	refusedAs(t, "another domain tag", err, ethproof.ReplayUnproven, ethproof.ReasonVersion)
	// A tampered storage node.
	p5 := w.clone()
	last := len(p5.After.StorageProof) - 1
	p5.After.StorageProof[last] = append(hexutil.Bytes(nil), p5.After.StorageProof[last]...)
	p5.After.StorageProof[last][len(p5.After.StorageProof[last])-1] ^= 1
	_, err = p5.Verify(w.settlement)
	refusedAs(t, "a tampered storage node", err, ethproof.ReplayUnproven, ethproof.ReasonProofDoesNotVerify)
	// An empty contract (no code) is no account.
	if !errors.Is(err, ethproof.ErrReplayGuard) {
		t.Fatal("every refusal is an ErrReplayGuard")
	}
}

func TestReplayGuard_TheSettlementItselfMustVerify(t *testing.T) {
	w := newWorld(t, worldOpts{after: 0})
	bad := *w.settlement
	hdr := append([]byte(nil), bad.Header...)
	hdr[len(hdr)-1] ^= 1
	bad.Header = hdr
	_, err := w.proof.Verify(&bad)
	refusedAs(t, "a settlement whose header does not hash to its block", err, ethproof.ReplayUnproven, ethproof.ReasonSettlementUnproven)
	_, err = w.proof.Verify(nil)
	refusedAs(t, "no settlement", err, ethproof.ReplayUnproven, ethproof.ReasonSettlementUnproven)
}

func TestReplayGuardEvidence_NamedStates(t *testing.T) {
	w := newWorld(t, worldOpts{after: 0})
	named := &ethproof.ReplayNamedState{State: ethproof.ReplayUnproven, Reason: ethproof.ReasonStateUnavailable, ChainID: testChainID,
		TxHash: w.settlement.TxHash, BlockNumber: testN, BlockHash: w.settlement.BlockHash, Contract: w.contract,
		Providers: []ethproof.ReplayProviderFailure{{Host: "publicnode", Error: "distance to target block exceeds maximum proof window"}}}
	ev := &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: named}
	chk, err := ev.Verify(w.settlement)
	if err != nil || chk.State != ethproof.ReplayUnproven || chk.Reason != ethproof.ReasonStateUnavailable || chk.Named == nil {
		t.Fatalf("a named state is reported as itself: %v %+v", err, chk)
	}
	// About another settlement: refused.
	bad := *named
	bad.TxHash = common.HexToHash("0x99")
	_, err = (&ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: &bad}).Verify(w.settlement)
	refusedAs(t, "a named state of another transaction", err, ethproof.ReplayUnproven, ethproof.ReasonBlockMismatch)
	// Neither, and both.
	_, err = (&ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain}).Verify(w.settlement)
	refusedAs(t, "neither a proof nor a state", err, ethproof.ReplayUnproven, ethproof.ReasonEmptyEvidence)
	_, err = (&ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: named, Proof: w.proof}).Verify(w.settlement)
	refusedAs(t, "both a proof and a state", err, ethproof.ReplayUnproven, ethproof.ReasonEmptyEvidence)
	// A state with no reason.
	nr := *named
	nr.Reason = ""
	_, err = (&ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: &nr}).Verify(w.settlement)
	refusedAs(t, "a state without a reason", err, ethproof.ReplayUnproven, ethproof.ReasonEmptyEvidence)
}
