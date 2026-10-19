// Copyright 2026 Certen Protocol

// Package s6replay1 is the conformance suite of the S6 replay-guard evidence (domain tag certen:s6-replay:v1): the
// vectors, the bounded mutation corpus and the judge that states Go's verdict on each. cmd/s6replayvectors writes them
// to pkg/ethproof/testdata/s6replay1; the TypeScript verifier consumes byte-identical copies (SPEC.md there).
package s6replay1

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/replayworld"
)

// Results of a judgement.
const (
	ResultProven  = "proven"  // the evidence is a proof and it verifies
	ResultStated  = "stated"  // the evidence is a named state, held to this settlement
	ResultRefused = "refused" // the evidence is refused, by the named state and reason
)

// MutationSeed is the fixed seed of the mutation corpus; MaxMutations bounds it.
const (
	MutationSeed = 0x5636_7265_706c_6179 // "V6replay"
	MaxMutations = 3000
)

// Log is a receipt log of the settlement.
type Log struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
}

// Settlement is what the settlement layer has already proven: the block header, the transaction (its binary
// encoding), and the receipt's status and logs.
type Settlement struct {
	HeaderRLP     string `json:"headerRlp"`
	TxRLP         string `json:"txRlp"`
	ReceiptStatus uint64 `json:"receiptStatus"`
	Logs          []Log  `json:"logs"`
}

// Expect is a verdict.
type Expect struct {
	Result         string   `json:"result"`
	State          string   `json:"state"`
	Reason         string   `json:"reason"`
	BeforeVerified bool     `json:"beforeVerified"`
	Established    []string `json:"established"`
}

// Vector is one conformance vector. Evidence is the exact evidence bytes (as a JSON string, UTF-8).
type Vector struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Settlement  Settlement `json:"settlement"`
	Evidence    string     `json:"evidence"`
	Expect      Expect     `json:"expect"`
}

// Mutation is one case of the corpus: the base vector's settlement, mutated evidence bytes, Go's verdict.
type Mutation struct {
	Name     string `json:"name"`
	Base     string `json:"base"`
	Evidence string `json:"evidence"`
	Expect   Expect `json:"expect"`
}

func refused(err error) Expect {
	var re *ethproof.ReplayError
	if !errors.As(err, &re) {
		panic(fmt.Sprintf("s6replay1: a refusal that is no named state: %v", err))
	}
	return Expect{Result: ResultRefused, State: re.State, Reason: re.Reason, Established: []string{}}
}

// DecodeSettlement decodes the settlement inputs; a settlement that does not decode is s6_replay_unproven
// {settlement_unproven}.
func DecodeSettlement(s Settlement) (*types.Header, *types.Transaction, bool, []*types.Log, error) {
	bad := func(format string, args ...interface{}) error {
		return &ethproof.ReplayError{State: ethproof.ReplayUnproven, Reason: ethproof.ReasonSettlementUnproven, Detail: fmt.Sprintf(format, args...)}
	}
	hraw, err := hexutil.Decode(s.HeaderRLP)
	if err != nil {
		return nil, nil, false, nil, bad("header: %v", err)
	}
	var h types.Header
	if err := rlp.DecodeBytes(hraw, &h); err != nil || h.Number == nil {
		return nil, nil, false, nil, bad("header does not decode: %v", err)
	}
	traw, err := hexutil.Decode(s.TxRLP)
	if err != nil {
		return nil, nil, false, nil, bad("transaction: %v", err)
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(traw); err != nil {
		return nil, nil, false, nil, bad("transaction does not decode: %v", err)
	}
	var logs []*types.Log
	for i, l := range s.Logs {
		lg := &types.Log{Address: common.HexToAddress(l.Address)}
		if !common.IsHexAddress(l.Address) {
			return nil, nil, false, nil, bad("log %d address", i)
		}
		for _, t := range l.Topics {
			b, err := hexutil.Decode(t)
			if err != nil || len(b) != 32 {
				return nil, nil, false, nil, bad("log %d topic", i)
			}
			lg.Topics = append(lg.Topics, common.BytesToHash(b))
		}
		if lg.Data, err = hexutil.Decode(l.Data); err != nil {
			return nil, nil, false, nil, bad("log %d data", i)
		}
		logs = append(logs, lg)
	}
	return &h, &tx, s.ReceiptStatus == 1, logs, nil
}

// Judge is Go's verdict: the settlement decoded, the evidence decoded strictly (DecodeReplayGuardEvidence), and
// verified against the settlement (ReplayGuardEvidence.VerifyAgainst).
func Judge(s Settlement, evidence []byte) Expect {
	h, tx, ok, logs, err := DecodeSettlement(s)
	if err != nil {
		return refused(err)
	}
	ev, err := ethproof.DecodeReplayGuardEvidence(evidence)
	if err != nil {
		return refused(err)
	}
	chk, err := ev.VerifyAgainst(h, tx, ok, logs)
	if err != nil {
		return refused(err)
	}
	out := Expect{Result: ResultProven, State: chk.State, Reason: chk.Reason, BeforeVerified: chk.BeforeVerified,
		Established: append([]string{}, chk.Established...)}
	if chk.Named != nil {
		out.Result = ResultStated
	}
	return out
}

// panicTB is the builder's TB outside a test.
type panicTB struct{}

func (panicTB) Helper()                   {}
func (panicTB) Fatal(args ...interface{}) { panic(fmt.Sprint(args...)) }

func settlementOf(w *replayworld.World) Settlement {
	tb := panicTB{}
	txEnc, err := w.Tx.MarshalBinary()
	if err != nil {
		tb.Fatal(err)
	}
	s := Settlement{HeaderRLP: hexutil.Encode(replayworld.RawHeader(tb, w.HeaderN)), TxRLP: hexutil.Encode(txEnc),
		ReceiptStatus: w.Receipt.Status, Logs: []Log{}}
	for _, l := range w.Receipt.Logs {
		lg := Log{Address: l.Address.Hex(), Topics: []string{}, Data: hexutil.Encode(l.Data)}
		for _, t := range l.Topics {
			lg.Topics = append(lg.Topics, t.Hex())
		}
		s.Logs = append(s.Logs, lg)
	}
	return s
}

// SettlementOf is the settlement inputs of a world.
func SettlementOf(w *replayworld.World) Settlement { return settlementOf(w) }

// ProofEvidence is the evidence bytes of a proof, as the generator writes them.
func ProofEvidence(p *ethproof.ReplayGuardProof) []byte { return proofEvidence(p) }

// StateEvidence is the evidence bytes of a named state, as the generator writes them.
func StateEvidence(st *ethproof.ReplayNamedState) []byte { return stateEvidence(st) }

// CloneProof is a deep copy of a proof.
func CloneProof(p *ethproof.ReplayGuardProof) *ethproof.ReplayGuardProof { return cloneProof(p) }

func marshal(v interface{}) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimRight(b.Bytes(), "\n")
}

func proofEvidence(p *ethproof.ReplayGuardProof) []byte {
	return marshal(&ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, Proof: p})
}

func stateEvidence(st *ethproof.ReplayNamedState) []byte {
	return marshal(&ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: st})
}

func cloneProof(p *ethproof.ReplayGuardProof) *ethproof.ReplayGuardProof {
	var out ethproof.ReplayGuardProof
	if err := json.Unmarshal(marshal(p), &out); err != nil {
		panic(err)
	}
	return &out
}

type builder struct {
	vectors []Vector
	worlds  map[string]*replayworld.World
}

func (b *builder) add(name, desc string, s Settlement, evidence []byte) {
	b.vectors = append(b.vectors, Vector{Name: fmt.Sprintf("%03d_%s", len(b.vectors)+1, name), Description: desc, Settlement: s,
		Evidence: string(evidence), Expect: Judge(s, evidence)})
}

// textual applies a tree edit to evidence JSON.
func textual(evidence []byte, edit func(root *node)) []byte {
	root := parseTree(evidence)
	edit(root)
	return root.bytes()
}

// BuildVectors builds every vector, in order.
func BuildVectors() []Vector {
	tb := panicTB{}
	world := func(o replayworld.Opts) *replayworld.World { return replayworld.New(tb, o) }
	b := &builder{}
	base := world(replayworld.Opts{})
	sBase := settlementOf(base)
	evBase := proofEvidence(base.Proof)
	chain := world(replayworld.Opts{After: 3})
	sChain := settlementOf(chain)
	other := common.HexToAddress("0x057fC30274d1AB39DC1EF51a84CF995c9b8c50f2")
	edit := func(w *replayworld.World, f func(p *ethproof.ReplayGuardProof)) []byte {
		p := cloneProof(w.Proof)
		f(p)
		return proofEvidence(p)
	}
	named := func(state, reason string, f func(st *ethproof.ReplayNamedState)) []byte {
		st := &ethproof.ReplayNamedState{State: state, Reason: reason, ChainID: replayworld.ChainID, TxHash: base.Tx.Hash(),
			BlockNumber: replayworld.N, BlockHash: base.HeaderN.Hash(), Contract: base.Contract}
		if f != nil {
			f(st)
		}
		return stateEvidence(st)
	}
	providers := []ethproof.ReplayProviderFailure{{Host: "sepolia.base.org", Error: "missing trie node"},
		{Host: "base-sepolia-rpc.publicnode.com", Error: "distance to target block exceeds maximum proof window"}}

	// Proven.
	b.add("valid_at_settlement_block", "After proven at the settlement block itself, Before proven at its parent", sBase, evBase)
	b.add("valid_after_header_chain", "After proven 3 blocks after the settlement block through linked headers", sChain, proofEvidence(chain.Proof))
	batch := world(replayworld.Opts{After: 1, Selector: replayworld.V73Batch})
	b.add("valid_batch_settlement", "a batchExecuteGovernanceProofDirect settlement", settlementOf(batch), proofEvidence(batch.Proof))
	b.add("before_unavailable_disclosed", "Before not served, disclosed with the providers tried: After alone is the claim", sBase,
		edit(base, func(p *ethproof.ReplayGuardProof) {
			p.Before = nil
			p.BeforeUnavailable = &ethproof.ReplayBeforeUnavailable{Reason: ethproof.ReasonStateUnavailable, Providers: providers}
		}))
	absent := world(replayworld.Opts{NoBeforeAcc: true})
	b.add("contract_absent_at_parent", "the account did not exist at the parent: a verified exclusion proof, every slot 0", settlementOf(absent), proofEvidence(absent.Proof))
	b.add("valid_uppercase_hex", "hex digits in upper case are the same values", sBase, textual(evBase, func(r *node) {
		for _, p := range []string{"proof.contract", "proof.slot.key", "proof.slot.slot", "proof.settlementBlock.hash", "proof.after.accountProof.0"} {
			n := r.at(p)
			n.str = "0x" + string(bytes.ToUpper([]byte(n.str[2:])))
		}
	}))
	bound := world(replayworld.Opts{After: ethproof.MaxReplayHeaderChain})
	b.add("chain_at_the_bound", "exactly 512 headers after the settlement block", settlementOf(bound), proofEvidence(bound.Proof))

	// Refuted / unproven by the proof's own content.
	set := world(replayworld.Opts{BeforeValue: big.NewInt(1)})
	b.add("slot_set_at_parent", "Before proves the slot already 1 at the parent", settlementOf(set), proofEvidence(set.Proof))
	unset := world(replayworld.Opts{AfterValue: big.NewInt(0)})
	b.add("after_value_zero", "After proves the slot 0 although the receipt holds the LeafConsumed", settlementOf(unset), proofEvidence(unset.Proof))
	two := world(replayworld.Opts{AfterValue: big.NewInt(2)})
	b.add("after_value_not_bool", "After proves 2, not the bool true", settlementOf(two), proofEvidence(two.Proof))
	btwo := world(replayworld.Opts{BeforeValue: big.NewInt(2)})
	b.add("before_value_not_bool", "Before proves 2, not the bool false", settlementOf(btwo), proofEvidence(btwo.Proof))
	b.add("wrong_mapping_key", "another consumed leaf's key and slot, proven 1, but not the leaf this receipt's LeafConsumed names", sBase,
		edit(base, func(p *ethproof.ReplayGuardProof) {
			p.Slot.Key = replayworld.OtherLeaf
			p.Slot.Slot = ethproof.ReplaySlotFor(replayworld.OtherLeaf, 4)
			p.After = base.After.Prove(base.Contract, p.Slot.Slot)
			p.Before = nil
			p.BeforeUnavailable = &ethproof.ReplayBeforeUnavailable{Reason: ethproof.ReasonStateUnavailable}
		}))
	b.add("slot_not_derived_from_key", "the right key, the slot of another key", sBase, edit(base, func(p *ethproof.ReplayGuardProof) {
		p.Slot.Slot = ethproof.ReplaySlotFor(replayworld.OtherLeaf, 4)
		p.After = base.After.Prove(base.Contract, p.Slot.Slot)
	}))
	b.add("wrong_base", "base 5 is not V7_3's pinned base 4", sBase, edit(base, func(p *ethproof.ReplayGuardProof) {
		p.Slot.Base = 5
		p.Slot.Slot = ethproof.ReplaySlotFor(base.Leaf, 5)
	}))
	b.add("wrong_derivation", "the derivation string is not the pinned one", sBase, edit(base, func(p *ethproof.ReplayGuardProof) {
		p.Slot.Derivation = "keccak256(key)"
	}))
	otherState := replayworld.BuildState(tb, replayworld.Account{Addr: other}, replayworld.Account{Addr: base.Contract, Code: replayworld.Code,
		Storage: map[common.Hash]*big.Int{base.Slot: big.NewInt(1), common.BigToHash(big.NewInt(77)): big.NewInt(5)}})
	b.add("proof_against_another_blocks_root", "After is a valid proof of the slot = 1, against another state root", sBase,
		edit(base, func(p *ethproof.ReplayGuardProof) { p.After = otherState.Prove(base.Contract, base.Slot) }))
	b.add("before_against_another_root", "Before is a proof against the settlement block's root, not the parent's", sBase,
		edit(base, func(p *ethproof.ReplayGuardProof) { p.Before.Proof = base.After.Prove(base.Contract, base.Slot) }))
	evOther := world(replayworld.Opts{EventFrom: &other})
	b.add("event_from_another_contract", "the LeafConsumed is emitted by another address", settlementOf(evOther), proofEvidence(evOther.Proof))
	toOther := world(replayworld.Opts{To: &other})
	b.add("tx_to_another_contract", "the transaction's target is not the proof's contract", settlementOf(toOther), proofEvidence(toOther.Proof))
	b.add("chain_id_mismatch", "the proof names chain 1, the transaction is of chain 84532", sBase,
		edit(base, func(p *ethproof.ReplayGuardProof) { p.ChainID = 1 }))
	noCode := world(replayworld.Opts{AfterCode: []byte{}})
	b.add("contract_without_code", "the contract holds no code at ProvenAt", settlementOf(noCode), proofEvidence(noCode.Proof))
	codeChanged := world(replayworld.Opts{BeforeCode: replayworld.OtherCode})
	b.add("code_changed_since_parent", "the contract's code at the parent is not its code at ProvenAt", settlementOf(codeChanged), proofEvidence(codeChanged.Proof))
	b.add("header_chain_not_linked", "headers 0 and 1 swapped", sChain, edit(chain, func(p *ethproof.ReplayGuardProof) {
		p.Headers[0], p.Headers[1] = p.Headers[1], p.Headers[0]
	}))
	b.add("header_chain_skips_a_block", "the first header after the settlement block left out", sChain, edit(chain, func(p *ethproof.ReplayGuardProof) {
		p.Headers = p.Headers[1:]
	}))
	b.add("proven_at_not_chain_end", "ProvenAt names a block the chain does not end at", sChain, edit(chain, func(p *ethproof.ReplayGuardProof) {
		p.ProvenAt.Number++
	}))
	b.add("header_undecodable", "a header of the chain is not a header", sChain, edit(chain, func(p *ethproof.ReplayGuardProof) {
		p.Headers[1] = hexutil.Bytes{0x01}
	}))
	long := world(replayworld.Opts{After: ethproof.MaxReplayHeaderChain + 1})
	b.add("chain_longer_than_512", "513 headers after the settlement block", settlementOf(long), proofEvidence(long.Proof))
	rev := world(replayworld.Opts{Reverted: true})
	b.add("settlement_not_executed", "the receipt is status 0", settlementOf(rev), proofEvidence(rev.Proof))
	b.add("generation_v7_2_unpinned", "CertenAccountV7_2 has no pinned layout", sBase, edit(base, func(p *ethproof.ReplayGuardProof) {
		p.Generation = ethproof.AccountGenerationV7_2
	}))
	b.add("generation_unknown", "an unknown generation", sBase, edit(base, func(p *ethproof.ReplayGuardProof) { p.Generation = "CertenAccountV9" }))
	v72 := world(replayworld.Opts{Selector: replayworld.V72Execute})
	b.add("selector_not_of_generation", "a V7_2 settlement call under a V7_3 proof", settlementOf(v72), proofEvidence(v72.Proof))
	noData := world(replayworld.Opts{NoCalldata: true})
	b.add("no_calldata", "the transaction carries no settlement call", settlementOf(noData), proofEvidence(noData.Proof))
	b.add("declared_value_mismatch", "After declares 0, proves 1", sBase, edit(base, func(p *ethproof.ReplayGuardProof) { p.After.Value = common.Hash{} }))
	b.add("declared_storage_hash_mismatch", "After declares another storage hash", sBase, edit(base, func(p *ethproof.ReplayGuardProof) { p.After.StorageHash[0] ^= 1 }))
	b.add("declared_code_hash_mismatch", "After declares another code hash", sBase, edit(base, func(p *ethproof.ReplayGuardProof) { p.After.CodeHash[0] ^= 1 }))
	b.add("declared_absent_but_present", "After declares the account absent, proves it present", sBase, edit(base, func(p *ethproof.ReplayGuardProof) { p.After.AccountAbsent = true }))
	b.add("declared_present_but_absent", "Before declares the account present, proves it absent", settlementOf(absent),
		edit(absent, func(p *ethproof.ReplayGuardProof) { p.Before.Proof.AccountAbsent = false }))
	b.add("declared_absent_with_nonzero_hashes", "Before is a verified exclusion proof but declares a code hash", settlementOf(absent),
		edit(absent, func(p *ethproof.ReplayGuardProof) { p.Before.Proof.CodeHash[0] ^= 1 }))
	b.add("settlement_block_mismatch", "the proof names another block as the settlement block", sBase, edit(base, func(p *ethproof.ReplayGuardProof) {
		p.SettlementBlock.Hash = base.Parent.Hash()
	}))
	b.add("before_and_disclosure_both", "both a Before proof and its unavailability", sBase, edit(base, func(p *ethproof.ReplayGuardProof) {
		p.BeforeUnavailable = &ethproof.ReplayBeforeUnavailable{Reason: ethproof.ReasonStateUnavailable}
	}))
	b.add("before_neither", "neither a Before proof nor its disclosure", sBase, edit(base, func(p *ethproof.ReplayGuardProof) { p.Before = nil }))
	b.add("before_unavailable_without_reason", "the disclosure gives no reason", sBase, edit(base, func(p *ethproof.ReplayGuardProof) {
		p.Before = nil
		p.BeforeUnavailable = &ethproof.ReplayBeforeUnavailable{Reason: ""}
	}))
	b.add("parent_header_not_the_parent", "the parent header is the settlement block's own header", sBase, edit(base, func(p *ethproof.ReplayGuardProof) {
		p.Before.ParentHeader = replayworld.RawHeader(tb, base.HeaderN)
	}))
	b.add("parent_header_undecodable", "the parent header is not a header", sBase, edit(base, func(p *ethproof.ReplayGuardProof) {
		p.Before.ParentHeader = hexutil.Bytes{0x01}
	}))
	b.add("settlement_header_undecodable", "the settlement inputs do not decode", Settlement{HeaderRLP: "0x01", TxRLP: sBase.TxRLP,
		ReceiptStatus: 1, Logs: sBase.Logs}, evBase)

	// Named states carried as the evidence.
	b.add("state_unproven_state_unavailable", "no provider served the state, each named", sBase, named(ethproof.ReplayUnproven, ethproof.ReasonStateUnavailable,
		func(st *ethproof.ReplayNamedState) {
			st.Providers = providers
			st.Detail = "no provider served block 5000"
		}))
	b.add("state_unproven_account_generation", "a V7_2 settlement: no pinned layout", sBase, named(ethproof.ReplayUnproven, ethproof.ReasonAccountGeneration, nil))
	b.add("state_event_missing", "the receipt holds no LeafConsumed of the target", sBase, named(ethproof.ReplayEventMissing, ethproof.ReasonNoEvent, nil))
	b.add("state_refuted_slot_set_at_parent", "the refutation, carrying its Before", sBase, named(ethproof.ReplayRefuted, ethproof.ReasonSlotSetAtParent,
		func(st *ethproof.ReplayNamedState) { st.Before = set.Proof.Before }))
	b.add("state_refuted_slot_unset_at_block", "the refutation of After", sBase, named(ethproof.ReplayRefuted, ethproof.ReasonSlotUnsetAtBlock, nil))
	b.add("state_about_another_tx", "the named state is about another transaction", sBase, named(ethproof.ReplayUnproven, ethproof.ReasonStateUnavailable,
		func(st *ethproof.ReplayNamedState) { st.TxHash = chain.Leaf }))
	b.add("state_about_another_block", "the named state is about another block", sBase, named(ethproof.ReplayUnproven, ethproof.ReasonStateUnavailable,
		func(st *ethproof.ReplayNamedState) { st.BlockNumber++ }))
	b.add("state_not_a_named_state", "\"proven\" is no named state", sBase, named(ethproof.ReplayProven, ethproof.ReasonStateUnavailable, nil))
	b.add("state_without_reason", "a named state without its reason", sBase, named(ethproof.ReplayUnproven, "", nil))

	// Strict decoding.
	evState := named(ethproof.ReplayUnproven, ethproof.ReasonStateUnavailable, nil)
	t := func(name, desc string, ev []byte, f func(r *node)) {
		b.add(name, desc, sBase, textual(ev, f))
	}
	b.add("decode_not_json", "not a JSON document", sBase, []byte("{"))
	b.add("decode_empty", "no bytes", sBase, []byte{})
	b.add("decode_trailing_data", "a second value after the document", sBase, append(append([]byte{}, evBase...), []byte(" {}")...))
	b.add("decode_duplicate_key_top", "version twice", sBase, bytes.Replace(evBase, []byte(`{"version":`), []byte(`{"version":"x","version":`), 1))
	b.add("decode_duplicate_key_nested", "slot.key twice", sBase, bytes.Replace(evBase, []byte(`"slot":{"key":`),
		[]byte(`"slot":{"key":"0x0000000000000000000000000000000000000000000000000000000000000000","key":`), 1))
	b.add("decode_leading_zero_number", "chainId 084532 is no JSON number", sBase, bytes.Replace(evBase, []byte(`"chainId":84532`), []byte(`"chainId":084532`), 1))
	b.add("decode_top_level_array", "the document is an array", sBase, []byte("[]"))
	t("decode_unknown_field_top", "a field the format does not have", evBase, func(r *node) { r.set("extra", jnum("1")) })
	t("decode_unknown_field_nested", "a field the format does not have, inside after", evBase, func(r *node) { r.at("proof.after").set("extra", jstr("x")) })
	t("decode_case_variant_key", "Version is not version", evBase, func(r *node) { r.rename("version", "Version") })
	t("decode_missing_version", "no version", evBase, func(r *node) { r.remove("version") })
	t("decode_missing_after", "no after", evBase, func(r *node) { r.at("proof").remove("after") })
	t("decode_missing_slot_key", "no slot.key", evBase, func(r *node) { r.at("proof.slot").remove("key") })
	t("decode_missing_headers", "no headers", evBase, func(r *node) { r.at("proof").remove("headers") })
	t("decode_missing_state_tx_hash", "a named state without txHash", evState, func(r *node) { r.at("state").remove("txHash") })
	t("decode_number_as_string", "chainId as a string", evBase, func(r *node) { r.at("proof").set("chainId", jstr("84532")) })
	t("decode_fraction", "chainId 84532.0", evBase, func(r *node) { r.at("proof").set("chainId", jnum("84532.0")) })
	t("decode_exponent", "chainId 8.4532e4", evBase, func(r *node) { r.at("proof").set("chainId", jnum("8.4532e4")) })
	t("decode_negative", "chainId -1", evBase, func(r *node) { r.at("proof").set("chainId", jnum("-1")) })
	t("decode_beyond_2_53", "settlementBlock.number 2^53", evBase, func(r *node) { r.at("proof.settlementBlock").set("number", jnum("9007199254740992")) })
	t("decode_hash_short", "a 31-byte hash", evBase, func(r *node) { n := r.at("proof.slot.key"); n.str = n.str[:64] })
	t("decode_hash_without_0x", "a hash without 0x", evBase, func(r *node) { n := r.at("proof.slot.key"); n.str = n.str[2:] + "00" })
	t("decode_hash_upper_0x", "a hash with 0X", evBase, func(r *node) { n := r.at("proof.slot.key"); n.str = "0X" + n.str[2:] })
	t("decode_address_long", "a 21-byte address", evBase, func(r *node) { n := r.at("proof.contract"); n.str += "00" })
	t("decode_bytes_odd", "an odd number of hex digits in a header", evBase, func(r *node) { n := r.at("proof.before.parentHeader"); n.str += "0" })
	t("decode_null_required", "accountProof null", evBase, func(r *node) { r.at("proof.after").set("accountProof", jraw('z')) })
	t("decode_null_optional", "before null", evBase, func(r *node) { r.at("proof").set("before", jraw('z')) })
	t("decode_bool_as_string", "accountAbsent \"true\"", evBase, func(r *node) { r.at("proof.after").set("accountAbsent", jstr("true")) })
	t("decode_headers_object", "headers an object", evBase, func(r *node) { r.at("proof").set("headers", jraw('o')) })
	t("decode_proof_array", "proof an array", evBase, func(r *node) { r.set("proof", jraw('a')) })
	t("decode_providers_object", "providers an object", evState, func(r *node) { r.at("state").set("providers", jraw('o')) })
	t("decode_both_proof_and_state", "a proof and a named state", evBase, func(r *node) { r.set("state", parseTree(evState).get("state")) })
	t("decode_neither_proof_nor_state", "only a version", evBase, func(r *node) { r.remove("proof") })
	t("decode_wrong_version", "the evidence's version is another domain", evBase, func(r *node) { r.set("version", jstr("certen:s6-replay:v2")) })
	t("decode_wrong_proof_version", "the proof's version is another domain", evBase, func(r *node) { r.at("proof").set("version", jstr("certen:s6-replay:v0")) })
	return b.vectors
}

// mutationBases are the vectors the corpus mutates (the valid ones; the 512-header vector is left out for size).
var mutationBases = []string{"001_valid_at_settlement_block", "002_valid_after_header_chain", "003_valid_batch_settlement",
	"004_before_unavailable_disclosed", "005_contract_absent_at_parent"}

type leaf struct {
	path string
	n    *node
}

func walk(n *node, path string, out *[]leaf) {
	*out = append(*out, leaf{path, n})
	switch n.kind {
	case 'o':
		for i, k := range n.keys {
			p := k
			if path != "" {
				p = path + "." + k
			}
			walk(n.vals[i], p, out)
		}
	case 'a':
		for i, v := range n.arr {
			walk(v, fmt.Sprintf("%s.%d", path, i), out)
		}
	}
}

func parentOf(root *node, path string) (*node, string) {
	i := len(path) - 1
	for i >= 0 && path[i] != '.' {
		i--
	}
	if i < 0 {
		return root, path
	}
	return root.at(path[:i]), path[i+1:]
}

func wrongType(n *node) *node {
	switch n.kind {
	case 's':
		return jnum("1")
	case 'n':
		return jstr(n.str)
	case 'b':
		return jnum("0")
	case 'a':
		return jraw('o')
	case 'o':
		return jraw('a')
	}
	return jstr("")
}

// BuildMutations builds the bounded corpus from the valid vectors with the fixed seed.
func BuildMutations(vectors []Vector) []Mutation {
	return BuildMutationsOf(vectors, mutationBases)
}

// BuildMutationsOf is the bounded mutation corpus of the named base vectors (the same seed, edits and bound as
// BuildMutations); a later set (s6replay2) mutates its own bases with it.
func BuildMutationsOf(vectors []Vector, bases []string) []Mutation {
	rng := rand.New(rand.NewSource(MutationSeed))
	byName := map[string]Vector{}
	for _, v := range vectors {
		byName[v.Name] = v
	}
	var out []Mutation
	for _, bn := range bases {
		v, ok := byName[bn]
		if !ok {
			panic("s6replay1: no base vector " + bn)
		}
		add := func(name string, ev []byte) {
			if string(ev) == v.Evidence {
				return // a no-op (an identical swap, an empty list reversed): not a mutation
			}
			out = append(out, Mutation{Name: fmt.Sprintf("%s/%s", bn, name), Base: bn, Evidence: string(ev), Expect: Judge(v.Settlement, ev)})
		}
		mut := func(name string, f func(r *node)) {
			r := parseTree([]byte(v.Evidence))
			f(r)
			add(name, r.bytes())
		}
		var leaves []leaf
		walk(parseTree([]byte(v.Evidence)), "", &leaves)
		for _, lf := range leaves[1:] {
			p := lf.path
			mut("remove:"+p, func(r *node) {
				par, k := parentOf(r, p)
				if par.kind == 'a' {
					var i int
					fmt.Sscanf(k, "%d", &i)
					par.arr = append(par.arr[:i:i], par.arr[i+1:]...)
					return
				}
				par.remove(k)
			})
			mut("null:"+p, func(r *node) {
				par, k := parentOf(r, p)
				if par.kind == 'a' {
					var i int
					fmt.Sscanf(k, "%d", &i)
					par.arr[i] = jraw('z')
					return
				}
				par.set(k, jraw('z'))
			})
			mut("wrongtype:"+p, func(r *node) {
				par, k := parentOf(r, p)
				if par.kind == 'a' {
					var i int
					fmt.Sscanf(k, "%d", &i)
					par.arr[i] = wrongType(par.arr[i])
					return
				}
				par.set(k, wrongType(par.get(k)))
			})
			switch {
			case lf.n.kind == 's' && len(lf.n.str) > 2 && lf.n.str[:2] == "0x":
				raw, err := hexutil.Decode(lf.n.str)
				if err != nil || len(raw) == 0 {
					continue
				}
				flips := 1
				if len(raw) > 32 {
					flips = 2
				}
				for f := 0; f < flips; f++ {
					pos := rng.Intn(len(raw))
					x := byte(rng.Intn(255) + 1)
					mut(fmt.Sprintf("flip:%s@%d^%02x", p, pos, x), func(r *node) {
						c := append([]byte(nil), raw...)
						c[pos] ^= x
						r.at(p).str = hexutil.Encode(c)
					})
				}
			case lf.n.kind == 'n':
				mut("increment:"+p, func(r *node) {
					n := r.at(p)
					var x uint64
					fmt.Sscanf(n.str, "%d", &x)
					n.str = fmt.Sprintf("%d", x+1)
				})
			case lf.n.kind == 'b':
				mut("negate:"+p, func(r *node) {
					n := r.at(p)
					if n.str == "true" {
						n.str = "false"
					} else {
						n.str = "true"
					}
				})
			}
		}
		// Swaps.
		swaps := [][2]string{{"proof.slot.key", "proof.slot.slot"}, {"proof.settlementBlock", "proof.provenAt"},
			{"proof.after.storageHash", "proof.after.codeHash"}, {"proof.after.accountProof", "proof.after.storageProof"}}
		r0 := parseTree([]byte(v.Evidence))
		if r0.at("proof").get("before") != nil {
			swaps = append(swaps, [2]string{"proof.after", "proof.before.proof"})
		}
		for _, sw := range swaps {
			a, bpath := sw[0], sw[1]
			mut("swap:"+a+"<>"+bpath, func(r *node) {
				pa, ka := parentOf(r, a)
				pb, kb := parentOf(r, bpath)
				na, nb := pa.get(ka), pb.get(kb)
				pa.set(ka, nb)
				pb.set(kb, na)
			})
		}
		replace := map[string]string{
			"contract:other":       "0x057fc30274d1ab39dc1ef51a84cf995c9b8c50f2",
			"slot.key:otherLeaf":   replayworld.OtherLeaf.Hex(),
			"slot.slot:otherSlot":  ethproof.ReplaySlotFor(replayworld.OtherLeaf, 4).Hex(),
			"settlementBlock:zero": common.Hash{}.Hex(),
		}
		keys := make([]string, 0, len(replace))
		for k := range replace {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val := replace[k]
			var path string
			fmt.Sscanf(k[:bytes.IndexByte([]byte(k), ':')], "%s", &path)
			if path == "settlementBlock" {
				path = "settlementBlock.hash"
			}
			mut("replace:"+k, func(r *node) { r.at("proof." + path).str = val })
		}
		mut("headers:reverse", func(r *node) {
			h := r.at("proof.headers")
			for i, j := 0, len(h.arr)-1; i < j; i, j = i+1, j-1 {
				h.arr[i], h.arr[j] = h.arr[j], h.arr[i]
			}
		})
		mut("headers:duplicate-first", func(r *node) {
			h := r.at("proof.headers")
			if len(h.arr) > 0 {
				h.arr = append([]*node{h.arr[0].clone()}, h.arr...)
			}
		})
	}
	if len(out) > MaxMutations {
		panic(fmt.Sprintf("s6replay1: %d mutations exceed the bound %d", len(out), MaxMutations))
	}
	return out
}

// Files are the suite's files by name: one JSON per vector, mutations.json.gz, manifest.json and MANIFEST.
func Files() map[string][]byte {
	vectors := BuildVectors()
	return SuiteFiles(vectors, BuildMutations(vectors), "cmd/s6replayvectors")
}

// SuiteFiles are a suite's files by name from its vectors and mutations; generator is the command that writes them.
func SuiteFiles(vectors []Vector, muts []Mutation, generator string) map[string][]byte {
	files := map[string][]byte{}
	type entry struct {
		File   string `json:"file"`
		Sha256 string `json:"sha256"`
	}
	manifest := struct {
		Domain        string  `json:"domain"`
		Generator     string  `json:"generator"`
		Spec          string  `json:"spec"`
		Vectors       []entry `json:"vectors"`
		Mutations     entry   `json:"mutations"`
		MutationCount int     `json:"mutationCount"`
		MutationsJSON string  `json:"mutationsJsonSha256"`
		MutationSeed  string  `json:"mutationSeed"`
	}{Domain: ethproof.ReplayGuardDomain, Generator: generator, Spec: "SPEC.md"}
	sum := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	for _, v := range vectors {
		enc, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			panic(err)
		}
		enc = append(enc, '\n')
		name := v.Name + ".json"
		files[name] = enc
		manifest.Vectors = append(manifest.Vectors, entry{File: name, Sha256: sum(enc)})
	}
	mj := append(marshal(muts), '\n')
	var gz bytes.Buffer
	zw, err := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	if err != nil {
		panic(err)
	}
	if _, err := zw.Write(mj); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	files["mutations.json.gz"] = gz.Bytes()
	manifest.Mutations = entry{File: "mutations.json.gz", Sha256: sum(gz.Bytes())}
	manifest.MutationCount = len(muts)
	manifest.MutationsJSON = sum(mj)
	manifest.MutationSeed = fmt.Sprintf("0x%x", uint64(MutationSeed))
	menc, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		panic(err)
	}
	menc = append(menc, '\n')
	files["manifest.json"] = menc
	files["MANIFEST"] = []byte(sum(menc) + "  manifest.json\n")
	return files
}
