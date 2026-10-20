// Copyright 2026 Certen Protocol

// Package s6replay3 is the third conformance set of the S6 replay-guard evidence (the same wire format and domain tag,
// certen:s6-replay:v1), written by RB10-B7: a named state held to the settlement's chain and contract and a refutation
// stated only with its verified Before (V-R10B notes); the canonical-header rule; the settlement transaction envelopes
// the verifier accepts (legacy, EIP-155 legacy, type 1, type 2, type 3 canonical and in its network form with a v0 or v1
// sidecar, type 4: RB10-F14, V-R10C D2); and hex-typed values carrying a JSON escape, which Go refuses
// s6_replay_unproven{wrong_type} (V-R10C D1). It supersedes s6replay1's 049 (testdata/s6replay1/SUPERSEDED.md);
// s6replay1 and s6replay2 are kept byte-identical. `go run ./cmd/s6replayvectors -set s6replay3` writes it to
// pkg/ethproof/testdata/s6replay3; the TypeScript verifier consumes byte-identical copies.
package s6replay3

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/replayworld"
	"github.com/certen/independant-validator/pkg/ethproof/s6replay1"
)

// Generator is the command line that writes this set.
const Generator = "cmd/s6replayvectors -set s6replay3"

// panicTB is the builder's TB outside a test.
type panicTB struct{}

func (panicTB) Helper()                   {}
func (panicTB) Fatal(args ...interface{}) { panic(fmt.Sprint(args...)) }

type builder struct{ vectors []s6replay1.Vector }

func (b *builder) add(name, desc string, s s6replay1.Settlement, evidence []byte) {
	b.vectors = append(b.vectors, s6replay1.Vector{Name: fmt.Sprintf("%03d_%s", len(b.vectors)+1, name), Description: desc,
		Settlement: s, Evidence: string(evidence), Expect: s6replay1.Judge(s, evidence)})
}

func named(w *replayworld.World, state, reason string, f func(st *ethproof.ReplayNamedState)) []byte {
	st := &ethproof.ReplayNamedState{State: state, Reason: reason, ChainID: replayworld.ChainID, TxHash: w.Tx.Hash(),
		BlockNumber: replayworld.N, BlockHash: w.HeaderN.Hash(), Contract: w.Contract}
	if f != nil {
		f(st)
	}
	return s6replay1.StateEvidence(st)
}

func encode(tx *types.Transaction) string {
	enc, err := tx.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return hexutil.Encode(enc)
}

// withTx is the world's settlement with its transaction replaced by tx (the same target, calldata and chain).
func withTx(w *replayworld.World, tx *types.Transaction) s6replay1.Settlement {
	s := s6replay1.SettlementOf(w)
	s.TxRLP = encode(tx)
	return s
}

// nonCanonicalList re-encodes an RLP list with a list-length prefix one byte longer than needed.
func nonCanonicalList(raw []byte) []byte {
	content, _, err := rlp.SplitList(raw)
	if err != nil {
		panic(err)
	}
	var lenBytes []byte
	for v := len(content); v > 0; v >>= 8 {
		lenBytes = append([]byte{byte(v)}, lenBytes...)
	}
	lenBytes = append([]byte{0}, lenBytes...)
	out := append([]byte{byte(0xf7 + len(lenBytes))}, lenBytes...)
	return append(out, content...)
}

// escX and esc0 are `"0x` with the x, or the 0, written as a JSON \u escape.
const (
	escX = `"0\u0078`
	esc0 = `"\u0030x`
	escV = `CertenAccount\u00567_3`
)

// escapeAt replaces the i-th occurrence of `"0x` in evidence by `"0x` (x escaped) or `"0x` (0 escaped).
func escapeAt(evidence string, i int, digit bool) (string, bool) {
	idx := -1
	from := 0
	for k := 0; k <= i; k++ {
		j := strings.Index(evidence[from:], `"0x`)
		if j < 0 {
			return "", false
		}
		idx = from + j
		from = idx + 1
	}
	repl := escX
	if digit {
		repl = esc0
	}
	return evidence[:idx] + repl + evidence[idx+3:], true
}

// escapeField escapes the 0x of the first hex value of the field key ("key":"0x… or "key":["0x…).
func escapeField(evidence, key string) string {
	for _, pre := range []string{`"` + key + `":"0x`, `"` + key + `":["0x`} {
		if j := strings.Index(evidence, pre); j >= 0 {
			k := j + len(pre) - 3
			return evidence[:k] + escX + evidence[k+3:]
		}
	}
	panic("s6replay3: no hex value of " + key)
}

// BuildVectors builds every vector, in order.
func BuildVectors() []s6replay1.Vector {
	tb := panicTB{}
	world := func(o replayworld.Opts) *replayworld.World { return replayworld.New(tb, o) }
	b := &builder{}
	base := world(replayworld.Opts{})
	sBase := s6replay1.SettlementOf(base)
	evBase := s6replay1.ProofEvidence(base.Proof)

	// Named states held to the settlement's chain and contract (V-R10B note, inside VerifyAgainst).
	b.add("state_honest_chain_and_contract", "a named state of the settlement's chain and contract", sBase,
		named(base, ethproof.ReplayUnproven, ethproof.ReasonStateUnavailable, nil))
	b.add("state_of_another_chain", "a named state whose chainId is not the transaction's", sBase,
		named(base, ethproof.ReplayUnproven, ethproof.ReasonStateUnavailable, func(st *ethproof.ReplayNamedState) { st.ChainID++ }))
	b.add("state_of_another_contract", "a named state whose contract is not the transaction's target", sBase,
		named(base, ethproof.ReplayUnproven, ethproof.ReasonStateUnavailable, func(st *ethproof.ReplayNamedState) {
			st.Contract = common.HexToAddress("0x00000000000000000000000000000000000000aa")
		}))
	b.add("state_receipt_unavailable_no_contract", "receipt_unavailable named before the capture had the transaction: no contract stated", sBase,
		named(base, ethproof.ReplayUnproven, ethproof.ReasonReceiptUnavailable, func(st *ethproof.ReplayNamedState) { st.Contract = common.Address{} }))
	b.add("state_unavailable_no_contract", "state_unavailable naming no contract although the transaction has a target", sBase,
		named(base, ethproof.ReplayUnproven, ethproof.ReasonStateUnavailable, func(st *ethproof.ReplayNamedState) { st.Contract = common.Address{} }))

	// A refutation is stated only with its verified Before (V-R10B note).
	set := world(replayworld.Opts{BeforeValue: big.NewInt(1)})
	sSet := s6replay1.SettlementOf(set)
	other := world(replayworld.Opts{BeforeValue: big.NewInt(1), BeforeCode: []byte{0x60, 0x00}})
	unset := world(replayworld.Opts{})
	b.add("refuted_with_verified_before", "s6_replay_refuted{slot_set_at_parent} carrying its own Before: the slot is 1 at the parent", sSet,
		named(set, ethproof.ReplayRefuted, ethproof.ReasonSlotSetAtParent, func(st *ethproof.ReplayNamedState) { st.Before = set.Proof.Before }))
	b.add("refuted_without_before", "s6_replay_refuted{slot_set_at_parent} carrying no Before", sSet,
		named(set, ethproof.ReplayRefuted, ethproof.ReasonSlotSetAtParent, nil))
	b.add("refuted_with_another_parent", "s6_replay_refuted{slot_set_at_parent} carrying another chain's parent", sSet,
		named(set, ethproof.ReplayRefuted, ethproof.ReasonSlotSetAtParent, func(st *ethproof.ReplayNamedState) { st.Before = other.Proof.Before }))
	b.add("refuted_before_proves_zero", "s6_replay_refuted{slot_set_at_parent} whose Before proves the slot 0", s6replay1.SettlementOf(unset),
		named(unset, ethproof.ReplayRefuted, ethproof.ReasonSlotSetAtParent, func(st *ethproof.ReplayNamedState) { st.Before = unset.Proof.Before }))

	// Header hashing: only the canonical RLP of a header is accepted (SPEC delta §2).
	chain := world(replayworld.Opts{After: 1})
	nc := s6replay1.CloneProof(chain.Proof)
	nc.Headers[0] = nonCanonicalList(nc.Headers[0])
	b.add("header_non_canonical_rlp", "a header after the settlement block with a non-canonical list-length prefix", s6replay1.SettlementOf(chain),
		s6replay1.ProofEvidence(nc))
	ncp := s6replay1.CloneProof(base.Proof)
	ncp.Before.ParentHeader = nonCanonicalList(ncp.Before.ParentHeader)
	b.add("parent_header_non_canonical_rlp", "the Before parent header with a non-canonical list-length prefix", sBase, s6replay1.ProofEvidence(ncp))
	sNC := sBase
	sNC.HeaderRLP = hexutil.Encode(nonCanonicalList(hexutil.MustDecode(sBase.HeaderRLP)))
	b.add("settlement_header_non_canonical_rlp", "the settlement header with a non-canonical list-length prefix", sNC, evBase)

	// Settlement transaction envelopes (RB10-F14, V-R10C D2): the same target, calldata and chain in every type.
	to, data := *base.Tx.To(), base.Tx.Data()
	cid := big.NewInt(replayworld.ChainID)
	gas := uint64(500000)
	legacy := types.NewTx(&types.LegacyTx{Nonce: 3, GasPrice: big.NewInt(2), Gas: gas, To: &to, Value: big.NewInt(0), Data: data, V: big.NewInt(27)})
	b.add("envelope_legacy_pre_eip155", "a legacy settlement transaction without a chain id (v = 27)", withTx(base, legacy), evBase)
	l155 := types.NewTx(&types.LegacyTx{Nonce: 3, GasPrice: big.NewInt(2), Gas: gas, To: &to, Value: big.NewInt(0), Data: data,
		V: new(big.Int).Add(new(big.Int).Mul(cid, big.NewInt(2)), big.NewInt(35))})
	b.add("envelope_legacy_eip155", "an EIP-155 legacy settlement transaction of the proof's chain", withTx(base, l155), evBase)
	l155other := types.NewTx(&types.LegacyTx{Nonce: 3, GasPrice: big.NewInt(2), Gas: gas, To: &to, Value: big.NewInt(0), Data: data,
		V: new(big.Int).Add(new(big.Int).Mul(new(big.Int).Add(cid, big.NewInt(1)), big.NewInt(2)), big.NewInt(35))})
	b.add("envelope_legacy_eip155_other_chain", "an EIP-155 legacy settlement transaction of another chain", withTx(base, l155other), evBase)
	al := types.NewTx(&types.AccessListTx{ChainID: cid, Nonce: 3, GasPrice: big.NewInt(2), Gas: gas, To: &to, Value: big.NewInt(0), Data: data})
	b.add("envelope_type1_access_list", "a type-1 (EIP-2930) settlement transaction", withTx(base, al), evBase)
	b.add("envelope_type2_dynamic_fee", "a type-2 (EIP-1559) settlement transaction (the base world's)", sBase, evBase)
	blobInner := &types.BlobTx{ChainID: uint256.NewInt(replayworld.ChainID), Nonce: 3, GasTipCap: uint256.NewInt(1), GasFeeCap: uint256.NewInt(2),
		Gas: gas, To: to, Value: uint256.NewInt(0), Data: data, BlobFeeCap: uint256.NewInt(1),
		BlobHashes: []common.Hash{common.HexToHash("0x0100000000000000000000000000000000000000000000000000000000000001")}}
	blob := types.NewTx(blobInner)
	b.add("envelope_type3_blob_canonical", "a type-3 (EIP-4844) settlement transaction in its canonical (block) form", withTx(base, blob), evBase)
	b.add("envelope_type3_blob_sidecar_v0", "a type-3 settlement transaction in its network form with a version-0 sidecar (no blobs)",
		withTx(base, blob.WithBlobTxSidecar(types.NewBlobTxSidecar(types.BlobSidecarVersion0, nil, nil, nil))), evBase)
	b.add("envelope_type3_blob_sidecar_v1", "a type-3 settlement transaction in its network form with a version-1 sidecar (no blobs)",
		withTx(base, blob.WithBlobTxSidecar(types.NewBlobTxSidecar(types.BlobSidecarVersion1, nil, nil, nil))), evBase)
	sc := types.NewTx(&types.SetCodeTx{ChainID: uint256.NewInt(replayworld.ChainID), Nonce: 3, GasTipCap: uint256.NewInt(1), GasFeeCap: uint256.NewInt(2),
		Gas: gas, To: to, Value: uint256.NewInt(0), Data: data, AuthList: []types.SetCodeAuthorization{}})
	b.add("envelope_type4_set_code", "a type-4 (EIP-7702) settlement transaction", withTx(base, sc), evBase)
	b.add("envelope_named_state_blob_sidecar_v0", "a named state held to a type-3 settlement in its network form (the hash excludes the sidecar)",
		withTx(base, blob.WithBlobTxSidecar(types.NewBlobTxSidecar(types.BlobSidecarVersion0, nil, nil, nil))),
		named(base, ethproof.ReplayUnproven, ethproof.ReasonStateUnavailable, func(st *ethproof.ReplayNamedState) { st.TxHash = blob.Hash() }))

	// Hex-typed values carrying a JSON escape (V-R10C D1): Go refuses s6_replay_unproven{wrong_type}.
	evS := string(evBase)
	for _, f := range []struct{ key, desc string }{
		{"contract", "the proof's contract (address)"}, {"key", "the slot key (hash)"}, {"slot", "the slot (hash)"},
		{"hash", "the settlement block hash (hash)"}, {"accountProof", "an After account-proof node (bytes)"},
		{"storageProof", "an After storage-proof node (bytes)"}, {"value", "the After value (hash)"},
		{"storageHash", "the After storage hash (hash)"}, {"codeHash", "the After code hash (hash)"},
		{"parentHeader", "the Before parent header (bytes)"},
	} {
		b.add("escaped_hex_proof_"+strings.ToLower(f.key), "a JSON escape (\\u0078) inside "+f.desc, sBase, []byte(escapeField(evS, f.key)))
	}
	evH := s6replay1.ProofEvidence(chain.Proof)
	b.add("escaped_hex_proof_headers", "a JSON escape (\\u0078) inside a header after the settlement block (bytes)", s6replay1.SettlementOf(chain),
		[]byte(escapeField(string(evH), "headers")))
	b.add("escaped_hex_proof_digit", "a JSON escape of the leading digit (\\u0030) of the proof's contract", sBase,
		[]byte(strings.Replace(evS, `"contract":"0x`, `"contract":`+esc0, 1)))
	stS := string(named(base, ethproof.ReplayUnproven, ethproof.ReasonStateUnavailable, nil))
	for _, f := range []struct{ key, desc string }{
		{"txHash", "the named state's txHash (hash)"}, {"blockHash", "the named state's blockHash (hash)"}, {"contract", "the named state's contract (address)"},
	} {
		b.add("escaped_hex_state_"+strings.ToLower(f.key), "a JSON escape (\\u0078) inside "+f.desc, sBase, []byte(escapeField(stS, f.key)))
	}
	refS := string(named(set, ethproof.ReplayRefuted, ethproof.ReasonSlotSetAtParent, func(st *ethproof.ReplayNamedState) { st.Before = set.Proof.Before }))
	b.add("escaped_hex_state_before_parent_header", "a JSON escape (\\u0078) inside a refutation's Before parent header", sSet,
		[]byte(escapeField(refS, "parentHeader")))
	// Where the escaped-hex refusal sits in the decode order (SPEC delta §4): after the whole schema check, before the
	// version and the one-of rule.
	escC := escapeField(evS, "contract")
	b.add("escaped_hex_order_after_schema", "an escaped hex value and an unknown field: the schema check refuses first", sBase,
		[]byte(strings.Replace(escC, `{"version":`, `{"extra":1,"version":`, 1)))
	b.add("escaped_hex_order_before_version", "an escaped hex value and an unknown version: the escape refuses first", sBase,
		[]byte(strings.Replace(escC, `{"version":"certen:s6-replay:v1","proof"`, `{"version":"certen:s6-replay:v0","proof"`, 1)))
	b.add("escaped_hex_order_before_one_of", "an escaped hex value and both a proof and a named state: the escape refuses first", sBase,
		[]byte(strings.TrimSuffix(escC, "}")+`,"state":`+strings.TrimSuffix(strings.SplitN(stS, `"state":`, 2)[1], "}")+"}"))
	b.add("escaped_string_control", "a JSON escape inside a string-typed field (generation): not a hex value, still proven", sBase,
		[]byte(strings.Replace(evS, `"generation":"CertenAccountV7_3"`, `"generation":"`+escV+`"`, 1)))
	return b.vectors
}

// MutationBases are the proof vectors the bounded corpus (s6replay1.BuildMutationsOf) mutates; the named states are
// mutated by BuildEscapeMutations.
var MutationBases = []string{"016_envelope_type1_access_list",
	"018_envelope_type3_blob_canonical", "019_envelope_type3_blob_sidecar_v0"}

// EscapeMutationBases are the vectors whose every hex value ("0x…) is mutated once with each JSON escape of its prefix.
var EscapeMutationBases = []string{"001_state_honest_chain_and_contract", "006_refuted_with_verified_before", "017_envelope_type2_dynamic_fee"}

// BuildEscapeMutations is, for each escape base, one mutation per hex value per escape form (x escaped, 0 escaped).
func BuildEscapeMutations(vectors []s6replay1.Vector) []s6replay1.Mutation {
	byName := map[string]s6replay1.Vector{}
	for _, v := range vectors {
		byName[v.Name] = v
	}
	var out []s6replay1.Mutation
	for _, bn := range EscapeMutationBases {
		v, ok := byName[bn]
		if !ok {
			panic("s6replay3: no escape base " + bn)
		}
		for i := 0; ; i++ {
			x, ok := escapeAt(v.Evidence, i, false)
			if !ok {
				break
			}
			d, _ := escapeAt(v.Evidence, i, true)
			out = append(out,
				s6replay1.Mutation{Name: fmt.Sprintf("%s/escape_x_%d", bn, i), Base: bn, Evidence: x, Expect: s6replay1.Judge(v.Settlement, []byte(x))},
				s6replay1.Mutation{Name: fmt.Sprintf("%s/escape_0_%d", bn, i), Base: bn, Evidence: d, Expect: s6replay1.Judge(v.Settlement, []byte(d))})
		}
	}
	return out
}

// Files are the set's files by name: one JSON per vector, mutations.json.gz, manifest.json and MANIFEST.
func Files() map[string][]byte {
	vectors := BuildVectors()
	muts := append(s6replay1.BuildMutationsOf(vectors, MutationBases), BuildEscapeMutations(vectors)...)
	return s6replay1.SuiteFiles(vectors, muts, Generator)
}
