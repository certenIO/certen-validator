// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// Package 2b-1: steps 15, 16, 17 and 20 of "Offline verification algorithm" (V2_SPEC_S8 r3.2): is the attestation present, the link of the
// attestation block B_v to the settlement block (same block, EIP-2935 hop chain, header spine), the attestation transaction and receipt
// with the strict ABI decode and the blob layout, and the binding of the signed message M. Reads go through env.Nodes (step 22b); the
// root names of a failing read are attest_post (the transaction and receipt of B_v, the record words of B_v), attest_pre, hop:<j> (the
// j-th hop header, 1-based, H_j = hopHeaders[j-1]) and settle (the last link of a hop chain is read under the settlement state root).

// RegisterSteps2b1 registers the four steps of package 2b-1.
func RegisterSteps2b1(reg *StepRegistry) error {
	for _, s := range []struct {
		id StepID
		fn StepFunc
	}{{Step15, b1Step15}, {Step16, b1Step16}, {Step17, b1Step17}, {Step20, b1Step20}} {
		if err := reg.Register(s.id, s.fn); err != nil {
			return err
		}
	}
	return nil
}

// ---- small helpers ----

func b1R(part string, st *StateError) PartResult {
	return PartResult{Part: part, Status: StatusRefused, State: st}
}
func b1U(part string, st *StateError) PartResult {
	return PartResult{Part: part, Status: StatusUnproven, State: st}
}

func b1Mismatch(field string) *StateError {
	return Must(CodeAttestMismatch, "", map[string]any{"field": field})
}

func b1LinkName(link uint8) string {
	switch link {
	case LinkHops:
		return HopLinkHops
	case LinkSameBlock:
		return HopLinkSameBlock // [r3.2:F16]
	}
	return HopLinkSpine
}

func b1Unlinked(link uint8, index int, reason string) *StateError {
	return Must(CodeHeaderUnlinked, "", map[string]any{"link": b1LinkName(link), "index": uint64(maxInt(index, 0)), "reason": reason})
}

func b1ProofInvalid(root string, a common.Address, slot common.Hash) *StateError {
	return Must(CodeProofInvalid, "", map[string]any{"root": root, "address": a, "slot": slot})
}

// b1ProofInvalidLeaf is the proof_invalid of the transaction and receipt proofs [r3.2:F16]: root attest_tx or attest_receipt, address A and
// slot rlp(txIndex) as 0x hex (the key of the trie walk).
func b1ProofInvalidLeaf(root string, a common.Address, txIndex uint64) *StateError {
	key, err := rlp.EncodeToBytes(txIndex)
	if err != nil {
		panic(err) // rlp of a uint64 cannot fail
	}
	return Must(CodeProofInvalid, "", map[string]any{"root": root, "address": a, "slot": "0x" + hex.EncodeToString(key)})
}

// b1ReadFailure classifies a read error: a ReadError is a proof that does not verify (returned as the state), anything else is a defect.
func b1ReadFailure(err error, root string, a common.Address, slot common.Hash) (*StateError, error) {
	var re *ReadError
	if errors.As(err, &re) {
		if re.Slot != nil {
			slot = *re.Slot
		}
		return b1ProofInvalid(root, a, slot), nil
	}
	return nil, err
}

func b1Word(n uint64) common.Hash { return common.BigToHash(new(big.Int).SetUint64(n)) }

// ---- step 15: attest present? ----

var (
	b1DetailTooLarge = regexp.MustCompile(`^(?:bytes|txs)=([0-9]{1,19});limit=([0-9]{1,19})$`)
	b1DetailReach    = regexp.MustCompile(`^gap=([0-9]{1,19});window=([0-9]{1,19});hops_carried=([0-9]{1,19});last_hop=([0-9]{1,19})$`)
)

func b1Nums(re *regexp.Regexp, detail string) ([]uint64, bool) {
	m := re.FindStringSubmatch(detail)
	if m == nil {
		return nil, false
	}
	out := make([]uint64, 0, len(m)-1)
	for _, s := range m[1:] {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}

// b1StatedStates are the states a Stated attest part decides: authorization_attest carries the reason of the part, intra_block_window is
// attest_absent (block_too_large keeps its numbers), registry_link is attest_absent [r3.2:F6]. ok is false when the carried detail of a
// reason that needs numbers does not parse (the part is then a refused container, see b1Step15).
func b1StatedStates(st *Stated) (auth, window *StateError, ok bool, err error) {
	absent := func(part string) *StateError {
		return Must(CodeUnproven, RowUnprovenAttestAbsent, map[string]any{"reason": RowUnprovenAttestAbsent, "part": part})
	}
	window = absent(JudgedIntraBlockWindow)
	switch st.Reason {
	case RowUnprovenCaptureNotAttemptedInWindow, RowUnprovenStateUnavailable, RowUnprovenAttestBlockStateUnavailable:
		fails := make([]any, 0, len(st.Failures))
		for _, f := range st.Failures {
			fails = append(fails, map[string]any{"host": f.Host, "error": f.Error})
		}
		auth, err = New(CodeUnproven, st.Reason, map[string]any{"reason": st.Reason, "part": JudgedAuthorizationAttest, "judgedBlock": st.JudgedBlock, "judgedHash": st.JudgedHash, "failures": fails})
	case RowUnprovenAttestEventNotFound:
		auth, err = New(CodeUnproven, st.Reason, map[string]any{"reason": st.Reason, "part": JudgedAuthorizationAttest})
	case RowUnprovenAttestBlockOutOfReach:
		n, good := b1Nums(b1DetailReach, st.Detail)
		if !good {
			return nil, nil, false, nil
		}
		auth, err = New(CodeUnproven, st.Reason, map[string]any{"reason": st.Reason, "gap": n[0], "window": n[1], "hops_carried": n[2], "last_hop": n[3]})
	case RowUnprovenBlockTooLarge:
		n, good := b1Nums(b1DetailTooLarge, st.Detail)
		if !good {
			return nil, nil, false, nil
		}
		auth, err = New(CodeUnproven, st.Reason, map[string]any{"reason": st.Reason, "part": JudgedAuthorizationAttest, "bytes": n[0], "limit": n[1]})
		if err == nil {
			window, err = New(CodeUnproven, st.Reason, map[string]any{"reason": st.Reason, "part": JudgedIntraBlockWindow, "bytes": n[0], "limit": n[1]})
		}
	default: // CheckStatedReasons-style list: the caller has already required a builder reason
		return nil, nil, false, fmt.Errorf("contractidentity: step 15: stated attest reason %q has no unproven row", st.Reason)
	}
	return auth, window, err == nil, err
}

// b1Step15 decides the attest parts when the attest part is Stated: authorization_attest (the carried reason), intra_block_window
// (attest_absent, or block_too_large{bytes,limit}) and, because step 21 reads the registry at B_v, registry_link (attest_absent) [r3.2:F6].
// A captured attest part sets AttestCaptured and decides nothing. A Stated reason outside the six builder reasons is
// evidence_malformed{part:attest,reason:unknown_stated_reason} (framework class); a block_too_large or attest_block_out_of_reach part whose
// detail does not carry its numbers (`bytes=<n>;limit=<m>`, `gap=..;window=..;hops_carried=..;last_hop=..`) is bad_stated_reason.
func b1Step15(env *Env) (StepOutput, error) {
	f := &env.Facts.B1
	st := env.AttestStated()
	if st == nil {
		f.AttestCaptured = true
		return StepOutput{}, nil
	}
	f.AttestCaptured = false
	if !Check("stated_reason_builders", st.Reason) {
		return StepOutput{Framework: Malformed(PartAttest, MalformedUnknownStatedReason, 0, 0, 0)}, nil
	}
	auth, window, ok, err := b1StatedStates(st)
	if err != nil {
		return StepOutput{}, err
	}
	if !ok {
		return StepOutput{Framework: Malformed(PartAttest, MalformedBadStatedReason, 0, 0, 0)}, nil
	}
	link := Must(CodeUnproven, RowUnprovenAttestAbsent, map[string]any{"reason": RowUnprovenAttestAbsent, "part": JudgedRegistryLink})
	return StepOutput{Parts: []PartResult{b1U(JudgedAuthorizationAttest, auth), b1U(JudgedIntraBlockWindow, window), b1U(JudgedRegistryLink, link)}}, nil
}

// ---- step 16: the link of B_v to the settlement block ----

// b1Step16 judges (a) the order, (b) link 1 hop chain, (c) link 2 spine (link 0 is the same block) and (d) the parent of B_v, then sets
// HeaderV, HeaderVParent and the two state roots. The facts are set whenever the headers can be read, also when the link is refused, so that
// the reads of the later steps are the reads of the algorithm; HeaderLinked says whether the link verified. Every read of the hop chain is
// performed even when an earlier link has already decided the part (step 22b); the first failing link, in link order, decides it.
func b1Step16(env *Env) (StepOutput, error) {
	f := env.Facts
	if !f.B1.AttestCaptured {
		return StepOutput{}, nil
	}
	a := env.Container.Attest.Attest
	if a == nil {
		return StepOutput{}, fmt.Errorf("contractidentity: step 16: captured attest part without a body")
	}
	s := f.A.SettleHeader
	if s.Hash == ([32]byte{}) {
		return StepOutput{}, fmt.Errorf("contractidentity: step 16: the settlement header was not read (step 2 did not run)")
	}
	if env.Ctx.Settlement == nil || env.Ctx.Settlement.Tx == nil {
		return StepOutput{}, fmt.Errorf("contractidentity: step 16: the leg context carries no settlement transaction index")
	}
	part := JudgedAuthorizationAttest
	incomplete := ""
	var verdict *PartResult // the first failing check decides
	decide := func(r PartResult) {
		if verdict == nil {
			verdict = &r
		}
	}
	// the two headers of B_v
	hv, errV := env.Header(a.HeaderV)
	hp, errP := env.Header(a.HeaderVParent)
	if errV != nil {
		decide(b1R(part, b1Unlinked(a.Link, 0, HopReasonHashChainBroken)))
		return StepOutput{Parts: []PartResult{*verdict}, ReadPlanIncomplete: "attest_header_unreadable"}, nil
	}
	// (a) order
	switch a.Link {
	case LinkSameBlock:
		if uint64(a.TxIndex) >= env.Ctx.Settlement.Tx.LeafIndex {
			decide(b1R(part, b1Mismatch("order")))
		}
	default:
		if hv.Number >= s.Number {
			decide(b1R(part, b1Mismatch("order")))
		}
	}
	walked := 0
	switch a.Link {
	case LinkSameBlock: // B_v is the settlement block
		if hv.Hash != s.Hash {
			decide(b1R(part, b1Unlinked(a.Link, 0, HopReasonHashChainBroken)))
		}
	case LinkHops:
		if err := b1HopChain(env, hv, a, &walked, &incomplete, decide); err != nil {
			return StepOutput{}, err
		}
	case LinkSpine:
		prevHash, prevNum := s.ParentHash, s.Number
		if len(a.Spine) == 0 {
			decide(b1R(part, b1Unlinked(a.Link, 0, HopReasonHashChainBroken)))
		}
		for j, raw := range a.Spine {
			h, err := env.Header(raw)
			if err != nil {
				decide(b1R(part, b1Unlinked(a.Link, j, HopReasonHashChainBroken)))
				break
			}
			if h.Hash != prevHash {
				decide(b1R(part, b1Unlinked(a.Link, j, HopReasonHashChainBroken)))
				break
			}
			if prevNum == 0 || h.Number != prevNum-1 {
				decide(b1R(part, b1Unlinked(a.Link, j, HopReasonNumbersNotConsecutive)))
				break
			}
			prevHash, prevNum = h.ParentHash, h.Number
			walked = j + 1
			if j == len(a.Spine)-1 && h.Hash != hv.Hash {
				decide(b1R(part, b1Unlinked(a.Link, j, HopReasonHashChainBroken)))
			}
		}
	default:
		return StepOutput{}, fmt.Errorf("contractidentity: step 16: link %d passed the decoder", a.Link)
	}
	// (d) the parent of B_v
	if errP != nil || hp.Hash != hv.ParentHash || hp.Number+1 != hv.Number {
		decide(b1R(part, b1Unlinked(a.Link, 0, HopReasonParentMismatch)))
	}
	b := &f.B1
	b.HeaderV, b.StateRootPost = hv, hv.StateRoot
	if errP == nil {
		b.HeaderVParent, b.StateRootPre = hp, hp.StateRoot
	}
	b.HopChain = HopChainResult{Link: a.Link, Walked: walked}
	b.HeaderLinked = verdict == nil
	out := StepOutput{ReadPlanIncomplete: incomplete}
	if errP != nil {
		out.ReadPlanIncomplete = "attest_parent_header_unreadable"
	}
	if verdict == nil {
		out.Parts = []PartResult{env.Verified(part)}
	} else {
		out.Parts = []PartResult{*verdict}
	}
	return out, nil
}

// b1HopChain is step 16(b): H_0 = headerV, H_1..H_k the hop headers, H_{k+1} the settlement header. Link i connects H_i to H_{i+1}:
// 0 < num(H_{i+1}) - num(H_i) <= W[chain] (numbers_not_consecutive when not ascending, gap_out_of_range when a link before the last is
// wider than W, attest_block_out_of_reach when the LAST link is wider and no further hop is carried), the history account at
// stateRoot(H_{i+1}) has the pinned code hash (history_code_mismatch) and its slot num(H_i) mod W holds keccak256(H_i) (slot_mismatch).
func b1HopChain(env *Env, hv finality.HeaderFields, a *AttestProof, walked *int, incomplete *string, decide func(PartResult)) error {
	part := JudgedAuthorizationAttest
	row, ok := env.Manifest.EIP2935(env.Ctx.Chain)
	if !ok || row.Window == 0 {
		return fmt.Errorf("contractidentity: step 16: the manifest has no eip2935 window for chain %d", env.Ctx.Chain)
	}
	hist := common.HexToAddress(row.Address)
	pin := common.HexToHash(row.CodeHash)
	hdrs := []finality.HeaderFields{hv}
	for j, raw := range a.HopHeaders {
		h, err := env.Header(raw)
		if err != nil {
			decide(b1R(part, b1Unlinked(LinkHops, j, HopReasonHashChainBroken)))
			*incomplete = "attest_hop_header_unreadable"
			return nil
		}
		hdrs = append(hdrs, h)
	}
	k := len(a.HopHeaders)
	hdrs = append(hdrs, env.Facts.A.SettleHeader)
	for i := 0; i <= k; i++ {
		lo, hi := hdrs[i], hdrs[i+1]
		root := AtSettle
		if i < k {
			root = fmt.Sprintf("hop:%d", i+1)
		}
		failed := false
		fail := func(st *StateError, class func(string, *StateError) PartResult) {
			if !failed {
				decide(class(part, st))
			}
			failed = true
		}
		switch {
		case hi.Number <= lo.Number:
			fail(b1Unlinked(LinkHops, i, HopReasonNumbersNotConsecutive), b1R)
		case hi.Number-lo.Number > row.Window && i == k:
			fail(Must(CodeUnproven, RowUnprovenAttestBlockOutOfReach, map[string]any{"reason": RowUnprovenAttestBlockOutOfReach, "gap": hi.Number - lo.Number,
				"window": row.Window, "hops_carried": uint64(k), "last_hop": lo.Number}), b1U)
		case hi.Number-lo.Number > row.Window:
			fail(b1Unlinked(LinkHops, i, HopReasonGapOutOfRange), b1R)
		}
		acct, err := ReadAccount(common.Hash(hi.StateRoot), env.Nodes, hist)
		if err != nil {
			st, derr := b1ReadFailure(err, root, hist, common.Hash{})
			if derr != nil {
				return derr
			}
			decide(b1R(part, st))
			*incomplete = "attest_hop_read"
			return nil
		}
		if !acct.Exists || acct.CodeHash != pin {
			fail(b1Unlinked(LinkHops, i, HopReasonHistoryCodeMismatch), b1R)
		}
		if acct.Exists {
			slot := b1Word(lo.Number % row.Window)
			w, err := ReadSlot(acct.StorageRoot, env.Nodes, slot)
			if err != nil {
				st, derr := b1ReadFailure(err, root, hist, slot)
				if derr != nil {
					return derr
				}
				decide(b1R(part, st))
				*incomplete = "attest_hop_read"
				return nil
			}
			if w == (common.Hash{}) || w != common.Hash(lo.Hash) {
				fail(b1Unlinked(LinkHops, i, HopReasonSlotMismatch), b1R)
			}
		}
		if !failed && *walked == i {
			*walked = i + 1
		}
	}
	return nil
}

// ---- step 17: the attestation transaction ----

// b1ExecSelector is the 4-byte selector the manifest pins for executeComprehensiveProof.
func b1ExecSelector(env *Env) ([4]byte, error) {
	s, ok := env.Manifest.Selector("CertenAnchorV8_2/executeComprehensiveProof")
	if !ok {
		return [4]byte{}, fmt.Errorf("contractidentity: the manifest has no selectors row CertenAnchorV8_2/executeComprehensiveProof")
	}
	b := common.FromHex(s.Selector)
	if len(b) != 4 {
		return [4]byte{}, fmt.Errorf("contractidentity: the manifest selector %q is not 4 bytes", s.Selector)
	}
	return [4]byte(b), nil
}

// b1Step17: inclusion of the transaction and the receipt at txIndex under the roots of headerV, the transaction type, the receipt status and
// the ProofExecuted log, the direct call of A, the strict ABI decode of executeComprehensiveProof and the blob layout.
//
// Decision order, where the specification lists the refusals but not their order (recorded as decision D-B1-1 in the check-in): the type
// (U attest_tx_type_unsupported), the receipt status (R status), then the call: when tx.to is A with the pinned selector the log must exist
// (R log); when it is not, a receipt that DOES carry the ProofExecuted log of A for this anchorId proves an attestation through a wrapper
// (U attest_indirect_call, "never a weaker pass"), a receipt that does not is R tx_to / R selector (the transaction at txIndex is not the
// attestation).
func b1Step17(env *Env) (StepOutput, error) {
	f := env.Facts
	if !f.B1.AttestCaptured {
		return StepOutput{}, nil
	}
	a := env.Container.Attest.Attest
	hv := f.B1.HeaderV
	if a == nil || hv.Hash == ([32]byte{}) {
		return StepOutput{}, nil // step 16 could not read the header and decided the part
	}
	part := JudgedAuthorizationAttest
	A := f.A.Anchor
	if A == (common.Address{}) {
		return StepOutput{}, fmt.Errorf("contractidentity: step 17: no anchor address (step 9 did not run)")
	}
	one := func(r PartResult) (StepOutput, error) { return StepOutput{Parts: []PartResult{r}}, nil }
	// inclusion of the leaves under the roots of B_v
	for _, rd := range []struct {
		name string
		root common.Hash
		want []byte
	}{{RootAttestTx, common.Hash(hv.TransactionRoot), a.TxLeaf}, {RootAttestReceipt, common.Hash(hv.ReceiptsRoot), a.ReceiptLeaf}} {
		leaf, err := ReadIndexedLeaf(rd.root, env.Nodes, uint64(a.TxIndex), env.Limits.MaxNodeBytes)
		if err != nil {
			var re *ReadError
			if !errors.As(err, &re) {
				return StepOutput{}, err
			}
			return StepOutput{Parts: []PartResult{b1R(part, b1ProofInvalidLeaf(rd.name, A, uint64(a.TxIndex)))}, ReadPlanIncomplete: "attest_inclusion_read"}, nil
		}
		if !bytes.Equal(leaf, rd.want) {
			return StepOutput{Parts: []PartResult{b1R(part, b1ProofInvalidLeaf(rd.name, A, uint64(a.TxIndex)))}, ReadPlanIncomplete: "attest_inclusion_leaf"}, nil
		}
	}
	// the transaction
	info, err := ClassifyTx(a.TxLeaf)
	if err != nil {
		return one(b1R(part, b1Mismatch("tx_to"))) // an authenticated leaf that is no transaction envelope is not a call of A
	}
	switch info.Type {
	case TxTypeLegacy, TxTypeAccessList, TxTypeDynamicFee, TxTypeSetCode:
	default:
		return one(b1U(part, Must(CodeUnproven, RowUnprovenAttestTxTypeUnsupported, map[string]any{"reason": RowUnprovenAttestTxTypeUnsupported, "type": fmt.Sprintf("0x%02x", info.Type)})))
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(a.TxLeaf); err != nil {
		return one(b1R(part, b1Mismatch("tx_to")))
	}
	rc, err := ethproof.DecodeReceiptLeaf(a.ReceiptLeaf)
	if err != nil {
		return one(b1R(part, b1Mismatch("status")))
	}
	f.B1.AttestTx, f.B1.AttestReceipt, f.B1.TxIndex = tx, rc, a.TxIndex
	if !rc.Succeeded() {
		return one(b1R(part, b1Mismatch("status")))
	}
	anchorID := f.A.AnchorID
	if anchorID == ([32]byte{}) {
		// the anchorId is topic1 of the LeafConsumed log of step 3; without a selected log the ProofExecuted log cannot be selected
		if f.A.PathFailure == nil {
			return StepOutput{}, fmt.Errorf("contractidentity: step 17: no anchorId and step 3 recorded no failure")
		}
		return one(b1U(part, f.A.PathFailure))
	}
	pe, ok := env.Manifest.Topic("ProofExecuted")
	if !ok {
		return StepOutput{}, fmt.Errorf("contractidentity: the manifest has no topics.ProofExecuted")
	}
	topic0 := common.HexToHash(pe.Topic0)
	var logs []*types.Log
	for _, l := range rc.Logs {
		if l.Address == A && len(l.Topics) == 2 && l.Topics[0] == topic0 && l.Topics[1] == common.Hash(anchorID) {
			logs = append(logs, l)
		}
	}
	execSel, err := b1ExecSelector(env)
	if err != nil {
		return StepOutput{}, err
	}
	var sel [4]byte
	copy(sel[:], tx.Data())
	to := common.Address{}
	toIsA := false
	if t := tx.To(); t != nil {
		to, toIsA = *t, *t == A
	}
	switch {
	case toIsA && sel == execSel:
		if len(logs) != 1 {
			return one(b1R(part, b1Mismatch("log")))
		}
	case len(logs) >= 1:
		return one(b1U(part, Must(CodeUnproven, RowUnprovenAttestIndirectCall, map[string]any{"reason": RowUnprovenAttestIndirectCall, "to": to, "selector": sel})))
	case !toIsA:
		return one(b1R(part, b1Mismatch("tx_to")))
	default:
		return one(b1R(part, b1Mismatch("selector")))
	}
	if _, err := DecodeProofExecutedData(logs[0].Data); err != nil {
		return one(b1R(part, b1Mismatch("log")))
	}
	// strict ABI decode of executeComprehensiveProof(bytes32,CertenProof)
	call, err := DecodeComprehensiveProofCall(tx.Data(), DefaultABILimits())
	if err != nil {
		var ae *ABIError
		if errors.As(err, &ae) {
			// a proven, successful attestation whose calldata the strict decoder refuses: U, never R and never a pass [r3.2:F16]
			field := ae.Field
			if field == "" {
				field = "input"
			}
			if len(field) > 64 {
				field = field[:64]
			}
			return one(b1U(part, Must(CodeUnproven, RowUnprovenAttestCalldataUndecodable, map[string]any{"reason": string(ae.Kind), "field": field})))
		}
		return StepOutput{}, err
	}
	f.B1.Call = AttestCall{AnchorID: call.AnchorID, OperationCommitment: call.Commitments.OperationCommitment, OuterSigned: call.BLS.SignedVotingPower,
		OuterTotal: call.BLS.TotalVotingPower, ValidatorAddresses: call.BLS.ValidatorAddresses, VotingPowers: call.BLS.VotingPowers,
		AuthorityLevel: call.Governance.AuthorityLevel}
	if call.AnchorID != anchorID {
		return one(b1R(part, b1Mismatch("anchor_id")))
	}
	// commitments.operationCommitment equals the operationID of the record (the usedCommitments key): the record read at N when step 11
	// established it, otherwise the batch facts of the context (F7); a difference is a flip that is not this transaction's
	opID := f.A.Record.OperationID
	if f.A.Record.BundleID != anchorID {
		opID = env.Ctx.Batch.OperationID
	}
	if call.Commitments.OperationCommitment != opID {
		return one(b1R(part, b1Mismatch(AttestFieldOperationCommitment))) // [r3.2:F16]
	}
	// the aggregate-signature blob
	blob, err := DecodeZKBlob(call.BLS.AggregateSignature)
	if err != nil || blob.MessageHash != call.BLS.MessageHash || blob.PubkeyCommitment == ([32]byte{}) {
		return one(b1R(part, b1Mismatch("blob_layout")))
	}
	f.B1.Call.BlobInnerSigned, f.B1.Call.BlobInnerTotal = blob.SignedVotingPower, blob.TotalVotingPower
	f.B1.MessageHash, f.B1.PKC = blob.MessageHash, blob.PubkeyCommitment
	return one(env.Verified(part))
}

// ---- step 20: message binding ----

var b1MessageTag = func() (t [32]byte) { copy(t[:], "certen:bls:v2:pre"); return }()

// b1Step20: M == keccak256(abi.encode(bytes32("certen:bls:v2:pre"), chainId, anchorId, record.executionCommitment, record.operationID,
// currentValidatorSetRoot_pre, record.accSetRoot, record.accIncarnation)). The record words come from step 11 when it established the record
// at N, otherwise (a Stated settle part, F7) from the record proven at B_v under stateRoot_post; currentValidatorSetRoot_pre is anchor slot
// 17 under stateRoot_pre. Both are read here under the root names attest_post and attest_pre, so the step does not depend on the spelling
// of the AUTH words of package 2b-2.
func b1Step20(env *Env) (StepOutput, error) {
	f := env.Facts
	if !f.B1.AttestCaptured || f.B1.MessageHash == ([32]byte{}) {
		return StepOutput{}, nil // steps 16-17 decided the part or could not establish M
	}
	part := JudgedAuthorizationAttest
	A, anchorID := f.A.Anchor, f.A.AnchorID
	rec := f.A.Record
	var exec, opID, accSet, inc [32]byte
	read := func(root string, sr [32]byte, slots ...common.Hash) ([]common.Hash, *StateError, error) {
		acct, err := ReadAccount(common.Hash(sr), env.Nodes, A)
		if err != nil {
			st, derr := b1ReadFailure(err, root, A, common.Hash{})
			return nil, st, derr
		}
		out := make([]common.Hash, len(slots))
		for i, s := range slots {
			w, err := ReadSlot(acct.StorageRoot, env.Nodes, s)
			if err != nil {
				st, derr := b1ReadFailure(err, root, A, s)
				return nil, st, derr
			}
			out[i] = w
		}
		return out, nil, nil
	}
	refuse := func(st *StateError) (StepOutput, error) {
		return StepOutput{Parts: []PartResult{b1R(part, st)}, ReadPlanIncomplete: "attest_message_read"}, nil
	}
	if rec.BundleID == anchorID {
		exec, opID, accSet, inc = rec.ExecutionCommitment, rec.OperationID, rec.AccSetRoot, rec.AccIncarnation
	} else {
		base := MappingSlotAt(KeyBytes32(anchorID), 1)
		ws, st, err := read(AtAttestPost, f.B1.StateRootPost, MemberSlot(base, 6), MemberSlot(base, 7), MemberSlot(base, 11), MemberSlot(base, 12))
		if err != nil {
			return StepOutput{}, err
		}
		if st != nil {
			return refuse(st)
		}
		exec, opID, accSet, inc = ws[0], ws[1], ws[2], ws[3]
	}
	ws, st, err := read(AtAttestPre, f.B1.StateRootPre, SlotIndex(17))
	if err != nil {
		return StepOutput{}, err
	}
	if st != nil {
		return refuse(st)
	}
	chain := new(big.Int).SetUint64(env.Ctx.Chain)
	enc := make([]byte, 0, 8*32)
	for _, w := range [][]byte{b1MessageTag[:], common.LeftPadBytes(chain.Bytes(), 32), anchorID[:], exec[:], opID[:], ws[0][:], accSet[:], inc[:]} {
		enc = append(enc, w...)
	}
	f.B1.MessageRecomputed = crypto.Keccak256Hash(enc)
	if f.B1.MessageRecomputed != common.Hash(f.B1.MessageHash) {
		return StepOutput{Parts: []PartResult{b1R(part, b1Mismatch("message_hash"))}}, nil
	}
	return StepOutput{Parts: []PartResult{env.Verified(part)}}, nil
}
