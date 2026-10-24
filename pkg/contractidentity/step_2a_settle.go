// Copyright 2026 Certen Protocol

package contractidentity

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// Package 2a, steps 10-14: the anchor chain at stateRoot_N, the state at settlement (Open entries) and the authority level.

// a2StatedOrRefusal is the common prologue of the anchor-chain steps (10-13): a Stated settle part decides the part with its carried
// reason. ok is true when the step is decided here.
func a2StatedOrRefusal(env *Env, part string) (PartResult, bool, error) {
	if st := env.SettleStated(); st != nil {
		u, err := a2StatedU(st, part)
		return a2U(part, u), true, err
	}
	return PartResult{}, false, nil
}

// ---- step 10 ----

func a2Step10(env *Env) (StepOutput, error) {
	f, m, ctx := &env.Facts.A, env.Manifest, env.Ctx
	if p, done, err := a2StatedOrRefusal(env, JudgedCodeIdentity); done {
		return a2One(p), err
	}
	row, ok := m.Deployment(ctx.Chain, RoleAnchor)
	if !ok {
		f.AnchorRefusal = Must(CodeAddressNotPublished, "", map[string]any{"role": RoleAnchor, "address": common.Address{}})
		return a2One(a2R(JudgedCodeIdentity, f.AnchorRefusal)), nil
	}
	bld, ok := m.Build(row.Build)
	if !ok {
		return StepOutput{}, fmt.Errorf("contractidentity: the manifest has no build %q", row.Build)
	}
	j, err := a2JudgeCode(a2Reader(env), RoleAnchor, "anchor", f.Anchor, bld, false)
	if err != nil {
		return StepOutput{}, err
	}
	if j.refusal != nil {
		f.AnchorRefusal = j.refusal
		return a2One(a2R(JudgedCodeIdentity, j.refusal)), nil
	}
	chainWord := common.BigToHash(new(big.Int).SetUint64(ctx.Chain))
	st, err := a2Immutables(RoleAnchor, j.code, bld, func(im Immutable, _ int) (common.Hash, error) {
		if im.Rule.Kind != "chainId" {
			return common.Hash{}, fmt.Errorf("contractidentity: anchor immutable %s has the rule kind %q", im.Name, im.Rule.Kind)
		}
		return chainWord, nil
	})
	if err != nil {
		return StepOutput{}, err
	}
	if st != nil {
		f.AnchorRefusal = st
		return a2One(a2R(JudgedCodeIdentity, st)), nil
	}
	f.AnchorState, f.AnchorCode = j.acct, j.code
	return a2One(env.Verified(JudgedCodeIdentity)), nil
}

// ---- step 11 ----

// a2Record fills the record fields from its 13 words (the layout of CertenAnchorV8_2 anchors[]): word 0 bundleId, 1 merkleRoot, 6
// executionCommitment, 7 operationID, 8 accumulateBlockHeight, 10 the packed flags, 11 accumulateValidatorSetRoot, 12 accumulateIncarnation.
func a2Record(words [13]common.Hash, isBatch, leafCount common.Hash) AnchorRecord {
	p := words[10]
	return AnchorRecord{
		Words: words, BundleID: words[0], MerkleRoot: words[1], ExecutionCommitment: words[6], OperationID: words[7], AccumulateBlockHeight: words[8],
		AccSetRoot: words[11], AccIncarnation: words[12], BatchLeafCount: leafCount,
		Valid: p[11] == 1, ProofExecuted: p[10] == 1, GovernanceExecuted: p[9] == 1, GovernanceLevel: p[8], IsBatchAnchor: isBatch == SlotIndex(1),
	}
}

func a2Step11(env *Env) (StepOutput, error) {
	f, ctx := &env.Facts.A, env.Ctx
	if p, done, err := a2StatedOrRefusal(env, JudgedRecord); done {
		return a2One(p), err
	}
	if f.AnchorID == ([32]byte{}) {
		return a2One(a2U(JudgedRecord, f.PathFailure)), nil
	}
	if f.AnchorRefusal != nil {
		return a2One(a2R(JudgedRecord, f.AnchorRefusal)), nil
	}
	r := a2Reader(env)
	rec := MappingSlotAt(KeyBytes32(f.AnchorID), 1)
	var words [13]common.Hash
	for k := range words {
		words[k] = r.slot(f.Anchor, f.AnchorState, MemberSlot(rec, uint64(k)))
	}
	isBatch := r.slot(f.Anchor, f.AnchorState, MappingSlotAt(KeyBytes32(f.AnchorID), 2))
	leafCount := r.slot(f.Anchor, f.AnchorState, MappingSlotAt(KeyBytes32(f.AnchorID), 3))
	if !r.ok() {
		if r.defect != nil {
			return StepOutput{}, r.defect
		}
		return StepOutput{Parts: []PartResult{a2R(JudgedRecord, r.bad)}, ReadPlanIncomplete: "anchor_record"}, nil
	}
	a := a2Record(words, isBatch, leafCount)
	inconsistent := func(field string) StepOutput {
		return a2One(a2R(JudgedRecord, Must(CodeRecordInconsistent, "", map[string]any{"field": field})))
	}
	if a.BundleID != f.AnchorID {
		return inconsistent("bundle_id"), nil
	}
	if !a.Valid || !a.ProofExecuted {
		return a2One(a2R(JudgedRecord, Must(CodeRecordNotExecuted, "", map[string]any{"anchorId": f.AnchorID, "valid": a.Valid, "proofExecuted": a.ProofExecuted}))), nil
	}
	f.Record = a
	if !a.IsBatchAnchor {
		return a2One(a2U(JudgedRecord, Must(CodeUnproven, RowUnprovenAnchorNotBatch, map[string]any{"anchorId": f.AnchorID}))), nil
	}
	packed := append([]byte("certen:batchbundle:v2"), common.BigToHash(new(big.Int).SetUint64(ctx.Chain)).Bytes()...)
	for _, w := range [][32]byte{a.MerkleRoot, a.BatchLeafCount, a.OperationID, a.AccumulateBlockHeight, a.AccSetRoot, a.AccIncarnation} {
		packed = append(packed, w[:]...)
	}
	if a2K(packed) != common.Hash(f.AnchorID) {
		return inconsistent("bundle_id"), nil
	}
	b := ctx.Batch
	for _, c := range []struct {
		field     string
		got, want [32]byte
	}{{"merkle_root", a.MerkleRoot, b.BatchRoot}, {"operation_id", a.OperationID, b.OperationID}, {"acc_set_root", a.AccSetRoot, b.AccSetRoot}, {"incarnation", a.AccIncarnation, b.Incarnation}} {
		if c.got != c.want {
			return inconsistent(c.field), nil
		}
	}
	return a2One(env.Verified(JudgedRecord)), nil
}

// ---- step 12 ----

func a2Step12(env *Env) (StepOutput, error) {
	f, m, ctx := &env.Facts.A, env.Manifest, env.Ctx
	if p, done, err := a2StatedOrRefusal(env, JudgedCodeIdentity); done {
		return a2One(p), err
	}
	if f.AnchorRefusal != nil {
		return a2One(a2R(JudgedCodeIdentity, f.AnchorRefusal)), nil
	}
	judged := []string{RuleVERIFIERID}
	r := a2Reader(env)
	w30 := r.slot(f.Anchor, f.AnchorState, SlotIndex(30))
	if !r.ok() {
		if r.defect != nil {
			return StepOutput{}, r.defect
		}
		return StepOutput{Parts: []PartResult{a2R(JudgedCodeIdentity, r.bad)}, ReadPlanIncomplete: "anchor_slot_30"}, nil
	}
	v := a2Low20(w30)
	f.VerifierFlags = [2]byte{w30[10], w30[9]}
	notPublished := func(role string, a common.Address) StepOutput {
		return StepOutput{Parts: []PartResult{a2R(JudgedCodeIdentity, Must(CodeAddressNotPublished, "", map[string]any{"role": role, "address": a}))}, RulesJudged: judged}
	}
	vrow, ok := m.Deployment(ctx.Chain, RoleBlsZkVerifier)
	if !ok || v == (common.Address{}) || common.HexToAddress(vrow.Address) != v {
		return notPublished(RoleBlsZkVerifier, v), nil
	}
	f.Verifier = v
	vb, ok := m.Build(vrow.Build)
	if !ok {
		return StepOutput{}, fmt.Errorf("contractidentity: the manifest has no build %q", vrow.Build)
	}
	jv, err := a2JudgeCode(r, RoleBlsZkVerifier, "blsZkVerifier", v, vb, false)
	if err != nil {
		return StepOutput{}, err
	}
	f.VerifierState = jv.acct
	if jv.refusal != nil {
		return StepOutput{Parts: []PartResult{a2R(JudgedCodeIdentity, jv.refusal)}, RulesJudged: judged}, nil
	}
	f.VerifierCode = jv.code
	var first common.Hash
	st, err := a2Immutables(RoleBlsZkVerifier, jv.code, vb, func(im Immutable, idx int) (common.Hash, error) {
		if im.Rule.Kind != "deployment" {
			return common.Hash{}, fmt.Errorf("contractidentity: verifier immutable %s has the rule kind %q", im.Name, im.Rule.Kind)
		}
		if idx == 0 {
			ref := im.References[0]
			first = common.BytesToHash(jv.code[ref.Start : ref.Start+32])
			first = a2Word(a2Low20(first)) // a word with garbage in its upper bytes is the mismatch of the first reference
		}
		return first, nil
	})
	if err != nil {
		return StepOutput{}, err
	}
	if st != nil {
		return StepOutput{Parts: []PartResult{a2R(JudgedCodeIdentity, st)}, RulesJudged: judged}, nil
	}
	g := a2Low20(first)
	grow, ok := m.Deployment(ctx.Chain, RoleGroth16Verifier)
	if !ok || common.HexToAddress(grow.Address) != g {
		return notPublished(RoleGroth16Verifier, g), nil
	}
	f.Groth16, f.Groth16Build = g, grow.Build
	gb, ok := m.Build(grow.Build)
	if !ok {
		return StepOutput{}, fmt.Errorf("contractidentity: the manifest has no build %q", grow.Build)
	}
	jg, err := a2JudgeCode(r, RoleGroth16Verifier, "", g, gb, false)
	if err != nil {
		return StepOutput{}, err
	}
	f.Groth16State = jg.acct
	if jg.refusal != nil {
		return StepOutput{Parts: []PartResult{a2R(JudgedCodeIdentity, jg.refusal)}, RulesJudged: judged}, nil
	}
	f.Groth16Code = jg.code
	return StepOutput{Parts: []PartResult{env.Verified(JudgedCodeIdentity)}, RulesJudged: judged}, nil
}

// ---- step 13 ----

func a2U64(w common.Hash) (uint64, bool) {
	b := new(big.Int).SetBytes(w[:])
	return b.Uint64(), b.IsUint64()
}

func a2Bool(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func a2Step13(env *Env) (StepOutput, error) {
	f, m, ctx := &env.Facts.A, env.Manifest, env.Ctx
	const part = JudgedStateAtSettlement
	if p, done, err := a2StatedOrRefusal(env, part); done {
		return a2One(p), err
	}
	if f.AnchorRefusal != nil || f.Verifier == (common.Address{}) || f.AnchorState.StorageRoot == (common.Hash{}) {
		// the anchor chain is not established (steps 10 and 12 said why): there is no state to compare and nothing to report here
		return StepOutput{Parts: []PartResult{env.Verified(part)}, ReadPlanIncomplete: "anchor_chain_not_established"}, nil
	}
	pol := m.Policy()
	r := a2Reader(env)
	A, V := f.Anchor, f.Verifier
	acctA, acctV := f.AnchorState, f.VerifierState
	_ = r.account(f.Groth16) // C01: the codeHash of G at N (proven by step 12; the account walk is the read the plan counts)
	words := map[string]common.Hash{}
	a := func(id string, s common.Hash) common.Hash { w := r.slot(A, acctA, s); words[id] = w; return w }
	paused := a("A01", SlotIndex(0))
	incomplete := ""
	if env.Container.Attest.Tag == TagCaptured {
		if pkc := env.Facts.B1.PKC; pkc != ([32]byte{}) {
			a("A05", MappingSlotAt(KeyBytes32(pkc), 4))
		} else {
			incomplete = "pkc_unavailable"
		}
	}
	a("A07", SlotIndex(5))
	bind := a("A08", SlotIndex(6))
	nWord := a("A10", SlotIndex(13))
	n, fits := a2U64(nWord)
	if r.ok() && (!fits || n > uint64(DefaultLimits().MaxValidators)) {
		incomplete = "validator_list_too_large"
		n = 0
	}
	for i := uint64(0); i < n && r.ok(); i++ {
		el, _, err := ArrayElementSlot(13, i, 20)
		if err != nil {
			return StepOutput{}, err
		}
		val := a(fmt.Sprintf("A10:%d", i), el)
		base := MappingSlotAt(KeyAddress(a2Low20(val)), 12)
		r.slot(A, acctA, base)
		r.slot(A, acctA, MemberSlot(base, 1))
		r.bytes(A, acctA, MemberSlot(base, 2), 256)
		r.slot(A, acctA, MemberSlot(base, 3))
	}
	a("A11", SlotIndex(14))
	num, den, root := a("A12", SlotIndex(15)), a("A13", SlotIndex(16)), a("A14", SlotIndex(17))
	owner := a("A16", SlotIndex(27))
	gov := a("A17", SlotIndex(29))
	s30 := a("A18", SlotIndex(30))
	words["A18"] = a2Word(a2Low20(s30))
	words["A19"], words["A20"], words["A21"] = common.BigToHash(new(big.Int).SetUint64(uint64(s30[11]))), common.BigToHash(new(big.Int).SetUint64(uint64(s30[10]))), common.BigToHash(new(big.Int).SetUint64(uint64(s30[9])))
	v0, v1, v2 := r.slot(V, acctV, SlotIndex(0)), r.slot(V, acctV, SlotIndex(1)), r.slot(V, acctV, SlotIndex(2))
	words["V01"], words["V02"], words["V03"] = v0, v1, v2
	ownersA, ownersV := m.OwnerCovering(ctx.Chain, "anchor", f.SettleHeader.Number), m.OwnerCovering(ctx.Chain, "blsZkVerifier", f.SettleHeader.Number)
	if len(ownersV) == 0 {
		ownersV = ownersA
	}
	seen := map[common.Address]bool{}
	for _, o := range append(append([]OwnerRow(nil), ownersA...), ownersV...) {
		if oa := common.HexToAddress(o.Address); !seen[oa] {
			seen[oa] = true
			r.account(oa) // C01: the pinned owner at N
		}
	}
	if !r.ok() {
		if r.defect != nil {
			return StepOutput{}, r.defect
		}
		return StepOutput{Parts: []PartResult{a2R(part, r.bad)}, ReadPlanIncomplete: "state_at_settlement"}, nil
	}
	f.SettleAUTH = words
	out := StepOutput{Parts: []PartResult{env.Verified(part)}, ReadPlanIncomplete: incomplete,
		RulesJudged: []string{RulePAUSED, RuleBINDING, RuleENABLED, RuleTHRESHOLDA, RuleTHRESHOLDV, RuleOWNER, RuleGOVVERIFIER, RuleMINGOV}}
	alert := func(field string, onchain, want any) error {
		o, err := env.Open(part, OpenAlert, CodeAlert, "", map[string]any{"field": field, "at": AtSettle, "onchain": onchain, "want": want})
		out.Open = append(out.Open, o)
		return err
	}
	ratio := func(n, d common.Hash) string {
		return new(big.Int).SetBytes(n[:]).String() + "/" + new(big.Int).SetBytes(d[:]).String()
	}
	var err error
	keep := func(e error) {
		if err == nil {
			err = e
		}
	}
	if paused[31] != 0 {
		keep(alert("paused", uint64(paused[31]), uint64(0)))
	}
	if bind[31] != byte(a2Bool(pol.PubkeyBindingEnforced)) {
		keep(alert("binding", uint64(bind[31]), a2Bool(pol.PubkeyBindingEnforced)))
	}
	if s30[11] != byte(a2Bool(pol.BLSZKVerificationEnabled)) {
		keep(alert("enabled", uint64(s30[11]), a2Bool(pol.BLSZKVerificationEnabled)))
	}
	wantA := ratio(common.BigToHash(new(big.Int).SetUint64(pol.BLSThreshold.Numerator)), common.BigToHash(new(big.Int).SetUint64(pol.BLSThreshold.Denominator)))
	if got := ratio(num, den); got != wantA {
		keep(alert("threshold", got, wantA))
	}
	wantV := ratio(common.BigToHash(new(big.Int).SetUint64(pol.VerifierThreshold.Numerator)), common.BigToHash(new(big.Int).SetUint64(pol.VerifierThreshold.Denominator)))
	if got := ratio(v0, v1); got != wantV {
		keep(alert("verifier_threshold", got, wantV))
	}
	for _, c := range []struct {
		got  common.Address
		rows []OwnerRow
	}{{a2Low20(owner), ownersA}, {a2Low20(v2), ownersV}} {
		in := false
		var want common.Address
		for i, o := range c.rows {
			if i == 0 {
				want = common.HexToAddress(o.Address)
			}
			in = in || common.HexToAddress(o.Address) == c.got
		}
		if !in {
			keep(alert("owner", c.got, want))
		}
	}
	if g := a2Low20(gov); g != (common.Address{}) {
		keep(alert("governance_verifier", g, common.Address{}))
	}
	if s30[10] < pol.MinimumGovernanceLevel {
		keep(alert("minimum_governance_level", uint64(s30[10]), uint64(pol.MinimumGovernanceLevel)))
	}
	// drift: a value that was equal at both attestation stations and differs at N (a legitimate rotation after the attestation)
	for _, id := range []string{"A05", "A07", "A10", "A11", "A14", "A18"} {
		att, ok := env.Facts.B2.Post.Words[id]
		if !ok {
			continue
		}
		if cur := words[id]; cur != att {
			o, e := env.Open(part, OpenDrift, CodeDrift, "", map[string]any{"field": id, "attest": att, "settle": cur})
			out.Open = append(out.Open, o)
			keep(e)
		}
	}
	_ = root
	return out, err
}

// ---- step 14 ----

var a2Levels = []string{LevelNONE, LevelOPERATOR, LevelMANAGER, LevelADMIN, LevelROOT}

func a2LevelOf(page uint64, book common.Hash, setWord, stored common.Hash, governing common.Hash) (level int, source string, invalid *big.Int) {
	switch {
	case page == 0 || book == (common.Hash{}):
		return 0, "none", nil
	case setWord != (common.Hash{}):
		v := new(big.Int).SetBytes(stored[:])
		if v.Cmp(big.NewInt(4)) > 0 {
			return 0, "stored", v
		}
		return int(v.Int64()), "stored", nil
	case book != governing:
		return 0, "none", nil
	case page == 1:
		return 4, "governing_default", nil
	case page == 2:
		return 3, "governing_default", nil
	}
	return 1, "governing_default", nil
}

// a2RequiredFor is `_requiredLevelFor` (CertenAccountV7_3.sol:661-678) applied to the stored requirement.
func a2RequiredFor(stored int, value *big.Int) int {
	if stored != 0 {
		return stored
	}
	ether := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	switch {
	case value.Cmp(new(big.Int).Mul(ether, big.NewInt(10))) >= 0:
		return 4
	case value.Cmp(ether) >= 0:
		return 3
	case value.Cmp(new(big.Int).Div(ether, big.NewInt(10))) >= 0:
		return 2
	}
	return 1
}

func a2Step14(env *Env) (StepOutput, error) {
	f, m, ctx := &env.Facts.A, env.Manifest, env.Ctx
	const part = JudgedAuthorityLevel
	if p, blocked, err := a2Blocked(env, part); blocked {
		return a2One(p), err
	}
	if f.PathFailure != nil {
		return a2One(a2U(part, f.PathFailure)), nil
	}
	if f.GoverningBookHash == (common.Hash{}) { // step 6 or 7 refused account_provenance: the governing default cannot be computed
		return a2One(a2U(part, Must(CodeUnproven, RowUnprovenAuthorityLevelUnproven, map[string]any{"reason": LevelReasonCalldataUndecodable, "field": "governing_book_hash"}))), nil
	}
	unproven := func(fields map[string]any) StepOutput {
		return a2One(a2U(part, Must(CodeUnproven, RowUnprovenAuthorityLevelUnproven, fields)))
	}
	call, err := DecodeSettlementCall(ctx.Tx.Data(), DefaultABILimits())
	if err != nil {
		var ae *ABIError
		if !errors.As(err, &ae) {
			return StepOutput{}, err
		}
		if ae.Kind == ABICap {
			return unproven(map[string]any{"reason": LevelReasonTooManyLegs, "count": ae.Got, "limit": ae.Limit}), nil
		}
		return unproven(map[string]any{"reason": LevelReasonCalldataUndecodable, "field": ae.Field}), nil
	}
	book, page := common.Hash(call.Proof.AuthorityBook), call.Proof.AuthorityPage
	r := a2Reader(env)
	setWord := r.slot(f.Account, f.AccountState, PageSlot(10, book, page))
	stored := r.slot(f.Account, f.AccountState, PageSlot(9, book, page))
	reqs := make([]common.Hash, len(call.Legs))
	for i, l := range call.Legs {
		reqs[i] = r.slot(f.Account, f.AccountState, MappingSlotAt(KeyBytes4(l.Selector), 8))
	}
	if !r.ok() {
		if r.defect != nil {
			return StepOutput{}, r.defect
		}
		return StepOutput{Parts: []PartResult{a2R(part, r.bad)}, ReadPlanIncomplete: "authority_level"}, nil
	}
	invalidWord := func(a common.Address, slot common.Hash) StepOutput {
		return a2One(a2R(part, Must(CodeProofInvalid, "", map[string]any{"root": AtSettle, "address": a, "slot": slot})))
	}
	if setWord != (common.Hash{}) && setWord != SlotIndex(1) {
		return invalidWord(f.Account, PageSlot(10, book, page)), nil
	}
	level, source, invalid := a2LevelOf(page, book, setWord, stored, f.GoverningBookHash)
	if invalid != nil {
		return a2One(a2R(part, Must(CodeAuthorityLevelInvalid, "", map[string]any{"field": LevelInvalidFieldPageLevel, "got": invalid}))), nil
	}
	required := make([]int, len(call.Legs))
	for i, l := range call.Legs {
		v := new(big.Int).SetBytes(reqs[i][:])
		if v.Cmp(big.NewInt(4)) > 0 {
			return invalidWord(f.Account, MappingSlotAt(KeyBytes4(l.Selector), 8)), nil
		}
		required[i] = a2RequiredFor(int(v.Int64()), l.Value)
	}
	for i, l := range call.Legs {
		if l.Target == f.Account {
			return unproven(map[string]any{"reason": LevelReasonSelfCallLeg, "leg": uint64(i)}), nil
		}
	}
	logged, ok := a2LoggedLevel(env, call)
	if !ok {
		return unproven(map[string]any{"reason": LevelReasonLevelLogMissing}), nil
	}
	if logged != level {
		return unproven(map[string]any{"reason": LevelReasonLevelDiffersFromLogged, "logged": a2Levels[logged], "computed": a2Levels[level]}), nil
	}
	obj := &AuthorityObject{Level: a2Levels[level], LoggedLevel: a2Levels[logged], Book: call.Proof.AuthorityBook, Page: page, Source: source}
	for i, l := range call.Legs {
		if level < required[i] {
			return unproven(map[string]any{"reason": LevelReasonLevelBelowRequiredAtN, "leg": uint64(i), "level": a2Levels[level], "required": a2Levels[required[i]]}), nil
		}
		obj.Legs = append(obj.Legs, AuthorityLeg{Target: l.Target, Selector: l.Selector, Value: l.Value, Required: a2Levels[required[i]]})
	}
	f.Authority = obj
	_ = m
	return a2One(env.Verified(part)), nil
}

// a2LoggedLevel reads the level the contract used from the logs of the account in the receipt: one GovernanceOperationExecuted per leg in
// leg order (topic2 = target) and, for a batch, exactly one GovernanceBatchExecuted (topic2 = anchorId, callCount = len), all with one level.
func a2LoggedLevel(env *Env, call *SettlementCall) (int, bool) {
	f := &env.Facts.A
	events := env.Manifest.AccountEventTopics()
	opT, okA := events["GovernanceOperationExecuted"]
	batchT, okB := events["GovernanceBatchExecuted"]
	if !okA || !okB {
		return 0, false
	}
	var ops, batches []*logEntry
	for _, l := range env.Ctx.Receipt.Logs {
		if l.Address != f.Account || len(l.Topics) != 3 {
			continue
		}
		switch l.Topics[0] {
		case a2Hash(opT.Topic0):
			ops = append(ops, &logEntry{l.Topics, l.Data})
		case a2Hash(batchT.Topic0):
			batches = append(batches, &logEntry{l.Topics, l.Data})
		}
	}
	if len(ops) != len(call.Legs) {
		return 0, false
	}
	level := -1
	same := func(lv uint8) bool {
		if level >= 0 && level != int(lv) {
			return false
		}
		level = int(lv)
		return true
	}
	for i, l := range call.Legs {
		if ops[i].topics[2] != a2Word(l.Target) {
			return 0, false
		}
		d, err := DecodeGovernanceOperationData(ops[i].data)
		if err != nil || !same(d.Level) {
			return 0, false
		}
	}
	if call.Batch {
		if len(batches) != 1 || batches[0].topics[2] != common.Hash(f.AnchorID) {
			return 0, false
		}
		d, err := DecodeGovernanceBatchData(batches[0].data)
		if err != nil || !d.CallCount.IsUint64() || d.CallCount.Uint64() != uint64(len(call.Legs)) || !same(d.Level) {
			return 0, false
		}
	}
	return level, level >= 0
}

type logEntry struct {
	topics []common.Hash
	data   []byte
}
