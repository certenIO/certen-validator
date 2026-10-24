// Copyright 2026 Certen Protocol

package contractidentity

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Package 2a: steps 1c, 2-14 of "Offline verification algorithm" (V2_SPEC_S8 r3.2). Steps 1c-9 and the shared helpers are in this file,
// steps 10-14 in step_2a_settle.go. Every proof read of these steps is judged at stateRoot_N (the root name "settle").

const (
	buildAccount = "CertenAccountV7_3/r5"
	buildFactory = "CertenAccountFactoryV11/r5"
	// entryPointLiteral is the spec literal of step 7 (the canonical ERC-4337 v0.7 EntryPoint) used when a manifest row carries no value.
	entryPointLiteral = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
)

// RegisterSteps2a registers the 14 steps of package 2a.
func RegisterSteps2a(reg *StepRegistry) error {
	for _, s := range []struct {
		id StepID
		fn StepFunc
	}{
		{Step1c, a2Step1c}, {Step2, a2Step2}, {Step3, a2Step3}, {Step4, a2Step4}, {Step5, a2Step5}, {Step6, a2Step6}, {Step7, a2Step7},
		{Step8, a2Step8}, {Step9, a2Step9}, {Step10, a2Step10}, {Step11, a2Step11}, {Step12, a2Step12}, {Step13, a2Step13}, {Step14, a2Step14},
	} {
		if err := reg.Register(s.id, s.fn); err != nil {
			return err
		}
	}
	return nil
}

// ---- small helpers ----

func a2R(part string, st *StateError) PartResult {
	return PartResult{Part: part, Status: StatusRefused, State: st}
}
func a2U(part string, st *StateError) PartResult {
	return PartResult{Part: part, Status: StatusUnproven, State: st}
}
func a2One(p PartResult) StepOutput { return StepOutput{Parts: []PartResult{p}} }

func a2K(b ...[]byte) common.Hash { return crypto.Keccak256Hash(b...) }

func a2Word(a common.Address) common.Hash { return common.BytesToHash(a[:]) }

// a2Low20 is the low 20 bytes of a word (a packed address at byte offset 0).
func a2Low20(w common.Hash) common.Address { return common.BytesToAddress(w[12:]) }

// a2Carried is the runtime code the container carries for an address, nil when it carries none.
func (e *Env) a2Carried(a common.Address) []byte {
	if e.Container == nil {
		return nil
	}
	for _, c := range e.Container.Codes {
		if c.Address == [20]byte(a) {
			return c.Runtime
		}
	}
	return nil
}

// a2Mask zeroes every reference range in a copy of code; a range reaching beyond the code is clamped (a truncated code is judged by its
// length first, so the clamp only decides what the refusal prints).
func a2Mask(code []byte, refs []Ref) []byte {
	out := append([]byte(nil), code...)
	for _, r := range refs {
		lo, hi := r.Start, r.Start+r.Length
		if lo < 0 {
			lo = 0
		}
		if hi > len(out) {
			hi = len(out)
		}
		for i := lo; i < hi; i++ {
			out[i] = 0
		}
	}
	return out
}

func a2BuildRefs(b Build) []Ref {
	var refs []Ref
	for _, im := range b.Immutables {
		refs = append(refs, im.References...)
	}
	return refs
}

// a2StatedU is the unproven state a Stated settle part carries into a part that needs a settlement-block read (step 1c(b)). Step 1c has
// refused every reason other than the two settle reasons, so any other reason here is a defect of the caller.
func a2StatedU(st *Stated, part string) (*StateError, error) {
	if st.Reason != RowUnprovenCaptureNotAttemptedInWindow && st.Reason != RowUnprovenStateUnavailable {
		return nil, fmt.Errorf("contractidentity: stated settle part with reason %q reached a settle-dependent step", st.Reason)
	}
	fails := make([]any, 0, len(st.Failures))
	for _, f := range st.Failures {
		fails = append(fails, map[string]any{"host": f.Host, "error": f.Error})
	}
	return New(CodeUnproven, st.Reason, map[string]any{"reason": st.Reason, "part": part, "judgedBlock": st.JudgedBlock, "judgedHash": st.JudgedHash, "failures": fails})
}

// a2rd reads the settle station: the first read that does not verify is the proof_invalid refusal, and nothing is read after it.
type a2rd struct {
	env    *Env
	root   common.Hash
	name   string
	bad    *StateError
	defect error
}

func a2Reader(env *Env) *a2rd {
	return &a2rd{env: env, root: common.Hash(env.Facts.A.StateRootN), name: AtSettle}
}

func (r *a2rd) fail(err error, a common.Address) {
	if r.bad != nil || r.defect != nil {
		return
	}
	var re *ReadError
	if errors.As(err, &re) {
		var slot common.Hash
		if re.Slot != nil {
			slot = *re.Slot
		}
		r.bad = Must(CodeProofInvalid, "", map[string]any{"root": r.name, "address": a, "slot": slot})
		return
	}
	r.defect = err
}

func (r *a2rd) ok() bool { return r.bad == nil && r.defect == nil }

func (r *a2rd) account(a common.Address) AccountState {
	if !r.ok() {
		return AccountState{}
	}
	st, err := ReadAccount(r.root, r.env.Nodes, a)
	if err != nil {
		r.fail(err, a)
		return AccountState{}
	}
	return st
}

func (r *a2rd) slot(a common.Address, acct AccountState, s common.Hash) common.Hash {
	if !r.ok() {
		return common.Hash{}
	}
	w, err := ReadSlot(acct.StorageRoot, r.env.Nodes, s)
	if err != nil {
		r.fail(err, a)
		return common.Hash{}
	}
	return w
}

func (r *a2rd) bytes(a common.Address, acct AccountState, s common.Hash, max uint64) []byte {
	if !r.ok() {
		return nil
	}
	b, err := ReadBytes(acct.StorageRoot, r.env.Nodes, s, max)
	if err != nil {
		r.fail(err, a)
		return nil
	}
	return b
}

// a2Code is the verdict on the code of one account at stateRoot_N.
type a2Code struct {
	acct    AccountState
	code    []byte
	gen     *Generation // the pinned:false generation row the code is (accounts and anchors only)
	refusal *StateError // account_absent, code_unproven_bytes, code_not_published or proof_invalid
}

func a2Hash(s string) common.Hash { return common.HexToHash(s) }

// a2JudgeCode proves the account, requires its carried code to hash to the proven codeHash and compares its masked keccak and length with
// the pinned build (steps 5, 8b, 10, 12). With scanGen the code may instead be a pinned:false generation of genRole.
func a2JudgeCode(r *a2rd, role, genRole string, addr common.Address, build Build, scanGen bool) (a2Code, error) {
	out := a2Code{}
	out.acct = r.account(addr)
	if !r.ok() {
		if r.defect != nil {
			return out, r.defect
		}
		out.refusal = r.bad
		return out, nil
	}
	if !out.acct.HasCode() {
		out.refusal = Must(CodeAccountAbsent, "", map[string]any{"role": role, "address": addr, "root": r.name})
		return out, nil
	}
	code := r.env.a2Carried(addr)
	if code == nil || a2K(code) != out.acct.CodeHash {
		out.refusal = Must(CodeCodeUnprovenBytes, "", map[string]any{"address": addr})
		return out, nil
	}
	out.code = code
	want := a2Hash(build.Runtime.MaskedKeccak)
	masked := a2K(a2Mask(code, a2BuildRefs(build)))
	if len(code) == build.Runtime.Bytes && masked == want {
		return out, nil
	}
	if scanGen {
		for _, g := range r.env.Manifest.Generations() {
			if g.Role == genRole && !g.Pinned && g.RuntimeBytes == len(code) && a2K(a2Mask(code, g.References)) == a2Hash(g.MaskedKeccak) {
				gg := g
				out.gen = &gg
				return out, nil
			}
		}
	}
	out.refusal = Must(CodeCodeNotPublished, "", map[string]any{"role": role, "address": addr, "code_hash": out.acct.CodeHash, "masked_keccak": masked, "want": want})
	return out, nil
}

func a2GenUnpinned(row string, g Generation, code []byte) *StateError {
	return Must(CodeUnproven, row, map[string]any{"generation": g.Generation, "code_hash": a2K(code), "kind": g.Kind})
}

// a2Immutables checks every reference of every immutable of build in code against want (the expected 32-byte value of the immutable, ok
// false when the rule needs nothing to compare); the first difference is immutable_mismatch{role,name,offset,got,want}.
func a2Immutables(role string, code []byte, build Build, want func(im Immutable, idx int) (common.Hash, error)) (*StateError, error) {
	for _, im := range build.Immutables {
		for i, ref := range im.References {
			if ref.Length != 32 || ref.Start < 0 || ref.Start+ref.Length > len(code) {
				return nil, fmt.Errorf("contractidentity: build %s immutable %s reference %d [%d,+%d) does not fit the %d byte code", build.Key(), im.Name, i, ref.Start, ref.Length, len(code))
			}
			w, err := want(im, i)
			if err != nil {
				return nil, err
			}
			got := common.BytesToHash(code[ref.Start : ref.Start+32])
			if got != w {
				return Must(CodeImmutableMismatch, "", map[string]any{"role": role, "name": im.Name, "offset": uint64(ref.Start), "got": got, "want": w}), nil
			}
		}
	}
	return nil, nil
}

// a2Blocked is what a step that depends on the established account (6-9, 14) decides while it is not: the carried Stated reason, the
// settlement-path failure, the unpinned generation or the refusal of step 5. ok is false when the account is established.
func a2Blocked(env *Env, part string) (StepOutput, bool, error) {
	f := &env.Facts.A
	inc := func(p PartResult) (StepOutput, bool, error) {
		return StepOutput{Parts: []PartResult{p}, ReadPlanIncomplete: "account_not_established"}, true, nil
	}
	if st := env.SettleStated(); st != nil {
		u, err := a2StatedU(st, part)
		if err != nil {
			return StepOutput{}, true, err
		}
		return a2One(a2U(part, u)), true, nil // the builder pruned the settle nodes: nothing is left unread
	}
	switch {
	case f.Account == (common.Address{}):
		if f.PathFailure == nil {
			return StepOutput{}, true, fmt.Errorf("contractidentity: no account was selected and step 3 recorded no failure")
		}
		return inc(a2U(part, f.PathFailure))
	case f.GenerationState != nil:
		return inc(a2U(part, f.GenerationState))
	case f.AccountRefusal != nil:
		return inc(a2R(part, f.AccountRefusal))
	case !f.AccountState.Exists:
		return StepOutput{}, true, fmt.Errorf("contractidentity: the account state is not established and no step refused it")
	}
	return StepOutput{}, false, nil
}

// ---- step 1c ----

func a2Step1c(env *Env) (StepOutput, error) {
	// 1c(a) (no container) is the prelude; 1c(c) is step 15. Here: a Stated settle part must carry one of the two settle reasons. The other
	// four builder reasons describe the attestation block; a settle part carrying one, like a reason outside the list, is a refused container.
	if st := env.SettleStated(); st != nil && st.Reason != RowUnprovenCaptureNotAttemptedInWindow && st.Reason != RowUnprovenStateUnavailable {
		return StepOutput{Framework: Malformed(PartSettle, MalformedUnknownStatedReason, 0, 0, 0)}, nil
	}
	return StepOutput{}, nil
}

// ---- step 2 ----

func a2Step2(env *Env) (StepOutput, error) {
	c, s := env.Container, env.Ctx.Settlement
	if c.Chain != env.Ctx.Chain {
		return StepOutput{Framework: BlockMismatch("chain", env.Ctx.Chain, c.Chain)}, nil
	}
	h, err := env.Header(s.Header)
	if err != nil {
		return StepOutput{Framework: BlockMismatch("number", c.Leg.Number, uint64(0))}, nil
	}
	if h.Number != c.Leg.Number {
		return StepOutput{Framework: BlockMismatch("number", h.Number, c.Leg.Number)}, nil
	}
	if h.Hash != c.Leg.Hash {
		return StepOutput{Framework: BlockMismatch("hash", h.Hash, c.Leg.Hash)}, nil
	}
	env.Facts.A.SettleHeader = h
	return StepOutput{}, nil
}

// ---- step 3 ----

func a2Step3(env *Env) (StepOutput, error) {
	ctx, m, f := env.Ctx, env.Manifest, &env.Facts.A
	lc, ok := m.Topic("LeafConsumed")
	if !ok {
		return StepOutput{}, fmt.Errorf("contractidentity: the manifest has no topics.LeafConsumed")
	}
	topic0 := a2Hash(lc.Topic0)
	var to common.Address
	hasTo := false
	if t := ctx.Tx.To(); t != nil {
		to, hasTo = *t, true
	}
	var sel [4]byte
	copy(sel[:], ctx.Tx.Data())
	unsupported := func(reason string) *StateError {
		return Must(CodeUnproven, RowUnprovenSettlementPathUnsupported, map[string]any{"to": to, "selector": sel, "reason": reason})
	}
	proven := ctx.S6Status == S6Proven
	// s6Parts is the contribution to s6_link when the path decides nothing about the link: not applicable (S6 made no claim or did not prove)
	// or, for a proven S6, the same unproven state as the path (the link cannot be judged without a selected account).
	s6Parts := func(fail *StateError) (PartResult, []OpenEntry, error) {
		if proven {
			return a2U(JudgedS6Link, fail), nil, nil
		}
		if ctx.S6Status == S6NotProven {
			o, err := env.Open(JudgedS6Link, OpenNotChecked, CodeNotChecked, RowNotCheckedS6LinkS6NotProven, map[string]any{"state": ctx.S6State})
			return env.NotApplicableS6(S6S6NotProven), []OpenEntry{o}, err
		}
		return env.NotApplicableS6(S6S6Silent), nil, nil
	}
	fail := func(st *StateError) (StepOutput, error) {
		f.PathFailure = st
		link, open, err := s6Parts(st)
		return StepOutput{Parts: []PartResult{a2U(JudgedSettlementPath, st), link}, Open: open}, err
	}
	// (a)
	if !ctx.Receipt.Succeeded() {
		return fail(Must(CodeUnproven, RowUnprovenSettlementNotExecuted, map[string]any{"status": ctx.Receipt.PostStateOrStatus}))
	}
	// (b)
	var cands []*types.Log
	foreign := 0
	for _, l := range ctx.Receipt.Logs {
		if len(l.Topics) != 3 || l.Topics[0] != topic0 {
			continue
		}
		if hasTo && l.Address == to {
			if !proven || l.Topics[2] == common.Hash(ctx.S6.LeafKey) {
				cands = append(cands, l)
			}
			continue
		}
		foreign++
	}
	switch {
	case len(cands) >= 2:
		return fail(unsupported("multiple_leaf_consumed"))
	case len(cands) == 0 && foreign >= 1:
		return fail(unsupported("not_direct_call"))
	case len(cands) == 0:
		if proven {
			return fail(Must(CodeUnproven, RowUnprovenSettlementEventMissing, map[string]any{"count": uint64(0)}))
		}
		if infra, role := a2Infrastructure(env, to, hasTo); infra {
			na := Must(CodeNotApplicable, RowNotApplicableCertenInfrastructureCall, map[string]any{"to": to, "role": role})
			var out StepOutput
			for _, p := range JudgedParts {
				switch p {
				case JudgedSettlementPath:
					out.Parts = append(out.Parts, PartResult{Part: p, Status: StatusNotApplicable, State: na})
				case JudgedS6Link:
					link, open, err := s6Parts(na)
					if err != nil {
						return StepOutput{}, err
					}
					out.Parts, out.Open = append(out.Parts, link), open
				default:
					out.Parts = append(out.Parts, PartResult{Part: p, Status: StatusNotApplicable})
				}
			}
			out.Halt, out.HaltReason = true, "certen_infrastructure_call"
			return out, nil
		}
		return fail(Must(CodeUnproven, RowUnprovenSettlementEventMissing, map[string]any{"count": uint64(0)}))
	}
	// one candidate: the account is its emitter; the path is direct (tx.to == emitter by construction of the candidates)
	cand := cands[0]
	f.Account, f.AnchorID, f.LeafKey, f.Selector = cand.Address, cand.Topics[1], cand.Topics[2], sel
	path, link := env.Verified(JudgedSettlementPath), env.Verified(JudgedS6Link)
	var opens []OpenEntry
	if !proven {
		var err error
		if link, opens, err = s6Parts(nil); err != nil {
			return StepOutput{}, err
		}
	} else if cand.Address != ctx.S6.Contract { // (c)
		link = a2R(JudgedS6Link, Must(CodeS6LinkMismatch, "", map[string]any{"field": "account"}))
	}
	// (e) the generation is the code
	if st := env.SettleStated(); st != nil {
		u, err := a2StatedU(st, JudgedSettlementPath)
		if err != nil {
			return StepOutput{}, err
		}
		path = a2U(JudgedSettlementPath, u)
	} else {
		bld, ok := m.Build(buildAccount)
		if !ok {
			return StepOutput{}, fmt.Errorf("contractidentity: the manifest has no build %s", buildAccount)
		}
		f.StateRootN = f.SettleHeader.StateRoot
		j, err := a2JudgeCode(a2Reader(env), RoleAccount, "account", cand.Address, bld, true)
		if err != nil {
			return StepOutput{}, err
		}
		switch {
		case j.gen != nil:
			f.GenerationState = a2GenUnpinned(RowUnprovenAccountGenerationUnpinned, *j.gen, j.code)
			path = a2U(JudgedSettlementPath, f.GenerationState)
		case j.refusal != nil:
			// step 5 decides code_identity; the path itself is direct
		default:
			f.Generation = buildAccount
			pinned := false
			for _, s := range m.AccountSelectors("V7_3") {
				pinned = pinned || strings.EqualFold(s.Selector, "0x"+fmt.Sprintf("%x", sel[:]))
			}
			if !pinned {
				f.PathFailure = unsupported("selector_not_pinned")
				path = a2U(JudgedSettlementPath, f.PathFailure)
			}
		}
	}
	return StepOutput{Parts: []PartResult{path, link}, Open: opens}, nil
}

// a2Infrastructure is the positive evidence of the last row of the step 3 table: tx.to is a deployments row of the chain and no log of
// the receipt is an account event.
func a2Infrastructure(env *Env, to common.Address, hasTo bool) (bool, string) {
	if !hasTo {
		return false, ""
	}
	row, ok := env.Manifest.DeploymentAt(env.Ctx.Chain, to.Hex())
	if !ok {
		return false, ""
	}
	events := env.Manifest.AccountEventTopics()
	for _, l := range env.Ctx.Receipt.Logs {
		if len(l.Topics) == 0 {
			continue
		}
		for _, t := range events {
			if l.Topics[0] == a2Hash(t.Topic0) {
				return false, ""
			}
		}
	}
	return true, row.Role
}

// ---- step 4 ----

func a2Step4(env *Env) (StepOutput, error) {
	ctx, f := env.Ctx, &env.Facts.A
	f.StateRootN = f.SettleHeader.StateRoot
	if ctx.S6Status != S6Proven || f.Account == (common.Address{}) {
		return StepOutput{}, nil // not applicable (decided by step 3), or step 3 refused the path
	}
	leg, s6 := env.Container.Leg, ctx.S6
	mismatch := func(field string) (StepOutput, error) {
		return a2One(a2R(JudgedS6Link, Must(CodeS6LinkMismatch, "", map[string]any{"field": field}))), nil
	}
	if s6.SettlementBlock != leg {
		return mismatch("block")
	}
	if s6.ProvenAt.Hash == leg.Hash {
		if s6.ProvenAt.Number != leg.Number {
			return mismatch("proven_at")
		}
		return a2One(env.Verified(JudgedS6Link)), nil
	}
	if st := env.SettleStated(); st != nil {
		u, err := a2StatedU(st, JudgedS6Link)
		return a2One(a2U(JudgedS6Link, u)), err
	}
	r := a2Reader(env)
	acct := r.account(f.Account)
	if !r.ok() {
		if r.defect != nil {
			return StepOutput{}, r.defect
		}
		return a2One(a2R(JudgedS6Link, r.bad)), nil
	}
	if acct.CodeHash != common.Hash(s6.CodeHash) {
		return mismatch("code_hash")
	}
	return a2One(env.Verified(JudgedS6Link)), nil
}

// ---- step 5 ----

func a2Step5(env *Env) (StepOutput, error) {
	f := &env.Facts.A
	if st := env.SettleStated(); st != nil {
		u, err := a2StatedU(st, JudgedCodeIdentity)
		return a2One(a2U(JudgedCodeIdentity, u)), err
	}
	if f.Account == (common.Address{}) {
		return StepOutput{Parts: []PartResult{a2U(JudgedCodeIdentity, f.PathFailure)}, ReadPlanIncomplete: "account_not_established"}, nil
	}
	bld, ok := env.Manifest.Build(buildAccount)
	if !ok {
		return StepOutput{}, fmt.Errorf("contractidentity: the manifest has no build %s", buildAccount)
	}
	j, err := a2JudgeCode(a2Reader(env), RoleAccount, "account", f.Account, bld, true)
	if err != nil {
		return StepOutput{}, err
	}
	switch {
	case j.gen != nil:
		return StepOutput{Parts: []PartResult{a2U(JudgedCodeIdentity, a2GenUnpinned(RowUnprovenAccountGenerationUnpinned, *j.gen, j.code))}, ReadPlanIncomplete: "account_generation_unpinned"}, nil
	case j.refusal != nil:
		f.AccountRefusal = j.refusal
		return StepOutput{Parts: []PartResult{a2R(JudgedCodeIdentity, j.refusal)}, ReadPlanIncomplete: "account_not_established"}, nil
	}
	f.AccountState, f.AccountCode = j.acct, j.code
	return a2One(env.Verified(JudgedCodeIdentity)), nil
}

// ---- step 6 ----

// a2IsGoverningBookOf is CertenAccountFactoryV11.isGoverningBookOf (CertenAccountFactoryV11.sol:162-176), byte for byte.
func a2IsGoverningBookOf(adiURL, book string) bool {
	a, b := []byte(adiURL), []byte(book)
	if len(a) == 0 || a[len(a)-1] == 0x2F || len(b) < len(a)+2 {
		return false
	}
	for i, c := range b {
		if c >= 0x41 && c <= 0x5A {
			return false
		}
		if i < len(a) {
			if c != a[i] {
				return false
			}
		} else if (i == len(a)) != (c == 0x2F) {
			return false
		}
	}
	return true
}

func a2Step6(env *Env) (StepOutput, error) {
	f := &env.Facts.A
	if out, blocked, err := a2Blocked(env, JudgedAccountProvenance); blocked {
		return out, err
	}
	r := a2Reader(env)
	max := uint64(DefaultLimits().MaxString)
	adi := r.bytes(f.Account, f.AccountState, SlotIndex(0), max)
	book := r.bytes(f.Account, f.AccountState, SlotIndex(11), max)
	if !r.ok() {
		if r.defect != nil {
			return StepOutput{}, r.defect
		}
		return StepOutput{Parts: []PartResult{a2R(JudgedAccountProvenance, r.bad)}, ReadPlanIncomplete: "account_strings"}, nil
	}
	canon := func(reason string) StepOutput {
		return a2One(a2R(JudgedAccountProvenance, Must(CodeAccountNotCanonical, "", map[string]any{"reason": reason})))
	}
	if string(adi) != env.Ctx.ADIURL {
		return canon("adi_url"), nil
	}
	if !a2IsGoverningBookOf(string(adi), string(book)) {
		return canon("governing_book"), nil
	}
	f.ADIURL, f.GoverningBook = string(adi), string(book)
	return a2One(env.Verified(JudgedAccountProvenance)), nil
}

// ---- step 7 ----

// a2ConstantWord is the value of a `constant` immutable: the manifest row's value, the spec literal when the row carries none.
func a2ConstantWord(rule ImmutableRule) common.Hash {
	v := rule.Value
	if v == "" {
		v = entryPointLiteral
	}
	return a2Word(common.HexToAddress(v))
}

func a2Step7(env *Env) (StepOutput, error) {
	f := &env.Facts.A
	if out, blocked, err := a2Blocked(env, JudgedAccountProvenance); blocked {
		return out, err
	}
	if f.ADIURL == "" { // step 6 refused the part
		return StepOutput{}, nil
	}
	bld, ok := env.Manifest.Build(f.Generation)
	if !ok {
		return StepOutput{}, fmt.Errorf("contractidentity: the manifest has no build %q", f.Generation)
	}
	ownerWord := a2Word(common.BytesToAddress(a2K([]byte(f.ADIURL)).Bytes()[12:]))
	bookHash := a2K([]byte(f.GoverningBook))
	st, err := a2Immutables(RoleAccount, f.AccountCode, bld, func(im Immutable, _ int) (common.Hash, error) {
		switch im.Rule.Kind {
		case "constant":
			return a2ConstantWord(im.Rule), nil
		case "adiDerivedOwner":
			return ownerWord, nil
		case "keccakOfGoverningBook":
			return bookHash, nil
		}
		return common.Hash{}, fmt.Errorf("contractidentity: account immutable %s has the rule kind %q, which step 7 does not know", im.Name, im.Rule.Kind)
	})
	if err != nil {
		return StepOutput{}, err
	}
	if st != nil {
		return a2One(a2R(JudgedAccountProvenance, st)), nil
	}
	f.GoverningBookHash = bookHash
	return a2One(env.Verified(JudgedAccountProvenance)), nil
}

// ---- step 8 ----

func a2PackStrings(parts ...any) ([]byte, error) {
	var args abi.Arguments
	for _, p := range parts {
		var t abi.Type
		var err error
		switch p.(type) {
		case common.Address:
			t, err = abi.NewType("address", "", nil)
		case string:
			t, err = abi.NewType("string", "", nil)
		default:
			return nil, fmt.Errorf("contractidentity: abi pack of %T", p)
		}
		if err != nil {
			return nil, err
		}
		args = append(args, abi.Argument{Type: t})
	}
	return args.Pack(parts...)
}

func a2Step8(env *Env) (StepOutput, error) {
	f, m, ctx := &env.Facts.A, env.Manifest, env.Ctx
	if out, blocked, err := a2Blocked(env, JudgedAccountProvenance); blocked {
		return out, err
	}
	if f.ADIURL == "" || f.GoverningBookHash == (common.Hash{}) { // step 6 or 7 refused the part: the factory reads cannot be derived
		return StepOutput{ReadPlanIncomplete: "account_strings_unavailable"}, nil
	}
	row, ok := m.Deployment(ctx.Chain, RoleAccountFactory)
	if !ok {
		return a2One(a2R(JudgedAccountProvenance, Must(CodeAddressNotPublished, "", map[string]any{"role": RoleAccountFactory, "address": common.Address{}}))), nil
	}
	factory := common.HexToAddress(row.Address)
	f.FactoryAddress = factory
	// the reads first (the plan reads the factory whatever (a) says)
	fb, ok := m.Build(buildFactory)
	if !ok {
		return StepOutput{}, fmt.Errorf("contractidentity: the manifest has no build %s", buildFactory)
	}
	r := a2Reader(env)
	j, err := a2JudgeCode(r, RoleAccountFactory, "factory", factory, fb, false)
	if err != nil {
		return StepOutput{}, err
	}
	var deployed, registered common.Hash
	var regKey common.Hash
	if j.refusal == nil {
		deployed = r.slot(factory, j.acct, MappingSlotAt(KeyAddress(f.Account), 2))
		enc, perr := a2PackStrings(f.ADIURL, f.GoverningBook)
		if perr != nil {
			return StepOutput{}, perr
		}
		regKey = a2K(enc)
		registered = r.slot(factory, j.acct, MappingSlotAt(KeyBytes32(regKey), 3))
		if !r.ok() {
			if r.defect != nil {
				return StepOutput{}, r.defect
			}
			j.refusal = r.bad
		}
	}
	canon := func(reason string) StepOutput {
		return a2One(a2R(JudgedAccountProvenance, Must(CodeAccountNotCanonical, "", map[string]any{"reason": reason})))
	}
	// (a) CREATE2
	creation, cerr := m.EmbeddedCreationArtifactBytes(buildAccount)
	if cerr != nil {
		return StepOutput{}, cerr
	}
	owner := common.BytesToAddress(a2K([]byte(f.ADIURL)).Bytes()[12:])
	entry := common.HexToAddress(entryPointLiteral)
	if ab, ok := m.Build(buildAccount); ok {
		for _, im := range ab.Immutables {
			if im.Rule.Kind == "constant" {
				entry = a2Low20(a2ConstantWord(im.Rule))
			}
		}
	}
	ctor, perr := a2PackStrings(entry, owner, f.ADIURL, f.GoverningBook)
	if perr != nil {
		return StepOutput{}, perr
	}
	initcode := append(append([]byte(nil), creation...), ctor...)
	salt := a2K([]byte(f.ADIURL))
	addr := common.BytesToAddress(a2K([]byte{0xff}, factory[:], salt[:], a2K(initcode).Bytes()).Bytes()[12:])
	if addr != f.Account {
		return canon("create2"), nil
	}
	// (b) the factory
	if j.refusal != nil {
		return a2One(a2R(JudgedAccountProvenance, j.refusal)), nil
	}
	st, err := a2Immutables(RoleAccountFactory, j.code, fb, func(im Immutable, _ int) (common.Hash, error) {
		if im.Rule.Kind != "constant" {
			return common.Hash{}, fmt.Errorf("contractidentity: factory immutable %s has the rule kind %q", im.Name, im.Rule.Kind)
		}
		return a2ConstantWord(im.Rule), nil
	})
	if err != nil {
		return StepOutput{}, err
	}
	if st != nil {
		return a2One(a2R(JudgedAccountProvenance, st)), nil
	}
	if deployed != SlotIndex(1) {
		return canon("deployed_flag"), nil
	}
	if registered != a2Word(f.Account) {
		return canon("registry"), nil
	}
	return a2One(env.Verified(JudgedAccountProvenance)), nil
}

// ---- step 9 ----

func a2Step9(env *Env) (StepOutput, error) {
	f, ctx := &env.Facts.A, env.Ctx
	row, ok := env.Manifest.Deployment(ctx.Chain, RoleAnchor)
	if ok {
		f.Anchor = common.HexToAddress(row.Address)
	}
	if out, blocked, err := a2Blocked(env, JudgedPointer); blocked {
		return out, err
	}
	if !ok {
		return a2One(a2R(JudgedPointer, Must(CodeAddressNotPublished, "", map[string]any{"role": RoleAnchor, "address": common.Address{}}))), nil
	}
	r := a2Reader(env)
	got := a2Low20(r.slot(f.Account, f.AccountState, SlotIndex(2)))
	if !r.ok() {
		if r.defect != nil {
			return StepOutput{}, r.defect
		}
		return a2One(a2R(JudgedPointer, r.bad)), nil
	}
	if got == f.Anchor {
		return a2One(env.Verified(JudgedPointer)), nil
	}
	// the pointer is not the manifest anchor: when the container carries the pointed contract, a pinned:false anchor generation is told
	// apart from a decoy (anchor_generation_unpinned versus pointer_mismatch); a pointer that cannot be identified is the mismatch
	if got != (common.Address{}) && env.a2Carried(got) != nil {
		if ab, ok := env.Manifest.Build(row.Build); ok {
			j, err := a2JudgeCode(a2Reader(env), RoleAnchor, "anchor", got, ab, true)
			if err != nil {
				return StepOutput{}, err
			}
			if j.gen != nil {
				return a2One(a2U(JudgedPointer, a2GenUnpinned(RowUnprovenAnchorGenerationUnpinned, *j.gen, j.code))), nil
			}
		}
	}
	return a2One(a2R(JudgedPointer, Must(CodePointerMismatch, "", map[string]any{"account": f.Account, "got": got, "want": f.Anchor}))), nil
}
