// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Package 2b-2: steps 18, 18b, 19 and 22 of "Offline verification algorithm" (V2_SPEC_S8 r3.2): the authorization state of the anchor and the
// verifier at stateRoot_pre and stateRoot_post of the attestation block B_v (the AUTH slot set, the byte rule and the flips, code identity
// at both stations), the uniqueness lemma U, the authorization rules with the verdict precedence of the "Policy rules" table, and rule IB
// (the owner EOA is code-empty with an equal nonce at both stations; the transaction census of B_v; the authWriters gate).
//
// Every read goes through env.Nodes (step 22b). The root names of a failing read are attest_pre and attest_post. The judgments of steps 18
// and 22 are made only against an authenticated block: when step 16 did not verify the link (Facts.B1.HeaderLinked is false) the reads are
// still made (the read plan is fixed by the algorithm, step 22b) but nothing is refused from a block the settlement header does not
// authenticate; step 18 then says code_identity is unproven and step 22 says intra_block_window is unproven (attest_absent), while the
// authorization_attest part stays with the state of step 16.

// RegisterSteps2b2 registers the four steps of package 2b-2.
func RegisterSteps2b2(reg *StepRegistry) error {
	for _, s := range []struct {
		id StepID
		fn StepFunc
	}{{Step18, b2Step18}, {Step18b, b2Step18b}, {Step19, b2Step19}, {Step22, b2Step22}} {
		if err := reg.Register(s.id, s.fn); err != nil {
			return err
		}
	}
	return nil
}

// ---- small helpers ----

func b2R(part string, st *StateError) PartResult {
	return PartResult{Part: part, Status: StatusRefused, State: st}
}
func b2U(part string, st *StateError) PartResult {
	return PartResult{Part: part, Status: StatusUnproven, State: st}
}

func b2Unproven(row string, fields map[string]any) *StateError {
	fields["reason"] = row
	return Must(CodeUnproven, row, fields)
}

func b2Absent(part string) *StateError {
	return b2Unproven(RowUnprovenAttestAbsent, map[string]any{"part": part})
}

func b2Flip() *StateError { return Must(CodeAttestMismatch, "", map[string]any{"field": "flip"}) }

func b2Mismatch(field string, onchain, want, at any) *StateError {
	return Must(CodeAuthorizationMismatch, "", map[string]any{"field": field, "onchain": onchain, "want": want, "at": at})
}

// b2WithPart copies a state and sets its `part` field when the state has one (a U of the part intra_block_window carried to authorization_attest).
func b2WithPart(st *StateError, part string) *StateError {
	if st == nil {
		return nil
	}
	f := map[string]any{}
	for k, v := range st.Fields {
		f[k] = v
	}
	if _, ok := f["part"]; ok {
		f["part"] = part
	}
	return Must(st.Code, st.Reason, f)
}

func b2Num(w common.Hash) *big.Int { return new(big.Int).SetBytes(w[:]) }

func b2Hash(v *big.Int) common.Hash { return common.BigToHash(v) }

func b2Ratio(n, d common.Hash) string { return b2Num(n).String() + "/" + b2Num(d).String() }

func b2Lower(a common.Address) string { return strings.ToLower(a.Hex()) }

// authOrder sorts AUTH row keys by row id, then numerically by the sub-key when it is a number, else by text.
func b2KeyLess(a, b string) bool {
	ia, sa, _ := strings.Cut(a, ":")
	ib, sb, _ := strings.Cut(b, ":")
	if ia != ib {
		return ia < ib
	}
	na, ea := strconv.ParseUint(sa, 10, 64)
	nb, eb := strconv.ParseUint(sb, 10, 64)
	if ea == nil && eb == nil {
		return na < nb
	}
	if (ea == nil) != (eb == nil) {
		return ea == nil
	}
	return sa < sb
}

// ---- reading one attestation station ----

type b2St struct {
	name string
	rd   *a2rd
	w    map[string]common.Hash
	acc  map[string]AccountState
	val  []ValidatorRow
	v, g common.Address
	vPub bool
}

// b2ReadStation reads the AUTH slot set (the frozen table "AUTH slot set and writer premise", rows A01-A21 less A06, V01-V03 and the account
// proofs of A, V, G) at one station. The first read that does not verify is the proof_invalid refusal and nothing is read after it.
func b2ReadStation(env *Env, name string, root common.Hash, A common.Address, anchorID, opID, pkc common.Hash) (*b2St, error) {
	s := &b2St{name: name, rd: &a2rd{env: env, root: root, name: name}, w: map[string]common.Hash{}, acc: map[string]AccountState{}}
	rd := s.rd
	acctA := rd.account(A)
	s.acc["A"] = acctA
	at := func(id string, sl common.Hash) common.Hash {
		w := rd.slot(A, acctA, sl)
		s.w[id] = w
		return w
	}
	at("A01", SlotIndex(0))
	rec := MappingSlotAt(KeyBytes32(anchorID), 1)
	for k := uint64(0); k < 13; k++ {
		at(fmt.Sprintf("A02:%d", k), MemberSlot(rec, k))
	}
	at("A03", MappingSlotAt(KeyBytes32(anchorID), 2))
	at("A04", MappingSlotAt(KeyBytes32(anchorID), 3))
	at("A05", MappingSlotAt(KeyBytes32(pkc), 4))
	at("A07", SlotIndex(5))
	at("A08", SlotIndex(6))
	n, fits := a2U64(at("A10", SlotIndex(13)))
	if rd.ok() && (!fits || n > uint64(DefaultLimits().MaxValidators)) {
		rd.bad = Must(CodeProofInvalid, "", map[string]any{"root": name, "address": A, "slot": SlotIndex(13)})
	}
	for i := uint64(0); rd.ok() && i < n; i++ {
		el, _, err := ArrayElementSlot(13, i, 20)
		if err != nil {
			return nil, err
		}
		addr := a2Low20(at(fmt.Sprintf("A10:%d", i), el))
		base := MappingSlotAt(KeyAddress(addr), 12)
		k := b2Lower(addr)
		w0 := rd.slot(A, acctA, base)
		w1 := rd.slot(A, acctA, MemberSlot(base, 1))
		kb := rd.bytes(A, acctA, MemberSlot(base, 2), 256)
		w3 := rd.slot(A, acctA, MemberSlot(base, 3))
		s.w["A09:"+k+":0"], s.w["A09:"+k+":1"], s.w["A09:"+k+":3"] = w0, w1, w3
		s.w["A09:"+k+":key"] = crypto.Keccak256Hash(kb)
		s.val = append(s.val, ValidatorRow{Address: addr, Registered: w0 == SlotIndex(1), Power: w1, BLSKey: kb})
	}
	at("A11", SlotIndex(14))
	at("A12", SlotIndex(15))
	at("A13", SlotIndex(16))
	at("A14", SlotIndex(17))
	at("A15", MappingSlotAt(KeyBytes32(opID), 18))
	at("A16", SlotIndex(27))
	at("A17", SlotIndex(29))
	s30 := at("A18", SlotIndex(30))
	s.w["A18"] = a2Word(a2Low20(s30))
	s.w["A19"], s.w["A20"], s.w["A21"] = b2Hash(big.NewInt(int64(s30[11]))), b2Hash(big.NewInt(int64(s30[10]))), b2Hash(big.NewInt(int64(s30[9])))
	s.v = a2Low20(s30)
	acctV := rd.account(s.v)
	s.acc["V"] = acctV
	for i, id := range []string{"V01", "V02", "V03"} {
		s.w[id] = rd.slot(s.v, acctV, SlotIndex(uint64(i)))
	}
	if row, ok := env.Manifest.DeploymentAt(env.Ctx.Chain, s.v.Hex()); ok && row.Role == RoleBlsZkVerifier {
		s.vPub = true
		if code := env.a2Carried(s.v); code != nil && a2K(code) == acctV.CodeHash {
			if bld, ok := env.Manifest.Build(row.Build); ok {
				for _, im := range bld.Immutables {
					if im.Rule.Kind == "deployment" && len(im.References) > 0 {
						ref := im.References[0]
						if ref.Length == 32 && ref.Start >= 0 && ref.Start+32 <= len(code) {
							s.g = a2Low20(common.BytesToHash(code[ref.Start : ref.Start+32]))
						}
						break
					}
				}
			}
		}
	}
	if s.g != (common.Address{}) {
		s.acc["G"] = rd.account(s.g)
	}
	if !rd.ok() {
		if rd.defect != nil {
			return nil, rd.defect
		}
		return s, nil
	}
	return s, nil
}

func (s *b2St) publish(root [32]byte) AuthStation {
	return AuthStation{StateRoot: root, Words: s.w, Accounts: s.acc, Verifier: s.v, VerifierPublished: s.vPub, Groth16: s.g}
}

// ---- code identity of A, V, G at one station ----

// b2Code judges the code of one account of a station: absent (account_absent), carried bytes missing (U code_not_carried), carried bytes that
// do not hash to the proven codeHash (code_unproven_bytes), masked hash or length different from the pinned build (code_not_published).
// part is the part the code_not_carried state is raised on. ok is the carried code when it is the pinned build.
func b2Code(env *Env, root, role string, a common.Address, acct AccountState, build Build, part string) (code []byte, st *StateError) {
	if !acct.HasCode() {
		return nil, Must(CodeAccountAbsent, "", map[string]any{"role": role, "address": a, "root": root})
	}
	c := env.a2Carried(a)
	if c == nil {
		return nil, b2Unproven(RowUnprovenCodeNotCarried, map[string]any{"part": part, "address": a})
	}
	if a2K(c) != acct.CodeHash {
		return nil, Must(CodeCodeUnprovenBytes, "", map[string]any{"address": a})
	}
	want := a2Hash(build.Runtime.MaskedKeccak)
	masked := a2K(a2Mask(c, a2BuildRefs(build)))
	if len(c) != build.Runtime.Bytes || masked != want {
		return nil, Must(CodeCodeNotPublished, "", map[string]any{"role": role, "address": a, "code_hash": acct.CodeHash, "masked_keccak": masked, "want": want})
	}
	return c, nil
}

// b2Chain judges A (the anchor build, DEPLOYMENT_CHAIN_ID references), V (a manifest blsZkVerifier row; its generated verifier G is named by
// the three references) and G at one station. The first failure is returned. A verifier address that is not a manifest row is not judged here:
// it is the rule VERIFIER-ID of step 19(a) (the code of a contract the manifest does not publish cannot be compared with a build).
func b2Chain(env *Env, s *b2St, A common.Address, part string) (*StateError, error) {
	m, chain := env.Manifest, env.Ctx.Chain
	arow, ok := m.Deployment(chain, RoleAnchor)
	if !ok {
		return Must(CodeAddressNotPublished, "", map[string]any{"role": RoleAnchor, "address": A}), nil
	}
	abld, ok := m.Build(arow.Build)
	if !ok {
		return nil, fmt.Errorf("contractidentity: the manifest has no build %q", arow.Build)
	}
	code, st := b2Code(env, s.name, RoleAnchor, A, s.acc["A"], abld, part)
	if st != nil {
		return st, nil
	}
	chainWord := common.BigToHash(new(big.Int).SetUint64(chain))
	st, err := a2Immutables(RoleAnchor, code, abld, func(im Immutable, _ int) (common.Hash, error) {
		if im.Rule.Kind != "chainId" {
			return common.Hash{}, fmt.Errorf("contractidentity: anchor immutable %s has the rule kind %q", im.Name, im.Rule.Kind)
		}
		return chainWord, nil
	})
	if err != nil || st != nil {
		return st, err
	}
	if !s.vPub {
		return nil, nil
	}
	vrow, _ := m.DeploymentAt(chain, s.v.Hex())
	vbld, ok := m.Build(vrow.Build)
	if !ok {
		return nil, fmt.Errorf("contractidentity: the manifest has no build %q", vrow.Build)
	}
	vcode, st := b2Code(env, s.name, RoleBlsZkVerifier, s.v, s.acc["V"], vbld, part)
	if st != nil {
		return st, nil
	}
	var first common.Hash
	st, err = a2Immutables(RoleBlsZkVerifier, vcode, vbld, func(im Immutable, idx int) (common.Hash, error) {
		if im.Rule.Kind != "deployment" {
			return common.Hash{}, fmt.Errorf("contractidentity: verifier immutable %s has the rule kind %q", im.Name, im.Rule.Kind)
		}
		if idx == 0 {
			ref := im.References[0]
			first = a2Word(a2Low20(common.BytesToHash(vcode[ref.Start : ref.Start+32])))
		}
		return first, nil
	})
	if err != nil || st != nil {
		return st, err
	}
	g := a2Low20(first)
	grow, ok := m.Deployment(chain, RoleGroth16Verifier)
	if !ok || common.HexToAddress(grow.Address) != g {
		return Must(CodeAddressNotPublished, "", map[string]any{"role": RoleGroth16Verifier, "address": g}), nil
	}
	gbld, ok := m.Build(grow.Build)
	if !ok {
		return nil, fmt.Errorf("contractidentity: the manifest has no build %q", grow.Build)
	}
	_, st = b2Code(env, s.name, RoleGroth16Verifier, g, s.acc["G"], gbld, part)
	return st, nil
}

// ---- step 18 ----

// b2Prereq is what step 18 needs: the captured attestation, the two state roots, the anchor address, the anchorId and the pkc.
func b2Prereq(env *Env) (string, error) {
	f := env.Facts
	switch {
	case !f.B1.AttestCaptured:
		return "attest_not_captured", nil
	case f.B1.StateRootPre == ([32]byte{}) || f.B1.StateRootPost == ([32]byte{}):
		return "attest_headers_unreadable", nil
	case f.A.Anchor == (common.Address{}):
		return "", fmt.Errorf("contractidentity: step 18: no anchor address (step 9 did not run)")
	case f.A.AnchorID == ([32]byte{}):
		return "anchor_id_unavailable", nil
	case f.B1.PKC == ([32]byte{}):
		return "attest_pkc_unavailable", nil
	}
	return "", nil
}

// b2Step18 reads the AUTH slot set at both stations, judges the code of A, V, G at both, applies the equality rule, the byte rule and the
// flips. Decision order within the part authorization_attest: code failure (the words of another code mean nothing), a wrong flip (R), the
// record created in B_v (U), the first changed row (U state_changed_in_block); a station that cannot be read is proof_invalid.
func b2Step18(env *Env) (StepOutput, error) {
	f := env.Facts
	why, err := b2Prereq(env)
	if err != nil {
		return StepOutput{}, err
	}
	unusable := func(reason string) StepOutput {
		out := StepOutput{Parts: []PartResult{b2U(JudgedCodeIdentity, b2Absent(JudgedCodeIdentity))}, ReadPlanIncomplete: reason}
		if why == "attest_not_captured" {
			out.ReadPlanIncomplete = "" // step 15 decided the parts; there is nothing to read
		}
		return out
	}
	if why != "" {
		return unusable(why), nil
	}
	A, anchorID, pkc := f.A.Anchor, common.Hash(f.A.AnchorID), common.Hash(f.B1.PKC)
	opID := common.Hash(env.Ctx.Batch.OperationID)
	stations := [2]struct {
		name string
		root [32]byte
	}{{AtAttestPre, f.B1.StateRootPre}, {AtAttestPost, f.B1.StateRootPost}}
	var st [2]*b2St
	var bad *StateError
	for i, s := range stations {
		r, err := b2ReadStation(env, s.name, common.Hash(s.root), A, anchorID, opID, pkc)
		if err != nil {
			return StepOutput{}, err
		}
		st[i] = r
		if bad == nil && !r.rd.ok() {
			bad = r.rd.bad
		}
	}
	if bad != nil {
		out := StepOutput{ReadPlanIncomplete: "attest_stations"}
		if f.B1.HeaderLinked {
			out.Parts = []PartResult{b2R(JudgedAuthorizationAttest, bad), b2R(JudgedCodeIdentity, bad)}
		} else {
			out.Parts = []PartResult{b2U(JudgedCodeIdentity, b2Absent(JudgedCodeIdentity))}
		}
		return out, nil
	}
	b := &f.B2
	b.Pre, b.Post = st[0].publish(stations[0].root), st[1].publish(stations[1].root)
	b.Validators = st[1].val
	pre, post := st[0], st[1]

	// equality rule, byte rule, flips
	validPre := pre.w["A02:10"][11] == 1
	b.RecordCreatedInBlock = !validPre
	var changed []AuthDiff
	keys := map[string]bool{}
	for k := range pre.w {
		keys[k] = true
	}
	for k := range post.w {
		keys[k] = true
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Slice(ordered, func(i, j int) bool { return b2KeyLess(ordered[i], ordered[j]) })
	for _, k := range ordered {
		if k == "A15" || k == "A02:10" || (!validPre && (strings.HasPrefix(k, "A02:") || k == "A03" || k == "A04")) {
			continue
		}
		if pre.w[k] != post.w[k] {
			changed = append(changed, AuthDiff{Row: k, Pre: pre.w[k], Post: post.w[k]})
		}
	}
	var flipBad bool
	if pre.w["A15"] != SlotIndex(0) || post.w["A15"] != SlotIndex(1) { // F1
		flipBad = true
	}
	if validPre { // F2: the byte rule on word 10 of the record
		p, q := pre.w["A02:10"], post.w["A02:10"]
		outside := !bytes.Equal(p[12:], q[12:]) || p[11] != q[11] || q[11] != 1 || !bytes.Equal(p[:8], q[:8]) || q[9] > 1
		if outside {
			changed = append(changed, AuthDiff{Row: "A02:10", Pre: p, Post: q})
			sort.SliceStable(changed, func(i, j int) bool { return b2KeyLess(changed[i].Row, changed[j].Row) })
		}
		if p[10] != 0 || q[10] != 1 || p[9] != 0 || p[8] != 0 {
			flipBad = true
		}
		if call := f.B1.Call; call.AnchorID != ([32]byte{}) && q[8] != call.AuthorityLevel {
			flipBad = true
		}
		b.GovernanceExecutedFlip = p[9] == 0 && q[9] == 1
	}
	b.Changed = changed

	// code identity of A, V, G at both stations
	var codeFail *StateError
	if f.B1.HeaderLinked {
		for _, s := range st {
			x, err := b2Chain(env, s, A, JudgedCodeIdentity)
			if err != nil {
				return StepOutput{}, err
			}
			if codeFail == nil {
				codeFail = x
			}
		}
	}
	b.CodeFailure = codeFail

	out := StepOutput{}
	if !f.B1.HeaderLinked {
		out.Parts = []PartResult{b2U(JudgedCodeIdentity, b2Absent(JudgedCodeIdentity))}
		return out, nil
	}
	if codeFail == nil {
		out.Parts = append(out.Parts, env.Verified(JudgedCodeIdentity))
	} else if codeFail.Code == CodeUnproven {
		out.Parts = append(out.Parts, b2U(JudgedCodeIdentity, codeFail))
	} else {
		out.Parts = append(out.Parts, b2R(JudgedCodeIdentity, codeFail))
	}
	block := f.B1.HeaderV.Number
	switch {
	case codeFail != nil && codeFail.Code == CodeUnproven:
		out.Parts = append(out.Parts, b2U(JudgedAuthorizationAttest, b2WithPart(codeFail, JudgedAuthorizationAttest)))
	case codeFail != nil:
		out.Parts = append(out.Parts, b2R(JudgedAuthorizationAttest, codeFail))
	case flipBad:
		out.Parts = append(out.Parts, b2R(JudgedAuthorizationAttest, b2Flip()))
	case b.RecordCreatedInBlock:
		out.Parts = append(out.Parts, b2U(JudgedAuthorizationAttest, Must(CodeUnproven, RowUnprovenRecordCreatedInBlock, map[string]any{"reason": RowUnprovenRecordCreatedInBlock, "block": block})))
	case len(changed) > 0:
		d := changed[0]
		out.Parts = append(out.Parts, b2U(JudgedAuthorizationAttest, Must(CodeUnproven, RowUnprovenStateChangedInBlock,
			map[string]any{"reason": RowUnprovenStateChangedInBlock, "field": d.Row, "pre": d.Pre, "post": d.Post, "block": block})))
	default:
		out.Parts = append(out.Parts, env.Verified(JudgedAuthorizationAttest))
	}
	return out, nil
}

// ---- step 18b: lemma U ----

// b2Step18b asserts what the lemma needs beyond the flips of step 18: the anchor is a batch anchor (only then is the usedCommitments key the
// record's operationID), the key step 18 read is the operationID of the record at B_v, and that operationID is bound to anchorId by the
// bundle-id recomputation (CertenAnchorV8_2.sol:869-878), so the block in which the key flips 0 to 1 is the attestation of THIS record. The
// pinned code (U1-U4) is the code of step 18: when the code of A is not established step 18 has decided the part.
func b2Step18b(env *Env) (StepOutput, error) {
	f := env.Facts
	post := f.B2.Post
	if !f.B1.AttestCaptured || !f.B1.HeaderLinked || post.Words == nil || f.B2.CodeFailure != nil {
		return StepOutput{}, nil // decided by steps 15-18
	}
	part := JudgedAuthorizationAttest
	anchorID := common.Hash(f.A.AnchorID)
	pre := f.B2.Pre
	if post.Words["A03"] != SlotIndex(1) || (!f.B2.RecordCreatedInBlock && pre.Words["A03"] != SlotIndex(1)) {
		return StepOutput{Parts: []PartResult{b2U(part, b2Unproven(RowUnprovenAnchorNotBatch, map[string]any{"anchorId": anchorID}))}}, nil
	}
	if post.Words["A02:7"] != common.Hash(env.Ctx.Batch.OperationID) {
		return StepOutput{Parts: []PartResult{b2R(part, b2Flip())}}, nil
	}
	packed := append([]byte("certen:batchbundle:v2"), common.BigToHash(new(big.Int).SetUint64(env.Ctx.Chain)).Bytes()...)
	for _, k := range []string{"A02:1", "A04", "A02:7", "A02:8", "A02:11", "A02:12"} {
		w := post.Words[k]
		packed = append(packed, w[:]...)
	}
	if a2K(packed) != anchorID {
		return StepOutput{Parts: []PartResult{b2R(part, Must(CodeRecordInconsistent, "", map[string]any{"field": "bundle_id"}))}}, nil
	}
	return StepOutput{Parts: []PartResult{env.Verified(part)}}, nil
}

// ---- step 19: the authorization rules ----

type b2Rule struct {
	// rows are the AUTH row ids (prefixes) whose equality at pre and post the verdict R needs.
	rows []string
	// u is true for a rule whose verdict is always U (GOVVERIFIER).
	u    bool
	test func(s *AuthStation, at string) *StateError
}

// b2Unchanged says that none of the rows (or their sub-keys) is in Facts.B2.Changed.
func b2Unchanged(ch []AuthDiff, rows []string) bool {
	for _, d := range ch {
		for _, r := range rows {
			if d.Row == r || strings.HasPrefix(d.Row, r+":") {
				return false
			}
		}
	}
	return true
}

// b2Validators rebuilds the validator rows of a station from its words.
func b2StationValidators(s *AuthStation) []ValidatorRow {
	n, _ := a2U64(s.Words["A10"])
	var out []ValidatorRow
	for i := uint64(0); i < n; i++ {
		a := a2Low20(s.Words[fmt.Sprintf("A10:%d", i)])
		k := b2Lower(a)
		out = append(out, ValidatorRow{Address: a, Registered: s.Words["A09:"+k+":0"] == SlotIndex(1), Power: s.Words["A09:"+k+":1"]})
	}
	return out
}

func b2SetRoot(s *AuthStation) (common.Hash, error) {
	vals := b2StationValidators(s)
	sort.Slice(vals, func(i, j int) bool { return bytes.Compare(vals[i].Address[:], vals[j].Address[:]) < 0 })
	addrs, powers := make([]common.Address, len(vals)), make([]*big.Int, len(vals))
	for i, v := range vals {
		addrs[i], powers[i] = v.Address, b2Num(v.Power)
	}
	enc, err := a2PackRoot(addrs, powers, b2Num(s.Words["A12"]), b2Num(s.Words["A13"]))
	if err != nil {
		return common.Hash{}, err
	}
	return a2K(enc), nil
}

func b2Step19(env *Env) (StepOutput, error) {
	f := env.Facts
	b := &f.B2
	if !f.B1.AttestCaptured || !f.B1.HeaderLinked || b.Post.Words == nil || b.Pre.Words == nil || b.CodeFailure != nil {
		return StepOutput{}, nil // decided by steps 15-18 (or not linked: step 16)
	}
	if !b.IB.Evaluated {
		return StepOutput{}, fmt.Errorf("contractidentity: step 19: rule IB (step 22) was not evaluated")
	}
	const part = JudgedAuthorizationAttest
	pol := env.Manifest.Policy()
	call := f.B1.Call
	callOK := call.AnchorID != ([32]byte{}) && call.OuterSigned != nil && call.OuterTotal != nil && call.BlobInnerSigned != nil && call.BlobInnerTotal != nil
	pkc := common.Hash(f.B1.PKC)
	out := StepOutput{RulesJudged: []string{RuleENABLED, RuleVERIFIERID, RuleBINDING, RuleTHRESHOLDA, RuleTHRESHOLDV, RuleSETROOT, RuleMINGOV, RulePAUSED, RuleGOVVERIFIER}}
	var firstErr error
	rules := []b2Rule{
		{[]string{"A19"}, false, func(s *AuthStation, at string) *StateError { // (a) ENABLED
			if s.Words["A19"] != SlotIndex(a2Bool(pol.BLSZKVerificationEnabled)) {
				return b2Mismatch(AuthFieldEnabled, b2Num(s.Words["A19"]).Uint64(), a2Bool(pol.BLSZKVerificationEnabled), at)
			}
			return nil
		}},
		{[]string{"A18"}, false, func(s *AuthStation, at string) *StateError { // (a) VERIFIER-ID
			if !s.VerifierPublished {
				return Must(CodeAddressNotPublished, "", map[string]any{"role": RoleBlsZkVerifier, "address": s.Verifier})
			}
			return nil
		}},
		{[]string{"A08"}, false, func(s *AuthStation, at string) *StateError { // (b) BINDING
			if s.Words["A08"] != SlotIndex(a2Bool(pol.PubkeyBindingEnforced)) {
				return b2Mismatch(AuthFieldBinding, b2Num(s.Words["A08"]).Uint64(), a2Bool(pol.PubkeyBindingEnforced), at)
			}
			return nil
		}},
		{[]string{"A05"}, false, func(s *AuthStation, at string) *StateError { // (b) authorizedPubkeyCommitments[pkc]
			if s.Words["A05"] != SlotIndex(1) {
				return Must(CodeCommitmentNotAuthorized, "", map[string]any{"pkc": pkc, "at": at})
			}
			return nil
		}},
		{[]string{"A12", "A13"}, false, func(s *AuthStation, at string) *StateError { // (c) THRESHOLD-A
			want := b2Ratio(b2Hash(new(big.Int).SetUint64(pol.BLSThreshold.Numerator)), b2Hash(new(big.Int).SetUint64(pol.BLSThreshold.Denominator)))
			if got := b2Ratio(s.Words["A12"], s.Words["A13"]); got != want {
				return b2Mismatch(AuthFieldThreshold, got, want, at)
			}
			return nil
		}},
		{[]string{"V01", "V02"}, false, func(s *AuthStation, at string) *StateError { // (c) THRESHOLD-V
			want := b2Ratio(b2Hash(new(big.Int).SetUint64(pol.VerifierThreshold.Numerator)), b2Hash(new(big.Int).SetUint64(pol.VerifierThreshold.Denominator)))
			if got := b2Ratio(s.Words["V01"], s.Words["V02"]); got != want {
				return b2Mismatch(AuthFieldVerifierThreshold, got, want, at)
			}
			return nil
		}},
		{[]string{"A09", "A10", "A11"}, false, func(s *AuthStation, at string) *StateError { // (d) registry
			vals := b2StationValidators(s)
			registered, sum := uint64(0), new(big.Int)
			for _, v := range vals {
				if v.Registered {
					registered++
				}
				sum.Add(sum, b2Num(v.Power))
			}
			if registered != uint64(len(vals)) {
				return b2Mismatch(AuthFieldCount, registered, uint64(len(vals)), at)
			}
			for _, v := range vals {
				if b2Num(v.Power).Sign() == 0 {
					return b2Mismatch(AuthFieldPower, v.Power, uint64(1), at)
				}
			}
			if sum.Cmp(b2Num(s.Words["A11"])) != 0 {
				return b2Mismatch(AuthFieldTotalPower, s.Words["A11"], b2Hash(sum), at)
			}
			return nil
		}},
		{[]string{"A09", "A10", "A12", "A13", "A14"}, false, func(s *AuthStation, at string) *StateError { // (e) SETROOT
			root, err := b2SetRoot(s)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return nil
			}
			if root != s.Words["A14"] {
				return b2Mismatch(AuthFieldSetRoot, s.Words["A14"], root, at)
			}
			return nil
		}},
		{[]string{"A09", "A10", "A11", "A12", "A13"}, false, func(s *AuthStation, at string) *StateError { // (f1) the anchor rule on the OUTER numbers
			if !callOK {
				return nil
			}
			return b2OuterRule(s, call, at)
		}},
		{[]string{"V01", "V02"}, false, func(s *AuthStation, at string) *StateError { // (f2) the verifier rule on the INNER numbers
			if !callOK {
				return nil
			}
			if !b2InnerOK(call.BlobInnerSigned, call.BlobInnerTotal, b2Num(s.Words["V02"]), b2Num(s.Words["V01"])) {
				return b2Mismatch(AuthFieldVerifierThreshold, b2Hash(call.BlobInnerSigned), b2Hash(call.BlobInnerTotal), at)
			}
			return nil
		}},
		{[]string{"A01"}, false, func(s *AuthStation, at string) *StateError { // (h) PAUSED
			if s.Words["A01"][31] != 0 {
				return b2Mismatch(AuthFieldPaused, uint64(s.Words["A01"][31]), uint64(0), at)
			}
			return nil
		}},
		{[]string{"A17"}, true, func(s *AuthStation, at string) *StateError { // (h) GOVVERIFIER: always U
			if g := a2Low20(s.Words["A17"]); g != (common.Address{}) {
				return b2Unproven(RowUnprovenGovernanceVerifierUnpinned, map[string]any{"address": g, "at": at})
			}
			return nil
		}},
		{[]string{"A20"}, false, func(s *AuthStation, at string) *StateError { // (h) MINGOV
			if got := b2Num(s.Words["A20"]).Uint64(); got < uint64(pol.MinimumGovernanceLevel) {
				return b2Mismatch(AuthFieldMinimumGovernanceLevel, got, uint64(pol.MinimumGovernanceLevel), at)
			}
			return nil
		}},
		{[]string{"A20"}, false, func(s *AuthStation, at string) *StateError { // (h) the decoded authorityLevel against minimumGovernanceLevel
			if callOK && uint64(call.AuthorityLevel) < b2Num(s.Words["A20"]).Uint64() {
				return Must(CodeAttestMismatch, "", map[string]any{"field": "authority_level"})
			}
			return nil
		}},
	}
	var verdict *PartResult
	for _, r := range rules {
		failPre, failPost := r.test(&b.Pre, AtAttestPre), r.test(&b.Post, AtAttestPost)
		if failPre == nil || failPost == nil || !b2Unchanged(b.Changed, r.rows) {
			continue // a violation at one station only, or a changed word, is state_changed_in_block (step 18)
		}
		if verdict != nil {
			continue
		}
		switch {
		case r.u:
			p := b2U(part, failPre)
			verdict = &p
		case b.IB.Verified:
			p := b2R(part, failPre)
			verdict = &p
		case b.IB.State != nil && b.IB.State.Code == CodeUnproven:
			p := b2U(part, b2WithPart(b.IB.State, part))
			verdict = &p
		case b.IB.State != nil:
			p := b2R(part, b.IB.State)
			verdict = &p
		default:
			return StepOutput{}, fmt.Errorf("contractidentity: step 19: rule IB is neither verified nor carries a state")
		}
	}
	if firstErr != nil {
		return StepOutput{}, firstErr
	}
	if verdict != nil {
		out.Parts = []PartResult{*verdict}
	} else {
		out.Parts = []PartResult{env.Verified(part)}
	}
	if callOK && (call.BlobInnerSigned.Cmp(call.OuterSigned) != 0 || call.BlobInnerTotal.Cmp(call.OuterTotal) != 0) { // (f3)
		o, err := env.Open(part, OpenAlert, CodeAlert, "", map[string]any{"field": "inner_outer_differ", "at": AtAttestPost,
			"onchain": call.BlobInnerSigned.String() + "/" + call.BlobInnerTotal.String(), "want": call.OuterSigned.String() + "/" + call.OuterTotal.String()})
		if err != nil {
			return StepOutput{}, err
		}
		out.Open = append(out.Open, o)
	}
	return out, nil
}

// b2InnerOK is BLSZKVerifierV2_1._checkThresholdOnChain: unchecked wrap-around products with the division guards, then lhs >= rhs.
func b2InnerOK(signed, total, den, num *big.Int) bool {
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	lhs := new(big.Int).Mod(new(big.Int).Mul(signed, den), mod)
	rhs := new(big.Int).Mod(new(big.Int).Mul(total, num), mod)
	if den.Sign() != 0 && new(big.Int).Div(lhs, den).Cmp(signed) != 0 {
		return false
	}
	if num.Sign() != 0 && new(big.Int).Div(rhs, num).Cmp(total) != 0 {
		return false
	}
	return lhs.Cmp(rhs) >= 0
}

// b2OuterRule is step 19(f1) at one station: the listed validators are registered with the registry's powers and are not repeated,
// outer.signed is their sum, outer.total is totalVotingPower, and outer.signed >= floor(totalVotingPower * num / den).
func b2OuterRule(s *AuthStation, call AttestCall, at string) *StateError {
	vals := b2StationValidators(s)
	reg := map[common.Address]ValidatorRow{}
	for _, v := range vals {
		reg[v.Address] = v
	}
	if len(call.ValidatorAddresses) != len(call.VotingPowers) {
		return b2Mismatch(AuthFieldCount, uint64(len(call.VotingPowers)), uint64(len(call.ValidatorAddresses)), at)
	}
	seen := map[common.Address]bool{}
	sum := new(big.Int)
	for i, a := range call.ValidatorAddresses {
		if seen[a] {
			return b2Mismatch(AuthFieldCount, uint64(len(seen)), uint64(len(call.ValidatorAddresses)), at)
		}
		seen[a] = true
		r, ok := reg[a]
		if !ok || !r.Registered {
			return b2Mismatch(AuthFieldKey, a, common.Address{}, at)
		}
		if call.VotingPowers[i] == nil || b2Num(r.Power).Cmp(call.VotingPowers[i]) != 0 {
			p := common.Hash{}
			if call.VotingPowers[i] != nil {
				p = b2Hash(call.VotingPowers[i])
			}
			return b2Mismatch(AuthFieldPower, r.Power, p, at)
		}
		sum.Add(sum, call.VotingPowers[i])
	}
	if sum.Cmp(call.OuterSigned) != 0 {
		return b2Mismatch(AuthFieldPower, b2Hash(sum), b2Hash(call.OuterSigned), at)
	}
	total := b2Num(s.Words["A11"])
	if call.OuterTotal.Cmp(total) != 0 {
		return b2Mismatch(AuthFieldTotalPower, s.Words["A11"], b2Hash(call.OuterTotal), at)
	}
	num, den := b2Num(s.Words["A12"]), b2Num(s.Words["A13"])
	if den.Sign() == 0 {
		return b2Mismatch(AuthFieldThreshold, b2Hash(call.OuterSigned), common.Hash{}, at)
	}
	required := new(big.Int).Div(new(big.Int).Mul(total, num), den)
	if call.OuterSigned.Cmp(required) < 0 {
		return b2Mismatch(AuthFieldThreshold, b2Hash(call.OuterSigned), b2Hash(required), at)
	}
	return nil
}

// ---- step 22: rule IB ----

// b2Frozen is the frozen IB allow-list (S8 spec "Mechanical premise", [r3.2:D14]): a constant of the verifier, not only a manifest field.
// An entry is the set of paths a function may write, or any (the constructor, deployment only).
type b2FrozenRow struct {
	any   bool
	paths []string
}

var b2Frozen = map[string]map[string]b2FrozenRow{
	"CertenAnchorV8_2": {
		"constructor":               {any: true},
		"createAnchor":              {paths: []string{"anchors[]"}},
		"createBatchAnchor":         {paths: []string{"anchors[]", "isBatchAnchor[]", "batchLeafCount[]"}},
		"executeComprehensiveProof": {paths: []string{"anchors[].proofExecuted", "anchors[].governanceLevel", "usedCommitments[]"}},
		"executeWithGovernance":     {paths: []string{"anchors[].governanceExecuted"}},
	},
	"BLSZKVerifierV2_1": {"constructor": {any: true}},
}

// b2GateCondition returns the build_without_writer_proof condition of a build, "" when rule IB may be applied to it.
func b2GateCondition(m *Manifest, key string) string {
	rec := m.AuthWritersFor(key)
	if rec == nil {
		return BuildCondStatusMissing
	}
	if rec.Status != "pass" {
		for _, c := range []string{BuildCondA, BuildCondB, BuildCondC, BuildCondD, BuildCondE, BuildCondF} {
			if rec.Conditions[c] != "pass" {
				return c
			}
		}
		return BuildCondStatusMissing
	}
	al, bld := m.AuthAllowListFor(key), Build{}
	if b, ok := m.Build(key); ok {
		bld = b
	}
	if al == nil {
		return BuildCondAllowlistNotFrozen
	}
	frozen, ok := b2Frozen[bld.Contract]
	if !ok {
		return BuildCondAllowlistNotFrozen
	}
	for _, row := range al.Rows {
		fr, ok := frozen[row.Function]
		if !ok || row.AllowedWrites.Any != fr.any || (row.AllowedWrites.Any && !row.DeploymentOnly) {
			return BuildCondAllowlistNotFrozen
		}
		for _, p := range row.AllowedWrites.Paths {
			in := false
			for _, q := range fr.paths {
				in = in || p == q
			}
			if !in {
				return BuildCondAllowlistNotFrozen
			}
		}
	}
	return ""
}

func b2TypeSet(l []int) map[byte]bool {
	m := map[byte]bool{}
	for _, t := range l {
		m[byte(t)] = true
	}
	return m
}

// b2Step22 is rule IB. It reads the owner accounts (row C01) at both stations whenever the stations were read (the read plan is fixed by the
// algorithm), then decides only against an authenticated block: the carried transaction list must be the block's (R attest_mismatch
// {block_txs}); the authWriters gate; the owner EOA is code-empty at both stations; the owner nonce is equal; every transaction type of B_v
// is covered or system for the chain.
func b2Step22(env *Env) (StepOutput, error) {
	f := env.Facts
	const part = JudgedIntraBlockWindow
	if !f.B1.AttestCaptured {
		return StepOutput{}, nil // step 15 decided the part
	}
	b := &f.B2
	if b.Pre.Words == nil || b.Post.Words == nil {
		return StepOutput{Parts: []PartResult{b2U(part, b2Absent(part))}, ReadPlanIncomplete: "attest_stations_unavailable"}, nil
	}
	rdPre := &a2rd{env: env, root: common.Hash(f.B1.StateRootPre), name: AtAttestPre}
	rdPost := &a2rd{env: env, root: common.Hash(f.B1.StateRootPost), name: AtAttestPost}
	var owners []OwnerCheck
	seen := map[common.Address]bool{}
	for _, s := range []*AuthStation{&b.Pre, &b.Post} {
		for _, id := range []string{"A16", "V03"} {
			o := a2Low20(s.Words[id])
			if seen[o] {
				continue
			}
			seen[o] = true
			owners = append(owners, OwnerCheck{Address: o, Pre: rdPre.account(o), Post: rdPost.account(o)})
		}
	}
	if !rdPre.ok() || !rdPost.ok() {
		for _, r := range []*a2rd{rdPre, rdPost} {
			if r.defect != nil {
				return StepOutput{}, r.defect
			}
		}
		bad := rdPre.bad
		if bad == nil {
			bad = rdPost.bad
		}
		if !f.B1.HeaderLinked {
			return StepOutput{Parts: []PartResult{b2U(part, b2Absent(part))}, ReadPlanIncomplete: "attest_owner"}, nil
		}
		b.IB = IBResult{Evaluated: true, State: bad}
		return StepOutput{Parts: []PartResult{b2R(part, bad)}, ReadPlanIncomplete: "attest_owner"}, nil
	}
	if !f.B1.HeaderLinked {
		return StepOutput{Parts: []PartResult{b2U(part, b2Absent(part))}}, nil
	}
	a := env.Container.Attest.Attest
	if a == nil {
		return StepOutput{}, fmt.Errorf("contractidentity: step 22: captured attest part without a body")
	}
	res := IBResult{Evaluated: true, Owners: owners}
	decide := func(st *StateError) (StepOutput, error) {
		res.State = st
		b.IB = res
		if st.Code == CodeUnproven {
			return StepOutput{Parts: []PartResult{b2U(part, st)}}, nil
		}
		return StepOutput{Parts: []PartResult{b2R(part, st)}}, nil
	}
	// the carried transaction list is the block's
	census, err := VerifyBlockTxs(common.Hash(f.B1.HeaderV.TransactionRoot), a.BlockTxs, int(a.TxIndex), a.TxLeaf, env.Limits)
	if err != nil {
		te, ok := err.(*TxError)
		if !ok {
			return StepOutput{}, err
		}
		if te.Kind == TxTooMany || te.Kind == TxTooLarge {
			return decide(b2Unproven(RowUnprovenBlockTooLarge, map[string]any{"part": part, "bytes": te.Got, "limit": te.Limit}))
		}
		return decide(Must(CodeAttestMismatch, "", map[string]any{"field": "block_txs"}))
	}
	res.Types = census.Distinct
	// the authWriters gate for the anchor and the verifier build rows
	for _, role := range []string{RoleAnchor, RoleBlsZkVerifier} {
		row, ok := env.Manifest.Deployment(env.Ctx.Chain, role)
		if !ok {
			return StepOutput{}, fmt.Errorf("contractidentity: step 22: the manifest has no %s deployment row for chain %d", role, env.Ctx.Chain)
		}
		if cond := b2GateCondition(env.Manifest, row.Build); cond != "" {
			return decide(b2Unproven(RowUnprovenBuildWithoutWriterProof, map[string]any{"part": part, "build": row.Build, "condition": cond}))
		}
	}
	// IB1: the owners are EOAs with an equal nonce
	for _, o := range owners {
		if o.Pre.HasCode() || o.Post.HasCode() {
			return decide(b2Unproven(RowUnprovenOwnerNotEoa, map[string]any{"part": part, "address": o.Address}))
		}
	}
	for _, o := range owners {
		if o.Pre.Nonce != o.Post.Nonce {
			return decide(b2Unproven(RowUnprovenOwnerActiveInBlock, map[string]any{"part": part, "address": o.Address, "pre": o.Pre.Nonce, "post": o.Post.Nonce}))
		}
	}
	// IB2: the census
	scan, ok := env.Manifest.TxScan(env.Ctx.Chain)
	if !ok {
		return StepOutput{}, fmt.Errorf("contractidentity: step 22: the manifest has no policy.txScan for chain %d", env.Ctx.Chain)
	}
	covered, system := b2TypeSet(scan.CoveredTypes), b2TypeSet(scan.SystemTypes)
	for i, ty := range census.Types {
		if !covered[ty] && !system[ty] {
			return decide(b2Unproven(RowUnprovenTxTypeUnsupported, map[string]any{"part": part, "type": fmt.Sprintf("0x%02x", ty), "index": uint64(i)}))
		}
	}
	res.Verified = true
	b.IB = res
	return StepOutput{Parts: []PartResult{env.Verified(part)}}, nil
}
