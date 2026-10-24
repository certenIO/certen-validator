// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
)

// Package 2c: steps 21 (registry emit, owner pin, registry link, pkc cross-check), 23 (the rules_not_judged of the report) and 24 (level
// binding to S7). The headline algebra itself is ComputeHeadline (types.go) and the runner (buildReport) calls it; this file fills the facts
// that algebra reads (Facts.C) and decides the parts of step 21. The decisions where the specification is silent are S8_FREEZE.md 6.11.

// Steps2c returns the step functions of package 2c.
func Steps2c() map[StepID]StepFunc {
	return map[StepID]StepFunc{Step21: c2Step21, Step23: c2Step23, Step24: c2Step24}
}

// RegisterSteps2c registers steps 21, 23 and 24.
func RegisterSteps2c(reg *StepRegistry) error {
	for _, id := range OwnedBy(Owner2c) {
		if err := reg.Register(id, Steps2c()[id]); err != nil {
			return err
		}
	}
	return nil
}

func c2U(part string, st *StateError) PartResult {
	return PartResult{Part: part, Status: StatusUnproven, State: st}
}
func c2R(part string, st *StateError) PartResult {
	return PartResult{Part: part, Status: StatusRefused, State: st}
}

// ---- step 24: level binding ----

// S7 finalized status texts printed in the report (S8_FREEZE 6.11, D10).
const (
	S7StatusVerified              = "verified"
	S7StatusVerifiedOtherBlock    = "verified_other_block"
	S7StatusVerifiedBlockNotShown = "verified_block_unavailable"
	S7StatusPending               = "pending"
	S7StatusNotApplicable         = "level_not_applicable"
	S7StatusAbsent                = "absent"
	S7StatusRefusedPrefix         = "refused:"
)

// c2FinalizedStatus renders the S7 `finalized` level of the report and says whether it authenticates THIS leg block: finalized is verified and
// the block S7 finalized has the leg's block hash (step 24).
func c2FinalizedStatus(s7 *finality.Report, leg BlockRef) (string, bool) {
	if s7.Unsupported != nil {
		return S7StatusRefusedPrefix + s7.Unsupported.Code, false
	}
	if s7.Broken != nil {
		return S7StatusRefusedPrefix + s7.Broken.Code, false
	}
	l, ok := s7.Levels[finality.LevelFinalized]
	if !ok {
		return S7StatusAbsent, false
	}
	switch l.Status {
	case finality.StatusVerified:
		switch {
		case s7.FinalizedBlock == nil && s7.FinalizedBlockState != nil:
			return S7StatusVerifiedBlockNotShown + ":" + s7.FinalizedBlockState.Code, false
		case s7.FinalizedBlock == nil:
			return S7StatusVerifiedBlockNotShown, false
		case s7.FinalizedBlock.Hash != leg.Hash:
			return S7StatusVerifiedOtherBlock, false
		}
		return S7StatusVerified, true
	case finality.StatusPending:
		return S7StatusPending, false
	case finality.StatusNotApplicable:
		return S7StatusNotApplicable, false
	case finality.StatusRefused:
		if l.State != nil {
			return S7StatusRefusedPrefix + l.State.Code, false
		}
		return S7StatusRefusedPrefix + "unnamed", false
	}
	return S7StatusAbsent, false
}

// c2Step24 is the level binding: state_root_authenticated := S7.finalized verified for THIS block; judged_at_level := the highest verified S7
// level. A chain that is not in the S7 table has no S8 statement: every part is unproven{part:all, reason:s7_chain_unsupported, chain} and the
// S7 refusal rides in s7_finalized_status.
func c2Step24(env *Env) (StepOutput, error) {
	s7 := env.Ctx.S7
	if s7 == nil {
		return StepOutput{}, fmt.Errorf("contractidentity: step 24: no S7 report (context validation should have refused)")
	}
	lb := &env.Facts.C.Level
	status, auth := c2FinalizedStatus(s7, env.Leg())
	*lb = LevelBinding{Authenticated: auth, S7FinalizedStatus: status}
	best := finality.LevelNone
	for l, st := range s7.Levels {
		// finalized counts only when it is the finalized status of THIS block; a finalized verified for another block is not a level reached here
		if st.Status == finality.StatusVerified && l > best && (l != finality.LevelFinalized || auth) {
			best = l
		}
	}
	lb.JudgedAtLevel = best.String()
	if s7.Unsupported != nil {
		st, err := New(CodeUnproven, RowUnprovenS7ChainUnsupported, map[string]any{"part": UnprovenPartAll, "chain": env.Ctx.Chain})
		if err != nil {
			return StepOutput{}, err
		}
		lb.JudgedAtLevel, lb.Authenticated = finality.LevelNone.String(), false
		out := StepOutput{Supersede: true}
		for _, p := range JudgedParts {
			out.Parts = append(out.Parts, c2U(p, st))
		}
		return out, nil
	}
	return StepOutput{}, nil
}

// ---- step 23: report assembly inputs ----

// FixedRulesNotJudged are the AUTH rows and exempt words that no rule judges, each with the reason printed (spec "Policy rules", the paragraph
// "Not judged, with the reason printed"); they are the same in every outcome.
func FixedRulesNotJudged() []RuleNotJudged {
	return []RuleNotJudged{
		{Row: "A21", Reason: "minimumGovernanceLevelForValueOps is read only by executeWithGovernance (CertenAnchorV8_2.sol:1398), not on the attestation path; reported in registry"},
		{Row: "A09:3", Reason: "registeredAt is informational; no acceptance decision reads it"},
		{Row: "slot19:usedNonces", Reason: "restrict-only: its single reader is nonceValid = !usedNonces[...] (CertenAnchorV8_2.sol:2002) and its single writer assigns the literal true (:1352)"},
		{Row: "slot28:operators", Reason: "not read by the attestation path"},
	}
}

// c2Step23 fills rules_not_judged. The headline algebra is evaluated by the runner over the part table and Facts.C (buildReport ->
// ComputeHeadline); its framework rows (steps 0-2 and 22b) are the runner's Framework refusal.
func c2Step23(env *Env) (StepOutput, error) {
	env.Facts.C.RulesNotJudged = FixedRulesNotJudged()
	return StepOutput{}, nil
}

// ---- step 21 ----

// RegistryWordsMissingError is a defect of the package that fills Facts.B2: the words of an attestation station that step 21 reads are
// incomplete. It is an error, never a verdict.
type RegistryWordsMissingError struct {
	Station string
	Missing []string
}

func (e *RegistryWordsMissingError) Error() string {
	return fmt.Sprintf("contractidentity: step 21: Facts.B2.%s lacks %v although the attestation part is captured", e.Station, e.Missing)
}

// c2BaseKeys are the Facts.B2 word keys step 21 reads at both attestation stations (bare AUTH row ids; A18 and A16/A17/V03 are addresses
// right-aligned in a word; A19-A21 are the byte values). The validator records use A10:<i> (list element i, address right-aligned) and
// A09:<0x lowercase address>:0 | :1 | :key (registered, votingPower, keccak256 of the key bytes); the manifest_history route reads
// A06:<0x lowercase 32-byte commitment> (authorizedPubkeyCommitments[c]).
var c2BaseKeys = []string{"A01", "A05", "A07", "A08", "A10", "A11", "A12", "A13", "A14", "A16", "A17", "A18", "A19", "A20", "A21", "V03"}

type c2Val struct {
	Addr                       common.Address
	Registered, Power, KeyHash common.Hash
}

type c2Station struct {
	Name, At string
	W        map[string]common.Hash
	N        uint64
	Vals     []c2Val
	TooLarge bool
}

func c2ValKey(a common.Address, suffix string) string {
	return "A09:" + strings.ToLower(a.Hex()) + ":" + suffix
}

// c2Load validates and indexes the words of one station.
func c2Load(name, at string, st AuthStation) (*c2Station, error) {
	s := &c2Station{Name: name, At: at, W: st.Words}
	var missing []string
	for _, k := range c2BaseKeys {
		if _, ok := st.Words[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, &RegistryWordsMissingError{Station: name, Missing: missing}
	}
	n, fits := a2U64(st.Words["A10"])
	if !fits || n > uint64(DefaultLimits().MaxValidators) {
		s.TooLarge = true
		return s, nil
	}
	s.N = n
	for i := uint64(0); i < n; i++ {
		el, ok := st.Words[fmt.Sprintf("A10:%d", i)]
		if !ok {
			missing = append(missing, fmt.Sprintf("A10:%d", i))
			continue
		}
		v := c2Val{Addr: a2Low20(el)}
		for _, k := range []struct {
			suffix string
			dst    *common.Hash
		}{{"0", &v.Registered}, {"1", &v.Power}, {"key", &v.KeyHash}} {
			w, ok := st.Words[c2ValKey(v.Addr, k.suffix)]
			if !ok {
				missing = append(missing, c2ValKey(v.Addr, k.suffix))
				continue
			}
			*k.dst = w
		}
		s.Vals = append(s.Vals, v)
	}
	if len(missing) > 0 {
		return nil, &RegistryWordsMissingError{Station: name, Missing: missing}
	}
	return s, nil
}

func (s *c2Station) sorted() []c2Val {
	out := append([]c2Val(nil), s.Vals...)
	sort.SliceStable(out, func(i, j int) bool { return bytes.Compare(out[i].Addr[:], out[j].Addr[:]) < 0 })
	return out
}

// c2Same reports the first word (in a fixed order) that differs between two stations; "" when every registry word is equal.
func c2Same(pre, post *c2Station) string {
	for _, k := range c2BaseKeys {
		if pre.W[k] != post.W[k] {
			return k
		}
	}
	if pre.N != post.N {
		return "A10"
	}
	for i := range post.Vals {
		a, b := pre.Vals[i], post.Vals[i]
		if a != b {
			return fmt.Sprintf("A10:%d", i)
		}
	}
	return ""
}

// c2Keyed pairs the post station's validators with the key bytes Facts.B2.Validators carries; the bytes must hash to the proven key word.
func c2Keyed(env *Env, post *c2Station) ([][]byte, error) {
	vs := env.Facts.B2.Validators
	if uint64(len(vs)) != post.N {
		return nil, &RegistryWordsMissingError{Station: "Validators", Missing: []string{fmt.Sprintf("%d entries for a validatorList of %d", len(vs), post.N)}}
	}
	keys := make([][]byte, len(vs))
	for i, v := range vs {
		if v.Address != post.Vals[i].Addr || crypto.Keccak256Hash(v.BLSKey) != post.Vals[i].KeyHash {
			return nil, &RegistryWordsMissingError{Station: "Validators", Missing: []string{fmt.Sprintf("entry %d is not the validator proven at post", i)}}
		}
		keys[i] = v.BLSKey
	}
	return keys, nil
}

// c2KeysDigest is keccak256(lp("certen:validator-keys:v1") || u32(n) || for each address ascending: B20(address) || lp(key)) (step 21c).
func c2KeysDigest(addrs []common.Address, keys [][]byte) common.Hash {
	idx := make([]int, len(addrs))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return bytes.Compare(addrs[idx[a]][:], addrs[idx[b]][:]) < 0 })
	pre := lp([]byte("certen:validator-keys:v1"))
	pre = binary.BigEndian.AppendUint32(pre, uint32(len(addrs)))
	for _, i := range idx {
		pre = append(pre, addrs[i][:]...)
		pre = append(pre, lp(keys[i])...)
	}
	return crypto.Keccak256Hash(pre)
}

func c2Frac(num, den uint64) string { return fmt.Sprintf("%d/%d", num, den) }

// c2ExpectedSubsets is the number of signer subsets whose power meets the threshold (signed*den >= total*num, the verifier's exact-ratio rule
// that implies the anchor's floor rule), enumerated when the validator list has at most 20 entries; nil otherwise. Only registered validators
// with a non-zero power can sign; total is totalVotingPower.
func c2ExpectedSubsets(powers []uint64, total, num, den uint64) *uint64 {
	n := len(powers)
	if n > 20 {
		return nil
	}
	rhs := new(big.Int).Mul(new(big.Int).SetUint64(total), new(big.Int).SetUint64(num))
	d := new(big.Int).SetUint64(den)
	sums := make([]*big.Int, 1<<n)
	sums[0] = new(big.Int)
	var count uint64
	for mask := 1; mask < 1<<n; mask++ {
		low := mask & -mask
		bit := 0
		for 1<<bit != low {
			bit++
		}
		sums[mask] = new(big.Int).Add(sums[mask&(mask-1)], new(big.Int).SetUint64(powers[bit]))
		if new(big.Int).Mul(sums[mask], d).Cmp(rhs) >= 0 {
			count++
		}
	}
	return &count
}

func c2AttestAbsentRegistry() (*StateError, error) {
	return New(CodeUnproven, RowUnprovenAttestAbsent, map[string]any{"part": JudgedRegistryLink})
}

// c2Owners are the manifest owner rows of role covering block (the verifier role falls back to the anchor rows when the manifest has none, as
// step 13 does).
func c2Owners(env *Env, role string, block uint64) []OwnerRow {
	rows := env.Manifest.OwnerCovering(env.Ctx.Chain, role, block)
	if len(rows) == 0 && role == "blsZkVerifier" && len(env.Manifest.OwnerRows(env.Ctx.Chain, role)) == 0 {
		rows = env.Manifest.OwnerCovering(env.Ctx.Chain, "anchor", block)
	}
	return rows
}

// c2CarryIB re-creates the U state of rule IB on another part (the part field is replaced): "the part carries the same U code".
func c2CarryIB(ib IBResult, part string) (*StateError, error) {
	f := map[string]any{}
	for k, v := range ib.State.Fields {
		f[k] = v
	}
	if _, has := f["part"]; has {
		f["part"] = part
	}
	reason, _ := f["reason"].(string)
	st, err := New(ib.State.Code, reason, f)
	if err != nil {
		return nil, fmt.Errorf("contractidentity: step 21: rule IB state %s %q does not carry over to %s: %w", ib.State.Code, reason, part, err)
	}
	return st, nil
}

// c2FieldKeys are the on-chain words a registry_mismatch field compares (F17): the verdict is R only when they are equal at pre and post.
// The roster fields compare the validator records (the list length and elements and each record's registered, power and key words; the
// informational registeredAt word is not judged).
func c2FieldKeys(field string, pre, post *c2Station) []string {
	switch field {
	case "threshold":
		return []string{"A12", "A13"}
	case "set_root", "certen_set_root", "message_root":
		return []string{"A14"}
	case "pkc":
		return []string{"A05"}
	}
	set := map[string]bool{"A10": true}
	for _, st := range []*c2Station{pre, post} {
		for k := range st.W {
			if (strings.HasPrefix(k, "A10:") || strings.HasPrefix(k, "A09:")) && !strings.HasSuffix(k, ":3") {
				set[k] = true
			}
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// c2Precedence applies the verdict precedence of the "Policy rules" table to a refusal of registry_link (F17): R only when every compared word is
// equal at attest_pre and attest_post AND rule IB is verified; a changed word is U state_changed_in_block, an equal word with rule IB not verified
// carries the U of rule IB, and a rule IB that has no verdict (the attestation block is not established) is attest_absent.
func c2Precedence(env *Env, pre, post *c2Station, block uint64, keys []string, refuse func() (*StateError, error)) (PartResult, error) {
	for _, k := range keys {
		if pre.W[k] != post.W[k] {
			st, err := New(CodeUnproven, RowUnprovenStateChangedInBlock, map[string]any{"field": k, "pre": pre.W[k], "post": post.W[k], "block": block})
			if err != nil {
				return PartResult{}, err
			}
			return c2U(JudgedRegistryLink, st), nil
		}
	}
	ib := env.Facts.B2.IB
	switch {
	case ib.Evaluated && ib.Verified:
		st, err := refuse()
		if err != nil {
			return PartResult{}, err
		}
		return c2R(JudgedRegistryLink, st), nil
	case ib.State != nil:
		st, err := c2CarryIB(ib, JudgedRegistryLink)
		if err != nil {
			return PartResult{}, err
		}
		return c2U(JudgedRegistryLink, st), nil
	}
	st, err := c2AttestAbsentRegistry()
	if err != nil {
		return PartResult{}, err
	}
	return c2U(JudgedRegistryLink, st), nil
}

// c2OwnerPin is step 21b. It returns the contribution on authorization_attest: nil when the pin holds at both stations (the caller emits
// verified), a state otherwise. Verdict precedence (spec "Policy rules"): R only when the word is equal at pre and post, fails at both and rule IB
// is verified; a changed word is U state_changed_in_block; an equal failing word with IB not verified carries the U of rule IB.
func c2OwnerPin(env *Env, pre, post *c2Station, block uint64) (*PartResult, error) {
	for _, o := range []struct{ field, key, role string }{{"anchor_owner", "A16", "anchor"}, {"verifier_owner", "V03", "blsZkVerifier"}} {
		pw, qw := pre.W[o.key], post.W[o.key]
		rows := c2Owners(env, o.role, block)
		in := func(w common.Hash) bool {
			for _, r := range rows {
				if w == a2Word(common.HexToAddress(r.Address)) {
					return true
				}
			}
			return false
		}
		if pw != qw {
			st, err := New(CodeUnproven, RowUnprovenStateChangedInBlock, map[string]any{"field": o.key, "pre": pw, "post": qw, "block": block})
			if err != nil {
				return nil, err
			}
			p := c2U(JudgedAuthorizationAttest, st)
			return &p, nil
		}
		if in(pw) {
			continue
		}
		ib := env.Facts.B2.IB
		switch {
		case ib.Evaluated && ib.Verified:
			want := common.Address{}
			if len(rows) > 0 {
				want = common.HexToAddress(rows[0].Address)
			}
			st, err := New(CodeAuthorizationMismatch, "", map[string]any{"field": o.field, "onchain": a2Low20(pw), "want": want, "at": AtAttestPre})
			if err != nil {
				return nil, err
			}
			p := c2R(JudgedAuthorizationAttest, st)
			return &p, nil
		case ib.State != nil:
			// the part carries the U code of rule IB (owner_active_in_block, owner_not_eoa, tx_type_unsupported, ...), on this part
			st, err := c2CarryIB(ib, JudgedAuthorizationAttest)
			if err != nil {
				return nil, err
			}
			p := c2U(JudgedAuthorizationAttest, st)
			return &p, nil
		default:
			// rule IB has no verdict (its reads were not made): another step decided the part, or the run fails loudly as an undecided part
			return &PartResult{}, nil
		}
	}
	return nil, nil
}

// c2Registry9Field compares Registry9 with the proven registry at post and pre and returns the first differing registry_mismatch field ("" when
// equal). Member lists are compared sorted ascending by address, member by member over the common prefix (address and registered, power, key),
// then the counts, the threshold, the root recomputed from Registry9 against currentValidatorSetRoot at post, Registry9.certenSetRoot against the
// post root and against the pre root (the root component of M, step 20): a root that changed inside B_v is message_root.
func c2Registry9Field(r9 *Registry9, pre, post *c2Station) (string, error) {
	type m struct {
		addr  common.Address
		power uint64
		key   common.Hash
	}
	rm := make([]m, len(r9.Members))
	for i, x := range r9.Members {
		kb, err := hex.DecodeString(x.BLSKey)
		if err != nil {
			return "", fmt.Errorf("contractidentity: step 21c: registry9 member %d key: %w", i, err)
		}
		rm[i] = m{x.Address, x.Power, crypto.Keccak256Hash(kb)}
	}
	sort.SliceStable(rm, func(i, j int) bool { return bytes.Compare(rm[i].addr[:], rm[j].addr[:]) < 0 })
	stations := []*c2Station{post, pre}
	for i := range rm {
		for _, st := range stations {
			oc := st.sorted()
			if i >= len(oc) {
				continue
			}
			switch {
			case oc[i].Addr != rm[i].addr || oc[i].Registered != common.BigToHash(big.NewInt(1)):
				return "member_address", nil
			case oc[i].Power != common.BigToHash(new(big.Int).SetUint64(rm[i].power)):
				return "member_power", nil
			case oc[i].KeyHash != rm[i].key:
				return "member_key", nil
			}
		}
	}
	for _, st := range stations {
		if uint64(len(rm)) != st.N {
			return "count", nil
		}
	}
	for _, st := range stations {
		if st.W["A12"] != common.BigToHash(new(big.Int).SetUint64(r9.Num)) || st.W["A13"] != common.BigToHash(new(big.Int).SetUint64(r9.Den)) {
			return "threshold", nil
		}
	}
	addrs := make([]common.Address, len(rm))
	powers := make([]*big.Int, len(rm))
	for i, x := range rm {
		addrs[i], powers[i] = x.addr, new(big.Int).SetUint64(x.power)
	}
	enc, err := a2PackRoot(addrs, powers, new(big.Int).SetUint64(r9.Num), new(big.Int).SetUint64(r9.Den))
	if err != nil {
		return "", err
	}
	root := crypto.Keccak256Hash(enc)
	if root != post.W["A14"] {
		return "set_root", nil
	}
	if common.Hash(r9.CertenSetRoot) != post.W["A14"] {
		return "certen_set_root", nil
	}
	if common.Hash(r9.CertenSetRoot) != pre.W["A14"] {
		return "message_root", nil
	}
	return "", nil
}

// c2History is step 21c without a Registry9: the manifest_history route. ok is true when every condition holds at post and pre; otherwise the
// returned Open entries say which (a single not_checked entry; never verified).
func c2History(env *Env, pre, post *c2Station, block uint64, keys [][]byte) (ok bool, open []OpenEntry, err error) {
	nc := func(part, reason string, f map[string]any) ([]OpenEntry, error) {
		f["part"], f["reason"] = part, reason
		row := part + " / " + reason
		o, e := env.Open(JudgedRegistryLink, OpenNotChecked, CodeNotChecked, row, f)
		return []OpenEntry{o}, e
	}
	rootPost, rootPre := strings.ToLower(post.W["A14"].Hex()), strings.ToLower(pre.W["A14"].Hex())
	row, found := env.Manifest.SetRootRowFor(env.Ctx.Chain, block, rootPost)
	if found && rootPre != rootPost {
		found = false // the row must commit to the root at BOTH stations
	}
	if !found {
		open, err = nc(JudgedRegistryLink, "no_registry_in_file", map[string]any{})
		return false, open, err
	}
	fail := func(reason string, f map[string]any) (bool, []OpenEntry, error) {
		o, e := nc("registry_keys", reason, f)
		return false, o, e
	}
	// (i) keysDigest
	if row.KeysDigest == nil {
		return fail("row_without_keys_digest", map[string]any{})
	}
	want := common.HexToHash(*row.KeysDigest)
	addrs := make([]common.Address, len(post.Vals))
	for i, v := range post.Vals {
		addrs[i] = v.Addr
	}
	gotPost := c2KeysDigest(addrs, keys)
	if gotPost != want {
		return fail("keys_digest_mismatch", map[string]any{"want": want, "got": gotPost})
	}
	same := len(pre.Vals) == len(post.Vals)
	for i := 0; same && i < len(post.Vals); i++ {
		same = pre.Vals[i].Addr == post.Vals[i].Addr && pre.Vals[i].KeyHash == post.Vals[i].KeyHash
	}
	if !same {
		// the key bytes of the pre station are not carried: the digest is taken over the key hashes (S8_FREEZE 6.11, D12)
		pa := make([]common.Address, len(pre.Vals))
		pk := make([][]byte, len(pre.Vals))
		for i, v := range pre.Vals {
			pa[i], pk[i] = v.Addr, v.KeyHash[:]
		}
		return fail("keys_digest_mismatch", map[string]any{"want": want, "got": c2KeysDigest(pa, pk)})
	}
	// (ii) threshold
	for _, st := range []*c2Station{post, pre} {
		if st.W["A12"] != common.BigToHash(new(big.Int).SetUint64(row.ThresholdNumerator)) || st.W["A13"] != common.BigToHash(new(big.Int).SetUint64(row.ThresholdDenominator)) {
			gn, ok1 := a2U64(st.W["A12"])
			gd, ok2 := a2U64(st.W["A13"])
			got := "out_of_range"
			if ok1 && ok2 {
				got = c2Frac(gn, gd)
			}
			return fail("threshold_mismatch", map[string]any{"want": c2Frac(row.ThresholdNumerator, row.ThresholdDenominator), "got": got})
		}
	}
	// (iii) pkcCount, the list and its shape
	if row.PKCCount == nil {
		return fail("row_without_pkc_count", map[string]any{})
	}
	for _, st := range []*c2Station{post, pre} {
		if st.W["A07"] != common.BigToHash(new(big.Int).SetUint64(*row.PKCCount)) {
			got, fits := a2U64(st.W["A07"])
			if !fits {
				got = ^uint64(0)
			}
			return fail("pkc_count_mismatch", map[string]any{"want": *row.PKCCount, "got": got})
		}
	}
	if row.PKCList == nil {
		return fail("pkc_list_absent", map[string]any{})
	}
	list := *row.PKCList
	if uint64(len(list)) != *row.PKCCount {
		return fail("pkc_count_mismatch", map[string]any{"want": *row.PKCCount, "got": uint64(len(list))})
	}
	cs := make([]common.Hash, len(list))
	for i, s := range list {
		raw, e := hex.DecodeString(strings.TrimPrefix(s, "0x"))
		if e != nil || len(raw) != 32 || !strings.HasPrefix(s, "0x") || (i > 0 && bytes.Compare(cs[i-1][:], raw) >= 0) {
			return fail("pkc_list_malformed", map[string]any{"index": uint64(i)})
		}
		cs[i] = common.BytesToHash(raw)
	}
	if len(list) > DefaultLimits().MaxPKCList {
		return fail("pkc_list_too_large", map[string]any{"count": uint64(len(list)), "limit": uint64(DefaultLimits().MaxPKCList)})
	}
	// (iv) every listed commitment is authorized at both stations (rows A06)
	for _, st := range []*c2Station{post, pre} {
		var missing []string
		for _, c := range cs {
			if _, has := st.W["A06:"+strings.ToLower(c.Hex())]; !has {
				missing = append(missing, "A06:"+strings.ToLower(c.Hex()))
			}
		}
		if len(missing) > 0 {
			return false, nil, &RegistryWordsMissingError{Station: st.Name, Missing: missing}
		}
	}
	for _, c := range cs {
		for _, st := range []*c2Station{post, pre} {
			if st.W["A06:"+strings.ToLower(c.Hex())] != common.BigToHash(big.NewInt(1)) {
				return fail("pkc_set_mismatch", map[string]any{"entry": c})
			}
		}
	}
	return true, nil, nil
}

func (s *c2Station) u64(k string) (uint64, bool) { return a2U64(s.W[k]) }

// c2Object is step 21a: the registry object as proven at B_v. It is emitted only when every registry word is equal at pre and post (the object
// states "post, and pre equal") and every number fits its field; otherwise nil (the state of step 18 says why).
func c2Object(env *Env, pre, post *c2Station, keys [][]byte) *RegistryObject {
	if c2Same(pre, post) != "" {
		return nil
	}
	f := env.Facts
	thN, ok1 := post.u64("A12")
	thD, ok2 := post.u64("A13")
	min, ok3 := post.u64("A20")
	minV, ok4 := post.u64("A21")
	cnt, ok5 := post.u64("A07")
	if !(ok1 && ok2 && ok3 && ok4 && ok5) || min > 255 || minV > 255 {
		return nil
	}
	o := &RegistryObject{
		Owner: a2Low20(post.W["A16"]), Root: post.W["A14"], ThresholdNum: thN, ThresholdDen: thD,
		TotalVotingPower: post.W["A11"].Big(), Count: post.N,
		AuthorizedCount: cnt, PKC: f.B1.PKC, PKCAuthorized: post.W["A05"] == common.BigToHash(big.NewInt(1)),
		Binding: post.W["A08"] == common.BigToHash(big.NewInt(1)), Verifier: a2Low20(post.W["A18"]),
		Paused: post.W["A01"] != (common.Hash{}), GovernanceVerifier: a2Low20(post.W["A17"]),
		MinimumGovernanceLvl: uint8(min), MinimumGovernanceLvlV: uint8(minV),
	}
	var powers []uint64
	powersFit := true
	for i, v := range post.Vals {
		o.Members = append(o.Members, RegistryMemberObject{Address: v.Addr, Power: v.Power.Big(), Registered: v.Registered == common.BigToHash(big.NewInt(1)), BLSKey: hex.EncodeToString(keys[i])})
		p, fits := a2U64(v.Power)
		powersFit = powersFit && fits
		if v.Registered == common.BigToHash(big.NewInt(1)) && p > 0 {
			powers = append(powers, p)
		}
	}
	if total, fits := a2U64(post.W["A11"]); fits && powersFit && post.N <= 20 {
		o.ExpectedSubsetCount = c2ExpectedSubsets(powers, total, thN, thD)
	}
	return o
}

func c2Step21(env *Env) (StepOutput, error) {
	f := env.Facts
	if !f.B1.AttestCaptured {
		return StepOutput{}, nil // step 15 decided authorization_attest, intra_block_window and registry_link
	}
	f.C.Registry, f.C.RegistryLink = nil, ""
	absent := func() (StepOutput, error) {
		st, err := c2AttestAbsentRegistry()
		if err != nil {
			return StepOutput{}, err
		}
		return StepOutput{Parts: []PartResult{c2U(JudgedRegistryLink, st)}}, nil
	}
	if !f.B1.HeaderLinked {
		return absent() // B_v is not linked to the settlement header: no word read under its roots is evidence (step 16 decided the part)
	}
	stations := [2]*c2Station{}
	for i, s := range []struct {
		name, at string
		st       AuthStation
	}{{"Pre", AtAttestPre, f.B2.Pre}, {"Post", AtAttestPost, f.B2.Post}} {
		if len(s.st.Words) == 0 {
			if s.st.StateRoot != ([32]byte{}) {
				return StepOutput{}, &RegistryWordsMissingError{Station: s.name, Missing: c2BaseKeys}
			}
			return absent() // step 18 did not read the station and decided authorization_attest
		}
		cs, err := c2Load(s.name, s.at, s.st)
		if err != nil {
			return StepOutput{}, err
		}
		if cs.TooLarge {
			return absent() // validatorList above the read plan's bound: step 18 said so
		}
		stations[i] = cs
	}
	pre, post := stations[0], stations[1]
	block := f.B1.HeaderV.Number
	keys, err := c2Keyed(env, post)
	if err != nil {
		return StepOutput{}, err
	}
	var out StepOutput
	out.RulesJudged = []string{"OWNER"}

	// (b) owner pin
	pin, err := c2OwnerPin(env, pre, post, block)
	if err != nil {
		return StepOutput{}, err
	}
	switch {
	case pin == nil:
		out.Parts = append(out.Parts, env.Verified(JudgedAuthorizationAttest))
	case pin.Part != "":
		out.Parts = append(out.Parts, *pin)
	}

	// (a) emit
	f.C.Registry = c2Object(env, pre, post, keys)

	// (c) registry link and (d) the pkc cross-check
	link := env.Verified(JudgedRegistryLink)
	if r9 := env.Ctx.Registry9; r9 != nil {
		field, err := c2Registry9Field(r9, pre, post)
		if err != nil {
			return StepOutput{}, err
		}
		if field != "" {
			link, err = c2Precedence(env, pre, post, block, c2FieldKeys(field, pre, post), func() (*StateError, error) {
				return New(CodeRegistryMismatch, "", map[string]any{"field": field})
			})
			if err != nil {
				return StepOutput{}, err
			}
		}
		switch {
		case r9.SignerCommitment == ([32]byte{}):
			o, err := env.Open(JudgedRegistryLink, OpenNotChecked, CodeNotChecked, "pkc_signer_check / no_s9_commitment", map[string]any{"part": "pkc_signer_check", "reason": "no_s9_commitment"})
			if err != nil {
				return StepOutput{}, err
			}
			out.Open = append(out.Open, o)
		case link.Status == StatusVerified && r9.SignerCommitment != f.B1.PKC:
			link, err = c2Precedence(env, pre, post, block, c2FieldKeys("pkc", pre, post), func() (*StateError, error) {
				return New(CodePkcMismatch, "", map[string]any{"s9": r9.SignerCommitment, "onchain": f.B1.PKC})
			})
			if err != nil {
				return StepOutput{}, err
			}
		}
		if link.Status == StatusVerified {
			f.C.RegistryLink = "via S9"
		}
	} else {
		ok, open, err := c2History(env, pre, post, block, keys)
		if err != nil {
			return StepOutput{}, err
		}
		out.Open = append(out.Open, open...)
		if ok {
			f.C.RegistryLink = "via manifest_history{keys:digest,pkc:exact_set}"
		}
	}
	out.Parts = append(out.Parts, link)
	return out, nil
}
