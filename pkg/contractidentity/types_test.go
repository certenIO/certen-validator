// Copyright 2026 Certen Protocol

package contractidentity

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// ---- LegContext (VS8-020, VS8-021) ----

func validContext() LegContext {
	return LegContext{
		Chain: 11155111,
		Settlement: &ethproof.Settlement{
			BlockHash: common.Hash(bytes32(0x11)), Header: []byte{0xc0},
			Tx: &ethproof.InclusionProof{LeafIndex: 3}, Receipt: &ethproof.InclusionProof{LeafIndex: 3},
		},
		Tx:       types.NewTx(&types.LegacyTx{}),
		Receipt:  &ethproof.ReceiptLeaf{},
		ADIURL:   "acc://x.acme",
		S6Status: S6Proven,
		S6: &S6Link{Contract: common.Address{1}, LeafKey: bytes32(2), SettlementBlock: BlockRef{5, bytes32(3)}, ProvenAt: BlockRef{5, bytes32(3)},
			CodeHash: bytes32(4)},
		Batch: BatchFacts{bytes32(5), bytes32(6), bytes32(7), bytes32(8)},
		S7:    &finality.Report{},
	}
}

func missingOf(t *testing.T, c LegContext) []string {
	t.Helper()
	err := c.ValidateContext()
	if err == nil {
		return nil
	}
	st, ok := AsState(err)
	if !ok || st.Code != CodeContextIncomplete {
		t.Fatalf("ValidateContext: %v", err)
	}
	if verr := Validate(st); verr != nil {
		t.Fatalf("not a registry state: %v", verr)
	}
	return st.Fields["missing"].([]string)
}

func TestVS8_020_ContextIncomplete(t *testing.T) {
	if m := missingOf(t, validContext()); m != nil {
		t.Fatalf("a complete context is refused: %v", m)
	}
	cases := []struct {
		name   string
		mutate func(c *LegContext)
		want   string
	}{
		{"settlement nil", func(c *LegContext) { c.Settlement = nil }, CtxSettlement},
		{"settlement without header", func(c *LegContext) { c.Settlement.Header = nil }, CtxSettlement},
		{"settlement without block hash", func(c *LegContext) { c.Settlement.BlockHash = common.Hash{} }, CtxSettlement},
		{"settlement without chain id", func(c *LegContext) { c.Chain = 0 }, CtxSettlement},
		{"settlement without tx proof", func(c *LegContext) { c.Settlement.Tx = nil }, CtxSettlement},
		{"settlement without receipt proof", func(c *LegContext) { c.Settlement.Receipt = nil }, CtxSettlement},
		{"tx", func(c *LegContext) { c.Tx = nil }, CtxTx},
		{"receipt", func(c *LegContext) { c.Receipt = nil }, CtxReceipt},
		{"adi_url empty", func(c *LegContext) { c.ADIURL = "" }, CtxADIURL},
		{"adi_url too long", func(c *LegContext) { c.ADIURL = strings.Repeat("a", 1025) }, CtxADIURL},
		{"s6 proven with S6 nil", func(c *LegContext) { c.S6 = nil }, CtxS6},
		{"s6 proven without contract", func(c *LegContext) { c.S6.Contract = common.Address{} }, CtxS6},
		{"s6 proven without leaf key", func(c *LegContext) { c.S6.LeafKey = [32]byte{} }, CtxS6},
		{"s6 proven without settlement block number", func(c *LegContext) { c.S6.SettlementBlock.Number = 0 }, CtxS6},
		{"s6 proven without settlement block hash", func(c *LegContext) { c.S6.SettlementBlock.Hash = [32]byte{} }, CtxS6},
		{"s6 proven without provenAt number", func(c *LegContext) { c.S6.ProvenAt.Number = 0 }, CtxS6},
		{"s6 proven without provenAt hash", func(c *LegContext) { c.S6.ProvenAt.Hash = [32]byte{} }, CtxS6},
		{"s6 proven without code hash", func(c *LegContext) { c.S6.CodeHash = [32]byte{} }, CtxS6},
		{"s6 status empty", func(c *LegContext) { c.S6Status = "" }, CtxS6},
		{"s6 status unknown", func(c *LegContext) { c.S6Status = "s6_maybe" }, CtxS6},
		{"s6_silent without a reason", func(c *LegContext) { c.S6Status = S6Silent; c.S6 = nil }, CtxS6},
		{"s6_silent with a reason outside the set", func(c *LegContext) { c.S6Status = S6Silent; c.S6Reason = "because" }, CtxS6},
		{"s6_not_proven without a state", func(c *LegContext) { c.S6Status = S6NotProven; c.S6 = nil }, CtxS6},
		{"batch root", func(c *LegContext) { c.Batch.BatchRoot = [32]byte{} }, CtxBatchRoot},
		{"batch operation id", func(c *LegContext) { c.Batch.OperationID = [32]byte{} }, CtxBatchOperationID},
		{"batch acc set root", func(c *LegContext) { c.Batch.AccSetRoot = [32]byte{} }, CtxBatchAccSetRoot},
		{"batch incarnation", func(c *LegContext) { c.Batch.Incarnation = [32]byte{} }, CtxBatchIncarnation},
		{"s7", func(c *LegContext) { c.S7 = nil }, CtxS7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validContext()
			tc.mutate(&c)
			if got := missingOf(t, c); len(got) != 1 || got[0] != tc.want {
				t.Fatalf("missing = %v, want [%s]", got, tc.want)
			}
		})
	}
	// every member absent: all ten tokens, in the order of item 2a
	if got := missingOf(t, LegContext{}); strings.Join(got, ",") != strings.Join(ContextTokens, ",") {
		t.Fatalf("empty context: %v", got)
	}
	var nilCtx *LegContext
	if err := nilCtx.ValidateContext(); err == nil {
		t.Fatal("nil context accepted")
	}
	if strings.Join(ContextTokens, ",") != "settlement,tx,receipt,adi_url,s6,batch.batchRoot,batch.batchOperationID,batch.accSetRoot,batch.incarnation,s7" {
		t.Fatal("context tokens drifted from the registry text")
	}
	// two defects at once: both listed, in table order
	c := validContext()
	c.Receipt, c.Batch.Incarnation, c.S7 = nil, [32]byte{}, nil
	if got := missingOf(t, c); strings.Join(got, ",") != "receipt,batch.incarnation,s7" {
		t.Fatalf("missing = %v", got)
	}
	// each valid S6 form
	c = validContext()
	c.S6Status, c.S6Reason, c.S6 = S6Silent, S6ReasonAbsent, nil
	if m := missingOf(t, c); m != nil {
		t.Fatalf("s6_silent with a reason refused: %v", m)
	}
	c.S6Reason = S6ReasonUnsupportedGeneration
	if m := missingOf(t, c); m != nil {
		t.Fatalf("s6_silent unsupported_generation refused: %v", m)
	}
	c = validContext()
	c.S6Status, c.S6State, c.S6 = S6NotProven, "replay_slot_unavailable", nil
	if m := missingOf(t, c); m != nil {
		t.Fatalf("s6_not_proven with a state refused: %v", m)
	}
}

// VS8-021: an S6 member present but unused (s6_silent / s6_not_proven) is ignored: the verdict equals that of S6 nil.
func TestVS8_021_UnusedS6IsIgnored(t *testing.T) {
	garbage := &S6Link{Contract: common.Address{0xff}}
	for _, st := range []S6Status{S6Silent, S6NotProven} {
		a, b := validContext(), validContext()
		for _, c := range []*LegContext{&a, &b} {
			c.S6Status = st
			c.S6Reason = S6ReasonAbsent
			c.S6State = "state"
		}
		a.S6, b.S6 = garbage, nil
		if x, y := missingOf(t, a), missingOf(t, b); strings.Join(x, ",") != strings.Join(y, ",") || x != nil {
			t.Fatalf("%s: garbage %v, nil %v", st, x, y)
		}
	}
}

func TestRegistry9Validate(t *testing.T) {
	ok := &Registry9{Members: []RegistryMember{{Address: common.Address{1}, Power: 1, BLSKey: "ab01"}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]*Registry9{
		"nil":        nil,
		"no members": {},
		"empty key":  {Members: []RegistryMember{{BLSKey: ""}}},
		"0x prefix":  {Members: []RegistryMember{{BLSKey: "0xab"}}},
		"upper case": {Members: []RegistryMember{{BLSKey: "AB"}}},
		"not hex":    {Members: []RegistryMember{{BLSKey: "zz"}}},
		"second bad": {Members: []RegistryMember{{BLSKey: "ab"}, {BLSKey: "AB"}}},
	} {
		if bad.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// the signer commitment may be zero
	ok.SignerCommitment = [32]byte{}
	if ok.Validate() != nil {
		t.Error("a zero signer commitment must be valid")
	}
}

// ---- the headline algebra (step 23) ----

func stRefused() *StateError {
	return Must(CodeRecordNotExecuted, "", map[string]any{"anchorId": bytes32(1), "valid": false, "proofExecuted": false})
}
func stUnproven() *StateError {
	return Must(CodeUnproven, RowUnprovenSettlementNotExecuted, map[string]any{"status": "0"})
}
func stAlert() *StateError {
	return Must(CodeAlert, "", map[string]any{"field": AlertBinding, "at": AtSettle, "onchain": "0", "want": "1"})
}
func stDrift() *StateError {
	return Must(CodeDrift, "", map[string]any{"field": "A14", "attest": "0x01", "settle": "0x02"})
}
func stNotChecked() *StateError {
	return Must(CodeNotChecked, RowNotCheckedRegistryLinkNoRegistryInFile, map[string]any{})
}
func stInfra() *StateError {
	return Must(CodeNotApplicable, RowNotApplicableCertenInfrastructureCall, map[string]any{"to": "0x01", "role": RoleAnchor})
}

func openEntry(part string) OpenEntry {
	switch part {
	case JudgedStateAtSettlement:
		return OpenEntry{Part: part, Kind: OpenDrift, State: stDrift()}
	case JudgedRegistryLink:
		return OpenEntry{Part: part, Kind: OpenNotChecked, State: stNotChecked()}
	}
	return OpenEntry{Part: part, Kind: OpenAlert, State: stAlert()}
}

type partKey struct {
	part  string
	st    PartStatus
	extra bool
}

var partCache = map[partKey]PartResult{}

func cachedPart(part string, st PartStatus, extra bool) PartResult {
	k := partKey{part, st, extra}
	if p, ok := partCache[k]; ok {
		return p
	}
	p := mkPart(part, st, extra)
	partCache[k] = p
	return p
}

func mkPart(part string, st PartStatus, extraOpen bool) PartResult {
	p := PartResult{Part: part, Status: st}
	switch st {
	case StatusRefused:
		p.State = stRefused()
	case StatusUnproven:
		p.State = stUnproven()
	case StatusNotApplicable:
		p.Reason = S6S6Silent
	case StatusOpen:
		p.Open = []OpenEntry{openEntry(part)}
	}
	if extraOpen && part == JudgedAuthorizationAttest {
		p.Open = append(p.Open, openEntry(part))
	}
	return p
}

// allowed lists the statuses each part can take in the exhaustive product.
func allowedStatuses(part string, registry9 bool) []PartStatus {
	switch part {
	case JudgedS6Link:
		return []PartStatus{StatusVerified, StatusRefused, StatusUnproven, StatusNotApplicable}
	case JudgedRegistryLink:
		if registry9 {
			return []PartStatus{StatusVerified, StatusRefused, StatusUnproven}
		}
		return []PartStatus{StatusVerified, StatusUnproven, StatusOpen}
	case JudgedStateAtSettlement:
		return []PartStatus{StatusVerified, StatusUnproven, StatusOpen}
	}
	return []PartStatus{StatusVerified, StatusRefused, StatusUnproven}
}

// oracle is the table of step 23 written from the specification text, without sharing any code with ComputeHeadline.
func oracle(parts []PartResult, registry9, auth, extraOpen bool) (kind string, refusedN, unprovenCoreN, openN int) {
	anyR, anyU := false, false
	for _, p := range parts {
		core := true
		switch p.Part {
		case JudgedStateAtSettlement:
			core = false
		case JudgedRegistryLink:
			core = registry9
		}
		if p.Status == StatusRefused {
			anyR = true
			refusedN++
		}
		if core && p.Status == StatusUnproven {
			anyU = true
			unprovenCoreN++
		}
		openN += len(p.Open)
	}
	switch {
	case anyR && auth:
		return HeadlineRefused, refusedN, unprovenCoreN, openN
	case anyR:
		return HeadlinePending, refusedN, unprovenCoreN, openN
	case anyU:
		return HeadlineUnproven, refusedN, unprovenCoreN, openN
	case !auth:
		return HeadlinePending, refusedN, unprovenCoreN, openN
	case openN > 0:
		return HeadlineVerifiedCore, refusedN, unprovenCoreN, openN
	}
	return HeadlineVerified, refusedN, unprovenCoreN, openN
}

// Every combination of part statuses (the product of the allowed statuses of the eleven parts), with and without a Registry9, with the
// state root authenticated and not, with and without an extra Open entry on a verified part: 1.9 million inputs, each checked against the
// oracle. verified_core is never produced without an Open entry and verified never with one.
func TestHeadlineAlgebraIsExhaustive(t *testing.T) {
	var combos, kinds = 0, map[string]int{}
	for _, registry9 := range []bool{false, true} {
		lists := make([][]PartStatus, len(JudgedParts))
		for i, name := range JudgedParts {
			lists[i] = allowedStatuses(name, registry9)
		}
		idx := make([]int, len(JudgedParts))
		for {
			for _, auth := range []bool{false, true} {
				for _, extra := range []bool{false, true} {
					parts := make([]PartResult, len(JudgedParts))
					for i, name := range JudgedParts {
						parts[i] = cachedPart(name, lists[i][idx[i]], extra)
					}
					in := HeadlineInput{Parts: parts, Registry9: registry9, StateRootAuthenticated: auth, LevelReached: "included", S7FinalizedStatus: "pending",
						JudgedAtLevel: "finalized", StateRoot: bytes32(9), Block: 42, RegistryLink: "via S9"}
					// the algebra itself on EVERY combination; the validating entry point (which re-validates every state) on a stride
					// of them and on every combination within two deviations from all-verified
					h, err := headlineAlgebra(in)
					if err != nil {
						t.Fatalf("combo %v auth=%v extra=%v: %v", idx, auth, extra, err)
					}
					deviations := 0
					for _, p := range parts {
						if p.Status != StatusVerified {
							deviations++
						}
					}
					if combos%97 == 0 || deviations <= 2 {
						hv, verr := ComputeHeadline(in)
						if verr != nil || hv.Kind != h.Kind || len(hv.Parts) != len(h.Parts) || len(hv.Open) != len(h.Open) || len(hv.Findings) != len(h.Findings) {
							t.Fatalf("combo %v: validating entry point %+v %v, algebra %+v", idx, hv, verr, h)
						}
					}
					want, refusedN, unprovenN, openN := oracle(parts, registry9, auth, extra)
					if h.Kind != want {
						t.Fatalf("combo %v registry9=%v auth=%v extra=%v: headline %s, oracle %s", idx, registry9, auth, extra, h.Kind, want)
					}
					switch h.Kind {
					case HeadlineRefused:
						if h.First != CodeRecordNotExecuted || len(h.Parts) != refusedN {
							t.Fatalf("refused: %+v", h)
						}
					case HeadlinePending:
						if len(h.Findings) != refusedN || h.LevelReached != "included" || h.S7FinalizedStatus != "pending" {
							t.Fatalf("pending: %+v", h)
						}
					case HeadlineUnproven:
						if len(h.Parts) != unprovenN || unprovenN == 0 {
							t.Fatalf("unproven: %+v", h)
						}
					case HeadlineVerifiedCore:
						if len(h.Open) != openN || openN == 0 {
							t.Fatalf("verified_core without its Open entries: %+v (open %d)", h, openN)
						}
					case HeadlineVerified:
						if openN != 0 || h.RegistryLink != "via S9" || h.Block != 42 {
							t.Fatalf("verified with %d Open entries: %+v", openN, h)
						}
					default:
						t.Fatalf("unexpected headline %s", h.Kind)
					}
					st, err := h.State()
					if err != nil {
						t.Fatalf("headline state: %v", err)
					}
					if err := Validate(st); err != nil {
						t.Fatalf("headline state %s: %v", st, err)
					}
					kinds[h.Kind]++
					combos++
				}
			}
			// next combination
			i := len(idx) - 1
			for i >= 0 {
				idx[i]++
				if idx[i] < len(lists[i]) {
					break
				}
				idx[i] = 0
				i--
			}
			if i < 0 {
				break
			}
		}
	}
	for _, k := range []string{HeadlineRefused, HeadlinePending, HeadlineUnproven, HeadlineVerifiedCore, HeadlineVerified} {
		if kinds[k] == 0 {
			t.Errorf("the product never produced %s", k)
		}
	}
	t.Logf("%d inputs: %v", combos, kinds)
}

func allVerified(registry9 bool) []PartResult {
	parts := make([]PartResult, len(JudgedParts))
	for i, name := range JudgedParts {
		parts[i] = PartResult{Part: name, Status: StatusVerified}
	}
	return parts
}

func verifiedInput() HeadlineInput {
	return HeadlineInput{Parts: allVerified(false), StateRootAuthenticated: true, LevelReached: "finalized", JudgedAtLevel: "finalized",
		StateRoot: bytes32(1), Block: 7, RegistryLink: "via manifest_history{keys:digest,pkc:exact_set}"}
}

func TestHeadlineRowsAndStates(t *testing.T) {
	// verified
	h, err := ComputeHeadline(verifiedInput())
	if err != nil || h.Kind != HeadlineVerified {
		t.Fatalf("%+v %v", h, err)
	}
	st, err := h.State()
	if err != nil {
		t.Fatal(err)
	}
	if string(st.Canonical()) != `{"code":"contract_identity_verified","fields":{"block":"7","judged_at_level":"finalized","registry_link":"via manifest_history{keys:digest,pkc:exact_set}","stateRoot":"0x`+strings.Repeat("01", 32)+`"}}` {
		t.Fatalf("verified state %s", st.Canonical())
	}
	// verified needs a registry_link value of the vocabulary and a level
	in := verifiedInput()
	in.RegistryLink = "via nothing"
	if _, err := ComputeHeadline(in); err == nil {
		t.Error("verified with an unknown registry_link value")
	}
	in = verifiedInput()
	in.JudgedAtLevel = ""
	if _, err := ComputeHeadline(in); err == nil {
		t.Error("verified without judged_at_level")
	}
	// pending needs level_reached
	in = verifiedInput()
	in.StateRootAuthenticated, in.LevelReached = false, ""
	if _, err := ComputeHeadline(in); err == nil {
		t.Error("pending without level_reached")
	}
	// the S6 not-proven Open entry on a not-applicable s6_link bars verified but not verified_core (VS8-049)
	in = verifiedInput()
	in.Parts[1] = PartResult{Part: JudgedS6Link, Status: StatusNotApplicable, Reason: S6S6NotProven,
		Open: []OpenEntry{{Part: JudgedS6Link, Kind: OpenNotChecked, State: Must(CodeNotChecked, RowNotCheckedS6LinkS6NotProven, map[string]any{"state": "replay_slot_unavailable"})}}}
	if h, err := ComputeHeadline(in); err != nil || h.Kind != HeadlineVerifiedCore || len(h.Open) != 1 {
		t.Fatalf("s6_not_proven: %+v %v", h, err)
	}
	in.Parts[1] = PartResult{Part: JudgedS6Link, Status: StatusNotApplicable, Reason: S6S6Silent}
	if h, err := ComputeHeadline(in); err != nil || h.Kind != HeadlineVerified {
		t.Fatalf("s6_silent: %+v %v", h, err)
	}
	// refused: first and parts in step order; the findings of a pending headline are sorted by (part, code, fields)
	in = verifiedInput()
	in.Parts[4] = mkPart(JudgedPointer, StatusRefused, false)
	in.Parts[2] = mkPart(JudgedCodeIdentity, StatusRefused, false)
	h, _ = ComputeHeadline(in)
	if h.Kind != HeadlineRefused || strings.Join(h.Parts, ",") != "code_identity,pointer" {
		t.Fatalf("refused: %+v", h)
	}
	in.StateRootAuthenticated = false
	in.LevelReached = "included"
	h, _ = ComputeHeadline(in)
	if h.Kind != HeadlinePending || len(h.Findings) != 2 {
		t.Fatalf("pending with findings: %+v", h)
	}
	if st, err := h.State(); err != nil || st.Fields["findings"] == nil || Validate(st) != nil {
		t.Fatalf("pending state: %v %v", st, err)
	}
	// ... and the pending without findings has no findings key
	in = verifiedInput()
	in.StateRootAuthenticated, in.LevelReached = false, "included"
	h, _ = ComputeHeadline(in)
	if st, _ := h.State(); h.Kind != HeadlinePending || st.Fields["findings"] != nil {
		t.Fatalf("pending without findings: %+v", st)
	}
	// unproven lists the core parts that are unproven, never a non-core one
	in = verifiedInput()
	in.Parts[10] = mkPart(JudgedStateAtSettlement, StatusUnproven, false)
	if h, _ := ComputeHeadline(in); h.Kind != HeadlineVerified {
		t.Fatalf("a non-core unproven part bars the headline: %+v", h)
	}
	in.Parts[0] = mkPart(JudgedSettlementPath, StatusUnproven, false)
	h, _ = ComputeHeadline(in)
	if h.Kind != HeadlineUnproven || strings.Join(h.Parts, ",") != "settlement_path" {
		t.Fatalf("unproven: %+v", h)
	}
	if st, _ := h.State(); st == nil || st.Code != CodeUnproven || st.Fields["reason"] != nil {
		t.Fatalf("unproven wrapper state %v", st)
	}
}

// The refused row also covers the framework refusals of steps 0-2 AND step 22b (nodes_unreferenced = malformed evidence), with or
// without the state root authenticated (VS8-183), whatever the parts say.
func TestHeadlineFrameworkRefusals(t *testing.T) {
	frameworks := []*StateError{
		ManifestCorrupt(), ManifestUnknown(5), ManifestShadow("builds", "k"), Unrecognised("contract-identity/v9"),
		Malformed(PartNodes, MalformedNodesUnreferenced, 3, 0, 0), // step 22b
		Malformed(PartContainer, MalformedTrailingBytes, 10, 1, 0),
		TooLarge(PartNodes, 20000, 16384), BlockMismatch(BlockFieldHash, bytes32(1), bytes32(2)), ContextIncomplete([]string{CtxS7}),
	}
	for _, fw := range frameworks {
		for _, auth := range []bool{false, true} {
			for _, parts := range [][]PartResult{nil, allVerified(false)} {
				h, err := ComputeHeadline(HeadlineInput{Framework: fw, Parts: parts, StateRootAuthenticated: auth, LevelReached: "included"})
				if err != nil {
					t.Fatalf("%s: %v", fw, err)
				}
				if h.Kind != HeadlineRefused || h.First != fw.Code {
					t.Fatalf("%s auth=%v: %+v", fw, auth, h)
				}
				if st, err := h.State(); err != nil || Validate(st) != nil {
					t.Fatalf("refused state: %v", err)
				}
			}
		}
	}
	// a judgement state is not a framework refusal
	if _, err := ComputeHeadline(HeadlineInput{Framework: stRefused()}); err == nil {
		t.Error("a judgement refusal accepted as a framework refusal")
	}
	if _, err := ComputeHeadline(HeadlineInput{Framework: &StateError{Code: CodeEvidenceTooLarge, Fields: map[string]any{"part": "bogus", "count": uint64(1), "limit": uint64(1)}}}); err == nil {
		t.Error("an invalid framework state accepted")
	}
}

func TestHeadlineNotApplicable(t *testing.T) {
	parts := make([]PartResult, len(JudgedParts))
	for i, name := range JudgedParts {
		parts[i] = PartResult{Part: name, Status: StatusNotApplicable, Reason: "certen_infrastructure_call"}
	}
	parts[0] = PartResult{Part: JudgedSettlementPath, Status: StatusNotApplicable, State: stInfra()}
	parts[1].Reason = S6S6Silent
	for _, auth := range []bool{false, true} {
		h, err := ComputeHeadline(HeadlineInput{Parts: parts, StateRootAuthenticated: auth, LevelReached: "included"})
		if err != nil || h.Kind != HeadlineNotApplicable || h.NotApplicable == nil {
			t.Fatalf("auth=%v: %+v %v", auth, h, err)
		}
		if st, err := h.State(); err != nil || st.Code != CodeNotApplicable || Validate(st) != nil {
			t.Fatalf("state %v %v", st, err)
		}
	}
	// settlement_path not applicable while another part was judged: a defect of the caller
	bad := append([]PartResult(nil), parts...)
	bad[2] = PartResult{Part: JudgedCodeIdentity, Status: StatusVerified}
	if _, err := ComputeHeadline(HeadlineInput{Parts: bad, LevelReached: "x"}); err == nil {
		t.Error("not_applicable settlement_path next to a verified part accepted")
	}
	// ... and a not-applicable part without settlement_path being so
	in := verifiedInput()
	in.Parts[2] = PartResult{Part: JudgedCodeIdentity, Status: StatusNotApplicable, Reason: "x"}
	if _, err := ComputeHeadline(in); err == nil {
		t.Error("code_identity not_applicable accepted while settlement_path is judged")
	}
}

func TestHeadlineRejectsMalformedInputs(t *testing.T) {
	mod := func(f func(in *HeadlineInput)) error {
		in := verifiedInput()
		f(&in)
		_, err := ComputeHeadline(in)
		return err
	}
	cases := map[string]func(in *HeadlineInput){
		"a part missing":                 func(in *HeadlineInput) { in.Parts = in.Parts[:10] },
		"a part repeated":                func(in *HeadlineInput) { in.Parts[3] = in.Parts[2] },
		"an unknown part":                func(in *HeadlineInput) { in.Parts[3].Part = "bogus" },
		"an unknown status":              func(in *HeadlineInput) { in.Parts[3].Status = "fine" },
		"a verified part with a state":   func(in *HeadlineInput) { in.Parts[3].State = stRefused() },
		"a refused part without state":   func(in *HeadlineInput) { in.Parts[4] = PartResult{Part: JudgedPointer, Status: StatusRefused} },
		"an unproven part without state": func(in *HeadlineInput) { in.Parts[4] = PartResult{Part: JudgedPointer, Status: StatusUnproven} },
		"a refused part with a U state": func(in *HeadlineInput) {
			in.Parts[4] = PartResult{Part: JudgedPointer, Status: StatusRefused, State: stUnproven()}
		},
		"an unproven part with a JR state": func(in *HeadlineInput) {
			in.Parts[4] = PartResult{Part: JudgedPointer, Status: StatusUnproven, State: stRefused()}
		},
		"a core part that is open": func(in *HeadlineInput) {
			in.Parts[4] = PartResult{Part: JudgedPointer, Status: StatusOpen, Open: []OpenEntry{openEntry(JudgedPointer)}}
		},
		"an open part without an entry": func(in *HeadlineInput) { in.Parts[10] = PartResult{Part: JudgedStateAtSettlement, Status: StatusOpen} },
		"an Open entry of another part": func(in *HeadlineInput) { in.Parts[3].Open = []OpenEntry{openEntry(JudgedPointer)} },
		"an Open entry of a wrong kind": func(in *HeadlineInput) {
			in.Parts[3].Open = []OpenEntry{{Part: JudgedAccountProvenance, Kind: OpenDrift, State: stAlert()}}
		},
		"an Open entry of a kind outside": func(in *HeadlineInput) {
			in.Parts[3].Open = []OpenEntry{{Part: JudgedAccountProvenance, Kind: "note", State: stAlert()}}
		},
		"an Open entry without a state": func(in *HeadlineInput) {
			in.Parts[3].Open = []OpenEntry{{Part: JudgedAccountProvenance, Kind: OpenAlert}}
		},
		"an Open entry with a bad state": func(in *HeadlineInput) {
			in.Parts[3].Open = []OpenEntry{{Part: JudgedAccountProvenance, Kind: OpenAlert, State: &StateError{Code: CodeAlert}}}
		},
		"a not_applicable s6_link with a reason outside": func(in *HeadlineInput) {
			in.Parts[1] = PartResult{Part: JudgedS6Link, Status: StatusNotApplicable, Reason: "who_knows"}
		},
	}
	for name, f := range cases {
		if err := mod(f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ---- the Report ----

func sampleReport(t *testing.T) Report {
	t.Helper()
	parts := allVerified(false)
	parts[8].Open = []OpenEntry{openEntry(JudgedIntraBlockWindow)}
	parts[9] = PartResult{Part: JudgedRegistryLink, Status: StatusOpen, Open: []OpenEntry{openEntry(JudgedRegistryLink)}}
	in := verifiedInput()
	in.Parts = parts
	h, err := ComputeHeadline(in)
	if err != nil || h.Kind != HeadlineVerifiedCore {
		t.Fatalf("%+v %v", h, err)
	}
	n := uint64(29)
	return Report{
		Headline: h, Parts: parts,
		RulesJudged:    []string{RuleOWNER, RulePAUSED, RuleBINDING},
		RulesNotJudged: []RuleNotJudged{{Row: "usedNonces", Reason: "restrict-only"}, {Row: "A21", Reason: "not read on the attestation path"}},
		Residuals:      FixedResiduals(),
		Registry: &RegistryObject{Owner: common.Address{1}, Root: bytes32(2), ThresholdNum: 2, ThresholdDen: 3, TotalVotingPower: big.NewInt(7), Count: 7,
			Members:         []RegistryMemberObject{{Address: common.Address{3}, Power: big.NewInt(1), Registered: true, BLSKey: "ab"}},
			AuthorizedCount: 29, PKC: bytes32(4), PKCAuthorized: true, ExpectedSubsetCount: &n, Binding: true, Verifier: common.Address{5}, MinimumGovernanceLvl: 1},
		Authority: &AuthorityObject{Level: LevelROOT, LoggedLevel: LevelROOT, Book: bytes32(6), Page: 1, Source: SourceGoverningDefault,
			Legs: []AuthorityLeg{{Target: common.Address{7}, Selector: [4]byte{1, 2, 3, 4}, Value: big.NewInt(0), Required: LevelOPERATOR}}},
		S6:            S6Report{Status: S6Proven},
		JudgedAtLevel: "finalized", StateRootAuthenticated: true, S7FinalizedStatus: "verified",
		Chain: 11155111, Block: 7, BlockHash: bytes32(8), ManifestSHA256: bytes32(9), ManifestSource: ManifestSourceEmbedded,
	}
}

func TestReportCanonicalForm(t *testing.T) {
	r := sampleReport(t)
	raw, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	// the JSON keys of item 2b, exactly (findings only in a pending headline with findings)
	for _, key := range []string{"headline", "parts", "open", "rules_judged", "rules_not_judged", "residuals", "registry", "authority", "s6", "judged_at_level",
		"state_root_authenticated", "s7_finalized_status", "chain", "block", "block_hash", "manifest_sha256", "manifest_source"} {
		if !strings.Contains(s, `"`+key+`":`) {
			t.Errorf("report lacks the key %s", key)
		}
	}
	if strings.Contains(s, `"findings"`) {
		t.Error("findings present in a verified_core report")
	}
	// canonical order: parts by name, rules_judged by id, rules_not_judged by (row, reason), residuals by id
	if i, j := strings.Index(s, `"part":"account_provenance"`), strings.Index(s, `"part":"settlement_path"`); i < 0 || j < 0 || i > j {
		t.Error("parts are not ordered by part name")
	}
	if !strings.Contains(s, `"rules_judged":["BINDING","OWNER","PAUSED"]`) {
		t.Errorf("rules_judged order: %s", s)
	}
	if !strings.Contains(s, `"rules_not_judged":[{"reason":"not read on the attestation path","row":"A21"},{"reason":"restrict-only","row":"usedNonces"}]`) {
		t.Errorf("rules_not_judged order: %s", s)
	}
	if !strings.Contains(s, `"residuals":["R-INNER","R-PKC","R-SETTLE-POINTER","R-WRITERS"]`) {
		t.Errorf("residuals: %s", s)
	}
	if !strings.Contains(s, `"chain":"11155111"`) || !strings.Contains(s, `"state_root_authenticated":true`) || !strings.Contains(s, `"expected_subset_count":"29"`) {
		t.Errorf("scalars: %s", s)
	}
	// determinism: the same report twice, and with the parts and rules shuffled
	again, _ := r.Canonical()
	if string(again) != s {
		t.Error("canonical form is not deterministic")
	}
	r2 := sampleReport(t)
	for i, j := 0, len(r2.Parts)-1; i < j; i, j = i+1, j-1 {
		r2.Parts[i], r2.Parts[j] = r2.Parts[j], r2.Parts[i]
	}
	r2.RulesJudged = []string{RulePAUSED, RuleBINDING, RuleOWNER}
	r2.RulesNotJudged[0], r2.RulesNotJudged[1] = r2.RulesNotJudged[1], r2.RulesNotJudged[0]
	if b, _ := r2.Canonical(); string(b) != s {
		t.Error("input order leaks into the canonical form")
	}
	// a pending headline with findings carries them
	in := verifiedInput()
	in.Parts[2] = mkPart(JudgedCodeIdentity, StatusRefused, false)
	in.StateRootAuthenticated, in.LevelReached, in.S7FinalizedStatus = false, "included", "pending"
	h, _ := ComputeHeadline(in)
	r3 := sampleReport(t)
	r3.Headline, r3.Parts, r3.StateRootAuthenticated = h, in.Parts, false
	b, err := r3.Canonical()
	if err != nil || !strings.Contains(string(b), `"findings":[{"code":"contract_identity_record_not_executed"`) {
		t.Fatalf("pending report: %v %s", err, b)
	}
}

func TestReportValidationRefusesWhatIsNotAReport(t *testing.T) {
	mods := map[string]func(r *Report){
		"a residual missing":          func(r *Report) { r.Residuals = r.Residuals[:3] },
		"a residual invented":         func(r *Report) { r.Residuals = append(r.Residuals, "R-OTHER") },
		"a residual repeated":         func(r *Report) { r.Residuals = []string{ResidualRPKC, ResidualRPKC, ResidualRINNER, ResidualRWRITERS} },
		"a rule outside the set":      func(r *Report) { r.RulesJudged = []string{"NOPE"} },
		"s6 status unknown":           func(r *Report) { r.S6.Status = "maybe" },
		"s6_silent without a reason":  func(r *Report) { r.S6 = S6Report{Status: S6Silent} },
		"s6_not_proven without state": func(r *Report) { r.S6 = S6Report{Status: S6NotProven} },
		"s6_proven with a reason":     func(r *Report) { r.S6 = S6Report{Status: S6Proven, Reason: "absent"} },
		"manifest source unknown":     func(r *Report) { r.ManifestSource = "somewhere" },
		"a repeated part":             func(r *Report) { r.Parts[1] = r.Parts[0] },
		"an authority level unknown":  func(r *Report) { r.Authority.Level = "OWNER" },
		"a registry without power":    func(r *Report) { r.Registry.TotalVotingPower = nil },
		"a headline of no kind":       func(r *Report) { r.Headline = Headline{} },
	}
	for name, f := range mods {
		r := sampleReport(t)
		f(&r)
		if _, err := r.Canonical(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	good := sampleReport(t)
	good.S6 = S6Report{Status: S6Silent, Reason: S6ReasonAbsent}
	if _, err := good.Canonical(); err != nil {
		t.Errorf("s6_silent with a reason: %v", err)
	}
	good.S6 = S6Report{Status: S6NotProven, State: "replay_slot_unavailable"}
	if _, err := good.Canonical(); err != nil {
		t.Errorf("s6_not_proven with a state: %v", err)
	}
}

// ---- Verifier ----

var _ Verifier = VerifierFunc(nil)

func TestVerifierFuncAdapts(t *testing.T) {
	called := false
	var v Verifier = VerifierFunc(func(ctx LegContext, container []byte, m *Manifest) (Report, error) {
		called = container != nil && m == nil && ctx.ADIURL == "x"
		return Report{ManifestSource: "marker"}, nil
	})
	r, err := v.Verify(LegContext{ADIURL: "x"}, []byte{1}, nil)
	if err != nil || !called || r.ManifestSource != "marker" {
		t.Fatalf("%v %v %v", r, called, err)
	}
}
