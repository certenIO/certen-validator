// Copyright 2026 Certen Protocol

package contractidentity

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// ---- LegContext (Freeze inventory item 2a) ----

// S6Status says what S6 (the replay-slot proof) established about the leg. The caller derives it as step 3 states: s6_proven iff
// ethproof.SettlementCallGeneration named a pinned generation and ReplayGuardCheck is ReplayProven; s6_silent iff S6 made NO claim (the
// call generation is not pinned, or no S6 evidence exists); s6_not_proven iff S6 judged the leg and did not prove it.
type S6Status string

const (
	S6Proven    S6Status = S6S6Proven
	S6Silent    S6Status = S6S6Silent
	S6NotProven S6Status = S6S6NotProven
)

// S6Link is what S8 needs from a ReplayGuardCheck (pkg/ethproof/replayguard.go:280-296): no state root, no accessor dispatch.
type S6Link struct {
	Contract        common.Address
	LeafKey         [32]byte
	SettlementBlock BlockRef
	ProvenAt        BlockRef
	CodeHash        [32]byte
}

// BatchFacts are the four batch values of the proof file; all are mandatory and non-zero (step 11 binds the anchor record to them).
type BatchFacts struct {
	BatchRoot   [32]byte
	OperationID [32]byte
	AccSetRoot  [32]byte
	Incarnation [32]byte
}

// RegistryMember is one validator of the S9 registry: key bytes are lowercase hex without 0x (the stored registry form, M17).
type RegistryMember struct {
	Address common.Address
	Power   uint64
	BLSKey  string
}

// Registry9 is the S9 validator registry for the batch (optional); SignerCommitment may be zero (the Open entry pkc_signer_check).
type Registry9 struct {
	Members          []RegistryMember
	Num, Den         uint64
	CertenSetRoot    [32]byte
	SignerCommitment [32]byte
}

// RegistryKeyHexLen is the length of a registry BLS key in hex characters: 96 bytes (M17).
const RegistryKeyHexLen = 192

// Validate checks the shape the S8 steps rely on: at least one member and keys of exactly RegistryKeyHexLen lowercase hex characters without a
// 0x prefix. A PRESENT Registry9 that fails it is context_incomplete{missing:[registry9]} [r3.2:E-g]; an absent one is legal.
func (r *Registry9) Validate() error {
	if r == nil {
		return fmt.Errorf("contractidentity: nil registry9")
	}
	if len(r.Members) == 0 {
		return fmt.Errorf("contractidentity: registry9 has no members")
	}
	for i, m := range r.Members {
		if len(m.BLSKey) != RegistryKeyHexLen || m.BLSKey != strings.ToLower(m.BLSKey) || strings.HasPrefix(m.BLSKey, "0x") {
			return fmt.Errorf("contractidentity: registry9 member %d: key is not lowercase hex without 0x", i)
		}
		for _, c := range m.BLSKey {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return fmt.Errorf("contractidentity: registry9 member %d: key is not hex", i)
			}
		}
	}
	return nil
}

// LegContext is everything S8 judges a leg against besides the container and the manifest. Chain is the settlement's chain id (the
// ethproof.Settlement carries none). Interface and field table: Freeze inventory item 2a; the refusal is
// context_incomplete{missing:[<name>]}.
type LegContext struct {
	Chain      uint64
	Settlement *ethproof.Settlement
	Tx         *types.Transaction
	Receipt    *ethproof.ReceiptLeaf
	ADIURL     string
	S6Status   S6Status
	S6Reason   string // required text for s6_silent: unsupported_generation | absent
	S6State    string // required for s6_not_proven: the S6 named state, verbatim
	S6         *S6Link
	Batch      BatchFacts
	Registry9  *Registry9
	S7         *finality.Report
}

// Names of the mandatory context members, in the order of item 2a (the `missing` tokens).
const (
	CtxSettlement       = "settlement"
	CtxTx               = "tx"
	CtxReceipt          = "receipt"
	CtxADIURL           = "adi_url"
	CtxS6               = "s6"
	CtxBatchRoot        = "batch.batchRoot"
	CtxBatchOperationID = "batch.batchOperationID"
	CtxBatchAccSetRoot  = "batch.accSetRoot"
	CtxBatchIncarnation = "batch.incarnation"
	CtxRegistry9        = "registry9"
	CtxS7               = "s7"
)

// ContextTokens are the `missing` tokens of context_incomplete in the order of item 2a.
var ContextTokens = []string{CtxSettlement, CtxTx, CtxReceipt, CtxADIURL, CtxS6, CtxBatchRoot, CtxBatchOperationID, CtxBatchAccSetRoot, CtxBatchIncarnation, CtxRegistry9, CtxS7}

func zero32(b [32]byte) bool { return b == [32]byte{} }

// ValidateContext raises context_incomplete{missing:[...]} listing every mandatory member that is absent or invalid, in item 2a order.
// A valid context returns nil. The S6 fields are validated by S6Status: a proven status needs a complete S6Link, a silent one a valid
// S6Reason, a not-proven one a non-empty S6State; the S6Link of a non-proven status is ignored (VS8-021).
func (c *LegContext) ValidateContext() error {
	var missing []string
	if c == nil {
		return ContextIncomplete(ContextTokens)
	}
	// settlement: header RLP, block hash, chain id and the transaction index present
	if s := c.Settlement; s == nil || len(s.Header) == 0 || zero32(s.BlockHash) || c.Chain == 0 || s.Tx == nil || s.Receipt == nil {
		missing = append(missing, CtxSettlement)
	}
	if c.Tx == nil {
		missing = append(missing, CtxTx)
	}
	if c.Receipt == nil {
		missing = append(missing, CtxReceipt)
	}
	if c.ADIURL == "" || len(c.ADIURL) > DefaultLimits().MaxString {
		missing = append(missing, CtxADIURL)
	}
	if !c.s6Valid() {
		missing = append(missing, CtxS6)
	}
	for _, b := range []struct {
		name string
		v    [32]byte
	}{{CtxBatchRoot, c.Batch.BatchRoot}, {CtxBatchOperationID, c.Batch.OperationID}, {CtxBatchAccSetRoot, c.Batch.AccSetRoot}, {CtxBatchIncarnation, c.Batch.Incarnation}} {
		if zero32(b.v) {
			missing = append(missing, b.name)
		}
	}
	if c.Registry9 != nil && c.Registry9.Validate() != nil {
		missing = append(missing, CtxRegistry9)
	}
	if c.S7 == nil {
		missing = append(missing, CtxS7)
	}
	if len(missing) > 0 {
		return ContextIncomplete(missing)
	}
	return nil
}

func (c *LegContext) s6Valid() bool {
	switch c.S6Status {
	case S6Proven:
		l := c.S6
		return l != nil && l.Contract != (common.Address{}) && !zero32(l.LeafKey) && l.SettlementBlock.Number != 0 && !zero32(l.SettlementBlock.Hash) &&
			l.ProvenAt.Number != 0 && !zero32(l.ProvenAt.Hash) && !zero32(l.CodeHash)
	case S6Silent:
		return Check("s6_reason", c.S6Reason)
	case S6NotProven:
		return c.S6State != ""
	}
	return false
}

// ---- part results and the headline algebra (step 23) ----

// PartStatus is the status of one part in the report (item 2b).
type PartStatus string

const (
	StatusVerified      PartStatus = "verified"
	StatusRefused       PartStatus = "refused"
	StatusUnproven      PartStatus = "unproven"
	StatusNotApplicable PartStatus = "not_applicable"
	StatusOpen          PartStatus = "open"
)

var partStatuses = []PartStatus{StatusVerified, StatusRefused, StatusUnproven, StatusNotApplicable, StatusOpen}

// JudgedParts are the parts of the report in step order (the Item 4 'judged part' vocabulary). The first nine are always core;
// registry_link is core only when a Registry9 is present; state_at_settlement is never core (it yields Open entries only).
var JudgedParts = []string{
	JudgedSettlementPath, JudgedS6Link, JudgedCodeIdentity, JudgedAccountProvenance, JudgedPointer, JudgedAuthorityLevel, JudgedRecord,
	JudgedAuthorizationAttest, JudgedIntraBlockWindow, JudgedRegistryLink, JudgedStateAtSettlement,
}

// IsCoreJudgedPart is the core set of step 23.
func IsCoreJudgedPart(part string, registry9 bool) bool {
	switch part {
	case JudgedRegistryLink:
		return registry9
	case JudgedStateAtSettlement:
		return false
	}
	for _, p := range JudgedParts {
		if p == part {
			return true
		}
	}
	return false
}

// OpenEntry is an entry that bars `verified` and does not bar `verified_core`: an alert, a drift or a not_checked.
type OpenEntry struct {
	Part  string
	Kind  string // alert | drift | not_checked
	State *StateError
}

func (o OpenEntry) object() map[string]any {
	return map[string]any{"part": o.Part, "kind": o.Kind, "code": o.State.Code, "fields": o.State.Fields}
}

// PartResult is the result of judging one part.
type PartResult struct {
	Part   string
	Status PartStatus
	// State is the named state of a refused, unproven or open part, and for settlement_path the not_applicable state of a call into CERTEN
	// infrastructure (step 3). It is nil for a verified part and for the not_applicable s6_link.
	State *StateError
	// Reason is the reason of a not_applicable part that has no State (s6_link: s6_silent | s6_not_proven).
	Reason string
	// Open are the Open entries this part raised (they ride on any status: a verified part may carry an alert).
	Open []OpenEntry
}

// Finding is a refused part's state carried by a pending headline (n2).
type Finding struct {
	Part  string
	State *StateError
}

// HeadlineInput is everything the algebra reads: the part results, the framework refusal (steps 0-2 and 22b), the S7 authentication of
// the state root (step 24) and the values a `verified` or `pending` headline reports.
type HeadlineInput struct {
	Parts []PartResult
	// Framework is a framework refusal of steps 0-2 or step 22b (class FR); when set, Parts may be empty (the steps after it did not run).
	Framework *StateError
	// Registry9 says whether a Registry9 was present (it makes registry_link a core part).
	Registry9 bool
	// StateRootAuthenticated is step 24: S7 finalized is verified for this very block.
	StateRootAuthenticated bool
	// LevelReached is the highest verified S7 level (pending headlines).
	LevelReached string
	// S7FinalizedStatus is the S7 finalized status or refusal, carried by a pending headline so that it never hides it (n2).
	S7FinalizedStatus string
	// JudgedAtLevel, StateRoot, Block and RegistryLink are the fields of a `verified` headline.
	JudgedAtLevel string
	StateRoot     [32]byte
	Block         uint64
	RegistryLink  string
}

// Headline is one of the six rows of step 23.
type Headline struct {
	// Kind is one of the headline vocabulary: refused, pending, unproven, verified_core, verified, not_applicable.
	Kind string
	// First and Parts: refused{first,parts} (First is the first refusal state; Parts the refused part names); unproven{parts} (the core parts that are unproven).
	First *StateError
	Parts []string
	// pending
	LevelReached      string
	Findings          []Finding
	S7FinalizedStatus string
	// verified_core
	Open []OpenEntry
	// verified
	JudgedAtLevel string
	StateRoot     [32]byte
	Block         uint64
	RegistryLink  string
	// not_applicable
	NotApplicable *StateError
}

// numJudgedParts is len(JudgedParts); TestJudgedPartsAreEleven keeps them equal.
const numJudgedParts = 11

var partIdx = func() map[string]int {
	m := make(map[string]int, len(JudgedParts))
	for i, p := range JudgedParts {
		m[p] = i
	}
	return m
}()

func partIndex(part string) int {
	if i, ok := partIdx[part]; ok {
		return i
	}
	return -1
}

func sortOpen(o []OpenEntry) {
	sort.SliceStable(o, func(i, j int) bool {
		a, b := o[i], o[j]
		if a.Part != b.Part {
			return a.Part < b.Part
		}
		if a.State.Code != b.State.Code {
			return a.State.Code < b.State.Code
		}
		fa, _ := Canonical(a.State.Fields)
		fb, _ := Canonical(b.State.Fields)
		return string(fa) < string(fb)
	})
}

// ComputeHeadline is the headline algebra of step 23 as a pure function. The first row that applies:
//
//	refused        a framework refusal (steps 0-2, 22b), or a refused part while the state root is authenticated
//	pending        (with findings) a refused part while the state root is NOT authenticated: the refusals ride in findings
//	unproven       no refusal; at least one core part is unproven
//	not_applicable the settlement_path part is the call-into-infrastructure state (step 3)
//	pending        all core parts verified (or not applicable); the state root is not authenticated
//	verified_core  all core parts verified; authenticated; at least one Open entry
//	verified       all core parts verified; authenticated; no Open entry
//
// verified_core is produced only with an Open entry and verified only without one, by construction; an input in which a part has the
// status open but no Open entry, a core part is open, a part is missing or repeated, or a state is not a registry state is an error
// (a defect of the caller, never a headline).
func ComputeHeadline(in HeadlineInput) (Headline, error) {
	if err := validateHeadlineInput(in); err != nil {
		return Headline{}, err
	}
	return headlineAlgebra(in)
}

// validateHeadlineInput rejects every input that is a defect of the caller rather than a verdict.
func validateHeadlineInput(in HeadlineInput) error {
	if in.Framework != nil {
		if err := Validate(in.Framework); err != nil {
			return err
		}
		reg, err := DefaultRegistry()
		if err != nil {
			return err
		}
		if rows := reg.RowsOf(in.Framework.Code); len(rows) == 0 || rows[0].Class != "FR" {
			return fmt.Errorf("contractidentity: headline: %s is not a framework refusal", in.Framework.Code)
		}
	}
	byPart := map[string]*PartResult{}
	for i := range in.Parts {
		p := &in.Parts[i]
		if partIndex(p.Part) < 0 {
			return fmt.Errorf("contractidentity: headline: unknown part %q", p.Part)
		}
		if byPart[p.Part] != nil {
			return fmt.Errorf("contractidentity: headline: part %q repeated", p.Part)
		}
		byPart[p.Part] = p
		if err := validatePartResult(p, in.Registry9); err != nil {
			return err
		}
	}
	if in.Framework != nil {
		return nil
	}
	if len(byPart) != len(JudgedParts) {
		return fmt.Errorf("contractidentity: headline: %d of %d parts present", len(byPart), len(JudgedParts))
	}
	// the call-into-infrastructure answer: every other part is not applicable, and nothing else may be
	naPath := byPart[JudgedSettlementPath].Status == StatusNotApplicable
	for _, name := range JudgedParts {
		p := byPart[name]
		switch {
		case naPath && name != JudgedSettlementPath && p.Status != StatusNotApplicable:
			return fmt.Errorf("contractidentity: headline: settlement_path is not applicable but %s is %s", name, p.Status)
		case !naPath && p.Status == StatusNotApplicable && name != JudgedS6Link:
			return fmt.Errorf("contractidentity: headline: part %s is not applicable but settlement_path is not", name)
		}
	}
	return nil
}

// headlineAlgebra is the table of step 23 on a validated input; the exhaustive test runs it on every combination of part statuses.
func headlineAlgebra(in HeadlineInput) (Headline, error) {
	var h Headline
	var byPart [numJudgedParts]*PartResult
	for i := range in.Parts {
		if k := partIndex(in.Parts[i].Part); k >= 0 {
			byPart[k] = &in.Parts[i]
		}
	}
	naPath := byPart[0] != nil && byPart[0].Status == StatusNotApplicable
	var refused, unprovenCore []string
	var firstRefusal *StateError
	var findings []Finding
	for k, name := range JudgedParts {
		p := byPart[k]
		if p == nil {
			continue
		}
		switch {
		case p.Status == StatusRefused:
			refused = append(refused, name)
			if firstRefusal == nil {
				firstRefusal = p.State
			}
			findings = append(findings, Finding{Part: name, State: p.State})
		case p.Status == StatusUnproven && IsCoreJudgedPart(name, in.Registry9):
			unprovenCore = append(unprovenCore, name)
		}
	}
	var open []OpenEntry
	for k := range JudgedParts {
		if p := byPart[k]; p != nil {
			open = append(open, p.Open...)
		}
	}
	sortOpen(open)
	switch {
	case in.Framework != nil:
		return Headline{Kind: HeadlineRefused, First: in.Framework, Parts: refused}, nil
	case len(refused) > 0 && in.StateRootAuthenticated:
		return Headline{Kind: HeadlineRefused, First: firstRefusal, Parts: refused}, nil
	case len(refused) > 0:
		if in.LevelReached == "" {
			return h, fmt.Errorf("contractidentity: headline: pending without level_reached")
		}
		return Headline{Kind: HeadlinePending, LevelReached: in.LevelReached, Findings: findings, S7FinalizedStatus: in.S7FinalizedStatus}, nil
	case len(unprovenCore) > 0:
		return Headline{Kind: HeadlineUnproven, Parts: unprovenCore}, nil
	case naPath:
		return Headline{Kind: HeadlineNotApplicable, NotApplicable: byPart[0].State}, nil
	case !in.StateRootAuthenticated:
		if in.LevelReached == "" {
			return h, fmt.Errorf("contractidentity: headline: pending without level_reached")
		}
		return Headline{Kind: HeadlinePending, LevelReached: in.LevelReached, S7FinalizedStatus: in.S7FinalizedStatus}, nil
	case len(open) > 0:
		return Headline{Kind: HeadlineVerifiedCore, Open: open}, nil
	}
	if !Check("registry_link_value", in.RegistryLink) {
		return h, fmt.Errorf("contractidentity: headline: verified needs a registry_link value of the vocabulary, got %q", in.RegistryLink)
	}
	if in.JudgedAtLevel == "" {
		return h, fmt.Errorf("contractidentity: headline: verified without judged_at_level")
	}
	return Headline{Kind: HeadlineVerified, JudgedAtLevel: in.JudgedAtLevel, StateRoot: in.StateRoot, Block: in.Block, RegistryLink: in.RegistryLink}, nil
}

func validatePartResult(p *PartResult, registry9 bool) error {
	ok := false
	for _, s := range partStatuses {
		if p.Status == s {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("contractidentity: headline: part %s has status %q", p.Part, p.Status)
	}
	core := IsCoreJudgedPart(p.Part, registry9)
	switch p.Status {
	case StatusVerified:
		if p.State != nil {
			return fmt.Errorf("contractidentity: headline: verified part %s carries a state", p.Part)
		}
	case StatusRefused, StatusUnproven:
		if p.State == nil {
			return fmt.Errorf("contractidentity: headline: %s part %s has no state", p.Status, p.Part)
		}
		if err := Validate(p.State); err != nil {
			return fmt.Errorf("contractidentity: headline: part %s: %w", p.Part, err)
		}
		reg, err := DefaultRegistry()
		if err != nil {
			return err
		}
		class := reg.RowsOf(p.State.Code)[0].Class
		if p.Status == StatusRefused && class != "JR" && class != "FR" {
			return fmt.Errorf("contractidentity: headline: refused part %s carries a %s state %s", p.Part, class, p.State.Code)
		}
		if p.Status == StatusUnproven && class != "U" {
			return fmt.Errorf("contractidentity: headline: unproven part %s carries a %s state %s", p.Part, class, p.State.Code)
		}
	case StatusOpen:
		if core {
			return fmt.Errorf("contractidentity: headline: core part %s cannot have the status open", p.Part)
		}
		if len(p.Open) == 0 {
			return fmt.Errorf("contractidentity: headline: part %s is open but raised no Open entry", p.Part)
		}
	case StatusNotApplicable:
		switch {
		case p.Part == JudgedSettlementPath && p.State != nil:
			if err := Validate(p.State); err != nil || p.State.Code != CodeNotApplicable {
				return fmt.Errorf("contractidentity: headline: settlement_path not_applicable needs the not_applicable state: %v", err)
			}
		case p.Part == JudgedS6Link && p.State == nil && (p.Reason == S6S6Silent || p.Reason == S6S6NotProven):
		case p.Part != JudgedSettlementPath && p.Part != JudgedS6Link && p.State == nil:
			// a part that was not judged because settlement_path is not applicable; the reason is the settlement_path reason
		default:
			return fmt.Errorf("contractidentity: headline: part %s cannot be not_applicable (reason %q)", p.Part, p.Reason)
		}
	}
	for _, o := range p.Open {
		if !Check("open_kind", o.Kind) || o.State == nil || o.Part != p.Part {
			return fmt.Errorf("contractidentity: headline: part %s carries a malformed Open entry", p.Part)
		}
		if err := Validate(o.State); err != nil {
			return fmt.Errorf("contractidentity: headline: part %s Open entry: %w", p.Part, err)
		}
		wantCode := map[string]string{OpenAlert: CodeAlert, OpenDrift: CodeDrift, OpenNotChecked: CodeNotChecked}[o.Kind]
		if o.State.Code != wantCode {
			return fmt.Errorf("contractidentity: headline: Open entry kind %s carries %s", o.Kind, o.State.Code)
		}
	}
	return nil
}

// State renders the headline as its registry state (refused, pending, unproven wrapper, verified_core, verified, not_applicable).
func (h Headline) State() (*StateError, error) {
	switch h.Kind {
	case HeadlineRefused:
		if h.First == nil {
			return nil, fmt.Errorf("contractidentity: refused headline without its first refusal")
		}
		return New(CodeRefused, "", map[string]any{"first": map[string]any{"code": h.First.Code, "fields": h.First.Fields}, "parts": nonNil(h.Parts)})
	case HeadlineUnproven:
		return New(CodeUnproven, "(wrapper)", map[string]any{"parts": nonNil(h.Parts)})
	case HeadlinePending:
		f := map[string]any{"level_reached": h.LevelReached, "next_level": "finalized"}
		if len(h.Findings) > 0 {
			f["findings"] = findingObjects(h.Findings)
		}
		if h.S7FinalizedStatus != "" {
			f["s7_finalized_status"] = h.S7FinalizedStatus
		}
		return New(CodePending, RowPendingStateRootNotAuthenticated, f)
	case HeadlineVerifiedCore:
		objs := make([]any, len(h.Open))
		for i, o := range h.Open {
			objs[i] = o.object()
		}
		return New(CodeVerifiedCore, "", map[string]any{"open": objs})
	case HeadlineVerified:
		return New(CodeVerified, "", map[string]any{"judged_at_level": h.JudgedAtLevel, "stateRoot": h.StateRoot, "block": h.Block, "registry_link": h.RegistryLink})
	case HeadlineNotApplicable:
		if h.NotApplicable == nil {
			return nil, fmt.Errorf("contractidentity: not_applicable headline without its state")
		}
		return h.NotApplicable, nil
	}
	return nil, fmt.Errorf("contractidentity: headline kind %q", h.Kind)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func findingObjects(f []Finding) []any {
	cp := append([]Finding(nil), f...)
	sort.SliceStable(cp, func(i, j int) bool {
		if cp[i].Part != cp[j].Part {
			return cp[i].Part < cp[j].Part
		}
		if cp[i].State.Code != cp[j].State.Code {
			return cp[i].State.Code < cp[j].State.Code
		}
		a, _ := Canonical(cp[i].State.Fields)
		b, _ := Canonical(cp[j].State.Fields)
		return string(a) < string(b)
	})
	out := make([]any, len(cp))
	for i, x := range cp {
		out[i] = map[string]any{"part": x.Part, "code": x.State.Code, "fields": x.State.Fields}
	}
	return out
}
