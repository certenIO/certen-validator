// Copyright 2026 Certen Protocol

package contractidentity

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common"
)

// ---- the Report (Freeze inventory item 2b) ----
//
// Report.Map / Report.Canonical render the JSON keys of the CLI --json output:
//
//	headline, parts, open, findings, rules_judged, rules_not_judged, residuals, registry, authority, s6, judged_at_level,
//	state_root_authenticated, s7_finalized_status, chain, block, block_hash, manifest_sha256, manifest_source
//
// with the canonical array order of item 2b: parts by part name; open and findings by (part, code, canonical JSON of the fields), bytewise;
// rules_judged by rule id; rules_not_judged by (row, reason); residuals by id. `findings` is present only in a pending headline that has
// findings (n2); `registry` and `authority` are present when their steps ran.

// AuthorityLeg is one leg of the settled call as step 14 decoded it.
type AuthorityLeg struct {
	Target   common.Address
	Selector [4]byte
	Value    *big.Int
	Required string // an authority level name
}

// AuthorityObject is the report's `authority` object (step 14).
type AuthorityObject struct {
	Level       string // authority level name (NONE ... ROOT)
	LoggedLevel string
	Book        [32]byte
	Page        uint64
	Source      string // stored | governing_default | none
	Legs        []AuthorityLeg
}

// Map renders the object with the keys {level, logged_level, book, page, source, legs[]}.
func (a AuthorityObject) Map() (map[string]any, error) {
	if !Check("authority_level", a.Level) || !Check("authority_level", a.LoggedLevel) || !Check("authority_source", a.Source) {
		return nil, fmt.Errorf("contractidentity: authority object: level %q logged %q source %q outside the vocabulary", a.Level, a.LoggedLevel, a.Source)
	}
	legs := make([]any, len(a.Legs))
	for i, l := range a.Legs {
		if !Check("authority_level", l.Required) || l.Value == nil {
			return nil, fmt.Errorf("contractidentity: authority object: leg %d is malformed", i)
		}
		legs[i] = map[string]any{"target": l.Target, "selector": l.Selector, "value": l.Value, "required": l.Required}
	}
	return map[string]any{"level": a.Level, "logged_level": a.LoggedLevel, "book": a.Book, "page": a.Page, "source": a.Source, "legs": legs}, nil
}

// RegistryMemberObject is one validator as proven on-chain at the attestation block.
type RegistryMemberObject struct {
	Address    common.Address
	Power      *big.Int
	Registered bool
	BLSKey     string
}

// RegistryObject is the report's `registry` object (step 21a).
type RegistryObject struct {
	Owner            common.Address
	Root             [32]byte
	ThresholdNum     uint64
	ThresholdDen     uint64
	TotalVotingPower *big.Int
	Count            uint64
	Members          []RegistryMemberObject
	// AuthorizedCommitments: slot 5 (count), the used pkc and whether it is authorized; ExpectedSubsetCount is printed beside the count
	// when it was enumerated (n <= 20), nil otherwise.
	AuthorizedCount       uint64
	PKC                   [32]byte
	PKCAuthorized         bool
	ExpectedSubsetCount   *uint64
	Binding               bool
	Verifier              common.Address
	Paused                bool
	GovernanceVerifier    common.Address
	MinimumGovernanceLvl  uint8
	MinimumGovernanceLvlV uint8 // minimumGovernanceLevelForValueOps
}

// Map renders the object with the keys of step 21a.
func (r RegistryObject) Map() (map[string]any, error) {
	if r.TotalVotingPower == nil {
		return nil, fmt.Errorf("contractidentity: registry object without totalVotingPower")
	}
	members := make([]any, len(r.Members))
	for i, m := range r.Members {
		if m.Power == nil {
			return nil, fmt.Errorf("contractidentity: registry member %d without power", i)
		}
		members[i] = map[string]any{"address": m.Address, "power": m.Power, "registered": m.Registered, "blsKey": m.BLSKey}
	}
	ac := map[string]any{"count": r.AuthorizedCount, "pkc": r.PKC, "pkcAuthorized": r.PKCAuthorized}
	if r.ExpectedSubsetCount != nil {
		ac["expected_subset_count"] = *r.ExpectedSubsetCount
	}
	return map[string]any{
		"owner": r.Owner, "root": r.Root, "threshold": map[string]any{"num": r.ThresholdNum, "den": r.ThresholdDen},
		"totalVotingPower": r.TotalVotingPower, "count": r.Count, "members": members, "authorizedCommitments": ac,
		"binding": r.Binding, "verifier": r.Verifier,
		"governance": map[string]any{"paused": r.Paused, "governanceVerifier": r.GovernanceVerifier, "minimumGovernanceLevel": uint64(r.MinimumGovernanceLvl), "minimumGovernanceLevelForValueOps": uint64(r.MinimumGovernanceLvlV)},
	}, nil
}

// RuleNotJudged is a rule or AUTH row that no rule judges, with the reason printed.
type RuleNotJudged struct {
	Row    string
	Reason string
}

// S6Report is the report's `s6` object, printed in every outcome (step 3).
type S6Report struct {
	Status S6Status
	Reason string // s6_silent only
	State  string // s6_not_proven only
}

// Report is the verdict of one leg.
type Report struct {
	Headline       Headline
	Parts          []PartResult
	RulesJudged    []string
	RulesNotJudged []RuleNotJudged
	Residuals      []string
	Registry       *RegistryObject
	Authority      *AuthorityObject
	S6             S6Report

	JudgedAtLevel          string
	StateRootAuthenticated bool
	S7FinalizedStatus      string

	Chain          uint64
	Block          uint64
	BlockHash      [32]byte
	ManifestSHA256 [32]byte
	ManifestSource string
}

// OpenEntries are every Open entry the parts raised, in canonical order.
func (r Report) OpenEntries() []OpenEntry {
	var out []OpenEntry
	for _, p := range r.Parts {
		out = append(out, p.Open...)
	}
	sortOpen(out)
	return out
}

// Residuals are the fixed residual ids printed in every report (they are properties of the contract design, not open parts).
func FixedResiduals() []string {
	return []string{ResidualRPKC, ResidualRINNER, ResidualRSETTLEPOINTER, ResidualRWRITERS}
}

// Validate checks the report against the vocabularies and the registry: every state is a registry state, the residuals are exactly the
// fixed four, the rule ids and the s6 triple are in their vocabularies, the manifest source is a source.
func (r Report) Validate() error {
	if _, err := r.Headline.State(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, p := range r.Parts {
		if partIndex(p.Part) < 0 || seen[p.Part] {
			return fmt.Errorf("contractidentity: report: part %q unknown or repeated", p.Part)
		}
		seen[p.Part] = true
		if p.State != nil {
			if err := Validate(p.State); err != nil {
				return fmt.Errorf("contractidentity: report: part %s: %w", p.Part, err)
			}
		}
	}
	res := append([]string(nil), r.Residuals...)
	sort.Strings(res)
	want := FixedResiduals()
	sort.Strings(want)
	if fmt.Sprint(res) != fmt.Sprint(want) {
		return fmt.Errorf("contractidentity: report: residuals %v, the fixed set is %v", r.Residuals, want)
	}
	for _, id := range r.RulesJudged {
		if !Check("rule_id", id) {
			return fmt.Errorf("contractidentity: report: rules_judged id %q outside the vocabulary", id)
		}
	}
	if r.S6 == (S6Report{}) {
		// the s6 object is printed in every outcome of step 3 onwards; a framework refusal of steps 0-1b happens before S6 is judged and the
		// context's own triple may be exactly what was incomplete (context_incomplete{s6}), so it prints none [F8]
		if !r.isPreludeRefusal() {
			return fmt.Errorf("contractidentity: report: the s6 object is missing")
		}
	} else if err := r.S6.validate(); err != nil {
		return err
	}
	if !Check("manifest_source", r.ManifestSource) {
		return fmt.Errorf("contractidentity: report: manifest_source %q", r.ManifestSource)
	}
	return nil
}

// validate checks the s6 triple: a status of the vocabulary with the reason or state it requires and nothing else.
func (s S6Report) validate() error {
	if !Check("s6_status", string(s.Status)) {
		return fmt.Errorf("contractidentity: report: s6 status %q", s.Status)
	}
	switch s.Status {
	case S6Silent:
		if !Check("s6_reason", s.Reason) || s.State != "" {
			return fmt.Errorf("contractidentity: report: s6_silent needs a reason and no state")
		}
	case S6NotProven:
		if s.State == "" || s.Reason != "" {
			return fmt.Errorf("contractidentity: report: s6_not_proven needs a state and no reason")
		}
	default:
		if s.Reason != "" || s.State != "" {
			return fmt.Errorf("contractidentity: report: s6_proven carries no reason and no state")
		}
	}
	return nil
}

// isPreludeRefusal is a refused headline whose first refusal is a framework state and that carries no part: the run ended in steps 0-1b.
func (r Report) isPreludeRefusal() bool {
	if r.Headline.Kind != HeadlineRefused || r.Headline.First == nil || len(r.Parts) != 0 {
		return false
	}
	reg, err := DefaultRegistry()
	if err != nil {
		return false
	}
	rows := reg.RowsOf(r.Headline.First.Code)
	return len(rows) > 0 && rows[0].Class == "FR"
}

// Map renders the report with the JSON keys of item 2b, ready for Canonical.
func (r Report) Map() (map[string]any, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	hs, err := r.Headline.State()
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"headline": map[string]any{"code": hs.Code, "fields": hs.Fields},
	}
	parts := append([]PartResult(nil), r.Parts...)
	sort.SliceStable(parts, func(i, j int) bool { return parts[i].Part < parts[j].Part })
	pobjs := make([]any, len(parts))
	for i, p := range parts {
		o := map[string]any{"part": p.Part, "status": string(p.Status)}
		if p.State != nil {
			o["state"] = map[string]any{"code": p.State.Code, "fields": p.State.Fields}
		}
		if p.Reason != "" {
			o["reason"] = p.Reason
		}
		pobjs[i] = o
	}
	out["parts"] = pobjs
	open := r.OpenEntries()
	oobjs := make([]any, len(open))
	for i, o := range open {
		oobjs[i] = o.object()
	}
	out["open"] = oobjs
	if r.Headline.Kind == HeadlinePending && len(r.Headline.Findings) > 0 {
		out["findings"] = findingObjects(r.Headline.Findings)
	}
	rj := append([]string(nil), r.RulesJudged...)
	sort.Strings(rj)
	out["rules_judged"] = rj
	rn := append([]RuleNotJudged(nil), r.RulesNotJudged...)
	sort.SliceStable(rn, func(i, j int) bool {
		if rn[i].Row != rn[j].Row {
			return rn[i].Row < rn[j].Row
		}
		return rn[i].Reason < rn[j].Reason
	})
	rnobjs := make([]any, len(rn))
	for i, x := range rn {
		rnobjs[i] = map[string]any{"row": x.Row, "reason": x.Reason}
	}
	out["rules_not_judged"] = rnobjs
	res := append([]string(nil), r.Residuals...)
	sort.Strings(res)
	out["residuals"] = res
	if r.Registry != nil {
		m, err := r.Registry.Map()
		if err != nil {
			return nil, err
		}
		out["registry"] = m
	}
	if r.Authority != nil {
		m, err := r.Authority.Map()
		if err != nil {
			return nil, err
		}
		out["authority"] = m
	}
	if r.S6 != (S6Report{}) {
		s6 := map[string]any{"status": string(r.S6.Status)}
		if r.S6.Reason != "" {
			s6["reason"] = r.S6.Reason
		}
		if r.S6.State != "" {
			s6["state"] = r.S6.State
		}
		out["s6"] = s6
	}
	out["judged_at_level"] = r.JudgedAtLevel
	out["state_root_authenticated"] = r.StateRootAuthenticated
	out["s7_finalized_status"] = r.S7FinalizedStatus
	out["chain"] = r.Chain
	out["block"] = r.Block
	out["block_hash"] = r.BlockHash
	out["manifest_sha256"] = r.ManifestSHA256
	out["manifest_source"] = r.ManifestSource
	return out, nil
}

// Canonical is the canonical JSON of the report: the form Go and TypeScript compare.
func (r Report) Canonical() ([]byte, error) {
	m, err := r.Map()
	if err != nil {
		return nil, err
	}
	return Canonical(m)
}
