// Copyright 2026 Certen Protocol

package finality

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type stateSpec struct {
	Group               string              `json:"group"`
	Optional            []string            `json:"optional"`
	Required            []string            `json:"required"`
	Scope               string              `json:"scope"`
	Enums               map[string][]string `json:"enums"`
	EnumsDefinedBy      map[string]string   `json:"enums_defined_by"`
	ConditionalRequired []struct {
		When     map[string]string `json:"when"`
		Required []string          `json:"required"`
	} `json:"conditional_required"`
}

type stateRegistry struct {
	Format         string                                 `json:"format"`
	Notes          []string                               `json:"notes"`
	PendingReasons map[string]struct{ Required []string } `json:"pending_reasons"`
	States         map[string]stateSpec                   `json:"states"`
}

func loadRegistry(t testing.TB) stateRegistry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "finality", "states.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r stateRegistry
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// section7Codes is the list of every code of V2_SPEC_S7 section 7, written out independently of the registry file.
var section7Codes = []string{
	// Framework R
	"finality_chain_unsupported", "finality_ledger_extension_invalid", "finality_chain_broken", "finality_evidence_unrecognised",
	"finality_evidence_malformed", "finality_block_mismatch", "finality_evidence_too_large", "finality_pins_corrupt",
	// N, P
	"level_not_applicable", "finality_pending",
	// L1 head R
	"finality_network_mismatch", "finality_fork_unsupported", "finality_pin_unknown", "finality_pin_mismatch", "finality_pin_window",
	"finality_bootstrap_invalid", "finality_link_invalid", "finality_participation_insufficient", "finality_signature_invalid",
	"finality_period_gap", "finality_block_not_covered", "finality_ledger_behind", "finality_header_chain_broken", "l1_finality_unproven",
	// Base R
	"game_challenger_wins", "game_not_resolved", "game_within_finality_delay", "game_blacklisted", "game_retired", "game_not_respected",
	"game_not_registered", "l1_system_paused", "contract_identity_unproven", "game_type_unsupported", "game_unrecognised",
	"output_root_mismatch", "l2_block_not_canonical", "l1_state_proof_invalid", "l1_tx_proof_invalid", "batcher_sender_mismatch",
	"batcher_tx_not_to_inbox", "blob_commitment_mismatch", "channel_incomplete", "channel_timed_out", "channel_malformed",
	"batch_not_found", "batch_binding_mismatch", "batch_outside_sequencing_window", "batch_format_unsupported",
	// Arbitrum R
	"rollup_unpinned", "pin_mismatch", "assertion_preimage_mismatch", "assertion_machine_not_finished", "assertion_not_confirmed",
	"assertion_unknown", "header_chain_exceeds_bound", "confirmed_by_owner_force", "confirmation_path_unproven",
	"l1_posted_content_not_found", "l1_batch_data_off_l1", "l1_batch_header_unknown", "l1_posted_delayed_origin_unproven", "pre_bold_block",
	// Adiri R
	"adiri_incarnation_mismatch", "evidence_pin_mismatch", "committee_chain_broken", "epoch_record_codec_unsupported",
	"finality_link_broken", "committee_shrunk",
	// Builder U
	"l1_blob_unavailable", "batcher_state_unavailable", "l2_headers_unavailable", "l2_header_unavailable",
	"assertion_history_unavailable", "finality_source_unavailable", "level_already_present",
}

var section7PendingReasons = []string{
	"no_evidence_in_file", "block_not_yet_covered", "no_covering_game", "game_unresolved", "within_finality_delay", "l1_posted_unproven",
	"awaiting_batch_post", "awaiting_l1_finality_of_batch", "awaiting_covering_assertion", "awaiting_assertion_confirmation",
	"awaiting_l1_finality_of_confirmation", "epoch_open", "epoch_certificate_pending", "epoch_overdue",
	"l1_proof_window_unavailable", "l1_state_unavailable", "finality_lc_unavailable", "finality_ledger_incomplete", "history_proof_unavailable",
}

func TestTheRegistryHoldsEveryCodeOfSection7AndNothingElseUnderSpecScope(t *testing.T) {
	reg := loadRegistry(t)
	if reg.Format != "certen-finality-states/2" {
		t.Fatalf("format %q", reg.Format)
	}
	want := map[string]bool{}
	for _, c := range section7Codes {
		want[c] = true
		s, ok := reg.States[c]
		if !ok {
			t.Errorf("section 7 code %q is not in states.json", c)
			continue
		}
		if s.Scope != "spec" {
			t.Errorf("%q has scope %q", c, s.Scope)
		}
	}
	for c, s := range reg.States {
		if s.Scope == "spec" && !want[c] {
			t.Errorf("%q has scope spec but is not a section 7 code", c)
		}
		if s.Scope != "spec" && s.Scope != "go_operational" {
			t.Errorf("%q has unknown scope %q", c, s.Scope)
		}
		if !sort.StringsAreSorted(s.Required) || !sort.StringsAreSorted(s.Optional) {
			t.Errorf("%q: field names must be sorted", c)
		}
	}
	for _, r := range section7PendingReasons {
		if _, ok := reg.PendingReasons[r]; !ok {
			t.Errorf("pending reason %q is not in states.json", r)
		}
	}
	if len(reg.PendingReasons) != len(section7PendingReasons) {
		t.Errorf("the pending reason set is closed: %d registered, %d in section 7", len(reg.PendingReasons), len(section7PendingReasons))
	}
}

func conforms(reg stateRegistry, s *StateError) string {
	spec, ok := reg.States[s.Code]
	if !ok {
		return "code " + s.Code + " is not registered"
	}
	allowed := map[string]bool{}
	required := append([]string(nil), spec.Required...)
	if s.Code == CodePending {
		// one finality_pending code with a CLOSED reason set; each reason adds its own required fields
		reason, _ := s.Fields["reason"].(string)
		pr, ok := reg.PendingReasons[reason]
		if !ok {
			return "finality_pending reason " + reason + " is not in the closed set"
		}
		required = append(required, pr.Required...)
	}
	// conditional requirements: when every key of `when` equals the state's field, more fields are required
	for _, c := range spec.ConditionalRequired {
		hit := true
		for k, v := range c.When {
			if fmt.Sprint(s.Fields[k]) != v {
				hit = false
			}
		}
		if hit {
			required = append(required, c.Required...)
		}
	}
	for _, f := range required {
		allowed[f] = true
		if _, has := s.Fields[f]; !has {
			return s.Code + " lacks required field " + f
		}
	}
	// closed enums: a field with a recorded set carries a member of it
	for f, set := range spec.Enums {
		v, has := s.Fields[f]
		if !has {
			continue
		}
		found := false
		for _, m := range set {
			if fmt.Sprint(v) == m {
				found = true
			}
		}
		if !found {
			return s.Code + " field " + f + " = " + fmt.Sprint(v) + " is not in its closed set"
		}
	}
	for _, f := range spec.Optional {
		allowed[f] = true
	}
	for f := range s.Fields {
		if !allowed[f] {
			return s.Code + " carries unregistered field " + f
		}
	}
	return ""
}

func TestEveryConstructorYieldsARegisteredCodeWithExactlyItsFields(t *testing.T) {
	reg := loadRegistry(t)
	b := testBase()
	_, kindErr := KindFor(ChainSepolia, LevelL1Posted)
	_, unsupportedErr := KindFor(1, LevelFinalized)
	_, levelOneErr := KindFor(ChainBaseSepolia, LevelIncluded)
	_, dupErr := NewAddendum(LegBindingOf(b), testProofID, buildChain(t, b, LevelFinalized), b.Chain, LevelFinalized, kBaseFin, nil)
	cases := map[string]*StateError{
		"Malformed":            Malformed("part", ReasonTruncated, 1, 2),
		"MalformedAt":          MalformedAt("part", 3, ReasonHeaderItemIsList, 1, 2),
		"AddendumMalformed":    AddendumMalformed("seq", AddendumBadValue),
		"AddendumMalformedKey": AddendumMalformed("addendum", AddendumUnknownKey, "key", "Seq"),
		"IncludedUnavailable":  IncludedUnavailable(IncludedNoSettlement, "chain", uint64(1)),
		"FinalizedBlockState":  FinalizedBlockUnavailable(1, 2, FinalizedBlockHeaderUnreadable, "index", uint64(8)),
		"Guard":                NewState(CodeGuardRefused, "proof_id", "x", "seq", uint64(1), "cause", "y"),
		"EvidenceTooLarge":     EvidenceTooLarge("part", 5, 4),
		"EvidenceUnrecognised": EvidenceUnrecognised("k", "v1"),
		"ChainUnsupported":     ChainUnsupported(1),
		"ChainBroken":          ChainBroken(2, CheckSeqGap, "want", uint64(3)),
		"ChainBroken legbind":  ChainBroken(0, CheckLegBinding, "want", b.Triple(), "got", b.Triple()),
		"ChainBroken kind":     ChainBroken(1, CheckKind, "chain", uint64(1), "level", LevelFinalized, "kind", "x"),
		"BlockMismatch":        BlockMismatch("blockNumber", uint64(1), uint64(2)),
		"PinsCorrupt":          PinsCorrupt(PinsSHA256Mismatch, "want_sha256", fill(1), "got_sha256", fill(2)),
		"PinsCorrupt indexed":  PinsCorrupt(PinsAnchorWspBelow256, "index", uint64(3)),
		"NotApplicableState":   NotApplicableState(ChainSepolia, LevelL1Posted, ReasonChainIsL1),
		"NoEvidenceInFile":     NoEvidenceInFile(ChainSepolia, LevelIncluded, LevelFinalized).State(),
		"Pending with eta":     (&PendingState{Chain: 1, LevelReached: LevelIncluded, NextLevel: LevelFinalized, Reason: "epoch_open", ETA: time.Unix(1, 0)}).State(),
		"KindFor n/a":          stateOf(t, kindErr),
		"KindFor unsupported":  stateOf(t, unsupportedErr),
		"KindFor level 1":      stateOf(t, levelOneErr),
		"level already":        stateOf(t, dupErr),
		"pins unknown":         NewState(CodePinUnknown, "chain", ChainSepolia, "kind", "eth_sepolia", "period", uint64(1)),
	}
	for name, s := range cases {
		if msg := conforms(reg, s); msg != "" {
			t.Errorf("%s: %s", name, msg)
		}
	}
	// pending: every registered reason, built with exactly its required extra fields
	for reason, spec := range reg.PendingReasons {
		extra := map[string]any{}
		for _, f := range spec.Required {
			extra[f] = "x"
		}
		s := (&PendingState{Chain: 1, LevelReached: LevelIncluded, NextLevel: LevelFinalized, Reason: reason, Judged: extra}).State()
		if msg := conforms(reg, s); msg != "" {
			t.Errorf("pending reason %s: %s", reason, msg)
		}
	}
}

// Every NewState call in the package's own sources names a registered code, and a call whose fields are literal pairs carries
// exactly the registered fields. An unregistered code or a missing field anywhere in the package fails here.
func TestNoCodeOrFieldOutsideTheRegistryIsRaisedAnywhereInThePackage(t *testing.T) {
	reg := loadRegistry(t)
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	consts := map[string]string{}
	var parsed []*ast.File
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, af)
		for _, d := range af.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.CONST {
				for _, sp := range gd.Specs {
					vs := sp.(*ast.ValueSpec)
					for i, n := range vs.Names {
						if i < len(vs.Values) {
							if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
								s, _ := strconv.Unquote(lit.Value)
								consts[n.Name] = s
							}
						}
					}
				}
			}
		}
	}
	// aliases of the form CodePinMissing = CodePinUnknown
	for _, af := range parsed {
		for _, d := range af.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.CONST {
				for _, sp := range gd.Specs {
					vs := sp.(*ast.ValueSpec)
					for i, n := range vs.Names {
						if i < len(vs.Values) {
							if id, ok := vs.Values[i].(*ast.Ident); ok {
								consts[n.Name] = consts[id.Name]
							}
						}
					}
				}
			}
		}
	}
	checked := 0
	for _, af := range parsed {
		ast.Inspect(af, func(n ast.Node) bool {
			if cl, ok := n.(*ast.CompositeLit); ok {
				if id, ok := cl.Type.(*ast.Ident); ok && id.Name == "StateError" && fset.Position(cl.Pos()).Filename != "state.go" {
					t.Errorf("%s: a StateError literal outside state.go bypasses the constructors", fset.Position(cl.Pos()))
				}
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			if !ok || fn.Name != "NewState" || len(call.Args) == 0 {
				return true
			}
			var code string
			switch a := call.Args[0].(type) {
			case *ast.Ident:
				c, ok := consts[a.Name]
				if !ok {
					return true // a variable code (helper constructors): covered by the constructor test
				}
				code = c
			case *ast.BasicLit:
				code, _ = strconv.Unquote(a.Value)
			default:
				return true
			}
			spec, ok := reg.States[code]
			if !ok {
				t.Errorf("%s: NewState raises %q, which is not in states.json", fset.Position(call.Pos()), code)
				return true
			}
			checked++
			if call.Ellipsis != token.NoPos {
				return true
			}
			keys := map[string]bool{}
			for i := 1; i < len(call.Args); i += 2 {
				lit, ok := call.Args[i].(*ast.BasicLit)
				if !ok {
					return true // a computed key: skip the field check for this call
				}
				k, _ := strconv.Unquote(lit.Value)
				keys[k] = true
			}
			allowed := map[string]bool{}
			for _, f := range spec.Required {
				allowed[f] = true
				if !keys[f] {
					t.Errorf("%s: NewState(%q) lacks required field %q", fset.Position(call.Pos()), code, f)
				}
			}
			for _, f := range spec.Optional {
				allowed[f] = true
			}
			for k := range keys {
				if !allowed[k] {
					t.Errorf("%s: NewState(%q) carries unregistered field %q", fset.Position(call.Pos()), code, k)
				}
			}
			return true
		})
	}
	if checked < 15 {
		t.Fatalf("the scan checked only %d NewState calls; the scanner is not seeing the package", checked)
	}
}

func TestCanonicalFormIsSortedWithU64AsDecimalStrings(t *testing.T) {
	s := NewState("finality_chain_broken", "seq", uint64(18446744073709551615), "check", "own_hash", "level", LevelFinalized, "h", fill(0xab),
		"nested", map[string]any{"z": uint64(1), "a": []byte{1, 2}}, "ok", true, "none", nil, "t", time.Unix(0, 0))
	got := string(s.Canonical())
	want := `{"code":"finality_chain_broken","fields":{"check":"own_hash","h":"` + strings.Repeat("ab", 32) +
		`","level":"finalized","nested":{"a":"0102","z":"1"},"none":null,"ok":true,"seq":"18446744073709551615","t":"1970-01-01T00:00:00Z"}}`
	if got != want {
		t.Fatalf("\n got  %s\n want %s", got, want)
	}
	if string(s.Canonical()) != got {
		t.Fatal("canonical form is not deterministic")
	}
}
