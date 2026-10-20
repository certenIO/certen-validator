// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// planRequest is the request of one level about the fixture's real Base block.
func planRequest(t *testing.T, f *upgraderFixture, level Level, body string) AppendRequest {
	t.Helper()
	pid, _ := ParseProofID(legID)
	s := f.src.settlements[legID]
	a := built(t, s.Included, level, body)
	return AppendRequest{ProofID: pid, Chain: ChainBaseSepolia, Settlement: s.Included, Level: level, Kind: a.Kind, Evidence: a.Evidence, Registry: f.reg}
}

func TestPlanAppendRecomputesTheChainUnderTheSettlementsD0AndJudgesBeforeItForms(t *testing.T) {
	f := newFixture(t, nil, UpgraderConfig{}, nil)
	pid, _ := ParseProofID(legID)
	s := f.src.settlements[legID]
	a, block, err := PlanAppend(planRequest(t, f, LevelL1Posted, "x"), nil)
	if err != nil || a.Seq != 1 || a.PrevHash != ([32]byte{}) || a.OwnHash != OwnHash(LegBindingOf(block), a) || block.Number != s.Block().Number {
		t.Fatalf("%v %+v", err, a)
	}
	if f.fin.calls != 0 {
		t.Fatal("the finalized Kind ran for an l1_posted request")
	}

	t.Run("a second addendum at a stored level is level_already_present and the Kind is not run", func(t *testing.T) {
		before := f.fin.calls
		_, _, err := PlanAppend(planRequest(t, f, LevelL1Posted, "again"), []Addendum{a})
		if st, ok := AsNamed(err); !ok || st.Code != CodeLevelAlreadyPresent || f.fin.calls != before {
			t.Fatalf("%v", err)
		}
	})
	t.Run("the next link follows the stored chain", func(t *testing.T) {
		b, _, err := PlanAppend(planRequest(t, f, LevelFinalized, "y"), []Addendum{a})
		if err != nil || b.Seq != 2 || b.PrevHash != a.OwnHash || VerifyChain(LegBindingOf(s.Block()), []Addendum{a, b}) != nil {
			t.Fatalf("%v %+v", err, b)
		}
	})
	t.Run("a stored chain under another D0 is refused at own_hash and nothing is formed", func(t *testing.T) {
		other := s.Block()
		other.Number++
		forged, err := NewAddendum(LegBindingOf(other), pid, nil, ChainBaseSepolia, LevelL1Posted, kBaseL1, planRequest(t, f, LevelL1Posted, "x").Evidence)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = PlanAppend(planRequest(t, f, LevelFinalized, "y"), []Addendum{forged})
		if st, ok := AsNamed(err); !ok || st.Code != CodeChainBroken || st.Fields["check"] != CheckOwnHash {
			t.Fatalf("%v", err)
		}
	})
	t.Run("the Kind's refusal is returned and level 1 cannot be asked for", func(t *testing.T) {
		refusing := newFixture(t, nil, UpgraderConfig{}, NewState("game_challenger_wins"))
		if _, _, err := PlanAppend(planRequest(t, refusing, LevelFinalized, "y"), nil); stateCodeOf(err) != "game_challenger_wins" {
			t.Fatalf("%v", err)
		}
		req := planRequest(t, f, LevelFinalized, "y")
		req.Level = LevelIncluded
		if _, _, err := PlanAppend(req, nil); stateCodeOf(err) != CodeChainBroken {
			t.Fatalf("%v", err)
		}
	})
	t.Run("an unregistered kind is finality_evidence_unrecognised; no registry is a refused request", func(t *testing.T) {
		bare := planRequest(t, f, LevelL1Posted, "x")
		bare.Registry = NewRegistry()
		if _, _, err := PlanAppend(bare, nil); stateCodeOf(err) != CodeEvidenceUnrecognised {
			t.Fatalf("%v", err)
		}
		bare.Registry = nil
		if _, _, err := PlanAppend(bare, nil); err == nil {
			t.Fatal("a request with no registry was planned")
		}
	})
	t.Run("a settlement that does not verify is finality_included_invalid", func(t *testing.T) {
		req := planRequest(t, f, LevelL1Posted, "x")
		req.Settlement = nil
		if _, _, err := PlanAppend(req, nil); stateCodeOf(err) != CodeIncludedUnavailable {
			t.Fatalf("%v", err)
		}
	})
}

func stateCodeOf(err error) string {
	if st, ok := AsNamed(err); ok {
		return st.Code
	}
	return ""
}

// ---- the portable member composed from the repository ----

type fakeSectionSource struct {
	*memStore
	src   *memSource
	noRef error
}

func (f fakeSectionSource) LegRef(_ context.Context, id string) (LegRef, error) {
	if f.noRef != nil {
		return LegRef{}, f.noRef
	}
	return f.src.legs[0], nil
}

func (f fakeSectionSource) LegSettlement(ctx context.Context, ref LegRef) (Settlement, error) {
	return f.src.LegSettlement(ctx, ref)
}

func TestComposeSectionBuildsTheSpec25MemberFromTheVerifiedLegAndTheStoredChain(t *testing.T) {
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	ctx := context.Background()
	src := fakeSectionSource{memStore: f.store, src: f.src}

	if s, err := ComposeSection(ctx, src, legID); err != nil || s != nil {
		t.Fatalf("a proof with no addenda has no section: %v %v", s, err)
	}
	if raw, err := ComposeSectionJSON(ctx, src, legID); err != nil || raw != nil {
		t.Fatalf("%s %v", raw, err)
	}
	f.u.RunOnce(ctx)
	raw, err := ComposeSectionJSON(ctx, src, legID)
	if err != nil || raw == nil {
		t.Fatalf("%v", err)
	}
	// exactly the spec-2.5 object: format, leg (chain, blockNumber, blockHash), addenda with the stored fields
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil || len(generic) != 3 {
		t.Fatalf("%s %v", raw, err)
	}
	for _, k := range []string{"format", "leg", "addenda"} {
		if _, ok := generic[k]; !ok {
			t.Fatalf("member %q missing: %s", k, raw)
		}
	}
	section, err := ParseSection(raw) // the strict parser a verifier uses accepts it
	if err != nil || section.Format != SectionFormat || len(section.Addenda) != 2 {
		t.Fatalf("%v %+v", err, section)
	}
	block := f.src.settlements[legID].Block()
	carried, _ := section.Leg.Ref()
	if carried.Chain != ChainBaseSepolia || carried.Number != block.Number || carried.Hash != block.Hash {
		t.Fatalf("the leg is the verified Settlement's block: %+v", section.Leg)
	}
	if err := CheckLegChain(block, carried, section.Addenda); err != nil {
		t.Fatal(err)
	}

	t.Run("a stored chain that does not verify is not composed", func(t *testing.T) {
		f.store.mu.Lock()
		f.store.chains[legID][1].OwnHash[0] ^= 1
		f.store.mu.Unlock()
		if _, err := ComposeSection(ctx, src, legID); stateCodeOf(err) != CodeChainBroken {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a proof with addenda and no settlement evidence has no leg to attach to", func(t *testing.T) {
		none := fakeSectionSource{memStore: f.store, src: f.src, noRef: IncludedUnavailable(IncludedNoExecutionProof, "proof_id", legID)}
		if _, err := ComposeSection(ctx, none, legID); stateCodeOf(err) != CodeIncludedUnavailable {
			t.Fatalf("%v", err)
		}
	})
	if _, err := ComposeSection(ctx, src, "not-a-uuid"); err == nil {
		t.Fatal("a bad proof id was composed")
	}
}

// ---- the builder status document ----

func TestBuilderStatusDocumentRoundTripsAndRefusesWhatItCannotStore(t *testing.T) {
	eta := time.Date(2026, 10, 24, 1, 2, 3, 0, time.UTC)
	pd := &PendingState{Chain: ChainBaseSepolia, LevelReached: LevelL1Posted, NextLevel: LevelFinalized, Reason: "game_unresolved", ETA: eta}
	for _, st := range []BuilderStatus{
		BuilderStatusOf(legID, ChainBaseSepolia, LevelFinalized, LevelL1Posted, pd, nil, false, time.Now()),
		BuilderStatusOf(legID, ChainBaseSepolia, LevelFinalized, LevelIncluded, nil, NewState(CodeBuildTimeout, "chain", uint64(1), "after", time.Second, "cause", "x"), false, time.Now()),
		BuilderStatusOf(legID, ChainBaseSepolia, LevelFinalized, LevelIncluded, nil, NewState("game_challenger_wins"), true, time.Now()),
		BuilderStatusOf(legID, ChainBaseSepolia, LevelFinalized, LevelIncluded, nil, NotApplicableState(ChainBaseSepolia, LevelFinalized, ReasonChainIsL1), false, time.Now()),
		VerifiedBuilderStatus(legID, ChainBaseSepolia, LevelL1Posted, 1, time.Now()),
	} {
		doc, err := st.Document()
		if err != nil {
			t.Fatalf("%+v: %v", st, err)
		}
		v, err := ParseBuilderStatusDocument(doc)
		if err != nil || v.Class != st.Class || v.LevelReached != st.LevelReached || v.NextLevel != st.NextLevel || !v.ETA.Equal(st.ETA) || v.Seq != st.Seq {
			t.Fatalf("%s: %v %+v", doc, err, v)
		}
		if (st.State == nil) != (v.State == nil) {
			t.Fatalf("%s", doc)
		}
	}
	if _, err := BuilderStatusOf(legID, 1, LevelIncluded, LevelIncluded, pd, nil, false, time.Now()).Document(); err == nil {
		t.Fatal("a status row for level 1 was rendered")
	}
	if _, err := (BuilderStatus{TargetLevel: LevelFinalized, Class: BuilderPending}).Document(); err == nil {
		t.Fatal("a pending status without its state was rendered")
	}
	if _, err := (BuilderStatus{TargetLevel: LevelFinalized, Class: BuilderVerified, State: NewState("x")}).Document(); err == nil {
		t.Fatal("a verified status with a state was rendered")
	}
	if _, err := ParseBuilderStatusDocument([]byte(`{"format":"other/1","class":"pending","levelReached":"included","nextLevel":"finalized"}`)); err == nil {
		t.Fatal("a document of another format was read")
	}
	if _, err := ParseBuilderStatusDocument([]byte(`{"format":"` + BuilderStatusFormat + `","class":"pending","levelReached":"included","nextLevel":"finalized","extra":1}`)); err == nil {
		t.Fatal("a document with an unknown member was read")
	}
}

// ---- the new tables: who writes them, and what the migration touches ----

var dbWrite = regexp.MustCompile(`(?is)(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?)\s+(?:ONLY\s+)?(?:public\.)?"?([a-z_][a-z0-9_]*)"?`)

func TestEachNewRepositoryWritesOnlyItsOwnTableAndMigration00028TouchesOnlyThem(t *testing.T) {
	root := repoRoot(t)
	for file, table := range map[string]string{"finality_status.go": "proof_finality_status", "finality_capture.go": "proof_finality_capture"} {
		raw, err := os.ReadFile(filepath.Join(root, "pkg", "database", file))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, m := range regexp.MustCompile("(?s)`([^`]*)`").FindAllStringSubmatch(string(raw), -1) {
			stmt := regexp.MustCompile(`(?i)DO[[:space:]]+UPDATE[[:space:]]+SET`).ReplaceAllString(m[1], "DO_UPSERT SET") // ON CONFLICT ... DO UPDATE is an upsert of the same table
			for _, w := range dbWrite.FindAllStringSubmatch(stmt, -1) {
				if !strings.EqualFold(w[1], table) {
					t.Errorf("%s writes %q: it may write only %s", file, w[1], table)
				}
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no write found: the scan is not seeing the SQL", file)
		}
	}
	mig, err := os.ReadFile(filepath.Join(root, "db", "migrations", "00028_proof_finality_status_capture.sql"))
	if err != nil {
		t.Fatal(err)
	}
	ddl := regexp.MustCompile(`(?i)\b(CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE|COMMENT\s+ON\s+TABLE|CREATE\s+(?:UNIQUE\s+)?INDEX\s+\S+\s+ON|CREATE\s+TRIGGER\s+\S+[\s\S]*?\bON)\s+(?:ONLY\s+)?(?:public\.)?"?([a-z_][a-z0-9_]*)"?`)
	seen := 0
	for _, m := range ddl.FindAllStringSubmatch(string(mig), -1) {
		seen++
		if n := strings.ToLower(m[2]); n != "proof_finality_status" && n != "proof_finality_capture" {
			t.Errorf("migration 00028 changes %q", n)
		}
	}
	if seen < 6 {
		t.Fatalf("only %d DDL statements recognised in migration 00028: the scan is not seeing the SQL", seen)
	}
	// the capture table is insert-only exactly like the addendum table: UPDATE, DELETE (row trigger) and TRUNCATE (statement trigger)
	text := string(mig)
	for _, want := range []string{"BEFORE UPDATE OR DELETE ON public.proof_finality_capture", "FOR EACH ROW", "BEFORE TRUNCATE ON public.proof_finality_capture", "FOR EACH STATEMENT", "restrict_violation"} {
		if !strings.Contains(text, want) {
			t.Errorf("migration 00028 lacks %q", want)
		}
	}
	if strings.Contains(text, "proof_finality_status_guard") {
		t.Error("the status table is mutable by design: it has no guard")
	}
}
