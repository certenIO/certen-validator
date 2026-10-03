package consensus

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ledger"
)

// The claim behind continuing older state - "no committed history contains a transaction of the new kind decided the
// old way" - is checked over the WHOLE chain, not only the blocks the committed-operation index has not yet read: a
// block an older binary committed and indexed can hold one. Before rules v12 a node whose index already covered the
// chain checked nothing at all (every case below marked "false" started). A code the kind's version never returns is
// history it does not reproduce too.
func TestCommittedRegistryAndReSealCodesAreChecked(t *testing.T) {
	f := newRegistryFixture(t)
	registry := rotJSON(t, f.registry(1, "ops-1", "ops-2"))
	reseal := []byte(fmt.Sprintf(`{"kind":%q,"chain_id":"certen-testnet"}`, AdminResealKind))
	for name, c := range map[string]struct {
		tx   []byte
		code uint32
		ok   bool
	}{
		"a registry refused by v10":                         {registry, codeBLSRegistryRefused, true},
		"a registry v9 judged as a ValidatorBlock (code 2)": {registry, 2, false},
		"a registry decided with a ValidatorBlock's code 1": {registry, 1, false},
		"a re-seal refused by v11":                          {reseal, codeAdminResealRefused, true},
		"a re-seal v10 judged as a ValidatorBlock (code 2)": {reseal, 2, false},
		"a re-seal decided with a ValidatorBlock's code 4":  {reseal, 4, false},
		"a ValidatorBlock-shaped non-kind tx with any code": {[]byte(`{"validator_id":"v"}`), 2, true},
	} {
		app := historyApp(t, 1)
		// The older binary that committed block 1 indexed it.
		if err := app.ledgerStore.RecordCommittedBlock(1, nil); err != nil {
			t.Fatal(err)
		}
		err := app.IndexCommittedHistory(&fakeHistory{base: 1, blocks: map[int64][][]byte{1: {c.tx}},
			times: map[int64]time.Time{1: beforeV9}, codes: map[int64][]uint32{1: {c.code}}})
		if c.ok != (err == nil) || (!c.ok && !errors.Is(err, ErrCommittedHistoryUnderCurrentRules)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A block holding two accepted validator rotations is history v12 does not reproduce (v12 accepts one per block); a
// block whose copy of its rotation was refused is v12's, and stamps the state v12.
func TestCommittedRotationsAreJudgedPerBlock(t *testing.T) {
	f := newRotationFixture()
	tx := rotJSON(t, f.rotation(1, f.validators[3], seededKey(0x79), "ops-1", "ops-2"))
	twin := append(append([]byte(nil), tx...), ' ')
	hist := func(codes ...uint32) *fakeHistory {
		return &fakeHistory{base: 1, blocks: map[int64][][]byte{1: {tx, twin}}, times: map[int64]time.Time{1: beforeV9},
			codes: map[int64][]uint32{1: codes}}
	}
	if err := historyApp(t, 1).IndexCommittedHistory(hist(0, 0)); !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) {
		t.Fatalf("a block with the same rotation accepted twice: %v", err)
	}
	app := historyApp(t, 1)
	if err := app.IndexCommittedHistory(hist(0, 6)); err != nil {
		t.Fatalf("a block whose copy was refused: %v", err)
	}
	if app.committedRulesVersion() != executionRulesV12 {
		t.Fatalf("stamped v%d", app.committedRulesVersion())
	}
	// Already indexed by the binary that committed it: still checked.
	indexed := historyApp(t, 1)
	if err := indexed.ledgerStore.RecordCommittedBlock(1, nil); err != nil {
		t.Fatal(err)
	}
	if err := indexed.IndexCommittedHistory(hist(0, 0)); !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) {
		t.Fatalf("an indexed block with the same rotation accepted twice: %v", err)
	}
}

// A policy update accepted again in a later block (v11's no-op) is history v12 does not reproduce; one refused there is
// v12's verdict and stamps the state v12.
func TestCommittedPolicyReplaysAreChecked(t *testing.T) {
	update := []byte(fmt.Sprintf(`{"kind":%q,"chain_id":"certen-testnet","mode":"off","activation_unix":1800000700,"version":2}`, PolicyUpdateKind))
	hist := func(code uint32) *fakeHistory {
		return &fakeHistory{base: 1, blocks: map[int64][][]byte{1: {update}, 2: {update}},
			times: map[int64]time.Time{1: beforeV9, 2: beforeV9}, codes: map[int64][]uint32{1: {0}, 2: {code}}}
	}
	scheduled := func(app *ValidatorApp) {
		st, err := app.ledgerStore.LoadEntitlementPolicy()
		if err != nil || st == nil {
			t.Fatalf("policy: (%v, %v)", st, err)
		}
		st.Schedule = append(st.Schedule, ledger.ScheduledPolicyChange{Mode: "off", ActivationUnix: 1800000700, Version: 2, ProposedAtHeight: 1})
		if err := app.ledgerStore.SaveEntitlementPolicy(st); err != nil {
			t.Fatal(err)
		}
	}
	bad := historyApp(t, 2)
	scheduled(bad)
	if err := bad.IndexCommittedHistory(hist(0)); !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) {
		t.Fatalf("an update accepted again a block later: %v", err)
	}
	good := historyApp(t, 2)
	scheduled(good)
	if err := good.IndexCommittedHistory(hist(5)); err != nil {
		t.Fatalf("an update refused a block later: %v", err)
	}
	if good.committedRulesVersion() != executionRulesV12 {
		t.Fatalf("stamped v%d", good.committedRulesVersion())
	}
}

// An accepted admin re-seal is history only when the committed policy records it at that height under its id; an
// accepted one with no record is divergent or corrupt state, refused by name - also on a chain already indexed.
func TestAnAcceptedReSealWithoutItsRecordIsRefused(t *testing.T) {
	f := newRotationFixture()
	_, to, _ := resealSets(f)
	reseal := resealFor(to, rotChain)
	raw := rotJSON(t, reseal)
	hist := &fakeHistory{base: 1, blocks: map[int64][][]byte{1: {raw}}, times: map[int64]time.Time{1: beforeV9},
		codes: map[int64][]uint32{1: {0}}}
	bare := historyApp(t, 1)
	if err := bare.ledgerStore.RecordCommittedBlock(1, nil); err != nil {
		t.Fatal(err)
	}
	err := bare.IndexCommittedHistory(hist)
	if !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) || !strings.Contains(err.Error(), "admin re-seal that was accepted, but the committed policy holds no record") {
		t.Fatalf("an accepted re-seal with no record: %v", err)
	}
	recorded := historyApp(t, 1)
	st, err := recorded.ledgerStore.LoadEntitlementPolicy()
	if err != nil || st == nil {
		t.Fatalf("policy: (%v, %v)", st, err)
	}
	st.AdminReseals = []ledger.AdminReseal{{Height: 1, ID: reseal.ResealID(), Keys: reseal.AdminKeys, Threshold: reseal.AdminThreshold}}
	if err := recorded.ledgerStore.SaveEntitlementPolicy(st); err != nil {
		t.Fatal(err)
	}
	if err := recorded.IndexCommittedHistory(hist); err != nil {
		t.Fatalf("an accepted re-seal with its record: %v", err)
	}
	// The exported check a tool runs: with the records, the same verdicts; without them, the acceptance is listed as
	// unread, never passed as checked.
	if v, u, err := CommittedBlockViolations(1, [][]byte{raw}, []uint32{0}, &CommittedRecords{Policy: st}); err != nil || len(v) != 0 || len(u) != 0 {
		t.Fatalf("with its record: %v %v %v", v, u, err)
	}
	if v, u, err := CommittedBlockViolations(1, [][]byte{raw}, []uint32{0}, &CommittedRecords{}); err != nil || len(v) != 1 || len(u) != 0 {
		t.Fatalf("records without it: %v %v %v", v, u, err)
	}
	if v, u, err := CommittedBlockViolations(1, [][]byte{raw}, []uint32{0}, nil); err != nil || len(v) != 0 || len(u) != 1 {
		t.Fatalf("records not read: %v %v %v", v, u, err)
	}
}

// Records without the registry log (a node of the first v12 release serves the admin record, not the log) leave every
// accepted registry unread - never passed, never refused for want of a log nobody read - while re-seals are still
// checked against the admin record. An empty log that WAS read is a log without the record: refused.
func TestARegistryLogNotReadIsUnreadNotMissing(t *testing.T) {
	f := newRegistryFixture(t)
	reg := f.registry(1, "ops-1", "ops-2")
	raw := rotJSON(t, reg)
	_, to, _ := resealSets(f.rotationFixture)
	reseal := resealFor(to, rotChain)
	resealRaw := rotJSON(t, reseal)
	policy := &ledger.EntitlementPolicyState{AdminKeys: f.policy.AdminKeys, AdminThreshold: 2}
	v, u, err := CommittedBlockViolations(1, [][]byte{raw, resealRaw}, []uint32{0, 0}, &CommittedRecords{Policy: policy})
	if err != nil || len(u) != 1 || !strings.Contains(u[0], "BLS registry (version 1)") || len(v) != 1 ||
		!strings.Contains(v[0], "admin re-seal that was accepted") {
		t.Fatalf("no registry log read: violations %v unread %v %v", v, u, err)
	}
	if v, u, err := CommittedBlockViolations(1, [][]byte{raw}, []uint32{0}, &CommittedRecords{Policy: policy,
		Registry: &ledger.BLSRegistryLog{}}); err != nil || len(v) != 1 || len(u) != 0 {
		t.Fatalf("a read registry log without the record: violations %v unread %v %v", v, u, err)
	}
}
