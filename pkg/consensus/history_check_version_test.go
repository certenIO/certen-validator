package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"

	dbm "github.com/cometbft/cometbft-db"

	"github.com/certen/independant-validator/pkg/kvdb"
	"github.com/certen/independant-validator/pkg/ledger"
)

// legacyWatermarkLedger is the ledger a production node holds after running the v12 binary from before history-check
// versions existed: its committed-operation index covers heights 1-top, and the kinds watermark it wrote - keyed by the
// rules version alone, "abci:kinds_checked_through:v12" - says the chain is checked through top. The raw KV is returned
// so the test reads the keys exactly as they are on disk.
func legacyWatermarkLedger(t testing.TB, top int64) (*ValidatorApp, ledger.KV) {
	t.Helper()
	t.Setenv("CERTEN_ENTITLEMENT_MODE", "")
	kv := kvdb.NewKVAdapter(dbm.NewMemDB())
	store := ledger.NewLedgerStore(kv)
	for h := int64(1); h <= top; h++ {
		if err := store.RecordCommittedBlock(h, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := kv.Set([]byte("abci:kinds_checked_through:v12"), heightBytes(top)); err != nil {
		t.Fatal(err)
	}
	app := NewValidatorApp(store, "certen-fictional-test")
	app.logger = persistQuietLog
	app.latestHeight = top
	return app, kv
}

func heightBytes(h int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(h))
	return b
}

func rawHeight(t *testing.T, kv ledger.KV, key string) int64 {
	t.Helper()
	b, err := kv.Get([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		return 0
	}
	if len(b) != 8 {
		t.Fatalf("%s is %d bytes", key, len(b))
	}
	return int64(binary.BigEndian.Uint64(b))
}

// The defect found live on 2026-10-03: the history check's watermark was keyed only by the rules version. PR #106 added
// checks (an accepted BLS registry, admin re-seal or admin rotation must have its record) without a new rules version,
// and production nodes had already run the earlier v12 binary, which saved "v12 checked through 2861". The new binary
// read that watermark, found nothing above it to check, and never ran the new checks against the live ledger. Here the
// ledger holds that old watermark at the top and a committed code-0 registry with no record: the node must refuse by
// name. With the record present it starts, writes the watermark of the checks it ran, and leaves the old one as it was.
func TestANewHistoryCheckRunsOverHistoryAnOlderBinaryMarkedChecked(t *testing.T) {
	f := newRegistryFixture(t)
	reg := f.registry(1, "ops-1", "ops-2")
	raw := rotJSON(t, reg)
	const top = 3
	hist := &fakeHistory{base: 1,
		blocks: map[int64][][]byte{1: {}, 2: {raw}, 3: {}},
		times:  map[int64]time.Time{1: beforeV9, 2: beforeV9, 3: beforeV9},
		codes:  map[int64][]uint32{1: {}, 2: {0}, 3: {}}}

	missing, kv := legacyWatermarkLedger(t, top)
	err := missing.IndexCommittedHistory(hist)
	if !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) ||
		!strings.Contains(err.Error(), "height 2 tx 0 is a BLS registry (version 1) that was accepted, but the committed registry log holds no record of it") {
		t.Fatalf("a v12 watermark from an older binary hid an accepted registry with no record: %v", err)
	}
	if got := rawHeight(t, kv, "abci:kinds_checked_through:v12"); got != top {
		t.Fatalf("the old watermark was changed to %d", got)
	}

	recorded, kv := legacyWatermarkLedger(t, top)
	if err := recorded.ledgerStore.SaveBLSRegistry(&ledger.BLSRegistryLog{Versions: []ledger.BLSRegistryRecord{
		{Version: 1, Height: 2, ID: reg.RegistryID()}}}); err != nil {
		t.Fatal(err)
	}
	if err := recorded.IndexCommittedHistory(hist); err != nil {
		t.Fatalf("the same history with the registry's record: %v", err)
	}
	// The watermark of this binary's rules and checks (v14 and history-check v4 since rules v14; v13:checks3 before).
	current := fmt.Sprintf("abci:kinds_checked_through:v%d:checks%d", CurrentExecutionRulesVersion, CommittedHistoryCheckVersion)
	if got := rawHeight(t, kv, current); got != top {
		t.Fatalf("the %s watermark is %d after a full check, want %d", current, got, top)
	}
	if got := rawHeight(t, kv, "abci:kinds_checked_through:v12"); got != top {
		t.Fatalf("the old watermark was changed to %d", got)
	}
	// Checked once: a second start reads nothing (a history with no blocks would fail any read).
	if err := recorded.IndexCommittedHistory(&fakeHistory{base: 1}); err != nil {
		t.Fatalf("a chain checked by these checks was read again: %v", err)
	}
}

// historyChecks are the declarations that decide what checkCommittedKinds finds in committed history. Any change to one
// of them is a change to the checks.
var historyChecks = []string{"kindViolation", "kindViolationWith", "CommittedRecords", "committedRecords", "rotationBlockVerdicts",
	"spineGenesisRecorded", "spineExtensionRecorded"}

// historyCheckFingerprints pins the checks each CommittedHistoryCheckVersion names. Version 1 is the checks of the
// binaries before history-check versions, which kept their watermark under the rules version alone.
var historyCheckFingerprints = map[uint64]string{
	2: "f9217e186c5e8bcd4d7e332f3f81a7008f8c1fae85e0b09f5048ca19ae039df2",
	3: "5cb03fe7b01d38fd1185a8fa3e15490b7218f6978227061b6f27adaa8d95a0a2",
	4: "e046ddd43626ef6f956f67426235fb4ca572ae84f839ac7626b746a5bc2e3360",
}

// historyCheckFingerprint hashes historyChecks as code: comments and layout are dropped, so only a change to what the
// checks do moves it.
func historyCheckFingerprint(t *testing.T) string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "committed_operations.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	decls := map[string]ast.Node{}
	for _, d := range file.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			decls[d.Name.Name] = d
		case *ast.GenDecl:
			for _, s := range d.Specs {
				if ts, ok := s.(*ast.TypeSpec); ok {
					decls[ts.Name.Name] = ts
				}
			}
		}
	}
	h := sha256.New()
	for _, name := range historyChecks {
		d, ok := decls[name]
		if !ok {
			t.Fatalf("history check %s is not declared in committed_operations.go: update historyChecks and bump "+
				"CommittedHistoryCheckVersion", name)
		}
		var b bytes.Buffer
		if err := format.Node(&b, fset, d); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(h, "%s\n%s\n", name, strings.Join(strings.Fields(b.String()), " "))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// A watermark is only as good as the checks it names: a binary whose checks differ from the ones a watermark was written
// by must re-check committed history. That holds only if CommittedHistoryCheckVersion moves with the checks, so a change
// to any of them fails here until the version is bumped and the new checks are pinned under it.
func TestTheHistoryCheckVersionNamesItsChecks(t *testing.T) {
	got := historyCheckFingerprint(t)
	want, ok := historyCheckFingerprints[CommittedHistoryCheckVersion]
	if !ok || want != got {
		t.Fatalf("the committed-history checks (%s) are not the ones history-check v%d names (fingerprint %s, pinned %q).\n"+
			"Bump CommittedHistoryCheckVersion in pkg/consensus/committed_operations.go, say what changed in its comment, and "+
			"pin %s under the new version in historyCheckFingerprints, so every node re-checks its history once under the "+
			"new checks.", strings.Join(historyChecks, ", "), CommittedHistoryCheckVersion, got, want, got)
	}
	seen := map[string]uint64{}
	for v, fp := range historyCheckFingerprints {
		if v < 2 || v > CommittedHistoryCheckVersion {
			t.Fatalf("history-check v%d is pinned, outside 2-%d", v, CommittedHistoryCheckVersion)
		}
		if other, dup := seen[fp]; dup {
			t.Fatalf("history-check v%d and v%d pin the same checks", v, other)
		}
		seen[fp] = v
	}
}
