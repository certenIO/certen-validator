package consensus

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Rules v13: the Accumulate validator-set spine as consensus state, judged on the real Kermit spine.

// spineFixture is Kermit's genesis inputs (re-derived offline from the incarnation evidence) and its archive of major
// header records, each as the hex an extension carries.
type spineFixture struct {
	*registryFixture
	inputs  proof.IncarnationInputs
	records []string
}

func newSpineFixture(t *testing.T) *spineFixture {
	t.Helper()
	raw, err := os.ReadFile("../proof/testdata/incarnation/kermit.json")
	if err != nil {
		t.Fatal(err)
	}
	var ev proof.IncarnationEvidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	rep, err := ev.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(rep.Incarnation[:]) != kermitIncarnationHex {
		t.Fatalf("the Kermit evidence re-derives incarnation %x", rep.Incarnation)
	}
	f, err := os.Open("../proof/v2/testdata/archive.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	arch, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	fx := &spineFixture{registryFixture: newRegistryFixture(t), inputs: rep.Inputs}
	if err := json.Unmarshal(arch, &fx.records); err != nil {
		t.Fatal(err)
	}
	// The archive's records are what an extension carries, and they decode as the proof package's archive does.
	if ar, err := proofv2.UnmarshalArchive(arch); err != nil || len(ar.Majors) != len(fx.records) || len(fx.records) < 150 {
		t.Fatalf("archive: %d records, %v", len(fx.records), err)
	}
	return fx
}

// genesisFor is the spine genesis transaction for inputs on chain.
func genesisFor(chain string, in proof.IncarnationInputs) *AccumulateSpineGenesisTx {
	return &AccumulateSpineGenesisTx{Kind: AccumulateSpineGenesisKind, ChainID: chain, MinorBlockIndex: in.GenesisMinorBlockIndex,
		RootChainAnchor: hex.EncodeToString(in.GenesisRootChainAnchor[:]), StateTreeAnchor: hex.EncodeToString(in.GenesisStateTreeAnchor[:]),
		TimeUnix: in.GenesisTimeUnix, NetworkRecord: hex.EncodeToString(in.NetworkRecord), GlobalsRecord: hex.EncodeToString(in.GlobalsRecord)}
}

// genesis is Kermit's spine genesis on the test chain, as bytes.
func (fx *spineFixture) genesis(t testing.TB) []byte {
	return rotJSON(t, genesisFor(rotChain, fx.inputs))
}

// extend carries major blocks first..last (1-based, inclusive) of the archive.
func (fx *spineFixture) extend(t testing.TB, first, last int) []byte {
	return rotJSON(t, &AccumulateSpineExtendTx{Kind: AccumulateSpineExtendKind, ChainID: rotChain, First: uint64(first),
		Records: fx.records[first-1 : last]})
}

// incarnationB is another incarnation's genesis: Kermit's inputs a second later, and the incarnation they compute.
func (fx *spineFixture) incarnationB(t testing.TB) (proof.IncarnationInputs, string) {
	in := fx.inputs
	in.GenesisTimeUnix++
	inc, err := proof.ComputeIncarnation(in)
	if err != nil {
		t.Fatal(err)
	}
	return in, hex.EncodeToString(inc[:])
}

// registryUnder is registry version under incarnation (hex), signed by ops-1 and ops-2.
func (fx *spineFixture) registryUnder(t testing.TB, version uint64, incarnation string) []byte {
	tx := fx.registry(version)
	tx.AccumulateIncarnation = "0x" + incarnation
	fx.sign(tx, "ops-1", "ops-2")
	return rotJSON(t, tx)
}

// spineApp is a node whose block 1 committed the Kermit registry: from height 2 a spine genesis can be judged.
func (fx *spineFixture) spineApp(t *testing.T) (*ValidatorApp, *ledger.LedgerStore) {
	t.Helper()
	app, store := rotationApp(t, fx.rotationFixture)
	if r := finalize(t, app, 1, abcitypes.CommitInfo{}, rotJSON(t, fx.registry(1, "ops-1", "ops-2"))); r.TxResults[0].Code != 0 {
		t.Fatalf("registry: %s", r.TxResults[0].Log)
	}
	commit(t, app)
	return app, store
}

func commit(t *testing.T, app *ValidatorApp) {
	t.Helper()
	if _, err := app.Commit(context.Background(), &abcitypes.RequestCommit{}); err != nil {
		t.Fatal(err)
	}
}

func spineLog(t *testing.T, store *ledger.LedgerStore) *ledger.AccumulateSpineLog {
	t.Helper()
	l, err := store.LoadAccumulateSpine()
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func wantCode(t *testing.T, what string, r *abcitypes.ExecTxResult, code uint32, logPart string) {
	t.Helper()
	if r.Code != code || !strings.Contains(r.Log, logPart) {
		t.Fatalf("%s: code %d %q, want %d containing %q", what, r.Code, r.Log, code, logPart)
	}
}

// The wire: ids bind every field, malformed bytes of a kind are the kind (refused by shape), and neither kind is the
// other or a ValidatorBlock.
func TestTheSpineTransactionsOnTheWire(t *testing.T) {
	fx := newSpineFixture(t)
	g := genesisFor(rotChain, fx.inputs)
	back, ok := DecodeAccumulateSpineGenesis(rotJSON(t, g))
	if !ok || back.GenesisID() != g.GenesisID() || back.CheckShape() != nil {
		t.Fatal("the genesis does not survive the wire")
	}
	for name, mutate := range map[string]func(*AccumulateSpineGenesisTx){
		"chain": func(x *AccumulateSpineGenesisTx) { x.ChainID = "other" },
		"time":  func(x *AccumulateSpineGenesisTx) { x.TimeUnix++ },
		"index": func(x *AccumulateSpineGenesisTx) { x.MinorBlockIndex++ },
		"root":  func(x *AccumulateSpineGenesisTx) { x.RootChainAnchor = strings.Repeat("ab", 32) },
	} {
		c := *g
		mutate(&c)
		if c.GenesisID() == g.GenesisID() {
			t.Fatalf("the genesis id does not bind its %s", name)
		}
	}
	e := &AccumulateSpineExtendTx{Kind: AccumulateSpineExtendKind, ChainID: rotChain, First: 1, Records: fx.records[:3]}
	e2 := *e
	e2.First = 2
	e3 := *e
	e3.Records = fx.records[:2]
	if e.ExtensionID() == e2.ExtensionID() || e.ExtensionID() == e3.ExtensionID() || !strings.HasPrefix(e.ExtensionID(), "accumulate-spine-extend:") {
		t.Fatal("the extension id does not bind its first block and records")
	}
	if _, ok := DecodeAccumulateSpineExtend(rotJSON(t, g)); ok {
		t.Fatal("a genesis decoded as an extension")
	}
	if x, ok := DecodeAccumulateSpineExtend([]byte(fmt.Sprintf(`{"kind":%q,"first":"one"}`, AccumulateSpineExtendKind))); !ok || x.CheckShape() == nil {
		t.Fatal("malformed bytes of the extension kind are not the kind, refused")
	}
	if x, ok := DecodeAccumulateSpineGenesis([]byte(fmt.Sprintf(`{"kind":%q,"time_unix":"x"}`, AccumulateSpineGenesisKind))); !ok || x.CheckShape() == nil {
		t.Fatal("malformed bytes of the genesis kind are not the kind, refused")
	}
	if isValidatorBlockTx(fx.genesis(t)) || isValidatorBlockTx(fx.extend(t, 1, 2)) {
		t.Fatal("a spine transaction is read back as a ValidatorBlock")
	}
	// The largest Kermit record is well within one record's bound, and a full extension within the extension's.
	total, largest := 0, 0
	for _, r := range fx.records[:maxSpineExtensionRecords] {
		total += len(r) / 2
		largest = max(largest, len(r)/2)
	}
	if largest > maxSpineRecordBytes || total > maxSpineExtensionBytes {
		t.Fatalf("Kermit's records: largest %d bytes, %d in 100", largest, total)
	}
	t.Logf("Kermit major records: largest %d bytes, %d bytes in %d", largest, total, maxSpineExtensionRecords)
}

// The mempool filters on shape: hex, record decoding and size. Proposals carrying spine transactions are not refused.
func TestCheckTxFiltersSpineTransactions(t *testing.T) {
	fx := newSpineFixture(t)
	app, _ := rotationApp(t, fx.rotationFixture)
	upper := genesisFor(rotChain, fx.inputs)
	upper.RootChainAnchor = strings.ToUpper(upper.RootChainAnchor)
	short := genesisFor(rotChain, fx.inputs)
	short.StateTreeAnchor = short.StateTreeAnchor[:62]
	tooMany := &AccumulateSpineExtendTx{Kind: AccumulateSpineExtendKind, ChainID: rotChain, First: 1, Records: fx.records[:maxSpineExtensionRecords+1]}
	notARecord := &AccumulateSpineExtendTx{Kind: AccumulateSpineExtendKind, ChainID: rotChain, First: 1, Records: []string{"00ff00ff"}}
	notHex := &AccumulateSpineExtendTx{Kind: AccumulateSpineExtendKind, ChainID: rotChain, First: 1, Records: []string{"zz"}}
	zeroFirst := &AccumulateSpineExtendTx{Kind: AccumulateSpineExtendKind, ChainID: rotChain, First: 0, Records: fx.records[:1]}
	for name, c := range map[string]struct {
		tx   []byte
		code uint32
	}{
		"genesis":                   {fx.genesis(t), 0},
		"extension":                 {fx.extend(t, 1, maxSpineExtensionRecords), 0},
		"genesis, uppercase hex":    {rotJSON(t, upper), codeSpineGenesisRefused},
		"genesis, short anchor":     {rotJSON(t, short), codeSpineGenesisRefused},
		"extension, 101 records":    {rotJSON(t, tooMany), codeSpineExtendRefused},
		"extension, not a record":   {rotJSON(t, notARecord), codeSpineExtendRefused},
		"extension, not hex":        {rotJSON(t, notHex), codeSpineExtendRefused},
		"extension, first block 0":  {rotJSON(t, zeroFirst), codeSpineExtendRefused},
		"extension, no records":     {[]byte(fmt.Sprintf(`{"kind":%q,"chain_id":%q,"first":1}`, AccumulateSpineExtendKind, rotChain)), codeSpineExtendRefused},
		"malformed, the kind (gen)": {[]byte(fmt.Sprintf(`{"kind":%q,"time_unix":"x"}`, AccumulateSpineGenesisKind)), codeSpineGenesisRefused},
	} {
		res, err := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: c.tx})
		if err != nil || res.Code != c.code {
			t.Errorf("%s: (%+v, %v), want code %d", name, res, err, c.code)
		}
	}
	pp, err := app.ProcessProposal(context.Background(), &abcitypes.RequestProcessProposal{Txs: [][]byte{fx.genesis(t), fx.extend(t, 1, 3)}})
	if err != nil || pp.Status != abcitypes.ResponseProcessProposal_ACCEPT {
		t.Fatalf("a proposal carrying spine transactions: (%v, %v)", pp, err)
	}
}

// A genesis needs a registry in force, this chain, and facts that recompute the registry's incarnation; once the spine
// is the registry's incarnation no other genesis is accepted, but the same one again in its own block is the no-op.
func TestASpineGenesisNeedsTheRegistrysIncarnation(t *testing.T) {
	fx := newSpineFixture(t)

	// No registry in force.
	bare, _ := rotationApp(t, fx.rotationFixture)
	wantCode(t, "no registry", finalize(t, bare, 1, abcitypes.CommitInfo{}, fx.genesis(t)).TxResults[0],
		codeSpineGenesisRefused, "no BLS registry is in force")
	// The registry accepted in the same block is not in force for it.
	r := finalize(t, bare, 1, abcitypes.CommitInfo{}, rotJSON(t, fx.registry(1, "ops-1", "ops-2")), fx.genesis(t))
	wantCode(t, "registry in the same block", r.TxResults[1], codeSpineGenesisRefused, "no BLS registry is in force")

	app, store := fx.spineApp(t)
	other := genesisFor("another-chain", fx.inputs)
	wantCode(t, "another chain", finalize(t, app, 2, abcitypes.CommitInfo{}, rotJSON(t, other)).TxResults[0],
		codeSpineGenesisRefused, `is for chain "another-chain"`)
	inB, _ := fx.incarnationB(t)
	wantCode(t, "another incarnation", finalize(t, app, 2, abcitypes.CommitInfo{}, rotJSON(t, genesisFor(rotChain, inB))).TxResults[0],
		codeSpineGenesisRefused, "not the registry's")
	if l := spineLog(t, store); l.Genesis != nil {
		t.Fatalf("a refused genesis was recorded: %+v", l.Genesis)
	}

	// Accepted, and the same genesis again in its block (other bytes) is the no-op: the same app hash as alone.
	g := fx.genesis(t)
	alone := finalize(t, app, 2, abcitypes.CommitInfo{}, g)
	twice := finalize(t, app, 2, abcitypes.CommitInfo{}, g, append(append([]byte(nil), g...), ' '))
	if twice.TxResults[0].Code != 0 || twice.TxResults[1].Code != 0 || !bytes.Equal(alone.AppHash, twice.AppHash) {
		t.Fatalf("the same genesis twice in its block: %d %d, app hash changed %v", twice.TxResults[0].Code,
			twice.TxResults[1].Code, !bytes.Equal(alone.AppHash, twice.AppHash))
	}
	commit(t, app)
	l := spineLog(t, store)
	if l.Genesis == nil || l.Genesis.Height != 2 || l.Genesis.Incarnation != "0x"+kermitIncarnationHex || len(l.Sets) != 1 ||
		l.Genesis.SetHash != proofv2.SpineSetHash(fx.inputs.NetworkRecord, fx.inputs.GlobalsRecord) || len(l.Checkpoints) != 0 {
		t.Fatalf("the recorded spine: %+v", l)
	}
	if app.committedRulesVersion() != executionRulesV13 {
		t.Fatalf("a spine verdict left the state stamped v%d", app.committedRulesVersion())
	}
	st, err := store.LoadABCIState()
	if err != nil || st.ExecutionRulesVersion != executionRulesV13 {
		t.Fatalf("committed state stamped (%+v, %v); want v13", st, err)
	}

	// Later, the same genesis again, and any other: the spine is the registry's incarnation.
	wantCode(t, "the genesis replayed", finalize(t, app, 3, abcitypes.CommitInfo{}, append(append([]byte(nil), g...), ' ', ' ')).TxResults[0],
		codeSpineGenesisRefused, "replaced only when the registry moves")
	wantCode(t, "another genesis", finalize(t, app, 3, abcitypes.CommitInfo{}, rotJSON(t, genesisFor(rotChain, inB))).TxResults[0],
		codeSpineGenesisRefused, "replaced only when the registry moves")
}

// An extension carries the next major blocks in sequence after the last checkpoint and every record verifies; one the
// chain already verified is stale (its own code); extended in chunks, the spine ends where one walk ends.
func TestASpineExtensionCarriesTheNextVerifiedMajorBlocks(t *testing.T) {
	fx := newSpineFixture(t)
	app, store := fx.spineApp(t)
	wantCode(t, "no genesis", finalize(t, app, 2, abcitypes.CommitInfo{}, fx.extend(t, 1, 5)).TxResults[0],
		codeSpineExtendRefused, "no spine genesis")
	finalize(t, app, 2, abcitypes.CommitInfo{}, fx.genesis(t))
	commit(t, app)

	wantCode(t, "a gap", finalize(t, app, 3, abcitypes.CommitInfo{}, fx.extend(t, 2, 5)).TxResults[0],
		codeSpineExtendRefused, "one cannot skip major blocks")
	// Records of other major blocks under first = 1: they do not verify in sequence.
	wrong := rotJSON(t, &AccumulateSpineExtendTx{Kind: AccumulateSpineExtendKind, ChainID: rotChain, First: 1, Records: fx.records[4:8]})
	wantCode(t, "records out of sequence", finalize(t, app, 3, abcitypes.CommitInfo{}, wrong).TxResults[0],
		codeSpineExtendRefused, "major block 1")
	// A tampered record: major block 3's anchor names another root chain anchor, under the same signatures.
	b, _ := hex.DecodeString(fx.records[2])
	rec := new(api.MajorHeaderRecord)
	if err := rec.UnmarshalBinary(b); err != nil {
		t.Fatal(err)
	}
	rec.Anchor.Message.(*messaging.TransactionMessage).Transaction.Body.(*protocol.DirectoryAnchor).RootChainAnchor[0] ^= 1
	nb, err := rec.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]string(nil), fx.records[:5]...)
	tampered[2] = hex.EncodeToString(nb)
	wantCode(t, "a tampered record", finalize(t, app, 3, abcitypes.CommitInfo{}, rotJSON(t, &AccumulateSpineExtendTx{
		Kind: AccumulateSpineExtendKind, ChainID: rotChain, First: 1, Records: tampered})).TxResults[0],
		codeSpineExtendRefused, "major block 3")
	other := &AccumulateSpineExtendTx{Kind: AccumulateSpineExtendKind, ChainID: "another-chain", First: 1, Records: fx.records[:3]}
	wantCode(t, "another chain", finalize(t, app, 3, abcitypes.CommitInfo{}, rotJSON(t, other)).TxResults[0],
		codeSpineExtendRefused, `is for chain "another-chain"`)
	if l := spineLog(t, store); len(l.Checkpoints) != 0 {
		t.Fatalf("refused extensions recorded %d checkpoints", len(l.Checkpoints))
	}

	// 1-60 then, in the same block, 61-100, and 1-60 again (the no-op).
	r := finalize(t, app, 3, abcitypes.CommitInfo{}, fx.extend(t, 1, 60), fx.extend(t, 61, 100), fx.extend(t, 1, 60))
	for i, x := range r.TxResults {
		if x.Code != 0 {
			t.Fatalf("tx %d: %d %s", i, x.Code, x.Log)
		}
	}
	commit(t, app)
	// Later: stale and overlapping extensions, by name and code.
	wantCode(t, "stale", finalize(t, app, 4, abcitypes.CommitInfo{}, fx.extend(t, 1, 60)).TxResults[0],
		codeSpineExtendStale, "verified through major block 100")
	wantCode(t, "overlapping", finalize(t, app, 4, abcitypes.CommitInfo{}, fx.extend(t, 90, 120)).TxResults[0],
		codeSpineExtendStale, "the next extension starts at 101")
	// The rest of the archive, one full extension per block (block 4 executed again, as a new execution of it).
	n := len(fx.records)
	for h, first := int64(4), 101; first <= n; h, first = h+1, first+maxSpineExtensionRecords {
		last := min(first+maxSpineExtensionRecords-1, n)
		if x := finalize(t, app, h, abcitypes.CommitInfo{}, fx.extend(t, first, last)).TxResults[0]; x.Code != 0 {
			t.Fatalf("%d-%d: %s", first, last, x.Log)
		}
		commit(t, app)
	}

	// The chain's spine is the one a single walk from genesis over the archive reaches.
	l := spineLog(t, store)
	if len(l.Checkpoints) != n {
		t.Fatalf("the chain verified %d major blocks of %d", len(l.Checkpoints), n)
	}
	ar, err := proofv2.UnmarshalArchive(func() []byte { b, _ := json.Marshal(fx.records); return b }())
	if err != nil {
		t.Fatal(err)
	}
	walk := &ledger.AccumulateSpineLog{Genesis: l.Genesis, Sets: l.Sets[:1]}
	cps, _, err := proofv2.ExtendSpine(walk, ar.Majors, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := range cps {
		got := l.Checkpoints[i]
		got.Height = 1
		if got != cps[i] {
			t.Fatalf("checkpoint %d: %+v, the walk's %+v", i+1, l.Checkpoints[i], cps[i])
		}
	}
	if sp, err := proofv2.SpineAt(l, uint64(n)); err != nil || sp.NextMajor != uint64(n)+1 {
		t.Fatalf("the spine restored at its last checkpoint: (%v, %v)", sp, err)
	}
}

// A block of spine transactions - refused and accepted, duplicates, a genesis and extensions after it - is decided
// identically however often it is executed: the same codes, the same logs, the same app hash, and the log written once.
// A second, independent node reaches the same app hash.
func TestABlockOfSpineTransactionsIsDeterministic(t *testing.T) {
	fx := newSpineFixture(t)
	g := fx.genesis(t)
	txs := [][]byte{fx.extend(t, 1, 10), g, fx.extend(t, 2, 10), fx.extend(t, 1, 10), fx.extend(t, 1, 10 /* again */),
		append(append([]byte(nil), g...), ' '), fx.extend(t, 5, 12), fx.extend(t, 11, 30)}
	want := []uint32{codeSpineExtendRefused, 0, codeSpineExtendRefused, 0, 0, 0, codeSpineExtendStale, 0}
	app, store := fx.spineApp(t)
	first := finalize(t, app, 2, abcitypes.CommitInfo{}, txs...)
	for i, r := range first.TxResults {
		if r.Code != want[i] {
			t.Fatalf("tx %d: %d %s, want %d", i, r.Code, r.Log, want[i])
		}
	}
	written := spineLog(t, store)
	for run := 0; run < 3; run++ {
		again := finalize(t, app, 2, abcitypes.CommitInfo{}, txs...)
		if !bytes.Equal(again.AppHash, first.AppHash) {
			t.Fatalf("run %d changed the app hash", run)
		}
		for i := range txs {
			if again.TxResults[i].Code != first.TxResults[i].Code || again.TxResults[i].Log != first.TxResults[i].Log {
				t.Fatalf("run %d tx %d: %d %q, first %d %q", run, i, again.TxResults[i].Code, again.TxResults[i].Log,
					first.TxResults[i].Code, first.TxResults[i].Log)
			}
		}
		if got := spineLog(t, store); len(got.Checkpoints) != 30 || len(got.Sets) != len(written.Sets) || *got.Genesis != *written.Genesis {
			t.Fatalf("run %d rewrote the log: %d checkpoints", run, len(got.Checkpoints))
		}
	}
	// The view the next transaction of the block is judged against, and what the intent rule reads mid-block.
	view, err := app.accumulateSpineAt(2)
	if err != nil || len(view.Checkpoints) != 30 || view.Genesis.Height != 2 {
		t.Fatalf("the spine at height 2 mid-block: (%v, %v)", view, err)
	}
	if _, err := app.accumulateSpineAt(1); !errors.Is(err, ErrSpineNotRegistryIncarnation) {
		t.Fatalf("the spine below height 1 (none): %v", err)
	}
	other, _ := fx.spineApp(t)
	if h := finalize(t, other, 2, abcitypes.CommitInfo{}, txs...).AppHash; !bytes.Equal(h, first.AppHash) {
		t.Fatal("two nodes disagree")
	}
	// The no-ops add nothing to the app hash: the accepted transactions alone hash the same.
	third, _ := fx.spineApp(t)
	if h := finalize(t, third, 2, abcitypes.CommitInfo{}, g, fx.extend(t, 1, 10), fx.extend(t, 11, 30)).AppHash; !bytes.Equal(h, first.AppHash) {
		t.Fatal("the no-ops changed the app hash")
	}
}

// The spine follows the registry's incarnation. Registry v1 under A; genesis A; an extension. The admins move the
// registry to incarnation B: the A spine is no longer extended, genesis B replaces the log (A's kept as Previous), and
// genesis A is then refused. Re-executing the replacing block decides it as before, from the log it replaced.
func TestTheSpineFollowsTheRegistrysIncarnation(t *testing.T) {
	fx := newSpineFixture(t)
	app, store := fx.spineApp(t) // registry v1, incarnation A (Kermit), at height 1
	finalize(t, app, 2, abcitypes.CommitInfo{}, fx.genesis(t), fx.extend(t, 1, 20))
	commit(t, app)
	inB, incB := fx.incarnationB(t)
	// In the registry's own block, A is still in force: the A spine is still extended.
	r3 := finalize(t, app, 3, abcitypes.CommitInfo{}, fx.registryUnder(t, 2, incB), fx.extend(t, 21, 25))
	if r3.TxResults[0].Code != 0 || r3.TxResults[1].Code != 0 {
		t.Fatalf("registry v2 under B, then an A extension in its block: %s / %s", r3.TxResults[0].Log, r3.TxResults[1].Log)
	}
	commit(t, app)
	if _, err := app.accumulateSpineAt(4); !errors.Is(err, ErrSpineNotRegistryIncarnation) {
		t.Fatalf("the A spine under registry B: %v", err)
	}

	genB := rotJSON(t, genesisFor(rotChain, inB))
	block4 := [][]byte{fx.extend(t, 26, 30), genB, fx.genesis(t)}
	r := finalize(t, app, 4, abcitypes.CommitInfo{}, block4...)
	wantCode(t, "an extension of the A spine", r.TxResults[0], codeSpineExtendRefused, "the spine is not the registry's incarnation")
	wantCode(t, "genesis B", r.TxResults[1], 0, "")
	wantCode(t, "genesis A after B", r.TxResults[2], codeSpineGenesisRefused, "replaced only when the registry moves")
	l := spineLog(t, store)
	if l.Genesis.Incarnation != "0x"+incB || l.Genesis.Height != 4 || len(l.Checkpoints) != 0 || len(l.Sets) != 1 ||
		l.Previous == nil || l.Previous.Genesis.Incarnation != "0x"+kermitIncarnationHex || len(l.Previous.Checkpoints) != 25 {
		t.Fatalf("the replaced log: %+v", l)
	}
	// Executed again, from the log it replaced: the same verdicts, and the log as the first execution wrote it.
	again := finalize(t, app, 4, abcitypes.CommitInfo{}, block4...)
	for i := range block4 {
		if again.TxResults[i].Code != r.TxResults[i].Code || again.TxResults[i].Log != r.TxResults[i].Log {
			t.Fatalf("re-executed tx %d: %d %q, first %d %q", i, again.TxResults[i].Code, again.TxResults[i].Log,
				r.TxResults[i].Code, r.TxResults[i].Log)
		}
	}
	if !bytes.Equal(again.AppHash, r.AppHash) {
		t.Fatal("re-executing the replacing block changed the app hash")
	}
	if got := spineLog(t, store); got.Genesis.Height != 4 || len(got.Previous.Checkpoints) != 25 || got.Previous.Previous != nil {
		t.Fatalf("re-execution rewrote the log: %+v", got)
	}
	commit(t, app)
	if view, err := app.accumulateSpineAt(5); err != nil || view.Genesis.Incarnation != "0x"+incB {
		t.Fatalf("the spine at height 5: (%v, %v)", view, err)
	}
	// Later: genesis A refused (the registry is B), genesis B again refused (the spine is the registry's).
	wantCode(t, "genesis A later", finalize(t, app, 5, abcitypes.CommitInfo{}, fx.genesis(t)).TxResults[0],
		codeSpineGenesisRefused, "replaced only when the registry moves")
	wantCode(t, "genesis B again", finalize(t, app, 5, abcitypes.CommitInfo{}, append(append([]byte(nil), genB...), ' ')).TxResults[0],
		codeSpineGenesisRefused, "replaced only when the registry moves")

	// History: every acceptance of this chain is found in its record, the replaced one through Previous.
	records := &CommittedRecords{Spine: spineLog(t, store)}
	for _, c := range []struct {
		height int64
		tx     []byte
	}{{2, fx.genesis(t)}, {2, fx.extend(t, 1, 20)}, {3, fx.extend(t, 21, 25)}, {4, genB}} {
		if v, _, err := CommittedBlockViolations(c.height, [][]byte{c.tx}, []uint32{0}, records); err != nil || len(v) != 0 {
			t.Fatalf("height %d: %v %v", c.height, v, err)
		}
	}
}

// History: a committed spine-kind transaction v12 decided as a ValidatorBlock is history v13 does not reproduce, and the
// node refuses to start on it; one decided as a spine transaction makes the state v13's; an accepted one must have its
// record.
func TestCommittedSpineHistoryIsChecked(t *testing.T) {
	fx := newSpineFixture(t)
	g, e := fx.genesis(t), fx.extend(t, 1, 4)
	hist := func(tx []byte, code uint32) *fakeHistory {
		return &fakeHistory{base: 1, blocks: map[int64][][]byte{1: {tx}}, times: map[int64]time.Time{1: beforeV9},
			codes: map[int64][]uint32{1: {code}}}
	}
	for _, c := range []struct {
		name string
		tx   []byte
		code uint32
	}{{"genesis, code 2", g, 2}, {"genesis, code 14", g, codeSpineExtendRefused}, {"genesis accepted, unrecorded", g, 0},
		{"extension, code 1", e, 1}, {"extension, code 13", e, codeSpineGenesisRefused}, {"extension accepted, unrecorded", e, 0}} {
		if err := historyApp(t, 1).IndexCommittedHistory(hist(c.tx, c.code)); !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	// Already indexed by the v12 binary that committed it: still checked.
	indexed := historyApp(t, 1)
	if err := indexed.ledgerStore.RecordCommittedBlock(1, nil); err != nil {
		t.Fatal(err)
	}
	if err := indexed.IndexCommittedHistory(hist(g, 2)); !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) {
		t.Fatalf("an indexed chain with a spine genesis decided as a ValidatorBlock: %v", err)
	}
	for _, c := range []struct {
		tx   []byte
		code uint32
	}{{g, codeSpineGenesisRefused}, {e, codeSpineExtendRefused}, {e, codeSpineExtendStale}} {
		app := historyApp(t, 1)
		if err := app.IndexCommittedHistory(hist(c.tx, c.code)); err != nil {
			t.Fatalf("refused by v13 with code %d: %v", c.code, err)
		}
		if app.committedRulesVersion() != executionRulesV13 {
			t.Fatalf("a committed spine verdict left the state stamped v%d", app.committedRulesVersion())
		}
	}
	// Accepted and recorded.
	accepted := historyApp(t, 1)
	in, _ := genesisFor(rotChain, fx.inputs).Inputs()
	inc, _ := proof.ComputeIncarnation(in)
	gen, set, err := proofv2.AcceptSpineGenesis(in, inc, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := accepted.ledgerStore.SaveAccumulateSpine(&ledger.AccumulateSpineLog{Genesis: gen, Sets: []ledger.AccumulateSpineSet{set}}); err != nil {
		t.Fatal(err)
	}
	if err := accepted.IndexCommittedHistory(hist(g, 0)); err != nil {
		t.Fatalf("a genesis accepted and recorded: %v", err)
	}
	// Records from a node before v13 (no spine log): an accepted spine transaction is a violation, never unread.
	v, u, err := CommittedBlockViolations(1, [][]byte{g}, []uint32{0}, &CommittedRecords{Policy: fx.policy})
	if err != nil || len(v) != 1 || len(u) != 0 {
		t.Fatalf("an accepted genesis against pre-v13 records: %v %v %v", v, u, err)
	}
}

// /certen/accumulate_spine answers the committed spine log.
func TestTheSpineQuery(t *testing.T) {
	fx := newSpineFixture(t)
	app, _ := fx.spineApp(t)
	finalize(t, app, 2, abcitypes.CommitInfo{}, fx.genesis(t), fx.extend(t, 1, 7))
	commit(t, app)
	res, err := app.Query(context.Background(), &abcitypes.RequestQuery{Path: "/certen/accumulate_spine"})
	if err != nil || res.Code != 0 {
		t.Fatalf("query: (%+v, %v)", res, err)
	}
	var l ledger.AccumulateSpineLog
	if err := json.Unmarshal(res.Value, &l); err != nil || l.Genesis == nil || len(l.Checkpoints) != 7 || res.Height != 2 {
		t.Fatalf("answered %+v (%v)", l, err)
	}
}

// A crafted record can make Accumulate's decoder, or the spine's verification, dereference nil. In CheckTx or
// FinalizeBlock that panic would stop every node on one transaction; instead the transaction is refused by name, the
// same way on every node. The crafted records here are real Kermit records with one bit flipped, found by trying each.
func TestAMalformedRecordIsRefusedNotAPanic(t *testing.T) {
	fx := newSpineFixture(t)
	b, _ := hex.DecodeString(fx.records[2])
	panics := func(f func()) (p bool) {
		defer func() { p = recover() != nil }()
		f()
		return false
	}
	var decodePanic, verifyPanic []byte
	for i := 0; i < len(b) && (decodePanic == nil || verifyPanic == nil); i++ {
		c := append([]byte(nil), b...)
		c[i] ^= 1
		r := new(api.MajorHeaderRecord)
		var err error
		if panics(func() { err = r.UnmarshalBinary(c) }) {
			if decodePanic == nil {
				decodePanic = c
			}
			continue
		}
		if err != nil || verifyPanic != nil {
			continue
		}
		in := fx.inputs
		inc, _ := proof.ComputeIncarnation(in)
		gen, set, _ := proofv2.AcceptSpineGenesis(in, inc, 1)
		l := &ledger.AccumulateSpineLog{Genesis: gen, Sets: []ledger.AccumulateSpineSet{set}}
		recs := make([]*api.MajorHeaderRecord, 3)
		for j := range recs {
			recs[j] = new(api.MajorHeaderRecord)
			rb, _ := hex.DecodeString(fx.records[j])
			if err := recs[j].UnmarshalBinary(rb); err != nil {
				t.Fatal(err)
			}
		}
		recs[2] = r
		if panics(func() { _, _, _ = proofv2.ExtendSpine(l, recs, 1) }) {
			verifyPanic = c
		}
	}
	if decodePanic == nil || verifyPanic == nil {
		t.Fatalf("no bit flip of Kermit's major block 3 panics the decoder (%v) or the verification (%v): the guard is "+
			"untested here", decodePanic != nil, verifyPanic != nil)
	}
	with := func(rec []byte) []byte {
		recs := append([]string(nil), fx.records[:3]...)
		recs[2] = hex.EncodeToString(rec)
		return rotJSON(t, &AccumulateSpineExtendTx{Kind: AccumulateSpineExtendKind, ChainID: rotChain, First: 1, Records: recs})
	}
	app, _ := fx.spineApp(t)
	finalize(t, app, 2, abcitypes.CommitInfo{}, fx.genesis(t))
	commit(t, app)
	res, err := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: with(decodePanic)})
	if err != nil || res.Code != codeSpineExtendRefused || !strings.Contains(res.Log, "malformed input") {
		t.Fatalf("CheckTx on a record that panics the decoder: (%+v, %v)", res, err)
	}
	r := finalize(t, app, 3, abcitypes.CommitInfo{}, with(decodePanic), with(verifyPanic), fx.extend(t, 1, 3))
	wantCode(t, "a record that panics the decoder", r.TxResults[0], codeSpineExtendRefused, "malformed input")
	wantCode(t, "a record that panics the verification", r.TxResults[1], codeSpineExtendRefused, "malformed input")
	wantCode(t, "the real records after them", r.TxResults[2], 0, "")
}
