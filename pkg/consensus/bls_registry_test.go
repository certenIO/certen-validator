package consensus

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/ledger"
)

// The live CERTEN validators' EVM addresses (RB3 post-rotation preflight, all three chains), in validator order.
var liveValidatorAddresses = []string{
	"0xd4A3dBbAE0C04D4307c5E00A5E05b66AcC289f5D", "0x5555afA8Ff8048BddAAC1554AFd790c9bf7ec6E0",
	"0x6ACaa68417F5ad5d4a02D9d3d72E291efFcDf30A", "0x16aB06F3634218a8f1F3B01dCdd32DDFbdc8a69D",
	"0xf150Ff923E29F797b4598b89bD7D02002D00Db3a", "0x70A6A81bb5E3B63B1929301239DE1F5c63Ec4F3a",
	"0xee2EfA29989Fe6E53572087680c661EC29e045Fe",
}

type registryFixture struct {
	*rotationFixture
	keys []*bls.PrivateKey
}

func newRegistryFixture(t testing.TB) *registryFixture {
	t.Helper()
	f := &registryFixture{rotationFixture: newRotationFixture()}
	for i := range liveValidatorAddresses {
		seed := make([]byte, 32)
		seed[0], seed[31] = 0xB1, byte(i+1)
		sk, _, err := bls.GenerateKeyPairFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		f.keys = append(f.keys, sk)
	}
	return f
}

// registry builds a registry of every member at version, each proving possession, signed by the named admins.
func (f *registryFixture) registry(version uint64, admins ...string) *BLSRegistryTx {
	tx := &BLSRegistryTx{Kind: BLSRegistryKind, ChainID: rotChain, Version: version,
		ThresholdNumerator: 2, ThresholdDenominator: 3, AccumulateIncarnation: "0x" + kermitIncarnationHex}
	for i, sk := range f.keys {
		m := ledger.BLSRegistryMember{ValidatorID: fmt.Sprintf("validator-%d", i+1), EVMAddress: liveValidatorAddresses[i],
			BLSPubKey: sk.PublicKey().Hex(), Power: 100}
		tx.Members = append(tx.Members, BLSRegistryEntry{BLSRegistryMember: m, Possession: SignPossession(sk, rotChain, m)})
	}
	f.sign(tx, admins...)
	return tx
}

func (f *registryFixture) sign(tx *BLSRegistryTx, admins ...string) {
	tx.Signatures = nil
	for _, id := range admins {
		tx.Signatures = append(tx.Signatures, PolicySignature{KeyID: id,
			Signature: hex.EncodeToString(ed25519.Sign(f.admins[id], tx.SigningBytes()))})
	}
}

// The CERTEN set root the registry records is the anchor contract's: for the live validators it is the root the
// live V8.1 anchors hold on all three chains (BLS keys are not part of it, so the 2026-09-26 key rotation left it).
func TestTheRegistrysSetRootIsTheLiveAnchorsRoot(t *testing.T) {
	f := newRegistryFixture(t)
	rec, err := VerifyBLSRegistry(f.registry(1, "ops-1", "ops-2"), rotChain, f.policy, &ledger.BLSRegistryLog{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if want := "0xa85a6911183f5085dedba666ab04b370550d8e0f1cd6b39dc0d716da7aa174e8"; rec.CertenSetRoot != want {
		t.Fatalf("registry set root %s, the live anchors' is %s", rec.CertenSetRoot, want)
	}
	if rec.AccumulateIncarnation != "0x"+kermitIncarnationHex || len(rec.Members) != 7 || rec.Members[0].ValidatorID != "validator-1" {
		t.Fatalf("recorded %+v", rec)
	}
}

func TestARegistryNeedsEverythingItClaims(t *testing.T) {
	f := newRegistryFixture(t)
	empty := &ledger.BLSRegistryLog{}
	if _, err := VerifyBLSRegistry(f.registry(1, "ops-1", "ops-2"), rotChain, f.policy, empty, 10); err != nil {
		t.Fatalf("a well-formed registry: %v", err)
	}
	other := newRegistryFixture(t)
	other.keys[0], _, _ = bls.GenerateKeyPairFromSeed(make([]byte, 32))

	refused := map[string]func() *BLSRegistryTx{
		"one admin of two": func() *BLSRegistryTx { return f.registry(1, "ops-1") },
		"another chain": func() *BLSRegistryTx {
			r := f.registry(1)
			r.ChainID = "other-chain"
			f.sign(r, "ops-1", "ops-2")
			return r
		},
		"a skipped version": func() *BLSRegistryTx { return f.registry(2, "ops-1", "ops-2") },
		"no members":        func() *BLSRegistryTx { r := f.registry(1); r.Members = nil; f.sign(r, "ops-1", "ops-2"); return r },
		"zero power": func() *BLSRegistryTx {
			r := f.registry(1)
			r.Members[3].Power = 0
			f.sign(r, "ops-1", "ops-2")
			return r
		},
		"threshold above one": func() *BLSRegistryTx {
			r := f.registry(1)
			r.ThresholdNumerator = 4
			f.sign(r, "ops-1", "ops-2")
			return r
		},
		"no incarnation": func() *BLSRegistryTx {
			r := f.registry(1)
			r.AccumulateIncarnation = ""
			f.sign(r, "ops-1", "ops-2")
			return r
		},
		"a zero address": func() *BLSRegistryTx {
			r := f.registry(1)
			r.Members[2].EVMAddress = "0x0000000000000000000000000000000000000000"
			f.sign(r, "ops-1", "ops-2")
			return r
		},
		"a repeated address": func() *BLSRegistryTx {
			r := f.registry(1)
			r.Members[2].EVMAddress = r.Members[1].EVMAddress
			f.sign(r, "ops-1", "ops-2")
			return r
		},
		"a repeated id": func() *BLSRegistryTx {
			r := f.registry(1)
			r.Members[2].ValidatorID = r.Members[1].ValidatorID
			f.sign(r, "ops-1", "ops-2")
			return r
		},
		"a key that is not BLS": func() *BLSRegistryTx {
			r := f.registry(1)
			r.Members[4].BLSPubKey = strings.Repeat("ab", 96)
			f.sign(r, "ops-1", "ops-2")
			return r
		},
		"a key without possession": func() *BLSRegistryTx {
			// validator-1 claims another key, with its own key's possession proof (the rogue-key case).
			r := f.registry(1)
			r.Members[0].BLSPubKey = other.keys[0].PublicKey().Hex()
			f.sign(r, "ops-1", "ops-2")
			return r
		},
		"a copied key": func() *BLSRegistryTx {
			// validator-2 registers validator-1's key, carrying validator-1's possession proof.
			r := f.registry(1)
			r.Members[1].BLSPubKey, r.Members[1].Possession = r.Members[0].BLSPubKey, r.Members[0].Possession
			f.sign(r, "ops-1", "ops-2")
			return r
		},
		"possession for another chain": func() *BLSRegistryTx {
			r := f.registry(1)
			r.Members[5].Possession = SignPossession(f.keys[5], "other-chain", r.Members[5].BLSRegistryMember)
			f.sign(r, "ops-1", "ops-2")
			return r
		},
		"members changed after the admins signed": func() *BLSRegistryTx { r := f.registry(1, "ops-1", "ops-2"); r.Members[6].Power = 1000; return r },
	}
	for name, build := range refused {
		if _, err := VerifyBLSRegistry(build(), rotChain, f.policy, empty, 10); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := VerifyBLSRegistry(f.registry(1, "ops-1", "ops-2"), rotChain, nil, empty, 10); err == nil {
		t.Error("accepted without a sealed admin quorum")
	}
}

// Through FinalizeBlock: accepted into the ledger and the app hash, in force from the next height, the next
// version only; refused with code 9; a registry is never mistaken for a ValidatorBlock; the v10 verdict is recorded.
func TestTheChainRecordsItsBLSRegistry(t *testing.T) {
	f := newRegistryFixture(t)
	app, store := rotationApp(t, f.rotationFixture)
	raw := func(r *BLSRegistryTx) []byte {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	if res, _ := app.CheckTx(nil, &abcitypes.RequestCheckTx{Tx: raw(f.registry(1, "ops-1", "ops-2"))}); res.Code != 0 {
		t.Fatalf("CheckTx refused a well-formed registry: %d %s", res.Code, res.Log)
	}
	bad := f.registry(1, "ops-1", "ops-2")
	bad.Members[0].Possession = bad.Members[1].Possession
	if res, _ := app.CheckTx(nil, &abcitypes.RequestCheckTx{Tx: raw(bad)}); res.Code != codeBLSRegistryRefused {
		t.Fatalf("CheckTx let a registry with a forged possession through: %d", res.Code)
	}

	resp := finalize(t, app, 1, abcitypes.CommitInfo{}, raw(f.registry(1, "ops-1")))
	if resp.TxResults[0].Code != codeBLSRegistryRefused {
		t.Fatalf("a registry short of the admin quorum: code %d", resp.TxResults[0].Code)
	}
	if !app.blockRulesV10Verdict {
		t.Fatal("a refused registry is a v10 verdict (v9 refused it with code 2)")
	}
	app.Commit(nil, nil)

	before := app.pendingAppHash
	resp = finalize(t, app, 2, abcitypes.CommitInfo{}, raw(f.registry(1, "ops-1", "ops-2")))
	if resp.TxResults[0].Code != 0 {
		t.Fatalf("a well-formed registry: code %d %s", resp.TxResults[0].Code, resp.TxResults[0].Log)
	}
	if string(app.pendingAppHash) == string(before) {
		t.Fatal("an accepted registry did not reach the app hash")
	}
	log, err := store.LoadBLSRegistry()
	if err != nil || len(log.Versions) != 1 || log.Versions[0].Height != 2 {
		t.Fatalf("recorded: %+v %v", log, err)
	}
	if RegistryAt(log, 2) != nil || RegistryAt(log, 3) == nil {
		t.Fatal("a registry is in force from the block after the one that accepted it")
	}
	// Replay of the accepting block reproduces its verdict.
	if again := finalize(t, app, 2, abcitypes.CommitInfo{}, raw(f.registry(1, "ops-1", "ops-2"))); again.TxResults[0].Code != 0 {
		t.Fatalf("replay of the accepting block: code %d", again.TxResults[0].Code)
	}
	app.Commit(nil, nil)
	if app.rulesV10FirstVerdict == 0 {
		t.Fatal("the first v10 verdict was not recorded")
	}
	if got := app.committedRulesVersion(); got != executionRulesV10 {
		t.Fatalf("state committed under v10 stamped v%d", got)
	}
	if again := finalize(t, app, 3, abcitypes.CommitInfo{}, raw(f.registry(1, "ops-1", "ops-2"))); again.TxResults[0].Code != codeBLSRegistryRefused {
		t.Fatalf("a used version at a later height: code %d", again.TxResults[0].Code)
	}
	if isValidatorBlockTx(raw(f.registry(2, "ops-1", "ops-2"))) {
		t.Fatal("a registry is judged as a ValidatorBlock")
	}
}

// History holding a registry-kind transaction decided v9's way (code 2) is refused at start. One v10 ACCEPTED (code 0)
// is history only when the committed registry log records it - at that height, under that version and id: an
// acceptance with no record is divergent or corrupt state and is refused by name. (This test used to pass an accepted
// registry with no record at all - the defect it now refuses.) One v10 refused (code 9) needs no record.
func TestHistoryWithARegistryV9RefusedIsNotContinued(t *testing.T) {
	f := newRegistryFixture(t)
	app, _ := rotationApp(t, f.rotationFixture)
	b, _ := json.Marshal(f.registry(1, "ops-1", "ops-2"))
	_, violations, err := app.historicalOperations(3, time.Unix(1_800_000_003, 0), [][]byte{b}, []uint32{2})
	if err != nil || len(violations) != 1 {
		t.Fatalf("v9-decided registry in history: %v %v", violations, err)
	}
	_, violations, err = app.historicalOperations(3, time.Unix(1_800_000_003, 0), [][]byte{b}, []uint32{0})
	if err != nil || len(violations) != 1 || !strings.Contains(violations[0], "holds no record of it") {
		t.Fatalf("an accepted registry with no record in history: %v %v", violations, err)
	}
	if _, violations, err = app.historicalOperations(3, time.Unix(1_800_000_003, 0), [][]byte{b}, []uint32{codeBLSRegistryRefused}); err != nil || len(violations) != 0 {
		t.Fatalf("a v10-refused registry in history: %v %v", violations, err)
	}
	// Accepted at height 3 by the chain itself, the record is there and the same history passes.
	if r := finalize(t, app, 3, abcitypes.CommitInfo{}, b); r.TxResults[0].Code != 0 {
		t.Fatalf("the registry: %s", r.TxResults[0].Log)
	}
	if _, violations, err = app.historicalOperations(3, time.Unix(1_800_000_003, 0), [][]byte{b}, []uint32{0}); err != nil || len(violations) != 0 {
		t.Fatalf("an accepted registry with its record in history: %v %v", violations, err)
	}
	// Recorded at another height, or another version's record, is not its record.
	if _, violations, err = app.historicalOperations(4, time.Unix(1_800_000_004, 0), [][]byte{b}, []uint32{0}); err != nil || len(violations) != 1 {
		t.Fatalf("an accepted registry whose record is at another height: %v %v", violations, err)
	}
}
