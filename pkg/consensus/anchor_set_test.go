package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/commitment"
	"github.com/certen/independant-validator/pkg/entitlement"
	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/supportedchains"
)

// The live V8 anchors (runbook docs/runbooks/rules-v14-ceiling-anchor-set.md): Base Sepolia and Ethereum Sepolia share
// one address, Arbitrum Sepolia has its own.
var (
	liveAnchorBaseAndSepolia = "0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c"
	liveAnchorArbitrum       = "0x3F5B4d4371f06bdFff341d08Ca72A156233e3eA6"
)

// liveAnchorSet is the anchor set the runbook commits, at version, signed by the named admins of f.
func liveAnchorSet(f *rotationFixture, version uint64, admins ...string) *AnchorSetTx {
	tx := &AnchorSetTx{Kind: AnchorSetKind, ChainID: rotChain, Version: version, Anchors: []ledger.AnchorSetEntry{
		{ChainID: 11155111, Anchor: liveAnchorBaseAndSepolia},
		{ChainID: 84532, Anchor: liveAnchorBaseAndSepolia},
		{ChainID: 421614, Anchor: liveAnchorArbitrum},
	}}
	return tx.signedBy(f.admins, admins...)
}

func (t *AnchorSetTx) signedBy(keys map[string]ed25519.PrivateKey, ids ...string) *AnchorSetTx {
	t.Signatures = nil
	for _, id := range ids {
		t.Signatures = append(t.Signatures, PolicySignature{KeyID: id, Signature: hex.EncodeToString(ed25519.Sign(keys[id], t.SigningBytes()))})
	}
	return t
}

// The encoding admins sign, pinned against an independent computation of the same length-prefixed fields (Python
// hashlib and printf | sha256sum, 2026-10-03): kind, chain, version, count, then each chain id with its lowercase anchor
// in chain-id order. The order the anchors are listed in and the case of their checksums change nothing.
func TestTheAnchorSetEncodingIsPinned(t *testing.T) {
	const pinned = "51985f55976189ba9fa5536aaf85a9988467d07dbbbfe8747bd171e52b272578"
	f := newRotationFixture()
	tx := liveAnchorSet(f, 1)
	if got := hex.EncodeToString(tx.SigningBytes()); got != pinned {
		t.Fatalf("signing bytes %s, pinned %s", got, pinned)
	}
	if tx.AnchorSetID() != "anchor-set:"+pinned {
		t.Fatalf("id %s", tx.AnchorSetID())
	}
	reordered := &AnchorSetTx{Kind: AnchorSetKind, ChainID: rotChain, Version: 1, Anchors: []ledger.AnchorSetEntry{
		{ChainID: 421614, Anchor: strings.ToLower(liveAnchorArbitrum)},
		{ChainID: 11155111, Anchor: strings.ToLower(liveAnchorBaseAndSepolia)},
		{ChainID: 84532, Anchor: liveAnchorBaseAndSepolia},
	}}
	if !bytes.Equal(reordered.SigningBytes(), tx.SigningBytes()) {
		t.Fatal("the same set listed in another order or case signs differently")
	}
	other := liveAnchorSet(f, 2)
	if bytes.Equal(other.SigningBytes(), tx.SigningBytes()) {
		t.Fatal("the version is not signed")
	}
}

// RB7 Task 5 (T5-3): the shape rule no longer says "exactly every catalogued chain". The catalogue grows (Telcoin Adiri,
// 2017, is catalogued and disabled), and a rule tied to a growing list would either demand an anchor that does not exist
// or judge the same transaction differently on two binaries. A set names each chain it lists once; a chain it leaves out
// is refused by name when a block targets it.
func TestAnAnchorSetMayLeaveACataloguedChainOutAndTheChainIsThenRefusedByName(t *testing.T) {
	if len(supportedchains.All) <= 3 {
		t.Fatalf("this test needs a catalogue larger than the three settlement chains, has %d", len(supportedchains.All))
	}
	f := newRotationFixture()
	set := liveAnchorSet(f, 1)
	if err := set.CheckShape(); err != nil {
		t.Fatalf("a set naming 3 of the %d catalogued chains: %v", len(supportedchains.All), err)
	}
	rec, err := VerifyAnchorSet(set.signedBy(f.admins, "ops-1", "ops-2"), rotChain, f.policy, nil, 5)
	if err != nil {
		t.Fatalf("the verified set: %v", err)
	}
	left := supportedchains.All[len(supportedchains.All)-1].ID // the last catalogued chain: not one of the live three
	if _, ok := CommittedAnchorOf(rec, left); ok {
		t.Fatalf("chain %d is in the live set", left)
	}
	vb := &ValidatorBlock{CrossChainProof: CrossChainProof{ChainTargets: []ChainTarget{target(left, liveAnchorArbitrum)}}}
	err = CheckChainTargetAnchors(vb, rec)
	if !errors.Is(err, ErrAnchorNotCommitted) || !strings.Contains(err.Error(), fmt.Sprintf("names chain %d", left)) {
		t.Fatalf("a target on a chain the set leaves out: %v", err)
	}
	if err := CheckChainTargetAnchors(&ValidatorBlock{CrossChainProof: CrossChainProof{ChainTargets: []ChainTarget{
		target(84532, liveAnchorBaseAndSepolia)}}}, rec); err != nil {
		t.Fatalf("a target on a chain the set commits: %v", err)
	}
}

func TestAnAnchorSetNeedsEverythingItClaims(t *testing.T) {
	f := newRotationFixture()
	good := func() *AnchorSetTx { return liveAnchorSet(f, 1) }
	verify := func(tx *AnchorSetTx, log *ledger.AnchorSetLog) error {
		_, err := VerifyAnchorSet(tx, rotChain, f.policy, log, 5)
		return err
	}
	rec, err := VerifyAnchorSet(good().signedBy(f.admins, "ops-1", "ops-2"), rotChain, f.policy, nil, 5)
	if err != nil {
		t.Fatalf("the live set signed by two admins: %v", err)
	}
	if rec.Height != 5 || rec.Version != 1 || len(rec.Anchors) != 3 || rec.Anchors[0].ChainID != 84532 ||
		rec.Anchors[2].Anchor != liveAnchorBaseAndSepolia || rec.Anchors[1].Anchor != liveAnchorArbitrum {
		t.Fatalf("record %+v", rec)
	}

	for name, tc := range map[string]struct {
		tx   func() *AnchorSetTx
		log  *ledger.AnchorSetLog
		want string
	}{
		"no chain at all": {tx: func() *AnchorSetTx {
			tx := good()
			tx.Anchors = nil
			return tx.signedBy(f.admins, "ops-1", "ops-2")
		}, want: "names at least one settlement chain"},
		"a chain that is not settled": {tx: func() *AnchorSetTx {
			tx := good()
			tx.Anchors = append(tx.Anchors, ledger.AnchorSetEntry{ChainID: 1, Anchor: liveAnchorArbitrum})
			return tx.signedBy(f.admins, "ops-1", "ops-2")
		}, want: "chain 1 is not a settlement chain"},
		"a chain twice": {tx: func() *AnchorSetTx {
			tx := good()
			tx.Anchors = append(tx.Anchors, ledger.AnchorSetEntry{ChainID: 84532, Anchor: liveAnchorArbitrum})
			return tx.signedBy(f.admins, "ops-1", "ops-2")
		}, want: "named twice"},
		"the zero address": {tx: func() *AnchorSetTx {
			tx := good()
			tx.Anchors[0].Anchor = common.Address{}.Hex()
			return tx.signedBy(f.admins, "ops-1", "ops-2")
		}, want: "not a non-zero 0x EVM address"},
		"no 0x": {tx: func() *AnchorSetTx {
			tx := good()
			tx.Anchors[0].Anchor = strings.TrimPrefix(liveAnchorBaseAndSepolia, "0x")
			return tx.signedBy(f.admins, "ops-1", "ops-2")
		}, want: "not a non-zero 0x EVM address"},
		"padding": {tx: func() *AnchorSetTx {
			tx := good()
			tx.Anchors[0].Anchor = " " + liveAnchorBaseAndSepolia
			return tx.signedBy(f.admins, "ops-1", "ops-2")
		}, want: "not a non-zero 0x EVM address"},
		"another chain": {tx: func() *AnchorSetTx {
			tx := good()
			tx.ChainID = "certen-other"
			return tx.signedBy(f.admins, "ops-1", "ops-2")
		}, want: "is for chain"},
		"not the next version": {tx: func() *AnchorSetTx { return liveAnchorSet(f, 2, "ops-1", "ops-2") },
			want: "not the next anchor-set version 1"},
		"a replayed version": {tx: func() *AnchorSetTx { return liveAnchorSet(f, 1, "ops-1", "ops-2") },
			log: &ledger.AnchorSetLog{Versions: []ledger.AnchorSetRecord{{Version: 1, Height: 2}}}, want: "not the next anchor-set version 2"},
		"one admin": {tx: func() *AnchorSetTx { return liveAnchorSet(f, 1, "ops-1") }, want: "anchor set"},
		"one admin twice": {tx: func() *AnchorSetTx {
			tx := liveAnchorSet(f, 1, "ops-1")
			tx.Signatures = append(tx.Signatures, tx.Signatures[0])
			return tx
		}, want: "anchor set"},
		"a stranger": {tx: func() *AnchorSetTx {
			return good().signedBy(map[string]ed25519.PrivateKey{"ops-1": f.admins["ops-1"], "ops-9": seededKey(0x99)}, "ops-1", "ops-9")
		}, want: "anchor set"},
		"signed, then changed": {tx: func() *AnchorSetTx {
			tx := liveAnchorSet(f, 1, "ops-1", "ops-2")
			tx.Anchors[2].Anchor = liveAnchorBaseAndSepolia
			return tx
		}, want: "anchor set"},
	} {
		t.Run(name, func(t *testing.T) {
			err := verify(tc.tx(), tc.log)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
	// A rotated admin set is the one that authorises: the genesis admins no longer do.
	b := setB(f)
	rotated := *f.policy
	rotated.AdminReseals = []ledger.AdminReseal{{Height: 3, Keys: b.public(), Threshold: 2, Kind: AdminRotateKind, Sequence: 1}}
	if _, err := VerifyAnchorSet(liveAnchorSet(f, 1, "ops-1", "ops-2"), rotChain, &rotated, nil, 4); err == nil {
		t.Fatal("the rotated-out admins authorised an anchor set")
	}
	if _, err := VerifyAnchorSet(good().signedBy(b, "new-a", "new-b"), rotChain, &rotated, nil, 4); err != nil {
		t.Fatalf("the admin set in force: %v", err)
	}
	if _, err := VerifyAnchorSet(good().signedBy(b, "new-a", "new-b"), rotChain, &rotated, nil, 3); err == nil {
		t.Fatal("the new admins authorised in the block that installed them")
	}
}

// anchoredBlockJSON is a ValidatorBlock that passes every invariant, for operation op by validator, settling on the
// given chain targets and carrying ev.
func anchoredBlockJSON(t *testing.T, op, validator string, targets []ChainTarget, ev *entitlement.Evidence) []byte {
	t.Helper()
	expiry := time.Unix(gateNow+7200, 0).UTC().Format(time.RFC3339)
	for i := range targets {
		targets[i].Commitment = "0xtargetcommit"
		targets[i].Expiry = expiry
		if targets[i].Chain == "" {
			targets[i].Chain = "evm"
		}
	}
	vb := ValidatorBlock{
		ValidatorID: validator, OperationCommitment: op, BlockHeight: 1,
		Timestamp: time.Unix(gateNow, 0).UTC().Format(time.RFC3339),
		GovernanceProof: GovernanceProof{OrganizationADI: gatePayer,
			AuthorizationLeaves: []AuthorizationLeaf{{KeyPage: "acc://payer.acme/book/1", KeyHash: "0xkh",
				Role: "DEFAULT_SIGNER", Signature: "0xleafsig"}},
			BLSAggregateSignature: "0xsig", BLSValidatorSetPubKey: "0xpub"},
		CrossChainProof:           CrossChainProof{OperationID: op, CrossChainCommitment: "0xcc", ChainTargets: targets},
		ExecutionProof:            ExecutionProof{Stage: ExecutionStagePre, ValidatorSignatures: []string{"0xvsig"}},
		AccumulateAnchorReference: AccumulateAnchorReference{AccountURL: gatePayer, TxHash: "0xtx", BlockHeight: 1},
		EntitlementEvidence:       ev,
	}
	leaves := []interface{}{vb.GovernanceProof.AuthorizationLeaves[0]}
	root, err := commitment.ComputeGovernanceMerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	vb.GovernanceProof.MerkleRoot = root
	if vb.BundleID, err = commitment.ComputeBundleID(vb.GovernanceProof, vb.CrossChainProof); err != nil {
		t.Fatal(err)
	}
	return rotJSON(t, vb)
}

func target(chainID int64, anchor string) ChainTarget {
	return ChainTarget{ChainID: chainID, ContractAddress: anchor, FunctionSelector: "0x34597e5a"}
}

// v14Step executes a block twice - the replay must decide it identically - checks the codes, and commits it.
func v14Step(t *testing.T, app *ValidatorApp, h int64, want []uint32, txs ...[]byte) *abcitypes.ResponseFinalizeBlock {
	t.Helper()
	resp := finalize(t, app, h, abcitypes.CommitInfo{}, txs...)
	again := finalize(t, app, h, abcitypes.CommitInfo{}, txs...)
	if !bytes.Equal(resp.AppHash, again.AppHash) {
		t.Fatalf("block %d: replay changed the app hash", h)
	}
	for i := range want {
		if resp.TxResults[i].Code != want[i] {
			t.Fatalf("block %d tx %d: code %d (%s), want %d", h, i, resp.TxResults[i].Code, resp.TxResults[i].Log, want[i])
		}
		if again.TxResults[i].Code != resp.TxResults[i].Code || again.TxResults[i].Log != resp.TxResults[i].Log {
			t.Fatalf("block %d tx %d: replay decided it differently", h, i)
		}
	}
	if _, err := app.Commit(context.Background(), &abcitypes.RequestCommit{}); err != nil {
		t.Fatal(err)
	}
	return resp
}

// RB4-F35: before v14 a ValidatorBlock naming any anchor was accepted - nothing in consensus compared it with anything.
// From the height after the first anchor set, every chain target must name its chain's committed anchor; before it the
// chain decides exactly as v13 did.
func TestTheFirstAnchorSetActivatesTheAnchorRule(t *testing.T) {
	f := newRotationFixture()
	app, store := rotationApp(t, f)
	wrong := common.HexToAddress("0x8398d7ebb7de3bb1d9a6f7e7aec7e2ac2c1e5339").Hex() // an anchor that is not committed
	right := []ChainTarget{target(84532, liveAnchorBaseAndSepolia), target(421614, liveAnchorArbitrum)}

	// Block 1, no anchor set: a block naming a retired anchor is accepted, as v13 accepted it.
	v14Step(t, app, 1, []uint32{0}, anchoredBlockJSON(t, "op-1", "validator-1", []ChainTarget{target(84532, wrong)}, nil))
	if app.committedRulesVersion() >= executionRulesV14 {
		t.Fatal("the state is v14's before any anchor set")
	}

	// Block 2: one admin is refused; two are accepted. The set is recorded at 2 and in force from 3 - a wrong anchor in
	// block 2 itself is still decided the v13 way.
	resp := v14Step(t, app, 2, []uint32{codeAnchorSetRefused, 0, 0},
		rotJSON(t, liveAnchorSet(f, 1, "ops-1")), rotJSON(t, liveAnchorSet(f, 1, "ops-1", "ops-2")),
		anchoredBlockJSON(t, "op-2", "validator-1", []ChainTarget{target(84532, wrong)}, nil))
	if !strings.Contains(resp.TxResults[0].Log, "anchor set refused") {
		t.Fatalf("refusal log %q", resp.TxResults[0].Log)
	}
	l, err := store.LoadAnchorSet()
	if err != nil || len(l.Versions) != 1 || l.Versions[0].Height != 2 || l.Versions[0].ID != liveAnchorSet(f, 1).AnchorSetID() {
		t.Fatalf("anchor set log (%+v, %v)", l, err)
	}
	if app.committedRulesVersion() != executionRulesV14 {
		t.Fatalf("after an anchor set the state is stamped v%d", app.committedRulesVersion())
	}
	without := finalize(t, newRotationAppFor(t, f), 2, abcitypes.CommitInfo{}, rotJSON(t, liveAnchorSet(f, 1, "ops-1")),
		anchoredBlockJSON(t, "op-2", "validator-1", []ChainTarget{target(84532, wrong)}, nil))
	if bytes.Equal(without.AppHash, resp.AppHash) {
		t.Fatal("the anchor set is not in the app hash")
	}

	// Block 3: every chain target is judged against the set.
	resp = v14Step(t, app, 3, []uint32{codeAnchorNotCommitted, codeAnchorNotCommitted, codeAnchorNotCommitted, codeAnchorNotCommitted, 0},
		anchoredBlockJSON(t, "op-3", "validator-1", []ChainTarget{target(84532, wrong)}, nil),
		anchoredBlockJSON(t, "op-4", "validator-1", []ChainTarget{target(84532, liveAnchorBaseAndSepolia), target(421614, liveAnchorBaseAndSepolia)}, nil),
		anchoredBlockJSON(t, "op-5", "validator-1", []ChainTarget{target(1, liveAnchorBaseAndSepolia)}, nil),
		anchoredBlockJSON(t, "op-6", "validator-1", []ChainTarget{target(84532, "evm_contract")}, nil),
		anchoredBlockJSON(t, "op-7", "validator-1", right, nil))
	for i, want := range []string{"names anchor " + wrong + "; anchor set v1 commits 0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c",
		"chain target 1 (chain 421614) names anchor 0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c; anchor set v1 commits 0x3F5B4d4371f06bdFff341d08Ca72A156233e3eA6",
		"chain 1, for which anchor set v1 commits no anchor", "names \"evm_contract\", which is not an anchor address"} {
		if !strings.Contains(resp.TxResults[i].Log, ReasonAnchorNotCommitted) || !strings.Contains(resp.TxResults[i].Log, want) {
			t.Fatalf("tx %d log %q, want %q", i, resp.TxResults[i].Log, want)
		}
	}

	// The same version again is refused; the next one by the admins is accepted and governs from the block after.
	moved := liveAnchorSet(f, 2)
	moved.Anchors[0].Anchor = liveAnchorArbitrum // Ethereum Sepolia moves
	v14Step(t, app, 4, []uint32{codeAnchorSetRefused, 0}, rotJSON(t, liveAnchorSet(f, 1, "ops-2", "ops-3")),
		rotJSON(t, moved.signedBy(f.admins, "ops-2", "ops-3")))
	v14Step(t, app, 5, []uint32{codeAnchorNotCommitted, 0},
		anchoredBlockJSON(t, "op-8", "validator-1", []ChainTarget{target(11155111, liveAnchorBaseAndSepolia)}, nil),
		anchoredBlockJSON(t, "op-9", "validator-1", []ChainTarget{target(11155111, liveAnchorArbitrum)}, nil))

	// The query answers what a tool reads.
	q, err := app.Query(context.Background(), &abcitypes.RequestQuery{Path: "/certen/anchor_set"})
	if err != nil || q.Code != 0 {
		t.Fatalf("query (%+v, %v)", q, err)
	}
	var got ledger.AnchorSetLog
	if err := json.Unmarshal(q.Value, &got); err != nil || len(got.Versions) != 2 || got.Versions[1].Height != 4 {
		t.Fatalf("query answered %s (%v)", q.Value, err)
	}
	if set, err := app.AnchorSetContext(); err != nil || set == nil || set.Version != 2 {
		t.Fatalf("the proposer's context (%+v, %v)", set, err)
	}
}

// RB4-F6 at the consensus rule: an unpriced ceiling is accepted below the v14 activation (v13's verdict, so history
// replays) and refused by name from the height after the first anchor set.
func TestAnUnpricedCeilingIsRefusedOnceRulesV14AreActive(t *testing.T) {
	f := newRotationFixture()
	cfg, ev := pricedFixture(t, entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 1_000, PerLegMicroUSD: 500})
	policy := *f.policy
	policy.Mode = string(EntitlementEnforce)
	policy.Keys = map[string]string{"k1": hex.EncodeToString(cfg.Keys["k1"])}
	pf := *f
	pf.policy = &policy
	app, _ := rotationApp(t, &pf)
	unpriced := []ChainTarget{target(84532, liveAnchorBaseAndSepolia), target(421614, liveAnchorArbitrum)}
	priced := []ChainTarget{target(84532, liveAnchorBaseAndSepolia)}

	v14Step(t, app, 1, []uint32{0, 0}, anchoredBlockJSON(t, "op-1", "validator-1", unpriced, ev),
		anchoredBlockJSON(t, "op-2", "validator-1", priced, ev))
	v14Step(t, app, 2, []uint32{0}, rotJSON(t, liveAnchorSet(f, 1, "ops-1", "ops-2")))
	resp := v14Step(t, app, 3, []uint32{4, 0}, anchoredBlockJSON(t, "op-3", "validator-1", unpriced, ev),
		anchoredBlockJSON(t, "op-4", "validator-1", priced, ev))
	if !strings.Contains(resp.TxResults[0].Log, entitlement.ReasonUnpriced) || !strings.Contains(resp.TxResults[0].Log, "421614") {
		t.Fatalf("the refusal does not name ENTITLEMENT_UNPRICED and the chain: %q", resp.TxResults[0].Log)
	}
}

// IndexCommittedHistory checks the v14 claim on every node: no committed anchor-set-kind transaction was decided any way
// but v14's, and an accepted one is recorded.
func TestCommittedAnchorSetHistoryIsChecked(t *testing.T) {
	f := newRotationFixture()
	raw := rotJSON(t, liveAnchorSet(f, 1, "ops-1", "ops-2"))
	hist := func(code uint32) *fakeHistory {
		return &fakeHistory{base: 1, blocks: map[int64][][]byte{1: {raw}}, times: map[int64]time.Time{1: beforeV9},
			codes: map[int64][]uint32{1: {code}}}
	}
	for _, code := range []uint32{1, 2, 4, 0} {
		err := historyApp(t, 1).IndexCommittedHistory(hist(code))
		if !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) || !strings.Contains(err.Error(), "anchor set") {
			t.Fatalf("an anchor set decided with code %d (and none recorded): %v", code, err)
		}
	}
	// Already indexed by a v13 binary: the kinds check still reads it.
	indexed := historyApp(t, 1)
	if err := indexed.ledgerStore.RecordCommittedBlock(1, nil); err != nil {
		t.Fatal(err)
	}
	if err := indexed.IndexCommittedHistory(hist(2)); !errors.Is(err, ErrCommittedHistoryUnderCurrentRules) {
		t.Fatalf("an already-indexed chain with an anchor set decided as a ValidatorBlock: %v", err)
	}
	refused := historyApp(t, 1)
	if err := refused.IndexCommittedHistory(hist(codeAnchorSetRefused)); err != nil {
		t.Fatalf("an anchor set refused by v14: %v", err)
	}
	if refused.committedRulesVersion() != executionRulesV14 {
		t.Fatalf("a committed anchor-set verdict left the state stamped v%d", refused.committedRulesVersion())
	}
	accepted := historyApp(t, 1)
	tx, _ := DecodeAnchorSet(raw)
	if err := accepted.ledgerStore.SaveAnchorSet(&ledger.AnchorSetLog{Versions: []ledger.AnchorSetRecord{
		{Version: 1, Height: 1, ID: tx.AnchorSetID()}}}); err != nil {
		t.Fatal(err)
	}
	if err := accepted.IndexCommittedHistory(hist(0)); err != nil {
		t.Fatalf("an anchor set accepted and recorded by v14: %v", err)
	}
	// The tool's check: a node that cannot serve the anchor set log (before v14) can have recorded none.
	v, u, err := CommittedBlockViolations(1, [][]byte{raw}, []uint32{0}, &CommittedRecords{})
	if err != nil || len(v) != 1 || len(u) != 0 {
		t.Fatalf("an accepted anchor set against records without the log: %v %v %v", v, u, err)
	}
}

func TestCheckTxFiltersAnchorsOnceASetIsInForce(t *testing.T) {
	f := newRotationFixture()
	app, _ := rotationApp(t, f)
	wrong := anchoredBlockJSON(t, "op-1", "validator-1", []ChainTarget{target(84532, liveAnchorArbitrum)}, nil)
	check := func(tx []byte) *abcitypes.ResponseCheckTx {
		r, err := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: tx})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := check(wrong); r.Code != 0 {
		t.Fatalf("before any anchor set: %d %s", r.Code, r.Log)
	}
	bad := liveAnchorSet(f, 1, "ops-1", "ops-2")
	bad.Anchors = append(bad.Anchors, bad.Anchors[0]) // a chain named twice
	if r := check(rotJSON(t, bad)); r.Code != codeAnchorSetRefused {
		t.Fatalf("a malformed anchor set entered the mempool: %d", r.Code)
	}
	if r := check(rotJSON(t, liveAnchorSet(f, 1))); r.Code != 0 {
		t.Fatalf("an unsigned but well-formed set is FinalizeBlock's to judge: %d %s", r.Code, r.Log)
	}
	v14Step(t, app, 1, []uint32{0}, rotJSON(t, liveAnchorSet(f, 1, "ops-1", "ops-2")))
	if r := check(wrong); r.Code != codeAnchorNotCommitted {
		t.Fatalf("after the anchor set: %d %s", r.Code, r.Log)
	}
	if r := check(anchoredBlockJSON(t, "op-2", "validator-1", []ChainTarget{target(84532, liveAnchorBaseAndSepolia)}, nil)); r.Code != 0 {
		t.Fatalf("the committed anchor: %d %s", r.Code, r.Log)
	}
}

type fixedAnchorSets struct {
	set *ledger.AnchorSetRecord
	err error
}

func (s fixedAnchorSets) AnchorSetContext() (*ledger.AnchorSetRecord, error) { return s.set, s.err }

// committedTestAnchors is an anchor set committing testAnchor(c) on every settlement chain - what the fake enqueuer
// settles on.
func committedTestAnchors() fixedAnchorSets {
	set := &ledger.AnchorSetRecord{Version: 1, Height: 1}
	for _, c := range []int64{11155111, 84532, 421614} {
		set.Anchors = append(set.Anchors, ledger.AnchorSetEntry{ChainID: c, Anchor: testAnchor(c).Hex()})
	}
	return fixedAnchorSets{set: set}
}

// The proposer's half: until an anchor set is committed no intent is admitted, by name and retried - never refused for
// good - and a node configured with another anchor than the committed one says so instead of building a block every
// peer refuses.
func TestTheProposerAdmitsNothingUntilAnAnchorSetIsCommitted(t *testing.T) {
	anchorOf := func(c int64) (common.Address, error) { return testAnchor(c), nil }
	for name, src := range map[string]AnchorSetSource{
		"no source":   nil,
		"no set":      fixedAnchorSets{},
		"unreadable":  fixedAnchorSets{err: errors.New("disk")},
		"another one": fixedAnchorSets{set: &ledger.AnchorSetRecord{Version: 3, Anchors: []ledger.AnchorSetEntry{{ChainID: 84532, Anchor: liveAnchorArbitrum}}}},
		"no entry":    fixedAnchorSets{set: &ledger.AnchorSetRecord{Version: 3}},
	} {
		err := CheckAnchorSetAdmission([]int64{84532}, src, anchorOf)
		if err == nil || !errors.Is(err, ErrBatchUnavailable) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := CheckAnchorSetAdmission([]int64{84532}, fixedAnchorSets{}, anchorOf); !errors.Is(err, ErrAnchorSetNotCommitted) {
		t.Fatalf("no set: %v", err)
	}
	if err := CheckAnchorSetAdmission([]int64{84532}, fixedAnchorSets{set: &ledger.AnchorSetRecord{Version: 3,
		Anchors: []ledger.AnchorSetEntry{{ChainID: 84532, Anchor: liveAnchorArbitrum}}}}, anchorOf); !errors.Is(err, ErrAnchorNotCommitted) ||
		!strings.Contains(err.Error(), "CERTEN_ANCHOR_V8_84532") {
		t.Fatalf("a configured anchor that is not the committed one: %v", err)
	}
	if err := CheckAnchorSetAdmission([]int64{84532, 421614}, committedTestAnchors(), anchorOf); err != nil {
		t.Fatalf("the committed anchors: %v", err)
	}

	// Through the batch path: an intent on a validator with no committed anchor set is retried by name, not refused.
	bv := refusalValidator(newFakeEnqueuer())
	bv.anchorSets = fixedAnchorSets{}
	err := enqueue(bv, batchableIntent(t, "i1", 84532))
	var r *BatchRefusal
	if !errors.As(err, &r) || r.Permanent || !errors.Is(err, ErrAnchorSetNotCommitted) {
		t.Fatalf("an intent before the anchor set: %v", err)
	}
}
