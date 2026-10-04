//go:build live

// Copyright 2026 Certen Protocol

package execution

// RB5-F15 against the deployed CertenOutcomeRegistryV1 on the three supported chains, read-only, through public
// providers (two per chain, RB5-F53 - the environment of outcome_live_test.go):
//
//   - TestLiveEveryRecordedOutcomeVerifiesOffline finds every BatchOutcomeRecorded event of each registry, builds the
//     record's evidence from the chain (the anchor's commitment, the record transaction proven into its block, the
//     anchor's validator registry and the quorum proof submitted), verifies it OFFLINE, and then online against the
//     registry. A chain whose registry records no outcome FAILS by name: "nothing recorded" is never a pass.
//   - TestLiveOutcomeEvidenceOfAResolvedMember builds a member's FULL evidence for the three anchors of cross-chain
//     intent 55d23cb0 from public data alone (the chain and the signed intent on Kermit) and verifies it offline and
//     online. With CERTEN_LIVE_OUTCOME_FIXTURE_DIR set it writes each as the fixture the unit tests verify.

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/consensus"
)

type liveRegistry struct {
	chain    int64
	env      string
	anchor   string
	registry string
	from     uint64 // a block before the registry was deployed (2026-10-03)
	bundle   string // the 55d23cb0 anchor
}

var liveRegistries = []liveRegistry{
	{11155111, "CERTEN_LIVE_SEPOLIA_RPC", "0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c", "0xd479841a17770D89Dae94B5b41C95D2117414c21",
		11_819_297, "0x692571219ee830e0374679ac99f960fbfee00be2c2f1ecb24da15ccc0137d736"},
	{84532, "CERTEN_LIVE_BASE_SEPOLIA_RPC", "0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c", "0xd479841a17770D89Dae94B5b41C95D2117414c21",
		47_500_000, "0x4fb6a9d7b7e39f0727d96c184ee91d30cbf3cee98a1cba81b7e00584f67a4f36"},
	{421614, "CERTEN_LIVE_ARBITRUM_SEPOLIA_RPC", "0x3F5B4d4371f06bdFff341d08Ca72A156233e3eA6", "0xbBa0a4aE0fDF5F7cFC7DE67358a32d1E82aFEE0e",
		315_000_000, "0xa7c028667ef5b1e6a91a1d086e8e91d9e46334fb7e8a1fc384397499791b87d1"},
}

func liveOutcomeChain(t *testing.T, ctx context.Context, c liveRegistry) (*AgreedOutcomeChain, string) {
	t.Helper()
	rpcURL := os.Getenv(c.env)
	if rpcURL == "" {
		t.Fatalf("the live build requires %s", c.env)
	}
	oc, err := NewAgreedOutcomeChain(ctx, c.chain, rpcURL, common.HexToAddress(c.anchor), common.HexToAddress(c.registry))
	if err != nil {
		t.Fatalf("chain %d needs two independent providers (set its *_URL_FALLBACKS): %v", c.chain, err)
	}
	return oc, rpcURL
}

// recordedBundles lists every anchor the registry records an outcome of, from its BatchOutcomeRecorded events.
func recordedBundles(t *testing.T, ctx context.Context, oc *AgreedOutcomeChain, from uint64) ([]common.Hash, uint64) {
	t.Helper()
	locs := oc.reader.Locators()
	if len(locs) == 0 {
		t.Fatal("no provider")
	}
	head, err := locs[0].Client.BlockNumber(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var out []common.Hash
	const chunk = 10_000
	for lo := from; lo <= head; lo += chunk {
		hi := min(lo+chunk-1, head)
		q := ethereum.FilterQuery{Addresses: []common.Address{oc.Registry()}, Topics: [][]common.Hash{{batchOutcomeRecordedTopic}},
			FromBlock: new(big.Int).SetUint64(lo), ToBlock: new(big.Int).SetUint64(hi)}
		got, err := filterLogsSplitting(ctx, locs[0].Client, q, lo, hi)
		if err != nil {
			t.Fatalf("BatchOutcomeRecorded in %d-%d on %s: %v", lo, hi, locs[0].Host, err)
		}
		for _, l := range got {
			out = append(out, l.Topics[1])
		}
	}
	return out, head
}

func TestLiveEveryRecordedOutcomeVerifiesOffline(t *testing.T) {
	for _, c := range liveRegistries {
		t.Run(fmt.Sprint(c.chain), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
			defer cancel()
			oc, rpcURL := liveOutcomeChain(t, ctx, c)
			bundles, head := recordedBundles(t, ctx, oc, c.from)
			if len(bundles) == 0 {
				t.Fatalf("chain %d: registry %s records NO batch outcome in blocks %d-%d - nothing to verify, and that is not a pass",
					c.chain, c.registry, c.from, head)
			}
			for _, b := range bundles {
				view, err := oc.AnchorView(ctx, b)
				if err != nil {
					t.Fatal(err)
				}
				rec, err := oc.RecordedOutcome(ctx, b, view.RecordedIn)
				if err != nil {
					t.Fatalf("anchor %s: %v", b.Hex(), err)
				}
				ev, err := BuildRecordEvidence(ctx, oc, c.chain, oc.Registry(), oc.Anchor(), view, rec, "", "")
				if err != nil {
					t.Fatalf("anchor %s: %v", b.Hex(), err)
				}
				chk, err := ev.VerifyRecordOffline()
				if err != nil {
					t.Fatalf("anchor %s offline: %v", b.Hex(), err)
				}
				online, err := VerifyOutcomeEvidenceOnline(ctx, rpcURL, ev)
				if err != nil {
					t.Fatalf("anchor %s online: %v", b.Hex(), err)
				}
				t.Logf("chain %d anchor %s… (%d leaves): outcome root %x… recorded in block %d by %s; %d signer(s), %s of %s power; "+
					"offline OK; online OK (set rotated: %v)", c.chain, b.Hex()[:18], view.LeafCount, chk.OutcomeRoot[:8], rec.Block,
					rec.Recorder.Hex(), chk.Signers, chk.SignedPower, chk.TotalPower, online.SetRotated)
			}
			t.Logf("chain %d: %d recorded outcome(s) in blocks %d-%d, every one verified offline and online", c.chain, len(bundles), c.from, head)
		})
	}
}

func TestLiveOutcomeEvidenceOfAResolvedMember(t *testing.T) {
	accURL := os.Getenv("CERTEN_LIVE_ACCUMULATE_URL")
	if accURL == "" {
		t.Fatal("the live build requires CERTEN_LIVE_ACCUMULATE_URL")
	}
	const adiData = "acc://rb4-phase-c-09282125.acme/data"
	blobsByOp := signedIntentsOf(t, accURL, adiData)
	for _, c := range liveRegistries {
		t.Run(fmt.Sprint(c.chain), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
			defer cancel()
			oc, rpcURL := liveOutcomeChain(t, ctx, c)
			bundle := common.HexToHash(c.bundle)
			view, err := oc.AnchorView(ctx, bundle)
			if err != nil {
				t.Fatal(err)
			}
			if view.RecordedRoot == ([32]byte{}) {
				t.Fatalf("chain %d anchor %s: the registry records NO outcome for it yet", c.chain, c.bundle)
			}
			tree, leaf := liveResolvedMemberTree(t, ctx, oc, c, view, blobsByOp)
			rec, err := oc.RecordedOutcome(ctx, bundle, view.RecordedIn)
			if err != nil {
				t.Fatal(err)
			}
			evs, err := BuildOutcomeEvidence(ctx, oc, OutcomeEvidenceInput{Registry: oc.Registry(), Anchor: oc.Anchor(), Tree: tree,
				Leaves: []OutcomeLeaf{leaf}, View: view, Record: rec})
			if err != nil {
				t.Fatal(err)
			}
			chk, err := evs[0].VerifyOffline()
			if err != nil {
				t.Fatal(err)
			}
			online, err := VerifyOutcomeEvidenceOnline(ctx, rpcURL, evs[0])
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range append(chk.Established, online.Established...) {
				t.Logf("  ✓ %s", s)
			}
			for _, s := range chk.NotEstablished {
				t.Logf("  – not established: %s", s)
			}
			if dir := os.Getenv("CERTEN_LIVE_OUTCOME_FIXTURE_DIR"); dir != "" {
				raw, err := json.MarshalIndent(evs[0], "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, fmt.Sprintf("outcome_evidence_%d.json", c.chain))
				if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("wrote %s", path)
			}
		})
	}
}

// liveResolvedMemberTree is the one-member tree of a 55d23cb0 anchor from public data - the settlement's calldata and the
// signed intent on Kermit - and its member's outcome leaf, derived as every validator derives it.
func liveResolvedMemberTree(t *testing.T, ctx context.Context, oc *AgreedOutcomeChain, c liveRegistry, view *OutcomeAnchorView,
	blobsByOp map[[32]byte][][]byte) (*OutcomeTree, OutcomeLeaf) {
	t.Helper()
	if view.LeafCount != 1 || view.Anchor == nil {
		t.Fatalf("anchor of %d leaves", view.LeafCount)
	}
	bundle := common.HexToHash(c.bundle)
	leafHash := view.Anchor.MerkleRoot
	account := common.HexToAddress("0x1019dbd51aaDAb221fEB6D7b6ffc96D4e5e321AC")
	searchFrom := time.Unix(view.Anchor.Timestamp.Int64(), 0).Add(-leafSpendMargin)
	cons, _, err := oc.LeafConsumption(ctx, account, leafHash, searchFrom)
	if err != nil || cons == nil {
		t.Fatalf("the leaf's consumption: %v", err)
	}
	client, err := ethclient.Dial(os.Getenv(c.env))
	if err != nil {
		t.Fatal(err)
	}
	tx, _, err := client.TransactionByHash(ctx, cons.Tx)
	if err != nil || tx.Hash() != cons.Tx {
		t.Fatalf("settlement %s: %v", cons.Tx.Hex(), err)
	}
	exec, err := decodeAccountExecution(tx.Data())
	if err != nil {
		t.Fatal(err)
	}
	m, err := outcomeAccountABI.MethodById(tx.Data()[:4])
	if err != nil {
		t.Fatal(err)
	}
	args, err := m.Inputs.Unpack(tx.Data()[4:])
	if err != nil {
		t.Fatal(err)
	}
	adi := reflect.ValueOf(args[len(args)-1]).FieldByName("AdiURL").String()
	blobs := blobsByOp[exec.OperationID]
	if blobs == nil || adi == "" {
		t.Fatalf("no signed intent for operation %x, or no ADI in the settlement", exec.OperationID)
	}
	legs, intentAccount, opID, err := memberLegsFromSignedIntent(blobs, c.chain)
	if err != nil || intentAccount != account || opID != exec.OperationID {
		t.Fatalf("the signed intent's member: %s %x %v", intentAccount.Hex(), opID, err)
	}
	if err := matchCommittedCalls(exec.Calls, committedCalls(legs)); err != nil {
		t.Fatal(err)
	}
	// The member's deadline as every validator computes it.
	ci := &consensus.CertenIntent{IntentData: blobs[0], CrossChainData: blobs[1], GovernanceData: blobs[2], ReplayData: blobs[3]}
	batchLegs, _, _, _, err := consensus.MemberLegsForChain(ci, c.chain)
	if err != nil {
		t.Fatal(err)
	}
	p := &PendingBatchIntent{ChainID: c.chain, Account: account, OperationID: opID}
	for _, l := range batchLegs {
		p.Legs = append(p.Legs, LegExecution{ChainID: c.chain, Target: common.Address(l.Target), Value: l.Value, Data: l.Data, Deadline: l.Deadline})
	}
	if order, err := consensus.DeclaredCrossChainOrder(ci); err != nil {
		t.Fatal(err)
	} else if order != nil {
		for i, ch := range order.Chains {
			if ch == c.chain {
				p.SequencePosition = i
			}
		}
	}
	deadline, ok := p.Deadline()
	if !ok {
		t.Fatal("no deadline")
	}
	member := OutcomeTreeMember{LeafIndex: 0, Leaf: leafHash, OperationID: opID, Account: account, ADIURL: adi,
		AuthorityBook: exec.AuthorityBook, AuthorityPage: exec.AuthorityPage, Deadline: deadline.Unix(), SearchFrom: searchFrom.Unix()}
	for _, l := range legs {
		tl := OutcomeTreeLeg{Target: l.Call.Target, Value: (*hexutil.Big)(new(big.Int).Set(callValue(l.Call.Value))), Data: l.Call.Data,
			State: l.State}
		for _, e := range l.Events {
			tl.Events = append(tl.Events, outcomeTreeEvent{Contract: e.Contract, Topic0: e.Topic0, DataHash: e.DataHash})
		}
		member.Legs = append(member.Legs, tl)
	}
	a := view.Anchor
	tree := &OutcomeTree{ChainID: c.chain, BundleID: bundle, Root: a.MerkleRoot, BatchOperationID: a.OperationID,
		BlockHeight: a.AccumulateBlockHeight.Uint64(), AccumulateSetRoot: a.AccumulateSetRoot, Incarnation: a.Incarnation,
		Members: []OutcomeTreeMember{member}}
	fin, err := oc.FinalizedHeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _, _, err := deriveMember(ctx, oc, tree, member, fin, nil)
	if err != nil {
		t.Fatalf("deriving the member's outcome: %v", err)
	}
	if !strings.EqualFold(common.Hash(leaf.BundleID).Hex(), c.bundle) {
		t.Fatalf("leaf of %x", leaf.BundleID)
	}
	return tree, leaf
}
