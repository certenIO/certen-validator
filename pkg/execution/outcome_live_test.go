//go:build live

// Copyright 2026 Certen Protocol

package execution

// RB5 D4 end to end on the three supported chains, read-only: the outcome of a REAL resolved V8.2 batch anchor derived
// from the chain through independent providers that agree, with the member's committed calls and effects taken from
// the user-signed intent on Kermit - and the deployed CertenOutcomeRegistryV1's outcomeMessage for that root equal to
// the Go message. Nothing is sent. Run with two independent providers per chain (RB5-F53):
//
//	CERTEN_LIVE_ACCUMULATE_URL=https://kermit.accumulatenetwork.io \
//	CERTEN_LIVE_SEPOLIA_RPC=https://ethereum-sepolia-rpc.publicnode.com \
//	ETHEREUM_SEPOLIA_URL_FALLBACKS=https://sepolia.gateway.tenderly.co \
//	CERTEN_LIVE_BASE_SEPOLIA_RPC=https://base-sepolia-rpc.publicnode.com \
//	BASE_SEPOLIA_URL_FALLBACKS=https://base-sepolia.gateway.tenderly.co \
//	CERTEN_LIVE_ARBITRUM_SEPOLIA_RPC=https://arbitrum-sepolia-rpc.publicnode.com \
//	ARBITRUM_SEPOLIA_URL_FALLBACKS=https://arbitrum-sepolia.gateway.tenderly.co \
//	go test -tags live ./pkg/execution -run LiveOutcomeOfAResolvedBatch
//
// The anchors are the three legs of cross-chain intent 55d23cb0 (2026-10-03): one-member V8.2 batch anchors whose
// member - account 0x1019dbd5… of acc://rb4-phase-c-09282125.acme, paying 1 wei on each chain - consumed its leaf under
// the anchor. Every member fact is read from the chain or from the signed intent on Kermit. What is NOT read here is
// the member's governance commitment and quorum-certified intent message, which only CERTEN's own records hold (the
// validators' kept trees and database, CERTEN's chain): they enter the batch operation id, so the kept-tree self-check
// that rebuilds the bundle id (OutcomeTree.Verify) is exercised by the unit tests, and this test derives each leaf with
// the same per-member derivation the kept tree feeds (deriveMember).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/accumulate"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

func TestLiveOutcomeOfAResolvedBatch(t *testing.T) {
	accURL := os.Getenv("CERTEN_LIVE_ACCUMULATE_URL")
	if accURL == "" {
		t.Fatal("the live build requires CERTEN_LIVE_ACCUMULATE_URL")
	}
	const adiData = "acc://rb4-phase-c-09282125.acme/data"
	blobsByOp := signedIntentsOf(t, accURL, adiData)

	for _, c := range []struct {
		chain    int64
		env      string
		anchor   string
		registry string
		bundle   string
	}{
		{11155111, "CERTEN_LIVE_SEPOLIA_RPC", "0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c", "0xd479841a17770D89Dae94B5b41C95D2117414c21",
			"0x692571219ee830e0374679ac99f960fbfee00be2c2f1ecb24da15ccc0137d736"},
		{84532, "CERTEN_LIVE_BASE_SEPOLIA_RPC", "0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c", "0xd479841a17770D89Dae94B5b41C95D2117414c21",
			"0x4fb6a9d7b7e39f0727d96c184ee91d30cbf3cee98a1cba81b7e00584f67a4f36"},
		{421614, "CERTEN_LIVE_ARBITRUM_SEPOLIA_RPC", "0x3F5B4d4371f06bdFff341d08Ca72A156233e3eA6", "0xbBa0a4aE0fDF5F7cFC7DE67358a32d1E82aFEE0e",
			"0xa7c028667ef5b1e6a91a1d086e8e91d9e46334fb7e8a1fc384397499791b87d1"},
	} {
		t.Run(fmt.Sprint(c.chain), func(t *testing.T) {
			rpcURL := os.Getenv(c.env)
			if rpcURL == "" {
				t.Fatalf("the live build requires %s", c.env)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			oc, err := NewAgreedOutcomeChain(ctx, c.chain, rpcURL, common.HexToAddress(c.anchor), common.HexToAddress(c.registry))
			if err != nil {
				t.Fatalf("chain %d needs two independent providers (set its *_URL_FALLBACKS): %v", c.chain, err)
			}
			if err := VerifyOutcomeRegistry(ctx, c.chain, oc.Registry(), oc.Anchor(), oc); err != nil {
				t.Fatalf("the deployed registry: %v", err)
			}
			bundle := common.HexToHash(c.bundle)

			// The anchor, agreed: attested, one leaf, no outcome recorded yet.
			view, err := oc.AnchorView(ctx, bundle)
			if err != nil {
				t.Fatal(err)
			}
			if !view.Anchor.Valid || !view.Anchor.ProofExecuted || view.Anchor.Version != contracts.BatchAnchorV8_2 || view.LeafCount != 1 {
				t.Fatalf("anchor %+v, %d leaves", view.Anchor, view.LeafCount)
			}
			if view.RecordedRoot != ([32]byte{}) {
				t.Logf("the registry already records outcome root %x (block %d)", view.RecordedRoot, view.RecordedIn)
			}
			leaf := view.Anchor.MerkleRoot // a one-leaf tree's root is its leaf

			// The member: whoever consumed the leaf under this anchor, its settlement's calldata naming the account and
			// operation, and the user-signed intent naming its committed calls and effects.
			account := common.HexToAddress("0x1019dbd51aaDAb221fEB6D7b6ffc96D4e5e321AC")
			searchFrom := time.Unix(view.Anchor.Timestamp.Int64(), 0).Add(-leafSpendMargin)
			cons, asOf, err := oc.LeafConsumption(ctx, account, leaf, searchFrom)
			if err != nil || cons == nil {
				t.Fatalf("the leaf's consumption: %+v as of %d, %v", cons, asOf, err)
			}
			if cons.Anchor != bundle {
				t.Fatalf("the leaf was consumed under %x, not this anchor", cons.Anchor)
			}
			client, err := ethclient.Dial(rpcURL)
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
			blobs := blobsByOp[exec.OperationID]
			if blobs == nil {
				t.Fatalf("no signed intent on %s has operation %x", adiData, exec.OperationID)
			}
			legs, intentAccount, opID, err := memberLegsFromSignedIntent(blobs, c.chain)
			if err != nil {
				t.Fatal(err)
			}
			if intentAccount != account || opID != exec.OperationID {
				t.Fatalf("the signed intent names account %s operation %x", intentAccount.Hex(), opID)
			}
			if err := matchCommittedCalls(exec.Calls, committedCalls(legs)); err != nil {
				t.Fatalf("the settlement is not the signed member: %v", err)
			}
			member := OutcomeTreeMember{LeafIndex: 0, Leaf: leaf, OperationID: opID, Account: account,
				AuthorityBook: exec.AuthorityBook, AuthorityPage: exec.AuthorityPage, SearchFrom: searchFrom.Unix()}
			for _, l := range legs {
				tl := OutcomeTreeLeg{Target: l.Call.Target, Value: (*hexutil.Big)(new(big.Int).Set(callValue(l.Call.Value))), Data: l.Call.Data,
					State: l.State}
				for _, e := range l.Events {
					tl.Events = append(tl.Events, outcomeTreeEvent{Contract: e.Contract, Topic0: e.Topic0, DataHash: e.DataHash})
				}
				member.Legs = append(member.Legs, tl)
			}

			// The leaf, derived as every validator derives it, at the agreed finalized chain.
			fin, err := oc.FinalizedHeader(ctx)
			if err != nil {
				t.Fatal(err)
			}
			tree := &OutcomeTree{ChainID: c.chain, BundleID: bundle}
			got, _, _, err := deriveMember(ctx, oc, tree, member, fin, nil)
			if err != nil {
				t.Fatalf("deriving the member's outcome: %v", err)
			}
			hdr, err := oc.HeaderAt(ctx, cons.Block)
			if err != nil {
				t.Fatal(err)
			}
			wantEffects := CommittedEffectsHash(legEvents(legs), legState(legs))
			if got.Status != OutcomeExecuted || got.Tx != cons.Tx || got.BlockNumber != cons.Block || got.BlockHash != hdr.Hash() ||
				got.ReceiptsRoot != hdr.ReceiptHash || got.EffectsHash != wantEffects {
				t.Fatalf("leaf %+v", got)
			}
			root, err := OutcomeRoot([]OutcomeLeaf{got}, 1)
			if err != nil {
				t.Fatal(err)
			}

			// The deployed registry signs exactly the Go outcome message for that root.
			onChain, err := oc.OutcomeMessage(ctx, bundle, root, view.At)
			if err != nil {
				t.Fatal(err)
			}
			want := contracts.ComputeEvmMessageHashV8_2_Outcome(c.chain, bundle, root, view.CurrentSetRoot,
				view.Anchor.AccumulateSetRoot, view.Anchor.Incarnation)
			if onChain != want {
				t.Fatalf("the registry signs %x, Go computes %x", onChain, want)
			}
			t.Logf("chain %d anchor %s: status %d, settlement %s in block %d, effects %x -> outcome root %x, message %x",
				c.chain, c.bundle[:10], got.Status, common.Hash(got.Tx).Hex(), got.BlockNumber, got.EffectsHash, root, want)
		})
	}
}

// signedIntentsOf reads every writeData intent on an ADI's data account from Accumulate, by operation id.
func signedIntentsOf(t *testing.T, accURL, dataAccount string) map[[32]byte][][]byte {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "query", "params": map[string]interface{}{
		"scope": dataAccount, "query": map[string]interface{}{"queryType": "chain", "name": "main",
			"range": map[string]interface{}{"start": 0, "count": 1000}}}})
	resp, err := http.Post(strings.TrimSuffix(accURL, "/")+"/v3", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Result struct {
			Records []struct {
				Entry string `json:"entry"`
			} `json:"records"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	adapter, err := accumulate.NewLiteClientAdapter(&accumulate.LiteClientConfig{NetworkURL: accURL, RequestTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	byOp := map[[32]byte][][]byte{}
	for _, r := range out.Result.Records {
		blobs, err := adapter.GetIntentBlobs(context.Background(), r.Entry, dataAccount)
		if err != nil || len(blobs) < 4 {
			continue // not an intent (the account's creation, another data entry)
		}
		ci := &consensus.CertenIntent{IntentData: blobs[0], CrossChainData: blobs[1], GovernanceData: blobs[2], ReplayData: blobs[3]}
		opHex, err := ci.OperationID()
		if err != nil {
			continue
		}
		byOp[common.HexToHash(opHex)] = blobs
	}
	if len(byOp) == 0 {
		t.Fatalf("no signed intent read from %s", dataAccount)
	}
	return byOp
}
