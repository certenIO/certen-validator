//go:build live

// Copyright 2026 Certen Protocol

package execution

// RB5 D4 backfill, read-only, on the three anchors of cross-chain intent 55d23cb0 (Accumulate transaction 0d316ec4…, as
// its Sepolia write-back on acc://certen-protocol.acme/execution-results names it): how much of each anchor's kept tree
// is rebuilt from what is PUBLIC, and verified against the chain. Run with the environment of outcome_live_test.go.
//
// Public, and verified here:
//   - the member's signed intent (Kermit), its intent id, operation id, account, committed calls and deadlines, and the
//     consensus time of the block it executed in (the chain entry's receipt);
//   - its ADI and its authority book and page: the settlement calldata names them, and the book's URL is confirmed by
//     its hash;
//   - from those, the member's v3 LEAF - recomputed from the signed intent - which equals each one-leaf anchor's root.
//
// Held only in CERTEN's records (the shared database's batch_transactions.governance_commitment and
// certified_intent_message, intent_quorum_certificates, CERTEN's chain), and NOT in the write-back either:
//   - the member's governance commitment (keccak of its G1 governance decision record), and
//   - its quorum-certified intent message.
// Both enter the batch operation id the anchor stores (v3), so the operation id and the bundle id are rebuilt only by
// `validator repair outcome-trees`, which reads them from the database as hints and keeps a tree only when they rebuild
// the anchor's operation id and bundle id exactly (unit-tested in outcome_backfill_test.go). The leaf and root checked
// here are the part that needs nothing of CERTEN's.

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/accumulate"
	"github.com/certen/independant-validator/pkg/consensus"
)

func TestLiveBackfillRebuildsEachResolvedAnchorsLeafFromPublicData(t *testing.T) {
	accURL := os.Getenv("CERTEN_LIVE_ACCUMULATE_URL")
	if accURL == "" {
		t.Fatal("the live build requires CERTEN_LIVE_ACCUMULATE_URL")
	}
	adapter, err := accumulate.NewLiteClientAdapter(&accumulate.LiteClientConfig{NetworkURL: accURL, RequestTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	src := AccumulateIntentSource{Adapter: adapter, URL: accURL}
	const (
		intentTx = "0d316ec4e96d24e3ac39771fdf94071fe17e3e334df21e2b02edbbca405c8e09"
		intentID = "0fca7cab-3270-4ab0-93e0-43035d220800"
	)
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
				t.Fatal(err)
			}
			bundle := common.HexToHash(c.bundle)
			view, err := oc.AnchorView(ctx, bundle)
			if err != nil {
				t.Fatal(err)
			}
			if view.LeafCount != 1 {
				t.Fatalf("anchor of %d leaves", view.LeafCount)
			}

			// The settlement names the ADI and the authority the leaf binds.
			account := common.HexToAddress("0x1019dbd51aaDAb221fEB6D7b6ffc96D4e5e321AC")
			cons, _, err := oc.LeafConsumption(ctx, account, view.Anchor.MerkleRoot, time.Unix(view.Anchor.Timestamp.Int64(), 0).Add(-leafSpendMargin))
			if err != nil || cons == nil {
				t.Fatalf("consumption: %v", err)
			}
			client, err := ethclient.Dial(rpcURL)
			if err != nil {
				t.Fatal(err)
			}
			tx, _, err := client.TransactionByHash(ctx, cons.Tx)
			if err != nil || tx.Hash() != cons.Tx {
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
			if adi == "" {
				t.Fatal("the settlement names no ADI")
			}
			exec, err := decodeAccountExecution(tx.Data())
			if err != nil {
				t.Fatal(err)
			}

			// The signed intent and the time it executed, from Kermit.
			blobs, executedAt, err := src.SignedIntent(ctx, intentTx, strings.TrimSuffix(adi, "/")+"/data")
			if err != nil {
				t.Fatal(err)
			}
			if got := intentIDFromBlob(blobs[0]); got != intentID {
				t.Fatalf("intent %q", got)
			}
			ci := &consensus.CertenIntent{IntentData: blobs[0], CrossChainData: blobs[1], GovernanceData: blobs[2], ReplayData: blobs[3]}
			batchLegs, _, acct, op, err := consensus.MemberLegsForChain(ci, c.chain)
			if err != nil || common.Address(acct) != account || op != exec.OperationID {
				t.Fatalf("the signed intent's member: account %x op %x (%v)", acct, op, err)
			}

			// The authority: the book's URL confirmed by the hash the settlement carries.
			book, page := strings.TrimSuffix(adi, "/")+"/book", fmt.Sprintf("%s/book/%d", strings.TrimSuffix(adi, "/"), exec.AuthorityPage)
			bookHash, pageIdx, err := AuthorityOf(page, book)
			if err != nil || bookHash != exec.AuthorityBook || pageIdx != exec.AuthorityPage {
				t.Fatalf("authority %s / %s does not hash to the settlement's: %v", page, book, err)
			}

			// The member's deadline as every validator computed it: never before the expiry its settlement carried.
			p := &PendingBatchIntent{IntentID: intentID, ChainID: c.chain, Account: account, OperationID: op, CommitTime: executedAt}
			for _, l := range batchLegs {
				p.Legs = append(p.Legs, LegExecution{ChainID: c.chain, Target: common.Address(l.Target), Value: l.Value, Data: l.Data,
					Deadline: l.Deadline})
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
			if !ok || deadline.Unix() < exec.ExpiresAt.Int64() {
				t.Fatalf("deadline %v is before the settlement's expiry %s", deadline, exec.ExpiresAt)
			}

			// The leaf, recomputed from the signed intent: the one-leaf anchor's root.
			commitment, err := p.ExecutionCommitment()
			if err != nil {
				t.Fatal(err)
			}
			leaf := ComputeBatchLeafV3(c.chain, BatchLeafInput{ADIURL: adi, ExecutionCommitment: commitment, OperationID: op,
				AuthorityBook: bookHash, AuthorityPage: pageIdx})
			if leaf != view.Anchor.MerkleRoot {
				t.Fatalf("the leaf rebuilt from the signed intent is %x, the anchor's root %x", leaf, view.Anchor.MerkleRoot)
			}
			t.Logf("chain %d anchor %s: leaf %x rebuilt from the signed intent = root; executed at %s, deadline %s (settlement expiry %s); "+
				"operation id %x and bundle id need the governance commitment and certified message CERTEN's records hold",
				c.chain, c.bundle[:10], leaf, executedAt.Format(time.RFC3339), deadline.Format(time.RFC3339),
				time.Unix(exec.ExpiresAt.Int64(), 0).UTC().Format(time.RFC3339), view.Anchor.OperationID)
		})
	}
}
