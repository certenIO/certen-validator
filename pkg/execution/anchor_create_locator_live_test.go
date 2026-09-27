//go:build live

// Live check of the create-transaction locator and the signed-transaction reader against production
// anchors (RB3-F33/F127), read-only. Behind the live build tag rather than a skip (00_STANDARD §2):
//
//	CERTEN_TEST_RPC_84532, CERTEN_TEST_RPC_421614, CERTEN_TEST_RPC_11155111 - an RPC URL per chain

package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

type liveAnchorRow struct {
	name             string
	chainID          int64
	bundle, root     string
	createTx         string // "" where the row lacks it
	verifyTx         string
	wantCreateSender string // "" where not asserted
}

// Production rows read 2026-09-27: the three e2e anchors (which the run log attributed to other validators
// - RB3-F23), the oldest chain_backfill row per chain, and the two rows that held 'already-exists'.
var liveAnchorRows = []liveAnchorRow{
	{"e2e base", 84532, "4ac6fd4fe485f39e6feb5f7686bf8aa089a24ccc950c5154993393b0fa4a83bd", "8040aa161ac5921cd442b9e33ba84f835b821a16ad08701b2ff37b2f68a1616c",
		"0x638128e7cf4ec9712be7549992a53b0977977152289e6257ef7bd2d56cb1154f", "0x3cc575e1c72bbe247190e7b77c70463c2b2b76159b777b784c6ef6dc6073cb3b", "0xd4a3dbbae0c04d4307c5e00a5e05b66acc289f5d"},
	{"e2e arbitrum", 421614, "4ab4cba9042486bd33a2d2bd44fce6b2ce9332285553302ff8cf95b7d2253e39", "513fd42e827a92bf8dc0ee8e932d3ef2a0f1d0d628d05315ada4622194e1562c",
		"0x8b4191000d65005f1dfebe1c31ccc62362043d39a185626d03309bbb8af66ef5", "0xa920ef95f6efaed3276a661e8522b90eaa2f9f0f959fd9ea37e9bcaa0a728a69", "0xd4a3dbbae0c04d4307c5e00a5e05b66acc289f5d"},
	{"e2e sepolia", 11155111, "1836920851813e69e4dc9131ea6025d6e9eeac912418bde3f09d9e72cf4337ab", "f84925dbb13524eb86895282639f52bbdbbbade75e32074490259a674c409f51",
		"0x32ccc1ff2f45267fcc59edb2fdcd256982ce8e38d57c5e3ce58d4dfca5a94ff2", "0xca564d2b4ff947a95e132aad3925bf03574db27da2412ff8430ce893498fe32b", "0xd4a3dbbae0c04d4307c5e00a5e05b66acc289f5d"},
	{"backfill base", 84532, "a9cc3e51e3f77f3ade8e6ae80ea30bb3b606e67b0a5df17cba94a287bfe4ff22", "d4d5fe5ca51b390b851000cd698dcd63e831e380732e78c31020f056669662b2",
		"", "0x0087cbb50a8a32c2a70300303d43bcccfea1f76519878c2822dadb5545c4d50f", ""},
	{"backfill arbitrum", 421614, "01276d0f696c08053211c8979aa008654c3746e489773b17014f5d6498048de0", "7ccea38f02d1bc61f494c9b34cd3596dec991aa080148e7dc352673f69545ad6",
		"", "0x054c6ee9797a53ac90d50db9ef43f8673a93c18bb468489851fd78fd4c34e7e1", ""},
	{"backfill sepolia", 11155111, "ae2e55762cccfd77a34c61ba2daaeee9a6e93c01049659bbbc8295245d913349", "921ba99426a162383869481debaeb69f1a530300c6d2972c39f8c88d93aebc26",
		"", "0x00b37e4148f8b780f4d6f0bd1e8aa18f688dfab20ff53db774053bc748cb7ed6", ""},
	{"sentinel 185d8b0d", 84532, "4234049a4fa6b77919ecaf8fef0d233f84ffc11518780f64e5404fd283344ded", "fbb36e3c75a7d7581069cba4a652183131d7abae0b7cd444a3e8ecd959cf10e4",
		"", "0x6551d889ac8ee5e9c11060ff67dc7a4627d81fc61bdb751f61c0b1297c054833", ""},
	{"sentinel 693b7edb", 84532, "74f5273f0697c1aab623a2e83f5c78fdbff1cad91d879601a70d8dfd785f295a", "03fa0acf6d584a6f4cd8e30cba94406e2946ecea7e551ac8371dbcb29565428f",
		"", "0xf04da6910d6b17928d8cb41fbad1539debc3da0a89031a822dc0235b7f511bb2", ""},
}

func TestLiveLocateAnchorCreateOnProductionAnchors(t *testing.T) {
	r := NewEthAnchorTxReader()
	defer r.Close()
	for _, id := range []int64{84532, 421614, 11155111} {
		url := os.Getenv(fmt.Sprintf("CERTEN_TEST_RPC_%d", id))
		if url == "" {
			t.Fatalf("the live build requires CERTEN_TEST_RPC_%d", id)
		}
		pool, err := ethrpc.NewPool(ethrpc.ParseEndpoints(url), 5*time.Second, log.New(io.Discard, "", 0))
		if err != nil {
			t.Fatal(err)
		}
		r.pools[id] = pool
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	for _, row := range liveAnchorRows {
		t.Run(row.name, func(t *testing.T) {
			var bundle, root [32]byte
			b, _ := hex.DecodeString(row.bundle)
			rt, _ := hex.DecodeString(row.root)
			copy(bundle[:], b)
			copy(root[:], rt)

			verify, err := r.ReadAnchorTx(ctx, row.chainID, row.verifyTx)
			if err != nil || !verify.Succeeded {
				t.Fatalf("verify tx: %+v, %v", verify, err)
			}
			call, err := DecodeExecuteComprehensiveProof(verify.Input)
			if err != nil || call.BundleID != bundle || call.MerkleRoot != root {
				t.Fatalf("verify calldata does not name this anchor: %v", err)
			}
			loc, err := r.LocateAnchorCreate(ctx, row.chainID, verify.To, bundle, root, verify.BlockNumber)
			if err != nil {
				t.Fatalf("locate: %v", err)
			}
			if row.createTx != "" && !strings.EqualFold(loc.TxHash, row.createTx) {
				t.Fatalf("located %s, the row names %s", loc.TxHash, row.createTx)
			}
			create, err := r.ReadAnchorTx(ctx, row.chainID, loc.TxHash)
			if err != nil || !create.Succeeded || create.BlockNumber != loc.Block {
				t.Fatalf("create tx: %+v, %v", create, err)
			}
			cb, cr, err := createBatchAnchorArgs(create.Input)
			if err != nil || cb != bundle || cr != root {
				t.Fatalf("create calldata does not name this anchor: %v", err)
			}
			if create.To != verify.To || !strings.EqualFold(create.From, loc.Validator.Hex()) {
				t.Fatalf("create to=%s from=%s; verify to=%s, anchor records creator %s", create.To, create.From, verify.To, loc.Validator.Hex())
			}
			if row.wantCreateSender != "" && create.From != row.wantCreateSender {
				t.Fatalf("create sender %s, want %s", create.From, row.wantCreateSender)
			}
			t.Logf("%s: anchor %s create %s@%d by %s; verify %s@%d by %s", row.name, verify.To,
				loc.TxHash, loc.Block, create.From, row.verifyTx, verify.BlockNumber, verify.From)
		})
	}
}

// Every canonical anchor in a read-only export (CERTEN_TEST_ANCHOR_EXPORT: a JSON array of rows) is taken
// through the repair's own confirmation - verify transaction, located or named create transaction, same
// contract, signer equal to the anchor's recorded creator - so a production repair run is known to refuse
// nothing before it is run. Reports who sent what.
func TestLiveRepairConfirmsEveryExportedAnchor(t *testing.T) {
	path := os.Getenv("CERTEN_TEST_ANCHOR_EXPORT")
	if path == "" {
		t.Fatal("the live build requires CERTEN_TEST_ANCHOR_EXPORT")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Batch, Bundle, Root, Create, Atx, Verify, Source string
		Chain, Vblock, Ablock, Completed                 int64
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	r := NewEthAnchorTxReader()
	defer r.Close()
	for _, id := range []int64{84532, 421614, 11155111} {
		// Comma-separated: several providers, as production configures, so one's rate limit or retention
		// hands the read to the next.
		urls := ethrpc.ParseEndpoints(os.Getenv(fmt.Sprintf("CERTEN_TEST_RPC_%d", id)))
		if len(urls) == 0 {
			t.Fatalf("the live build requires CERTEN_TEST_RPC_%d", id)
		}
		pool, err := ethrpc.NewPool(urls, 5*time.Second, log.New(io.Discard, "", 0))
		if err != nil {
			t.Fatal(err)
		}
		r.pools[id] = pool
	}
	cfg := AnchorRepairConfig{Reader: r, Now: time.Now}
	var completedDiffers []string
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	senders := map[string]int{}
	var failures []string
	located, blockDiffers, vblockDiffers := 0, 0, 0
	for i, row := range rows {
		time.Sleep(400 * time.Millisecond) // public endpoints: stay under their per-second limits
		if !IsTransactionHash(row.Atx) {
			row.Atx = "" // what migration 00010 makes of a sentinel
		}
		root, _ := hex.DecodeString(row.Root)
		anchor := database.CanonicalAnchor{ChainID: row.Chain, BundleID: row.Bundle, Root: root,
			AnchorCreateTx: row.Create, AnchorTxHash: row.Atx, VerifyTx: row.Verify, VerifyBlock: row.Vblock, AnchorBlockNum: row.Ablock}
		fail := func(format string, args ...any) {
			failures = append(failures, fmt.Sprintf("%d %s chain %d bundle %s: %s", i, row.Batch, row.Chain, row.Bundle, fmt.Sprintf(format, args...)))
		}
		verify, refusal, err := confirmVerify(ctx, cfg, anchor)
		if err != nil || refusal != "" {
			fail("verify %s: %v %s", row.Verify, err, refusal)
			continue
		}
		creator := ""
		if anchor.AnchorCreateTx == "" {
			bundle, _ := bytes32FromHex(row.Bundle)
			var rt [32]byte
			copy(rt[:], root)
			loc, err := r.LocateAnchorCreate(ctx, row.Chain, verify.Contract, bundle, rt, uint64(verify.BlockNumber))
			if err != nil {
				fail("locate: %v", err)
				continue
			}
			if row.Atx != "" && !sameHex(row.Atx, loc.TxHash) {
				fail("anchor_tx_hash %s, located %s", row.Atx, loc.TxHash)
				continue
			}
			anchor.AnchorCreateTx, creator = loc.TxHash, strings.ToLower(loc.Validator.Hex())
			located++
		}
		facts, refusal, err := confirmAnchor(ctx, cfg, anchor)
		if err != nil || refusal != "" {
			fail("create %s: %v %s", anchor.AnchorCreateTx, err, refusal)
			continue
		}
		if !sameHex(facts.Contract, verify.Contract) || (creator != "" && !sameHex(facts.Sender, creator)) {
			fail("create at %s by %s; verify at %s; creator %s", facts.Contract, facts.Sender, verify.Contract, creator)
			continue
		}
		if row.Ablock != facts.BlockNumber {
			blockDiffers++
		}
		if row.Vblock != verify.BlockNumber {
			vblockDiffers++
		}
		// consensus_completed_at is the time the quorum was confirmed on-chain: the verify block's time.
		vt, err := poolCreateChain{r.pools[row.Chain]}.BlockTime(ctx, uint64(verify.BlockNumber))
		if err != nil {
			fail("verify block %d time: %v", verify.BlockNumber, err)
			continue
		}
		if int64(vt) != row.Completed {
			completedDiffers = append(completedDiffers, fmt.Sprintf("%s %s: consensus_completed_at %d, verify block %d at %d (%+ds)",
				row.Source, row.Batch, row.Completed, verify.BlockNumber, vt, row.Completed-int64(vt)))
		}
		senders[fmt.Sprintf("%d create %s", row.Chain, facts.Sender)]++
		senders[fmt.Sprintf("%d verify %s", row.Chain, verify.Sender)]++
	}
	t.Logf("%d anchors: %d create transactions located, %d anchor blocks and %d verify blocks the repair would fill or correct",
		len(rows), located, blockDiffers, vblockDiffers)
	t.Logf("%d rows whose consensus_completed_at is not their verify block's time", len(completedDiffers))
	for _, d := range completedDiffers {
		t.Logf("completed differs: %s", d)
	}
	for k, n := range senders {
		t.Logf("sender %s: %d", k, n)
	}
	for _, f := range failures {
		t.Errorf("would be refused: %s", f)
	}
}
