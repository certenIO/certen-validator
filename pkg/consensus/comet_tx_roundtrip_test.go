package consensus

// C5-D1: the transaction CERTEN's consensus carries the proof-v2 document in must pass EVERY limit between the proposer
// and a committed block, up to the mempool's max_tx_bytes. Measured live on 2026-10-18: every intent certificate whose
// document was large was certified and then refused at the proposer's own CometBFT RPC with
//
//	RPC error -32600 - Invalid Request: error reading request body: http: request body too large
//
// because rpc.max_body_bytes (1,000,000) binds before mempool.max_tx_bytes (1 MiB) once the transaction is base64
// encoded inside the JSON-RPC body (4 bytes per 3, so about 740 KB of transaction).
//
// These tests use the engine as production does (NewRealCometBFTEngine over a stock CometBFT configuration, the real
// HTTP client of the engine, a real node with its RPC server, mempool and consensus) and only symbols that exist at
// the base commit, so they fail there by behaviour, not by compilation.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"fmt"
	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/config"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	cmthttp "github.com/cometbft/cometbft/rpc/client/http"
	"github.com/cometbft/cometbft/store"
	cmttypes "github.com/cometbft/cometbft/types"
)

// sinkApp admits and commits every transaction: the tests are about the path TO the application, not about what an
// application does with a transaction.
type sinkApp struct{ abcitypes.BaseApplication }

// soloEngine is a RealCometBFTEngine over one in-process validator with a stock CometBFT configuration
// (config.DefaultConfig, as the three production builders start from), its own RPC server on a loopback port, and an
// in-memory database. The engine is started by the caller (its first broadcast starts it).
func soloEngine(t *testing.T, app abcitypes.Application) *RealCometBFTEngine {
	t.Helper()
	home := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.SetRoot(home)
	config.EnsureRoot(home)
	cfg.DBBackend = "memdb"
	cfg.P2P.ListenAddress = fmt.Sprintf("tcp://127.0.0.1:%d", freePort(t))
	cfg.RPC.ListenAddress = fmt.Sprintf("tcp://127.0.0.1:%d", freePort(t))
	cfg.Consensus.CreateEmptyBlocks = false
	cfg.Consensus.TimeoutPropose = 1500 * time.Millisecond
	cfg.Consensus.TimeoutCommit = 200 * time.Millisecond
	cfg.P2P.PexReactor = false // one node, no peers to find (and no address book written at Stop)
	cfg.TxIndex.Indexer = "null"
	cfg.Instrumentation.Prometheus = false

	priv := cmted25519.GenPrivKey()
	genesis := &cmttypes.GenesisDoc{
		ChainID: "tx-limit-test", GenesisTime: time.Now().UTC(), ConsensusParams: cmttypes.DefaultConsensusParams(),
		InitialHeight: 1,
		Validators:    []cmttypes.GenesisValidator{{PubKey: priv.PubKey(), Power: 10, Name: "solo"}},
	}
	if err := genesis.ValidateAndComplete(); err != nil {
		t.Fatal(err)
	}
	if err := genesis.SaveAs(cfg.GenesisFile()); err != nil {
		t.Fatal(err)
	}
	privval.NewFilePV(priv, cfg.PrivValidatorKeyFile(), cfg.PrivValidatorStateFile()).Save()
	nodeKey := &p2p.NodeKey{PrivKey: cmted25519.GenPrivKey()}
	if err := nodeKey.SaveAs(cfg.NodeKeyFile()); err != nil {
		t.Fatal(err)
	}

	engine, err := NewRealCometBFTEngine(cfg, app, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Cleanup(func() {
		// The node's routines (the address book's last save among them) finish after Stop returns; the temporary
		// directory is removed only once they have.
		_ = engine.Stop()
		engine.node.Wait()
	})
	return engine
}

// randomTx is a transaction of exactly n random bytes (random so no two are the same transaction to the mempool cache).
func randomTx(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// blockHolding is the height of the block in bs that holds tx, or 0.
func blockHolding(bs *store.BlockStore, tx []byte) int64 {
	for h := bs.Base(); h > 0 && h <= bs.Height(); h++ {
		blk := bs.LoadBlock(h)
		if blk == nil {
			continue
		}
		for _, got := range blk.Data.Txs {
			if bytes.Equal(got, tx) {
				return h
			}
		}
	}
	return 0
}

// A transaction of 900,000 bytes and one of exactly max_tx_bytes go through the engine's real client path - the
// JSON-RPC body, the RPC server, the mempool and the application's CheckTx - are admitted, gossiped into a block and
// committed; one byte over is refused by the node BY NAME (the mempool's "Tx too large"), which shows the RPC body
// limit is no longer what stops it.
func TestARealEngineAdmitsAndCommitsTransactionsUpToMaxTxBytes(t *testing.T) {
	engine := soloEngine(t, &sinkApp{})
	maxTx := engine.cometCfg.Mempool.MaxTxBytes
	if maxTx != 1<<20 {
		t.Fatalf("mempool.max_tx_bytes is %d; the evidence budgets (pkg/proof/v2/xbudget.go) are written against 1 MiB", maxTx)
	}

	for _, size := range []int{900_000, maxTx} {
		tx := randomTx(t, size)
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		err := engine.BroadcastAppTxSync(ctx, tx)
		cancel()
		if err != nil {
			t.Fatalf("a transaction of %d bytes (max_tx_bytes %d) was not admitted: %v", size, maxTx, err)
		}
		deadline := time.Now().Add(30 * time.Second)
		for blockHolding(engine.node.BlockStore(), tx) == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("the admitted transaction of %d bytes was not committed in 30s", size)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// One byte over max_tx_bytes, straight at the node's RPC (bypassing anything the engine checks first): the node's
	// own refusal is the mempool's, by name, with both numbers - not "request body too large".
	over := randomTx(t, maxTx+1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := engine.rpcClient.BroadcastTxSync(ctx, over)
	if err == nil {
		t.Fatalf("a transaction of %d bytes (max_tx_bytes %d + 1) was admitted", maxTx+1, maxTx)
	}
	want := fmt.Sprintf("Tx too large. Max size is %d, but got %d", maxTx, maxTx+1)
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("one byte over max_tx_bytes was refused as %q; want the mempool's named refusal %q", err.Error(), want)
	}
}

// paddedBlockOfSize is a ValidatorBlock whose JSON encoding is exactly size bytes, grown through a field no commitment
// covers (the execution proof's signatures).
func paddedBlockOfSize(t *testing.T, op string, size int) (*ValidatorBlock, []byte) {
	t.Helper()
	vb := decodeBlock(t, persistTestBlockJSON(t, op, "G2", "validator-1"))
	vb.ExecutionProof.ValidatorSignatures = append(vb.ExecutionProof.ValidatorSignatures, "")
	base, err := json.Marshal(vb)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) >= size {
		t.Fatalf("the smallest block is %d bytes, over the %d asked for", len(base), size)
	}
	vb.ExecutionProof.ValidatorSignatures[len(vb.ExecutionProof.ValidatorSignatures)-1] = strings.Repeat("a", size-len(base))
	enc, err := json.Marshal(vb)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != size {
		t.Fatalf("padded block is %d bytes, want %d", len(enc), size)
	}
	return vb, enc
}

// The same through a network: four validators on loopback, each a real CometBFT node running the production ValidatorApp
// (the helper of the rotation rehearsal), a ValidatorBlock of 900,000 bytes and one of exactly max_tx_bytes offered to
// one node's RPC. The mempool gossips it, the proposer puts it in a block, the block's parts reach the others, and every
// node has it in its block store - a transaction of that size crosses the mempool reactor's and the consensus reactor's
// channels too.
func TestAFourNodeNetworkGossipsAndCommitsAValidatorBlockOfMaxTxBytes(t *testing.T) {
	f := newRotationFixture()
	var adminEnv []string
	for _, id := range []string{"ops-1", "ops-2", "ops-3"} {
		adminEnv = append(adminEnv, id+":"+f.policy.AdminKeys[id])
	}
	t.Setenv("CERTEN_ENTITLEMENT_MODE", "off")
	t.Setenv("CERTEN_ENTITLEMENT_ADMIN_KEYS", strings.Join(adminEnv, ","))
	t.Setenv("CERTEN_ENTITLEMENT_ADMIN_THRESHOLD", "2")
	t.Setenv("CERTEN_BLOCK_RETENTION", "0")

	nodes, _, _, _ := startRehearsalNetworkWith(t, f, 4, true)
	client, err := cmthttp.New(nodes[0].rpcURL, "/websocket")
	if err != nil {
		t.Fatal(err)
	}
	for i, size := range []int{900_000, 1 << 20} {
		_, tx := paddedBlockOfSize(t, fmt.Sprintf("op-gossip-%d", i), size)
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		res, err := client.BroadcastTxSync(ctx, tx)
		cancel()
		if err != nil {
			t.Fatalf("a ValidatorBlock of %d bytes was not admitted by the node's RPC: %v", size, err)
		}
		t.Logf("size %d: CheckTx code=%d log=%q", size, res.Code, res.Log)
		if res.Code != 0 {
			t.Fatalf("a ValidatorBlock of %d bytes was refused by CheckTx: code %d %s", size, res.Code, res.Log)
		}
		for _, n := range nodes {
			n := n
			waitNetwork(t, fmt.Sprintf("%s to hold the %d-byte block", n.name, size), 60*time.Second, func() bool {
				return blockHolding(n.node.BlockStore(), tx) != 0
			})
		}
	}
}
