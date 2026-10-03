package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	cmtcfg "github.com/cometbft/cometbft/config"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	nm "github.com/cometbft/cometbft/node"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	"github.com/cometbft/cometbft/proxy"
	"github.com/cometbft/cometbft/rpc/client/local"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// RB3-F95 phase 2 REHEARSAL: the rotation runbook, step by step, on a real CometBFT network of four
// in-process validators running this ValidatorApp. What it proves:
//
//  1. a rotation signed by the admin quorum commits and CometBFT moves the slot to the new key two blocks
//     later, with no restart of anything;
//  2. the chain keeps committing while the rotated validator is not yet running its new key;
//  3. a second rotation is REFUSED until the first one's new key has signed a block - so two validators
//     can never be mid-rotation at once, however rotations are submitted;
//  4. the operator's swap - move the old key file aside (never delete it) and start the node with the new
//     key's seed - brings the validator back on its new key through ensureCometKeys, the production path;
//  5. the chain records the adoption, then accepts the next rotation;
//  6. every node stays on one chain throughout (a node whose app hash diverged would halt).

type rehearsalNode struct {
	name string
	home string
	cfg  *cmtcfg.Config
	kv   *memKV // the node's application ledger; survives the node's restart, as the volume does
	// CometBFT's own stores (block store, state), kept across the node's restart the same way. In memory
	// because stopping a node in-process closes its LevelDB under a still-running peer routine (a
	// CometBFT v0.38.0 race that panics the whole process); production restarts are a new process.
	dbs    map[string]dbm.DB
	app    *ValidatorApp
	node   *nm.Node
	client *local.Local
	// rpcURL is the node's CometBFT RPC when the network serves one (startRehearsalNetworkWith), else "".
	rpcURL string
}

// freePort returns a port a node can listen on, chosen BELOW every OS's ephemeral range (Windows 49152-65535, Linux
// 32768-60999 by default). A port from ":0" is ephemeral: once released, the next outbound connection anywhere on the
// machine may take it as its source port before the node binds it - under a loaded run one in sixty networks failed
// to start that way (RB5-F24). Ports in [20000, 32000) are never handed out as source ports, so only an explicit
// listener can hold one, and this one is checked free.
func freePort(t *testing.T) int {
	t.Helper()
	usedPortsMu.Lock()
	defer usedPortsMu.Unlock()
	start := 20000 + int(time.Now().UnixNano()%12000)
	for i := 0; i < 12000; i++ {
		port := 20000 + (start-20000+i)%12000
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		l.Close()
		if !usedPorts[port] {
			usedPorts[port] = true
			return port
		}
	}
	t.Fatal("no free port below the ephemeral ranges")
	return 0
}

// usedPorts keeps one test process from handing the same port to two nodes.
var (
	usedPortsMu sync.Mutex
	usedPorts   = map[int]bool{}
)

func waitNetwork(t *testing.T, what string, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (n *rehearsalNode) start(t *testing.T, genesis *cmttypes.GenesisDoc) {
	t.Helper()
	app := NewValidatorApp(ledger.NewLedgerStore(n.kv), "validator-chain-"+n.name)
	app.logger = log.New(io.Discard, "", 0)
	if err := app.RecoverState(); err != nil {
		t.Fatalf("%s: recover: %v", n.name, err)
	}
	if err := app.SetGenesis(genesis); err != nil {
		t.Fatal(err)
	}
	pv := privval.LoadFilePV(n.cfg.PrivValidatorKeyFile(), n.cfg.PrivValidatorStateFile())
	nodeKey, err := p2p.LoadNodeKey(n.cfg.NodeKeyFile())
	if err != nil {
		t.Fatal(err)
	}
	node, err := nm.NewNode(n.cfg, pv, nodeKey, proxy.NewLocalClientCreator(app),
		nm.DefaultGenesisDocProviderFunc(n.cfg), n.dbProvider,
		nm.DefaultMetricsProvider(n.cfg.Instrumentation), rehearsalLogger(n.name))
	if err != nil {
		t.Fatalf("%s: new node: %v", n.name, err)
	}
	if err := node.Start(); err != nil {
		t.Fatalf("%s: start: %v", n.name, err)
	}
	n.app, n.node, n.client = app, node, local.New(node)
}

func (n *rehearsalNode) dbProvider(ctx *cmtcfg.DBContext) (dbm.DB, error) {
	if n.dbs == nil {
		n.dbs = map[string]dbm.DB{}
	}
	if db, ok := n.dbs[ctx.ID]; ok {
		return db, nil
	}
	db := dbm.NewMemDB()
	n.dbs[ctx.ID] = db
	return db, nil
}

// rehearsalLogger shows CometBFT's errors (and, with CERTEN_REHEARSAL_LOG=info, everything) - a halted
// network has to say why.
func rehearsalLogger(name string) cmtlog.Logger {
	l := cmtlog.NewTMLogger(cmtlog.NewSyncWriter(os.Stderr)).With("node", name)
	level := "error"
	if v := os.Getenv("CERTEN_REHEARSAL_LOG"); v != "" {
		level = v
	}
	opt, err := cmtlog.AllowLevel(level)
	if err != nil {
		opt, _ = cmtlog.AllowLevel("error")
	}
	return cmtlog.NewFilter(l, opt)
}

func (n *rehearsalNode) stop(t *testing.T) {
	t.Helper()
	if n.node == nil {
		return
	}
	if err := n.node.Stop(); err != nil {
		t.Fatalf("%s: stop: %v", n.name, err)
	}
	n.node.Wait()
	n.node = nil
}

func (n *rehearsalNode) height() int64 {
	if n.node == nil {
		return 0
	}
	return n.node.BlockStore().Height()
}

func TestRotationRehearsalOnALiveNetwork(t *testing.T) {
	f := newRotationFixture()
	var adminEnv []string
	for _, id := range []string{"ops-1", "ops-2", "ops-3"} {
		adminEnv = append(adminEnv, id+":"+f.policy.AdminKeys[id])
	}
	t.Setenv("CERTEN_ENTITLEMENT_MODE", "off")
	t.Setenv("CERTEN_ENTITLEMENT_ADMIN_KEYS", strings.Join(adminEnv, ","))
	t.Setenv("CERTEN_ENTITLEMENT_ADMIN_THRESHOLD", "2")
	t.Setenv("CERTEN_BLOCK_RETENTION", "0")

	const size = 4
	nodes, genesis, keys, tick := startRehearsalNetwork(t, f, size)

	submit := func(via *rehearsalNode, tx *ValidatorRotationTx) (uint32, string, int64) {
		t.Helper()
		t.Logf("submit v%d via %s at heights %d/%d/%d/%d", tx.Version, via.name, nodes[0].height(), nodes[1].height(), nodes[2].height(), nodes[3].height())
		res, err := via.client.BroadcastTxCommit(context.Background(), cmttypes.Tx(rotJSON(t, tx)))
		if err != nil {
			t.Fatalf("broadcast: %v (heights now %d/%d/%d/%d)", err, nodes[0].height(), nodes[1].height(), nodes[2].height(), nodes[3].height())
		}
		if res.CheckTx.Code != 0 {
			return res.CheckTx.Code, res.CheckTx.Log, 0
		}
		return res.TxResult.Code, res.TxResult.Log, res.Height
	}
	inSet := func(via *rehearsalNode, height int64, pub ed25519.PublicKey) bool {
		t.Helper()
		vals, err := via.client.Validators(context.Background(), &height, nil, nil)
		if err != nil {
			t.Fatalf("validators at %d: %v", height, err)
		}
		addr := cmted25519.PubKey(pub).Address()
		for _, v := range vals.Validators {
			if v.Address.String() == addr.String() {
				return true
			}
		}
		return false
	}

	// 1. Rotate v2 to a key backed by a fresh secret seed.
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	newKey := ed25519.PrivateKey(keyFromSeed(seed, labelPrivval))
	newPub := newKey.Public().(ed25519.PublicKey)
	code, logText, h := submit(nodes[0], f.rotation(1, keys[2], newKey, "ops-1", "ops-2"))
	if code != 0 {
		t.Fatalf("rotation refused: %d %s", code, logText)
	}
	// Accepted at h; the proof block h+1 follows by itself; the chain then idles until a tick.
	waitNetwork(t, "the proof block after the rotation", 60*time.Second, func() bool { return nodes[0].height() >= h+1 })
	for nodes[0].height() < h+3 {
		tick(nodes[0], 1)
	}
	if inSet(nodes[0], h+2, keys[2].Public().(ed25519.PublicKey)) || !inSet(nodes[0], h+2, newPub) {
		t.Fatalf("the slot did not move to the new key at height %d", h+2)
	}
	if !inSet(nodes[0], h+1, keys[2].Public().(ed25519.PublicKey)) {
		t.Fatalf("the old key left before height %d", h+2)
	}

	// 2. v2 still runs its old key, so it signs nothing that counts - and the chain goes on with three.
	before := nodes[0].height()
	tick(nodes[1], 3)
	waitNetwork(t, "the chain to go on without the rotated validator", 30*time.Second, func() bool { return nodes[0].height() >= before+3 })

	// 3. Another validator cannot be rotated while v2 is not on its new key.
	// Its own 32-byte seed. (A truncation of v2's seed is not another key: HMAC zero-pads a short key, so
	// seed[:31] backs v2's new key whenever seed[31] is 0 - one run in 256 rotated "another" validator to a key
	// already in the set, RB5-F24.)
	otherSeed := make([]byte, 32)
	if _, err := rand.Read(otherSeed); err != nil {
		t.Fatal(err)
	}
	other := ed25519.PrivateKey(keyFromSeed(otherSeed, labelPrivval))
	if code, logText, _ := submit(nodes[1], f.rotation(2, keys[3], other, "ops-1", "ops-2")); code == 0 ||
		!strings.Contains(logText, "has not been adopted") {
		t.Fatalf("a second validator was rotated while the first is mid-rotation: %d %s", code, logText)
	}

	// 4. The operator's swap, exactly as the runbook: stop v2, move the old key file aside, start with the
	// new key's seed. ensureCometKeys writes the key from the seed and keeps the signing state.
	nodes[2].stop(t)
	dropStalePeer(t, nodes, 2)
	oldKeyFile := nodes[2].cfg.PrivValidatorKeyFile()
	if err := os.Rename(oldKeyFile, oldKeyFile+".retired-v1"); err != nil {
		t.Fatal(err)
	}
	rep, err := ensureCometKeys(nodes[2].home, "v2", rotChain, env(map[string]string{envPrivvalSeed: hex.EncodeToString(seed)}), nil)
	if err != nil {
		t.Fatalf("ensureCometKeys: %v", err)
	}
	if !rep.PrivvalFromSeed || !rep.PrivvalPubKey.Equals(cmted25519.PubKey(newPub)) {
		t.Fatalf("the node did not come back on its new key: %+v", rep)
	}
	if _, err := os.Stat(oldKeyFile + ".retired-v1"); err != nil {
		t.Fatalf("the retired key file is gone: %v", err)
	}
	nodes[2].start(t, genesis)

	// 5. v2 catches up and signs with its new key; the chain records the adoption and accepts the next
	// rotation.
	adopted := func() bool {
		l, err := ledger.NewLedgerStore(nodes[0].kv).LoadValidatorRotations()
		return err == nil && len(l.Rotations) == 1 && l.Rotations[0].AdoptedHeight > 0
	}
	// On an idle chain adoption needs blocks: one the new key signs, and a later one carrying that commit. Only a
	// node IN CONSENSUS signs: v2 first block-syncs, and its height reaches the others' while it is still doing so -
	// ticks counted from then were spent before it could sign at all (RB5-F24: one full-suite run in 12 used all
	// twenty on a still-syncing v2). From the switch to consensus the new key's signature lands within 2-3 blocks
	// (measured over 12 runs under load), so twenty is a bound on adoption, not on the restart.
	joined := func() bool {
		return nodes[2].height() >= nodes[0].height() && !nodes[2].node.ConsensusReactor().WaitSync()
	}
	for deadline := time.Now().Add(90 * time.Second); !joined(); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			var peers []string
			for _, n := range nodes {
				peers = append(peers, fmt.Sprintf("%s:%d", n.name, n.node.Switch().Peers().Size()))
			}
			t.Fatalf("v2 did not join consensus in 90s: heights %d/%d/%d/%d, v2 blocksyncing=%v, peers %v",
				nodes[0].height(), nodes[1].height(), nodes[2].height(), nodes[3].height(),
				nodes[2].node.ConsensusReactor().WaitSync(), peers)
		}
	}
	newAddr := cmted25519.PubKey(newPub).Address()
	var commits []string // per tick: the commit's height, whether it holds the new key, how many signed
	for i := 0; i < 20 && !adopted(); i++ {
		tick(nodes[0], 1)
		h := nodes[0].height()
		if c, err := nodes[0].client.Commit(context.Background(), &h); err == nil {
			signed, hasNew := 0, false
			for _, s := range c.Commit.Signatures {
				if s.BlockIDFlag == cmttypes.BlockIDFlagCommit {
					signed++
					hasNew = hasNew || bytes.Equal(s.ValidatorAddress, newAddr)
				}
			}
			commits = append(commits, fmt.Sprintf("%d:%d/%v", h, signed, hasNew))
		}
	}
	if !adopted() {
		pv, _ := nodes[2].node.PrivValidator().GetPubKey()
		var rs string
		if st, err := nodes[2].client.ConsensusState(context.Background()); err == nil {
			rs = string(st.RoundState)
		}
		t.Fatalf("twenty blocks after v2 joined consensus, the new key's signature was not recorded (heights %d/%d/%d/%d); "+
			"commits height:signed/holds-new-key %v; v2 privval %s (new key %s), v2 peers %d, v2 at %s",
			nodes[0].height(), nodes[1].height(), nodes[2].height(), nodes[3].height(), commits,
			pv.Address(), newAddr, nodes[2].node.Switch().Peers().Size(), rs)
	}
	code, logText, h2 := submit(nodes[1], f.rotation(2, keys[3], other, "ops-1", "ops-3"))
	if code != 0 {
		t.Fatalf("the next rotation after adoption was refused: %d %s", code, logText)
	}

	// 6. One chain: every node, v2 included, commits past the second rotation.
	tick(nodes[0], 3)
	waitNetwork(t, "every node to commit past the second rotation", 90*time.Second, func() bool {
		for _, n := range nodes {
			if n.height() < h2+3 {
				return false
			}
		}
		return true
	})
	for _, n := range nodes {
		l, err := ledger.NewLedgerStore(n.kv).LoadValidatorRotations()
		if err != nil || len(l.Rotations) != 2 {
			t.Fatalf("%s's rotation log: (%+v, %v)", n.name, l, err)
		}
	}

	// 7. The whole fleet restarts (a deploy): every node hands CometBFT the height and app hash it
	// committed, with both rotations in its history, and the chain carries on. v3 is still on its old key
	// (its rotation is pending), so three of four sign - enough.
	for _, n := range nodes {
		n.stop(t)
	}
	for _, n := range nodes {
		n.start(t, genesis)
	}
	restartedAt := nodes[0].height()
	waitNetwork(t, "the restarted fleet to connect", 90*time.Second, func() bool {
		for _, n := range nodes {
			if n.node.Switch().Peers().Size() < size-1 {
				return false
			}
		}
		return true
	})
	tick(nodes[0], 3)
	waitNetwork(t, "the restarted fleet to commit", 90*time.Second, func() bool {
		for _, n := range nodes {
			if n.height() < restartedAt+3 {
				return false
			}
		}
		return true
	})
	for _, n := range nodes {
		st, err := ledger.NewLedgerStore(n.kv).LoadABCIState()
		if err != nil || st.ExecutionRulesVersion != executionRulesV8 {
			t.Fatalf("%s: state after the rotations is stamped (%+v, %v); want v8", n.name, st, err)
		}
	}
}

// dropStalePeer does for a node stopped in this process what the process exit of a production validator does: the
// connections others still hold to it are closed. CometBFT (v0.38 p2p/switch.go addPeer) accepts a peer that dials
// in while the switch is stopping, logs "Won't start a peer - switch is not running" and returns without closing
// the connection; in a separate process the exit closes it, here it stays open, the others keep a live "peer" with
// the stopped node's id, and refuse the restarted node's dials as a duplicate until their ping times out (~105 s).
// That left a restarted v2 with no peers in 1 of 40 runs (RB5-F24). Every entry for the stopped node is stale: it
// is not running.
func dropStalePeer(t *testing.T, nodes []*rehearsalNode, stopped int) {
	t.Helper()
	key, err := p2p.LoadNodeKey(nodes[stopped].cfg.NodeKeyFile())
	if err != nil {
		t.Fatal(err)
	}
	id := key.ID()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		for i, n := range nodes {
			if i == stopped || n.node == nil {
				continue
			}
			if p := n.node.Switch().Peers().Get(id); p != nil {
				n.node.Switch().StopPeerForError(p, "the node it names was stopped (the connection a process exit closes)")
			}
		}
	}
}

// startRehearsalNetwork starts size in-process validators of f on rotChain - real CometBFT networking, the production
// ValidatorApp, empty blocks off as in production - waits for the first block, makes two more, and returns the nodes,
// the genesis, the validators' keys and tick (blocks on demand, as `validator-rotate tick` does). The caller sets the
// sealed policy's environment first.
func startRehearsalNetwork(t *testing.T, f *rotationFixture, size int) ([]*rehearsalNode, *cmttypes.GenesisDoc,
	[]ed25519.PrivateKey, func(via *rehearsalNode, n int)) {
	t.Helper()
	return startRehearsalNetworkWith(t, f, size, false)
}

// startRehearsalNetworkWith is startRehearsalNetwork; with rpc, every node also serves CometBFT's RPC on a loopback port
// (rehearsalNode.rpcURL), so the operator tools can be run against the network as against the fleet.
func startRehearsalNetworkWith(t *testing.T, f *rotationFixture, size int, rpc bool) ([]*rehearsalNode, *cmttypes.GenesisDoc,
	[]ed25519.PrivateKey, func(via *rehearsalNode, n int)) {
	t.Helper()
	genesis := &cmttypes.GenesisDoc{
		ChainID: rotChain, GenesisTime: time.Now().UTC(), ConsensusParams: cmttypes.DefaultConsensusParams(),
		InitialHeight: 1,
	}
	keys := make([]ed25519.PrivateKey, size)
	nodes := make([]*rehearsalNode, size)
	ports := make([]int, size)
	for i := range nodes {
		keys[i] = f.validators[i]
		ports[i] = freePort(t)
		genesis.Validators = append(genesis.Validators, cmttypes.GenesisValidator{
			PubKey: cmted25519.PubKey(keys[i].Public().(ed25519.PublicKey)), Power: 10, Name: fmt.Sprintf("v%d", i)})
	}
	if err := genesis.ValidateAndComplete(); err != nil {
		t.Fatal(err)
	}

	var peers []string
	for i := range nodes {
		home := t.TempDir()
		cfg := cmtcfg.DefaultConfig()
		cfg.SetRoot(home)
		cmtcfg.EnsureRoot(home)
		// Realistic timeouts, scaled down: CometBFT's test values (tens of milliseconds) are tighter than four
		// fsyncing nodes on one machine can meet, and the rounds then climb without end.
		cfg.Consensus = cmtcfg.DefaultConsensusConfig()
		cfg.Consensus.TimeoutPropose = 1500 * time.Millisecond
		cfg.Consensus.TimeoutPrevote = 500 * time.Millisecond
		cfg.Consensus.TimeoutPrecommit = 500 * time.Millisecond
		cfg.Consensus.TimeoutCommit = 200 * time.Millisecond
		// As production (bft_integration.go): blocks only for transactions and the proof block after an
		// app-hash change. Everything below that needs blocks makes them with ticks, as the runbook does.
		cfg.Consensus.CreateEmptyBlocks = false
		cfg.Consensus.SetWalFile(filepath.Join(home, "data", "cs.wal", "wal"))
		cfg.P2P.ListenAddress = fmt.Sprintf("tcp://127.0.0.1:%d", ports[i])
		cfg.P2P.AllowDuplicateIP, cfg.P2P.AddrBookStrict, cfg.P2P.PexReactor = true, false, false
		cfg.RPC.ListenAddress = ""
		rpcURL := ""
		if rpc {
			rpcPort := freePort(t)
			cfg.RPC.ListenAddress = fmt.Sprintf("tcp://127.0.0.1:%d", rpcPort)
			rpcURL = fmt.Sprintf("http://127.0.0.1:%d", rpcPort)
		}
		cfg.TxIndex.Indexer = "null"
		cfg.Instrumentation.Prometheus = false
		if err := genesis.SaveAs(cfg.GenesisFile()); err != nil {
			t.Fatal(err)
		}
		privval.NewFilePV(cmted25519.PrivKey(keys[i]), cfg.PrivValidatorKeyFile(), cfg.PrivValidatorStateFile()).Save()
		nodeKey := &p2p.NodeKey{PrivKey: cmted25519.GenPrivKey()}
		if err := nodeKey.SaveAs(cfg.NodeKeyFile()); err != nil {
			t.Fatal(err)
		}
		peers = append(peers, fmt.Sprintf("%s@127.0.0.1:%d", nodeKey.ID(), ports[i]))
		nodes[i] = &rehearsalNode{name: fmt.Sprintf("v%d", i), home: home, cfg: cfg, kv: newMemKV(), rpcURL: rpcURL}
	}
	for i, n := range nodes {
		var others []string
		for j, p := range peers {
			if j != i {
				others = append(others, p)
			}
		}
		n.cfg.P2P.PersistentPeers = strings.Join(others, ",")
		n.start(t, genesis)
	}
	t.Cleanup(func() {
		for _, n := range nodes {
			n.stop(t)
		}
	})
	waitNetwork(t, "the network to commit its first block", 60*time.Second, func() bool { return nodes[0].height() >= 1 })

	// tick makes the chain produce n blocks, as `validator-rotate tick` does.
	tick := func(via *rehearsalNode, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			nonce := make([]byte, 16)
			if _, err := rand.Read(nonce); err != nil {
				t.Fatal(err)
			}
			res, err := via.client.BroadcastTxCommit(context.Background(),
				cmttypes.Tx(rotJSON(t, ChainTickTx{Kind: ChainTickKind, Nonce: hex.EncodeToString(nonce)})))
			if err != nil {
				t.Fatalf("tick: %v", err)
			}
			if res.CheckTx.Code != 0 || res.TxResult.Code != 0 {
				t.Fatalf("tick refused: %s %s", res.CheckTx.Log, res.TxResult.Log)
			}
		}
	}
	tick(nodes[0], 2)

	return nodes, genesis, keys, tick
}
