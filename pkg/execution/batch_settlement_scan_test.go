package execution

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// scanChain is a JSON-RPC node over a handful of blocks: enough of eth_getBlockByNumber (single and
// batched, by number and by tag), eth_getTransactionByHash and eth_getTransactionReceipt for the scan
// of earlier settlement windows to run against real encodings.
type scanChain struct {
	mu        sync.Mutex
	chainID   *big.Int
	times     []uint64 // block n's timestamp
	finalized uint64
	txs       map[common.Hash]*types.Transaction
	inBlock   map[common.Hash]uint64
	status    map[common.Hash]uint64
	nullBlock map[uint64]bool      // answer null for these blocks
	noReceipt map[common.Hash]bool // answer null for these receipts
	blockTxs  map[uint64][]common.Hash
	senders   map[common.Hash]common.Address
}

func (c *scanChain) header(n uint64) *types.Header {
	return &types.Header{Number: new(big.Int).SetUint64(n), Time: c.times[n], Difficulty: big.NewInt(0),
		GasLimit: 30_000_000, BaseFee: big.NewInt(1)}
}

func (c *scanChain) blockJSON(n uint64, full bool) interface{} {
	if int(n) >= len(c.times) || c.nullBlock[n] {
		return nil
	}
	raw, _ := json.Marshal(c.header(n))
	var m map[string]interface{}
	_ = json.Unmarshal(raw, &m)
	m["hash"] = c.header(n).Hash()
	txs := []interface{}{}
	for _, h := range c.blockTxs[n] {
		if full {
			txs = append(txs, map[string]interface{}{"hash": h, "from": c.senders[h], "to": c.txs[h].To()})
		} else {
			txs = append(txs, h)
		}
	}
	m["transactions"] = txs
	m["uncles"] = []interface{}{}
	return m
}

func (c *scanChain) handle(method string, params []json.RawMessage) interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch method {
	case "eth_chainId":
		return hexutil.EncodeBig(c.chainID)
	case "eth_getBlockByNumber":
		var tag string
		_ = json.Unmarshal(params[0], &tag)
		full := false
		if len(params) > 1 {
			_ = json.Unmarshal(params[1], &full)
		}
		var n uint64
		switch tag {
		case "latest":
			n = uint64(len(c.times) - 1)
		case "finalized":
			n = c.finalized
		default:
			n, _ = hexutil.DecodeUint64(tag)
		}
		return c.blockJSON(n, full)
	case "eth_getTransactionByHash":
		var h common.Hash
		_ = json.Unmarshal(params[0], &h)
		tx := c.txs[h]
		if tx == nil {
			return nil
		}
		raw, _ := json.Marshal(tx)
		var m map[string]interface{}
		_ = json.Unmarshal(raw, &m)
		m["blockNumber"] = hexutil.EncodeUint64(c.inBlock[h])
		m["blockHash"] = c.header(c.inBlock[h]).Hash()
		m["from"] = c.senders[h]
		m["transactionIndex"] = "0x0"
		return m
	case "eth_getTransactionReceipt":
		var h common.Hash
		_ = json.Unmarshal(params[0], &h)
		if c.txs[h] == nil || c.noReceipt[h] {
			return nil
		}
		r := &types.Receipt{Type: c.txs[h].Type(), Status: c.status[h], TxHash: h, Logs: []*types.Log{},
			BlockNumber: new(big.Int).SetUint64(c.inBlock[h]), BlockHash: c.header(c.inBlock[h]).Hash(), GasUsed: 21000,
			CumulativeGasUsed: 21000, EffectiveGasPrice: big.NewInt(1)}
		return r
	}
	return nil
}

func (c *scanChain) serve(t *testing.T) *ethclient.Client {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		type req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		answer := func(q req) map[string]interface{} {
			return map[string]interface{}{"jsonrpc": "2.0", "id": q.ID, "result": c.handle(q.Method, q.Params)}
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
			var qs []req
			_ = json.Unmarshal(body, &qs)
			out := make([]interface{}, 0, len(qs))
			for _, q := range qs {
				out = append(out, answer(q))
			}
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		var q req
		_ = json.Unmarshal(body, &q)
		_ = json.NewEncoder(w).Encode(answer(q))
	}))
	t.Cleanup(srv.Close)
	cl, err := ethclient.Dial(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

type scanFixture struct {
	chain   *scanChain
	orch    *BatchOrchestrator
	member  *PendingBatchIntent
	tree    *BatchTree
	att     anchorAttestation
	key     *ecdsa.PrivateKey
	settler common.Address
	roster  []common.Address
}

// newScanFixture: 60 blocks, one per 30s from T0; the attestation in block 2; finalized block 55.
func newScanFixture(t *testing.T) *scanFixture {
	key, _ := crypto.GenerateKey()
	settler := crypto.PubkeyToAddress(key.PublicKey)
	c := &scanChain{chainID: big.NewInt(11155111), finalized: 55, txs: map[common.Hash]*types.Transaction{},
		inBlock: map[common.Hash]uint64{}, status: map[common.Hash]uint64{}, nullBlock: map[uint64]bool{},
		noReceipt: map[common.Hash]bool{}, blockTxs: map[uint64][]common.Hash{}, senders: map[common.Hash]common.Address{}}
	for n := uint64(0); n < 60; n++ {
		c.times = append(c.times, uint64(odT0.Unix())+n*30-60)
	}
	m := odMember(1, odChain, 100)
	in, _ := m.LeafInput()
	tree, _ := BuildBatchTree(odChain, []BatchLeafInput{in}, 100)
	cl := c.serve(t)
	return &scanFixture{chain: c, member: m, tree: tree, key: key, settler: settler,
		roster: []common.Address{settler, odOtherAddr},
		orch:   &BatchOrchestrator{ecm: &EthereumContractManager{client: cl}, logf: func(string, ...interface{}) {}},
		att:    anchorAttestation{Block: 2, Time: time.Unix(int64(c.times[2]), 0), From: settler}}
}

// settle puts a settlement of the fixture's member, sent by the settler, into block n.
func (f *scanFixture) settle(t *testing.T, n uint64, nonce uint64, status uint64, expiresAt int64) common.Hash {
	t.Helper()
	leg := f.member.Legs[0]
	proof := contracts.AccountProofV7{AdiURL: f.member.ADIURL, AnchorId: f.tree.BundleID, MerkleProof: [][32]byte{},
		OperationID: f.member.OperationID, Timestamp: big.NewInt(int64(f.chain.times[n]) - 10),
		ExpiresAt: big.NewInt(expiresAt), Nonce: big.NewInt(0), RequiredLevel: requiredLevelForLegs(f.member.Legs)}
	data, err := certenAccountV7ABI.Pack("executeGovernanceProofDirect", leg.Target, leg.Value, leg.Data, proof)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.SignNewTx(f.key, types.LatestSignerForChainID(f.chain.chainID), &types.DynamicFeeTx{
		ChainID: f.chain.chainID, Nonce: nonce, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2),
		Gas: 500000, To: &f.member.Account, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	h := tx.Hash()
	f.chain.txs[h], f.chain.inBlock[h], f.chain.status[h], f.chain.senders[h] = tx, n, status, f.settler
	f.chain.blockTxs[n] = append(f.chain.blockTxs[n], h)
	return h
}

func (f *scanFixture) scan(t *testing.T, untilBlock uint64) (priorAttempt, bool, error) {
	t.Helper()
	return f.orch.priorSettlementAttempt(context.Background(), f.member, f.tree, f.att,
		time.Unix(int64(f.chain.times[untilBlock]), 0), f.roster)
}

// The case the takeover must never get wrong: the attester's settlement reverted and it recorded the
// failure. The taker finds that revert in the finalized chain, whoever is reachable.
func TestScan_FindsTheAttestersRecordedRevert(t *testing.T) {
	f := newScanFixture(t)
	h := f.settle(t, 20, 0, 0, int64(f.chain.times[40]))
	pa, found, err := f.scan(t, 50)
	if err != nil || !found || !pa.Reverted || pa.Tx != h.Hex() || pa.From != f.settler {
		t.Fatalf("found=%t attempt=%+v err=%v; want the attester's revert %s", found, pa, err, h.Hex())
	}
}

// A revert on the settlement's own timing never tried the member; its sender does not record it.
func TestScan_IgnoresATimingRevert(t *testing.T) {
	f := newScanFixture(t)
	f.settle(t, 20, 0, 0, int64(f.chain.times[19])) // expired before it mined
	if _, found, err := f.scan(t, 50); err != nil || found {
		t.Fatalf("found=%t err=%v; a timing revert is not an outcome", found, err)
	}
}

// A block the node answers null for is not an empty block: the scan stops and saves nothing past it,
// so the revert in it is found once the node has it.
func TestScan_NullBlockIsAGapNotAnEmptyBlock(t *testing.T) {
	f := newScanFixture(t)
	h := f.settle(t, 20, 0, 0, int64(f.chain.times[40]))
	f.chain.nullBlock[20] = true
	if _, found, err := f.scan(t, 50); err == nil || found {
		t.Fatalf("found=%t err=%v; a missing block must stop the scan", found, err)
	}
	if done := f.orch.scanned[f.tree.BundleID]; done >= 20 {
		t.Fatalf("progress saved to %d, past the missing block 20", done)
	}
	f.chain.nullBlock[20] = false
	if pa, found, err := f.scan(t, 50); err != nil || !found || pa.Tx != h.Hex() {
		t.Fatalf("after the gap closed: found=%t err=%v; want the revert", found, err)
	}
}

// A transaction from a finalized block whose receipt the node cannot find is a node's gap, not "no
// attempt".
func TestScan_MissingReceiptIsAGap(t *testing.T) {
	f := newScanFixture(t)
	h := f.settle(t, 20, 0, 0, int64(f.chain.times[40]))
	f.chain.noReceipt[h] = true
	if _, found, err := f.scan(t, 50); err == nil || found {
		t.Fatalf("found=%t err=%v; a missing receipt must stop the scan", found, err)
	}
	f.chain.noReceipt[h] = false
	if _, found, err := f.scan(t, 50); err != nil || !found {
		t.Fatalf("found=%t err=%v; want the revert once the receipt is served", found, err)
	}
}

// The scan never goes past the finalized block, whatever time it is asked to reach.
func TestScan_StopsAtTheFinalizedBlock(t *testing.T) {
	f := newScanFixture(t)
	f.settle(t, 57, 0, 0, int64(f.chain.times[59])) // mined after the finalized block 55
	if _, found, err := f.scan(t, 59); err != nil || found {
		t.Fatalf("found=%t err=%v; nothing past finalized may be read", found, err)
	}
	if done := f.orch.scanned[f.tree.BundleID]; done > 55 {
		t.Fatalf("progress saved to %d, past finalized 55", done)
	}
}

// Other members' settlements, other senders and successful settlements are told apart.
func TestScan_OnlyThisMembersSettlementCounts(t *testing.T) {
	f := newScanFixture(t)
	other := odMember(2, odChain, 101) // a different operation on the same account
	saved := f.member
	f.member = other
	f.settle(t, 10, 0, 0, int64(f.chain.times[40]))
	f.member = saved
	if _, found, err := f.scan(t, 50); err != nil || found {
		t.Fatalf("found=%t err=%v; another member's settlement is not this one's", found, err)
	}
	f2 := newScanFixture(t)
	h := f2.settle(t, 12, 0, 1, int64(f2.chain.times[40]))
	if pa, found, err := f2.scan(t, 50); err != nil || !found || pa.Reverted || pa.Tx != h.Hex() {
		t.Fatalf("found=%t attempt=%+v err=%v; want the successful settlement", found, pa, err)
	}
}
