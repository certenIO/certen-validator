package execution

import (
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
	"github.com/ethereum/go-ethereum/ethclient"
)

// RB7 Task 5 (T5-6): the search for the transaction that spent a member's leaf used a fixed 300,000-block back-search
// when the forward search from a floor found nothing. On Arbitrum Sepolia (about four blocks a second) that is about
// 21 hours, so a leaf spent earlier than that, with a first-seen floor that came later, read as "not in view" for ever.
// The floor is now the member's commit time, which no spend can precede, and the search runs forward only.

const (
	floorHead  = uint64(2_000_000)
	floorSpend = uint64(1_600_000) // 400,000 blocks (about 28 hours) before the head
)

// floorNode is a JSON-RPC node with an Arbitrum-like clock and one LeafConsumed log.
type floorNode struct {
	mu     sync.Mutex
	lowest uint64
	sender common.Address
	logTx  common.Hash
}

func (n *floorNode) serve(t *testing.T) *ethclient.Client {
	t.Helper()
	n.lowest = floorHead
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var q struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal(body, &q)
		var result interface{}
		n.mu.Lock()
		switch q.Method {
		case "eth_blockNumber":
			result = hexutil.EncodeUint64(floorHead)
		case "eth_getBlockByNumber":
			var tag string
			_ = json.Unmarshal(q.Params[0], &tag)
			num := floorHead
			if strings.HasPrefix(tag, "0x") {
				num, _ = hexutil.DecodeUint64(tag)
			}
			raw, _ := json.Marshal(&types.Header{Number: new(big.Int).SetUint64(num), Time: arbitrumLikeTime(num),
				Difficulty: big.NewInt(0), GasLimit: 30_000_000, BaseFee: big.NewInt(1)})
			var m map[string]interface{}
			_ = json.Unmarshal(raw, &m)
			m["transactions"], m["uncles"] = []interface{}{}, []interface{}{}
			result = m
		case "eth_getLogs":
			var f struct {
				From string `json:"fromBlock"`
				To   string `json:"toBlock"`
			}
			_ = json.Unmarshal(q.Params[0], &f)
			from, _ := hexutil.DecodeUint64(f.From)
			to, _ := hexutil.DecodeUint64(f.To)
			if from < n.lowest {
				n.lowest = from
			}
			logs := []interface{}{}
			if floorSpend >= from && floorSpend <= to {
				logs = append(logs, map[string]interface{}{"address": common.Address{}, "topics": []common.Hash{},
					"data": "0x", "blockNumber": hexutil.EncodeUint64(floorSpend), "transactionHash": n.logTx,
					"transactionIndex": "0x0", "blockHash": common.Hash{}, "logIndex": "0x0", "removed": false})
			}
			result = logs
		case "eth_getTransactionByHash":
			result = map[string]interface{}{"hash": n.logTx, "from": n.sender}
		}
		n.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": q.ID, "result": result})
	}))
	t.Cleanup(srv.Close)
	cl, err := ethclient.Dial(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

func floorFixture(t *testing.T) (*BatchOrchestrator, *floorNode, *PendingBatchIntent) {
	node := &floorNode{sender: common.HexToAddress("0x00000000000000000000000000000000000000a1"), logTx: common.HexToHash("0xbeef")}
	cl := node.serve(t)
	o := &BatchOrchestrator{ecm: &EthereumContractManager{client: cl}, logf: t.Logf, clock: newChainClock(odChain, cl)}
	m := odMember(1, odChain, 100)
	return o, node, m
}

func blockTime(n uint64) time.Time { return time.Unix(int64(arbitrumLikeTime(n)), 0) }

func TestLeafSpentHoursBeforeAFirstSeenFloorIsFoundFromTheCommitTime(t *testing.T) {
	o, node, m := floorFixture(t)
	m.CommitTime = blockTime(floorSpend - 1000)
	m.FirstSeen = blockTime(floorHead - 10) // this node saw the member long after another validator settled it
	tx, from, found, err := o.leafConsumedTx(t.Context(), m, [32]byte{})
	if err != nil || !found || from != node.sender || tx != node.logTx.Hex() {
		t.Fatalf("a spend 400,000 blocks before the head was not found: tx=%s from=%s found=%v err=%v", tx, from.Hex(), found, err)
	}
}

func TestLeafSearchNeverGoesBelowTheCommitTimeBlock(t *testing.T) {
	o, node, m := floorFixture(t)
	m.CommitTime = blockTime(1_900_000)
	_, _, found, err := o.leafConsumedTx(t.Context(), m, [32]byte{})
	if err != nil || found {
		t.Fatalf("no spend after the commit time: found=%v err=%v", found, err)
	}
	// The commit second less the 60 s margin: 60 s is 240 blocks, and blocks share a second (four per second).
	floor := uint64(1_900_000) - 240 - 4
	if node.lowest < floor || node.lowest > 1_900_000 {
		t.Fatalf("searched down to block %d; the floor is the commit block less a minute (about %d)", node.lowest, floor)
	}
}

func TestMemberWithNoCommitTimeAndNoAnchorHasNoFloorByName(t *testing.T) {
	o, node, m := floorFixture(t)
	m.FirstSeen = blockTime(floorHead - 10)
	_, _, found, err := o.leafConsumedTx(t.Context(), m, [32]byte{})
	if err == nil || found || !strings.Contains(err.Error(), "no commit time") {
		t.Fatalf("a member with no floor must be refused by name, not guessed: found=%v err=%v", found, err)
	}
	if node.lowest != floorHead {
		t.Fatalf("a log search ran (down to block %d) for a member with no floor", node.lowest)
	}
}
