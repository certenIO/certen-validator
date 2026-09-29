package execution

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// RB3-F33, forward: a validator whose createBatchAnchor finds the anchor already there - another validator
// created it - records the transaction that did, located on chain and read back, instead of nothing.

// createdAnchorChain is a JSON-RPC chain holding one anchor, created by one signed createBatchAnchor
// transaction in block createdIn, with its BatchAnchorCreated log.
type createdAnchorChain struct {
	chainID   int64
	anchor    common.Address
	times     []uint64
	createdIn uint64
	creator   common.Address // what anchors(bundle).validator records
	tx        *types.Transaction
	bundle    [32]byte
	root      [32]byte
}

func testKey(label string) *ecdsa.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	k, err := crypto.ToECDSA(seed[:])
	if err != nil {
		panic(err)
	}
	return k
}

func (c *createdAnchorChain) serve(t *testing.T) *ethclient.Client {
	t.Helper()
	parsed, err := abiFromJSON(anchorsABIJSON)
	if err != nil {
		t.Fatal(err)
	}
	event := anchorEventsABI.Events["BatchAnchorCreated"]
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		var result any
		switch req.Method {
		case "eth_chainId":
			result = hexutil.EncodeBig(big.NewInt(c.chainID))
		case "eth_blockNumber":
			result = hexutil.EncodeUint64(uint64(len(c.times) - 1))
		case "eth_getBlockByHash":
			if strings.Contains(string(req.Params[0]), strings.TrimPrefix(c.blockHash().Hex(), "0x")) {
				result = c.header(c.createdIn)
			}
		case "eth_getBlockByNumber":
			var tag string
			_ = json.Unmarshal(req.Params[0], &tag)
			n, _ := hexutil.DecodeUint64(tag)
			if n < uint64(len(c.times)) {
				result = c.header(n)
			}
		case "eth_call":
			packed, err := parsed.Methods["anchors"].Outputs.Pack(c.bundle, c.root, [32]byte{}, [32]byte{}, [32]byte{}, [32]byte{},
				c.root, [32]byte{7}, big.NewInt(9), new(big.Int).SetUint64(c.times[c.createdIn]), c.creator, true, true, false, uint8(2))
			if err != nil {
				t.Error(err)
			}
			result = hexutil.Bytes(packed)
		case "eth_getLogs":
			var q struct {
				FromBlock, ToBlock string
			}
			_ = json.Unmarshal(req.Params[0], &q)
			from, _ := hexutil.DecodeUint64(q.FromBlock)
			to, _ := hexutil.DecodeUint64(q.ToBlock)
			logs := []*types.Log{}
			if c.createdIn >= from && c.createdIn <= to {
				logs = append(logs, &types.Log{
					Address: c.anchor, BlockNumber: c.createdIn, TxHash: c.tx.Hash(),
					Topics: []common.Hash{event.ID, common.Hash(c.bundle), common.Hash(c.root), common.BytesToHash(c.creator.Bytes())},
					Data:   []byte{},
				})
			}
			result = logs
		case "eth_getTransactionByHash":
			raw, _ := c.tx.MarshalJSON()
			m := map[string]any{}
			_ = json.Unmarshal(raw, &m)
			from, _ := types.Sender(types.LatestSignerForChainID(big.NewInt(c.chainID)), c.tx)
			m["from"] = strings.ToLower(from.Hex())
			m["blockNumber"] = hexutil.EncodeUint64(c.createdIn)
			m["blockHash"] = c.blockHash().Hex()
			m["transactionIndex"] = "0x0"
			result = m
		case "eth_getTransactionReceipt":
			result = map[string]any{
				"transactionHash": c.tx.Hash().Hex(), "transactionIndex": "0x0",
				"blockHash":   c.blockHash().Hex(),
				"blockNumber": hexutil.EncodeUint64(c.createdIn), "cumulativeGasUsed": "0x1", "gasUsed": "0x1",
				"effectiveGasPrice": "0x1", "logs": []any{}, "logsBloom": "0x" + strings.Repeat("00", 256),
				"status": "0x1", "type": "0x2", "contractAddress": nil,
			}
		default:
			t.Errorf("unexpected %s", req.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	t.Cleanup(server.Close)
	client, err := ethclient.Dial(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func (c *createdAnchorChain) header(n uint64) *types.Header {
	return &types.Header{Number: new(big.Int).SetUint64(n), Time: c.times[n], Difficulty: big.NewInt(0)}
}

// blockHash is the hash of the creating block's header, as a real chain names it.
func (c *createdAnchorChain) blockHash() common.Hash { return c.header(c.createdIn).Hash() }

func newCreatedAnchorChain(t *testing.T, signer *ecdsa.PrivateKey) *createdAnchorChain {
	t.Helper()
	c := &createdAnchorChain{
		chainID: 84532, anchor: common.HexToAddress("0x00000000000000000000000000000000000a1c40"),
		times: make([]uint64, 600), createdIn: 431,
		creator: crypto.PubkeyToAddress(testKey("anchor creator").PublicKey),
		bundle:  [32]byte{0xb0}, root: [32]byte{0x0e},
	}
	for i := range c.times {
		c.times[i] = 1_790_000_000 + uint64(i)*2
	}
	anchor := c.anchor
	tx, err := types.SignNewTx(signer, types.LatestSignerForChainID(big.NewInt(c.chainID)), &types.DynamicFeeTx{
		ChainID: big.NewInt(c.chainID), Nonce: 3, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 500000,
		To: &anchor, Data: createBatchAnchorCall(t, c.bundle, c.root),
	})
	if err != nil {
		t.Fatal(err)
	}
	c.tx = tx
	return c
}

func TestAnAnchorAnotherValidatorCreatedIsRecordedWithItsCreateTransaction(t *testing.T) {
	c := newCreatedAnchorChain(t, testKey("anchor creator"))
	o := &BatchOrchestrator{incarnation: testIncarnation, ecm: &EthereumContractManager{client: c.serve(t)}, anchorV7: c.anchor, logf: t.Logf}
	tree := &BatchTree{ChainID: c.chainID, BundleID: c.bundle, Root: c.root}

	created, err := o.existingAnchorCreation(context.Background(), tree, 0)
	if err != nil {
		t.Fatal(err)
	}
	if created.TxHash != c.tx.Hash().Hex() || created.Block != c.createdIn || created.Sender != strings.ToLower(c.creator.Hex()) {
		t.Fatalf("created %+v; want %s in block %d by %s", created, c.tx.Hash().Hex(), c.createdIn, c.creator.Hex())
	}
	// Another validator's transaction is not this validator's spend.
	if created.Paid != "" || created.GasUsed != 0 {
		t.Fatalf("another validator's anchor is reported as paid by this one: %+v", created)
	}
	created.onTree(tree)
	if tree.AnchorCreateTx != created.TxHash || tree.AnchorCreateBlock != c.createdIn || tree.AnchorCreateSender != created.Sender {
		t.Fatalf("tree %+v", tree)
	}
}

// A located transaction the anchor's recorded creator did not sign is not taken as the create transaction.
func TestALocatedCreateTransactionMustBeSignedByTheRecordedCreator(t *testing.T) {
	c := newCreatedAnchorChain(t, testKey("someone else"))
	o := &BatchOrchestrator{incarnation: testIncarnation, ecm: &EthereumContractManager{client: c.serve(t)}, anchorV7: c.anchor, logf: t.Logf}
	_, err := o.existingAnchorCreation(context.Background(), &BatchTree{ChainID: c.chainID, BundleID: c.bundle, Root: c.root}, 0)
	if err == nil || !strings.Contains(err.Error(), "records creator") {
		t.Fatalf("err = %v; want the signer refused", err)
	}
	if IsChainReadError(err) {
		t.Fatal("a contradiction was reported as an unread chain - it would be retried for ever as if transient")
	}
}
