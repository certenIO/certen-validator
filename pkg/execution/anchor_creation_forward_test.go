package execution

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/execution/contracts"

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
	dup       *types.Transaction // the creator's duplicate createBatchAnchor call, never mined
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
	server := httptest.NewServer(c.handler(t, false))
	t.Cleanup(server.Close)
	client, err := ethclient.Dial(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

// provide serves the chain from one provider per entry of liars, each on its own loopback host - a liar names, as the
// creation, the creator's duplicate createBatchAnchor call (dup), which the chain never mined - configured as production
// configures Base Sepolia's providers, and returns a client of the first, the orchestrator's own.
func (c *createdAnchorChain) provide(t *testing.T, liars ...bool) *ethclient.Client {
	t.Helper()
	urls := make([]string, len(liars))
	for i, lie := range liars {
		l, err := net.Listen("tcp", endpointHosts[i])
		if err != nil {
			t.Fatalf("listen on %s: %v", endpointHosts[i], err)
		}
		server := httptest.NewUnstartedServer(c.handler(t, lie))
		server.Listener = l
		server.Start()
		t.Cleanup(server.Close)
		urls[i] = server.URL
	}
	t.Setenv("BASE_SEPOLIA_RPC_URL", urls[0])
	t.Setenv("BASE_SEPOLIA_URL_FALLBACKS", strings.Join(urls[1:], ","))
	t.Setenv("INFURA_BASE_SEPOLIA_URL", "")
	t.Setenv("ALCHEMY_BASE_SEPOLIA_URL", "")
	client, err := ethclient.Dial(urls[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func (c *createdAnchorChain) handler(t *testing.T, lie bool) http.Handler {
	t.Helper()
	parsed, err := abiFromJSON(contracts.CertenAnchorV8_2BatchABI)
	if err != nil {
		t.Fatal(err)
	}
	event := anchorEventsABI.Events["BatchAnchorCreated"]
	// The transaction this provider says created the anchor, in the creating block, and the log its receipt carries.
	stated, statedHash := c.createdIn, c.blockHash()
	creation := c.tx
	if lie {
		creation = c.dup
	}
	createLog := func() *types.Log {
		return &types.Log{Address: c.anchor, BlockNumber: stated, BlockHash: statedHash, TxHash: creation.Hash(),
			Topics: []common.Hash{event.ID, common.Hash(c.bundle), common.Hash(c.root), common.BytesToHash(c.creator.Bytes())},
			Data:   []byte{}}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			for _, n := range []uint64{c.createdIn, c.createdIn + 1} {
				if strings.Contains(string(req.Params[0]), strings.TrimPrefix(c.header(n).Hash().Hex(), "0x")) {
					result = c.header(n)
				}
			}
		case "eth_getBlockByNumber":
			var tag string
			_ = json.Unmarshal(req.Params[0], &tag)
			n, _ := hexutil.DecodeUint64(tag)
			if tag == "latest" {
				n = uint64(len(c.times) - 1)
			}
			if n < uint64(len(c.times)) {
				result = c.header(n)
			}
		case "eth_call":
			packed, err := parsed.Methods["anchors"].Outputs.Pack(c.bundle, c.root, [32]byte{}, [32]byte{}, [32]byte{}, [32]byte{},
				c.root, [32]byte{7}, big.NewInt(9), new(big.Int).SetUint64(c.times[c.createdIn]), c.creator, true, true, false, uint8(2),
				testAccSet, testIncarnation)
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
				logs = append(logs, createLog())
			}
			result = logs
		case "eth_getTransactionByHash":
			if !strings.Contains(string(req.Params[0]), strings.TrimPrefix(creation.Hash().Hex(), "0x")) {
				break
			}
			raw, _ := creation.MarshalJSON()
			m := map[string]any{}
			_ = json.Unmarshal(raw, &m)
			from, _ := types.Sender(types.LatestSignerForChainID(big.NewInt(c.chainID)), creation)
			m["from"] = strings.ToLower(from.Hex())
			m["blockNumber"] = hexutil.EncodeUint64(stated)
			m["blockHash"] = statedHash.Hex()
			m["transactionIndex"] = "0x0"
			result = m
		case "eth_getTransactionReceipt":
			if !strings.Contains(string(req.Params[0]), strings.TrimPrefix(creation.Hash().Hex(), "0x")) {
				break
			}
			result = map[string]any{
				"transactionHash": creation.Hash().Hex(), "transactionIndex": "0x0",
				"blockHash":   statedHash.Hex(),
				"blockNumber": hexutil.EncodeUint64(stated), "cumulativeGasUsed": "0x1", "gasUsed": "0x1",
				"effectiveGasPrice": "0x1", "logs": []*types.Log{createLog()}, "logsBloom": "0x" + strings.Repeat("00", 256),
				"status": "0x1", "type": "0x2", "contractAddress": nil,
			}
		default:
			t.Errorf("unexpected %s", req.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	})
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
		root:    [32]byte{0x0e},
	}
	c.bundle = v82CreateBundle(c.chainID, c.root)
	for i := range c.times {
		c.times[i] = 1_790_000_000 + uint64(i)*2
	}
	anchor := c.anchor
	tx, err := types.SignNewTx(signer, types.LatestSignerForChainID(big.NewInt(c.chainID)), &types.DynamicFeeTx{
		ChainID: big.NewInt(c.chainID), Nonce: 3, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 500000,
		To: &anchor, Data: v82CreateCall(c.chainID, c.root),
	})
	if err != nil {
		t.Fatal(err)
	}
	c.tx = tx
	if c.dup, err = types.SignNewTx(signer, types.LatestSignerForChainID(big.NewInt(c.chainID)), &types.DynamicFeeTx{
		ChainID: big.NewInt(c.chainID), Nonce: 4, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 500000,
		To: &anchor, Data: v82CreateCall(c.chainID, c.root),
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAnAnchorAnotherValidatorCreatedIsRecordedWithItsCreateTransaction(t *testing.T) {
	c := newCreatedAnchorChain(t, testKey("anchor creator"))
	o := &BatchOrchestrator{incarnation: testIncarnation, ecm: &EthereumContractManager{client: c.provide(t, false, false)}, anchorV7: c.anchor, logf: t.Logf}
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
	o := &BatchOrchestrator{incarnation: testIncarnation, ecm: &EthereumContractManager{client: c.provide(t, false, false)}, anchorV7: c.anchor, logf: t.Logf}
	_, err := o.existingAnchorCreation(context.Background(), &BatchTree{ChainID: c.chainID, BundleID: c.bundle, Root: c.root}, 0)
	if err == nil || !strings.Contains(err.Error(), "records creator") {
		t.Fatalf("err = %v; want the signer refused", err)
	}
	if IsChainReadError(err) {
		t.Fatal("a contradiction was reported as an unread chain - it would be retried for ever as if transient")
	}
}

// The orchestrator's own provider names, as another validator's anchor creation, that validator's duplicate
// createBatchAnchor call - signed, same bundle and root, never mined - with a receipt for it; the other provider tells
// the truth. What the orchestrator records on the tree - written to the database and stated in layer 5 -
// is never that one provider's word (RB5-F53).
func TestASingleLyingProvidersAnchorCreationIsNotWrittenToTheTree(t *testing.T) {
	c := newCreatedAnchorChain(t, testKey("anchor creator"))
	o := &BatchOrchestrator{incarnation: testIncarnation, ecm: &EthereumContractManager{client: c.provide(t, true, false)}, anchorV7: c.anchor, logf: t.Logf}
	tree := &BatchTree{ChainID: c.chainID, BundleID: c.bundle, Root: c.root}
	created, err := o.existingAnchorCreation(context.Background(), tree, 0)
	if err == nil {
		t.Fatalf("THE regression: one provider's anchor creation was recorded: %s in block %d (created by %s)", created.TxHash, created.Block, c.tx.Hash().Hex())
	}
	if !strings.Contains(err.Error(), c.dup.Hash().Hex()) {
		t.Fatalf("refused, but not by name: %v", err)
	}
}

// v82CreateOpID and v82CreateHeight are the created anchor's one-member V8.2 batch, committing the fixture's Accumulate
// set and incarnation; its bundle is the one those arguments derive, as a real V8.2 anchor's is.
var v82CreateOpID = [32]byte{0x0f}

const v82CreateHeight = 9360888

func v82CreateBundle(chainID int64, root [32]byte) [32]byte {
	return contracts.DeriveV8_2BatchBundleID(chainID, root, 1, v82CreateOpID, v82CreateHeight, testAccSet, testIncarnation)
}

// v82CreateCall is that anchor's createBatchAnchor calldata (seven arguments).
func v82CreateCall(chainID int64, root [32]byte) []byte {
	w := func(v uint64) []byte { b := make([]byte, 32); new(big.Int).SetUint64(v).FillBytes(b); return b }
	bundle := v82CreateBundle(chainID, root)
	d := append([]byte{}, contracts.CreateBatchAnchorV8_2Selector[:]...)
	for _, x := range [][]byte{bundle[:], root[:], w(1), v82CreateOpID[:], w(v82CreateHeight), testAccSet[:], testIncarnation[:]} {
		d = append(d, x...)
	}
	return d
}
