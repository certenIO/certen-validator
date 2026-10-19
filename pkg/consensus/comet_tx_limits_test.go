package consensus

// C5-D1: the limits a transaction meets between the proposer and a committed block (comet_tx_limits.go), pinned for
// every place a CometBFT configuration is built, and the named refusal when a transaction exceeds what the path
// accepts. See comet_tx_roundtrip_test.go for the round trip through a real node.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cometbft/cometbft/config"
	cmthttp "github.com/cometbft/cometbft/rpc/client/http"
	cmttypes "github.com/cometbft/cometbft/types"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// broadcastRequestBody is the body the engine's real CometBFT HTTP client posts for BroadcastTxSync of a transaction
// of txLen bytes, captured from the client itself - nothing about the JSON-RPC wrapper is assumed. It returns the
// body's length and the number of digits of the request id it carried (the id is a JSON number that grows with the
// number of calls the client has made).
func broadcastRequestBody(t *testing.T, txLen int) (bodyLen, idDigits int) {
	t.Helper()
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(body, &req)
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"code":0,"data":"","log":"","codespace":"","hash":"%X"}}`, req.ID, make([]byte, 32))
	}))
	defer srv.Close()
	client, err := cmthttp.New(srv.URL, "/websocket")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.BroadcastTxSync(context.Background(), cmttypes.Tx(make([]byte, txLen))); err != nil {
		t.Fatalf("the client's request was not answered: %v", err)
	}
	var req struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	return len(body), len(req.ID)
}

// The largest id the client can send is an int64: 19 digits.
const maxRequestIDDigits = 19

// requiredBodyBytes is the smallest rpc.max_body_bytes that admits a BroadcastTxSync request carrying a transaction
// of txLen bytes, measured on the real client, with the widest request id it can use.
func requiredBodyBytes(t *testing.T, txLen int) int64 {
	t.Helper()
	body, idDigits := broadcastRequestBody(t, txLen)
	wrapper := body - base64.StdEncoding.EncodedLen(txLen)
	if wrapper <= 0 {
		t.Fatalf("a request of %d bytes for a transaction of %d: the wrapper is %d bytes", body, txLen, wrapper)
	}
	return int64(base64.StdEncoding.EncodedLen(txLen) + wrapper + (maxRequestIDDigits - idDigits))
}

var txLimitTestLog = log.New(io.Discard, "", 0)

// Every configuration the repo builds for a CometBFT node must carry a transaction of max_tx_bytes through its RPC
// server: the body limit covers the transaction base64-encoded (4 bytes per 3) plus the JSON-RPC wrapper, and
// max_tx_bytes stays at the 1 MiB the proof-v2 evidence budgets are written against.
func TestEveryCometBFTConfigBuilderLetsTheRPCCarryAMaxTxBytesTransaction(t *testing.T) {
	unified, _ := unifiedCometConfig("validator-1", func(string) string { return "" }, txLimitTestLog)
	builders := map[string]*config.Config{
		"NewValidatorChainEngine":  validatorChainCometConfig("validator-1", 26656, 26657),
		"NewUnifiedCometBFTEngine": unified,
		"NewProductionEngine": productionCometConfig(EngineConfig{
			ValidatorID: "validator-1", HomeDir: t.TempDir(), P2PPort: 26656, RPCPort: 26657, ChainID: "certen-testnet",
		}, txLimitTestLog),
	}
	for name, cfg := range builders {
		if cfg.Mempool.MaxTxBytes < proofv2.ConsensusTxLimit {
			t.Errorf("%s: mempool.max_tx_bytes %d is below the %d the evidence budget (proofv2.ConsensusTxLimit) is written against",
				name, cfg.Mempool.MaxTxBytes, proofv2.ConsensusTxLimit)
		}
		need := requiredBodyBytes(t, cfg.Mempool.MaxTxBytes)
		if cfg.RPC.MaxBodyBytes < need {
			t.Errorf("%s: rpc.max_body_bytes %d cannot carry a transaction of mempool.max_tx_bytes %d: its broadcast request is %d bytes "+
				"(the largest transaction the RPC accepts is about %d)",
				name, cfg.RPC.MaxBodyBytes, cfg.Mempool.MaxTxBytes, need, cfg.RPC.MaxBodyBytes/4*3)
		}
	}
}

// applyCometTxLimits only ever raises: a body limit already above what max_tx_bytes needs is kept, and a raised
// max_tx_bytes raises the body limit with it.
func TestTheBodyLimitFollowsMaxTxBytesAndIsOnlyRaised(t *testing.T) {
	cfg := config.DefaultConfig()
	applyCometTxLimits(cfg)
	if want := requiredBodyBytes(t, cfg.Mempool.MaxTxBytes); cfg.RPC.MaxBodyBytes < want {
		t.Fatalf("default max_tx_bytes: body limit %d < required %d", cfg.RPC.MaxBodyBytes, want)
	}
	cfg = config.DefaultConfig()
	cfg.RPC.MaxBodyBytes = 64 << 20
	applyCometTxLimits(cfg)
	if cfg.RPC.MaxBodyBytes != 64<<20 {
		t.Fatalf("a body limit of 64 MiB was changed to %d", cfg.RPC.MaxBodyBytes)
	}
	cfg = config.DefaultConfig()
	cfg.Mempool.MaxTxBytes = 4 << 20
	applyCometTxLimits(cfg)
	if want := requiredBodyBytes(t, 4<<20); cfg.RPC.MaxBodyBytes < want {
		t.Fatalf("max_tx_bytes 4 MiB: body limit %d < required %d", cfg.RPC.MaxBodyBytes, want)
	}
}

// The path limit is the smallest of: the RPC body (as a raw transaction), the mempool's max_tx_bytes, and the block's
// data capacity (what CometBFT's own TxPreCheck uses). The named bound is the one that binds.
func TestThePathLimitIsTheSmallestLimitAndNamesTheBindingOne(t *testing.T) {
	cfg := config.DefaultConfig()
	applyCometTxLimits(cfg)

	// Default consensus params, seven validators: the mempool binds.
	def := cmttypes.DefaultConsensusParams().Block.MaxBytes
	limit, bound := transactionPathLimit(cfg, def, 7)
	if limit != cfg.Mempool.MaxTxBytes || bound != "mempool.max_tx_bytes" {
		t.Fatalf("default params: limit %d bound %q; want %d mempool.max_tx_bytes", limit, bound, cfg.Mempool.MaxTxBytes)
	}

	// A block too small for a max_tx_bytes transaction binds, by CometBFT's own formula.
	const small = 900_000
	limit, bound = transactionPathLimit(cfg, small, 7)
	data := cmttypes.MaxDataBytesNoEvidence(small, 7)
	if bound != "block.max_bytes" {
		t.Fatalf("block.max_bytes %d: limit %d bound %q; want block.max_bytes", small, limit, bound)
	}
	// The limit is the largest raw transaction CometBFT's own pre-check (the protobuf size against the data capacity)
	// admits: the pre-check admits it, and rejects one byte more.
	if got := cmttypes.ComputeProtoSizeForTxs([]cmttypes.Tx{make(cmttypes.Tx, limit)}); got > data {
		t.Fatalf("a transaction of the stated limit %d has protobuf size %d > data capacity %d", limit, got, data)
	}
	if got := cmttypes.ComputeProtoSizeForTxs([]cmttypes.Tx{make(cmttypes.Tx, limit+1)}); got <= data {
		t.Fatalf("a transaction of %d bytes (limit+1) also fits the data capacity %d (protobuf size %d)", limit+1, data, got)
	}
	// -1 is CometBFT's "the protocol maximum" (100 MiB).
	if limit, bound = transactionPathLimit(cfg, -1, 7); limit != cfg.Mempool.MaxTxBytes || bound != "mempool.max_tx_bytes" {
		t.Fatalf("block.max_bytes -1: limit %d bound %q", limit, bound)
	}

	// A body limit left at CometBFT's default binds first, and the limit is the largest raw transaction it carries.
	stock := config.DefaultConfig()
	limit, bound = transactionPathLimit(stock, def, 7)
	if bound != "rpc.max_body_bytes" || limit >= stock.Mempool.MaxTxBytes {
		t.Fatalf("stock config: limit %d bound %q; the 1,000,000-byte body must bind below max_tx_bytes", limit, bound)
	}
	if need := requiredBodyBytes(t, limit); need > stock.RPC.MaxBodyBytes {
		t.Fatalf("a transaction of the stated limit %d needs a body of %d > rpc.max_body_bytes %d", limit, need, stock.RPC.MaxBodyBytes)
	}
	// The limit is conservative by at most the envelope allowance (the real wrapper is ~110 bytes of it).
	if need := requiredBodyBytes(t, limit+rpcEnvelopeAllowance); need <= stock.RPC.MaxBodyBytes {
		t.Fatalf("the stated limit %d is not within the allowance of the largest: %d bytes also fit a body of %d",
			limit, limit+rpcEnvelopeAllowance, stock.RPC.MaxBodyBytes)
	}
}

// The proposer path. A certified block whose encoding exceeds what the path accepts is not sent to be refused by the
// RPC as "request body too large": it is refused before any broadcast by the named state tx_too_large{size,limit},
// which says what binds. The engine needs no running node for that (it has not been started).
func TestAnOversizedValidatorBlockIsRefusedByNameWithItsSizeAndTheLimit(t *testing.T) {
	app := newPersistTestApp(t)
	cfg := config.DefaultConfig()
	applyCometTxLimits(cfg)
	engine := &RealCometBFTEngine{app: app, cometCfg: cfg, logger: persistQuietLog}
	limit := cfg.Mempool.MaxTxBytes

	vb, enc := paddedBlockOfSize(t, "op-padded", limit+1)
	_, err := engine.BroadcastValidatorBlockCommit(context.Background(), vb)
	var tl *TxTooLargeError
	if !errors.As(err, &tl) {
		t.Fatalf("a block of %d bytes (limit %d) was not refused by name: %v", len(enc), limit, err)
	}
	if tl.Size != len(enc) || tl.Limit != limit || tl.Bound != "mempool.max_tx_bytes" {
		t.Fatalf("tx_too_large carries size %d limit %d bound %q; want %d %d mempool.max_tx_bytes", tl.Size, tl.Limit, tl.Bound, len(enc), limit)
	}
	if !errors.Is(err, ErrTxTooLarge) {
		t.Fatalf("the refusal does not match ErrTxTooLarge: %v", err)
	}
	for _, want := range []string{"tx_too_large{", fmt.Sprintf("size=%d", len(enc)), fmt.Sprintf("limit=%d", limit), "mempool.max_tx_bytes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not say %q", err.Error(), want)
		}
	}

	// The ENGINE's other broadcast names it the same way.
	if err := engine.BroadcastAppTxSync(context.Background(), make([]byte, limit+1)); !errors.Is(err, ErrTxTooLarge) {
		t.Fatalf("BroadcastAppTxSync of max_tx_bytes+1: %v", err)
	}

	// Exactly the limit is not refused by name (it goes on to be broadcast: here the engine has no node, so it
	// does not get that far - checked on the size rule itself).
	if err := checkTransactionFits(limit, limit, "mempool.max_tx_bytes"); err != nil {
		t.Fatalf("a transaction of exactly the limit was refused: %v", err)
	}
	if err := checkTransactionFits(limit+1, limit, "mempool.max_tx_bytes"); !errors.Is(err, ErrTxTooLarge) {
		t.Fatalf("one byte over the limit: %v", err)
	}
}

// How discovery must treat the refusal (pkg/intent/tx_too_large_test.go pins the intent side): it is not a transport
// error to retry with the same bytes, and it is not a permanent defect of the intent.
func TestTxTooLargeIsNeitherTransientNorPermanent(t *testing.T) {
	err := fmt.Errorf("BFT broadcast failed: %w", checkTransactionFits(1<<20+1, 1<<20, "mempool.max_tx_bytes"))
	if isTransientBroadcastError(err) {
		t.Fatal("tx_too_large is classed transient: the same bytes would be offered again")
	}
	if errors.Is(err, ErrIntentPermanentlyInvalid) {
		t.Fatal("tx_too_large is classed permanent: the document shrinks after the next Accumulate major block")
	}
}
