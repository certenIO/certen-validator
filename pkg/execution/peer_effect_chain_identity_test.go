package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
)

// RB3-F46: a peer selected the committed call legs to verify by the leg's free-text chain name against
// the chain name the REQUESTING executor supplied, and when none matched and the executor left the
// execution hash empty it signed without verifying anything. Naming the chain by its numeric id -
// the registry's own key - was enough to skip every leg of an intent with two call legs.

// observedChain is the chain the peer re-observed the anchor transaction on.
type observedChain struct {
	chain.ChainExecutionStrategy
	id  string
	rpc string
}

func (c observedChain) ChainID() string { return c.id }
func (c observedChain) Config() *chain.ChainConfig {
	return &chain.ChainConfig{ChainID: c.id, RPC: c.rpc}
}

// txRPC serves one signed transaction carrying data over JSON-RPC - what the peer's calldata
// cross-check fetches - and refuses every other method, so a test sees any call it did not expect.
func txRPC(t *testing.T, chainID int64, data []byte) (string, common.Hash) {
	t.Helper()
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x1111111111111111111111111111111111111111")
	tx := types.MustSignNewTx(key, types.LatestSignerForChainID(big.NewInt(chainID)), &types.DynamicFeeTx{
		ChainID: big.NewInt(chainID), Nonce: 1, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2),
		Gas: 50000, To: &to, Value: big.NewInt(5), Data: data,
	})
	raw, err := tx.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	body["blockHash"] = common.Hash{1}.Hex()
	body["blockNumber"] = "0x10"
	body["transactionIndex"] = "0x0"
	body["from"] = ethcrypto.PubkeyToAddress(key.PublicKey).Hex()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := map[string]interface{}{"jsonrpc": "2.0", "id": req.ID}
		switch req.Method {
		case "eth_getTransactionByHash":
			resp["result"] = body
		default:
			resp["error"] = map[string]interface{}{"code": -32601, "message": fmt.Sprintf("unexpected method %s", req.Method)}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, tx.Hash()
}

func twoCallLegsBlob(t *testing.T) []byte {
	t.Helper()
	leg := func(name string, id int64) map[string]interface{} {
		return map[string]interface{}{
			"chain": name, "chainId": id, "from": "0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B",
			"executionPayload": map[string]interface{}{
				"target": "0xE3b7678231642e4de600C601Ff422654D17203f3", "value": "0", "callData": "0x33d425c411",
				"expectedEvents": []interface{}{map[string]interface{}{"contract": "0xE3b7678231642e4de600C601Ff422654D17203f3", "topic0": rbTopic0().Hex()}},
			},
		}
	}
	b, err := json.Marshal(map[string]interface{}{"legs": []interface{}{leg("base-sepolia", 84532), leg("arbitrum-sepolia", 421614)}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRB3F46_PeerCannotBeSteeredPastTheCommittedCall(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	o := orch(&mockQueryClient{blobs: [][]byte{intentBlob("x"), twoCallLegsBlob(t)}})
	for _, named := range []string{"421614", "arbitrum-sepolia", "Arbitrum One"} {
		msg := &attestation.AttestationMessage{
			IntentID: "x", TargetChain: named, AnchorTxHash: "0xabc",
			AccumulateTxHash: "h", AccumulateAccountURL: "a", ExecutionTxHash: "",
		}
		// The peer observed chain 421614; its committed call must be verified there whatever the
		// executor called the chain. With no RPC to verify on, that is a refusal - never a pass.
		if err := o.peerVerifyCommittedEffect(context.Background(), msg, observedChain{id: "421614"}, false); err == nil {
			t.Errorf("executor naming the chain %q skipped the committed call's verification", named)
		}
	}
}

// The chain the peer observed decides; without one there is nothing to select legs by.
func TestRB3F46_PeerRefusesWithoutTheObservedChain(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	o := orch(&mockQueryClient{blobs: [][]byte{intentBlob("x"), twoCallLegsBlob(t)}})
	msg := &attestation.AttestationMessage{IntentID: "x", TargetChain: "421614", AnchorTxHash: "0xabc", AccumulateTxHash: "h", AccumulateAccountURL: "a"}
	if err := o.peerVerifyCommittedEffect(context.Background(), msg, nil, false); err == nil {
		t.Error("a peer with no observed chain verified nothing and passed")
	}
}
