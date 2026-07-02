package execution

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/intent"
)

// WORKSTREAM 1 (RB-SEC-3/4/5/9) — the validator calldata choke point.
// These drive extractAllLegsFromIntent with adversarial leg shapes and assert it
// fails closed (returns nil) or executes the COMMITTED target/value.

const ws1Emitter = "0xE3b7678231642e4de600C601Ff422654D17203f3"

func ws1CallData() []byte {
	// ping(bytes32) selector + a 32-byte id
	cd := []byte{0x33, 0xd4, 0x25, 0xc4}
	id := make([]byte, 32)
	for i := range id {
		id[i] = 0x11
	}
	return append(cd, id...)
}

// ws1Leg builds a single-leg crossChainData blob. ep is the executionPayload map (or nil).
func ws1Leg(chain string, chainID int64, to string, ep map[string]interface{}) []byte {
	leg := map[string]interface{}{
		"legId": "leg-0", "from": "0x1111111111111111111111111111111111111111",
		"to": to, "amountWei": "0", "chainId": chainID, "chain": chain,
	}
	if ep != nil {
		leg["executionPayload"] = ep
	}
	blob := map[string]interface{}{"protocol": "CERTEN", "version": "2.0", "legs": []interface{}{leg}}
	b, _ := json.Marshal(blob)
	return b
}

// validCallEP builds a correctly-committed executionPayload for a ping() call to target.
func validCallEP(chainID int64, target string, value *big.Int, callData []byte) map[string]interface{} {
	dataHash := ethcrypto.Keccak256Hash(callData)
	commit := computeExecutionCommitment(chainID, common.HexToAddress(target), value, callData)
	return map[string]interface{}{
		"target": target, "value": value.String(),
		"callData": "0x" + fmt.Sprintf("%x", callData), "dataHash": dataHash.Hex(),
		"chainId": chainID, "executionCommitment": common.Hash(commit).Hex(),
	}
}

func ws1Extract(t *testing.T, ccd []byte) []LegExecution {
	t.Helper()
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	btce := NewBFTTargetChainExecutor(rb1Logger{})
	return btce.extractAllLegsFromIntent(&intent.CertenIntent{IntentID: "ws1", CrossChainData: ccd})
}

// RB-SEC-3: the executed target/value come from executionPayload, NOT top-level leg.To.
func TestWS1_ExecutesCommittedTargetNotTopLevelTo(t *testing.T) {
	cd := ws1CallData()
	ep := validCallEP(11155111, ws1Emitter, big.NewInt(0), cd)
	// top-level `to` is a DIFFERENT (attacker) address; must be ignored.
	ccd := ws1Leg("ethereum-sepolia", 11155111, "0x000000000000000000000000000000000000dEaD", ep)
	legs := ws1Extract(t, ccd)
	if len(legs) != 1 {
		t.Fatalf("expected 1 leg, got %d", len(legs))
	}
	if legs[0].Target != common.HexToAddress(ws1Emitter) {
		t.Errorf("executed target must be committed emitter, got %s (leg.To must be ignored)", legs[0].Target.Hex())
	}
	if fmt.Sprintf("%x", legs[0].Data) != fmt.Sprintf("%x", cd) {
		t.Errorf("leg data mismatch")
	}
}

// RB-SEC-3: dataHash that doesn't match keccak256(callData) ⇒ reject.
func TestWS1_RejectsDataHashMismatch(t *testing.T) {
	cd := ws1CallData()
	ep := validCallEP(11155111, ws1Emitter, big.NewInt(0), cd)
	ep["dataHash"] = common.HexToHash("0xdead").Hex() // wrong
	if legs := ws1Extract(t, ws1Leg("ethereum-sepolia", 11155111, ws1Emitter, ep)); legs != nil {
		t.Errorf("dataHash mismatch must reject, got %d legs", len(legs))
	}
}

// RB-SEC-3: commitment that doesn't match ⇒ reject.
func TestWS1_RejectsCommitmentMismatch(t *testing.T) {
	cd := ws1CallData()
	ep := validCallEP(11155111, ws1Emitter, big.NewInt(0), cd)
	ep["executionCommitment"] = common.HexToHash("0xbeef").Hex() // wrong
	if legs := ws1Extract(t, ws1Leg("ethereum-sepolia", 11155111, ws1Emitter, ep)); legs != nil {
		t.Errorf("commitment mismatch must reject, got %d legs", len(legs))
	}
}

// RB-SEC-4: calldata leg with EMPTY executionCommitment ⇒ reject (no skip-then-execute).
func TestWS1_RejectsEmptyCommitmentOnCalldataLeg(t *testing.T) {
	cd := ws1CallData()
	ep := validCallEP(11155111, ws1Emitter, big.NewInt(0), cd)
	ep["executionCommitment"] = "" // empty
	if legs := ws1Extract(t, ws1Leg("ethereum-sepolia", 11155111, ws1Emitter, ep)); legs != nil {
		t.Errorf("empty commitment on a calldata leg must reject, got %d legs", len(legs))
	}
	// Also empty dataHash ⇒ reject.
	ep2 := validCallEP(11155111, ws1Emitter, big.NewInt(0), cd)
	ep2["dataHash"] = ""
	if legs := ws1Extract(t, ws1Leg("ethereum-sepolia", 11155111, ws1Emitter, ep2)); legs != nil {
		t.Errorf("empty dataHash on a calldata leg must reject, got %d legs", len(legs))
	}
}

// RB-SEC-5: a non-EVM chain name carrying EVM calldata ⇒ reject (ambiguous routing).
func TestWS1_RejectsNonEVMNameWithCalldata(t *testing.T) {
	cd := ws1CallData()
	// Even with a valid commitment, a cardano-named leg carrying EVM calldata is rejected.
	ep := validCallEP(11155111, ws1Emitter, big.NewInt(0), cd)
	for _, chain := range []string{"cardano-preview", "cardano-x", "near-testnet", "solana-devnet"} {
		if legs := ws1Extract(t, ws1Leg(chain, 11155111, ws1Emitter, ep)); legs != nil {
			t.Errorf("chain=%s with EVM calldata must reject, got %d legs", chain, len(legs))
		}
	}
}

// SEC-M1: a leg whose executionPayload.chainId differs from the routed (top-level) chainId
// must be rejected — even with a commitment valid for ep.ChainID — so the commitment always
// binds the chain we actually execute on (no chain-redirect via the on-chain backstop alone).
func TestWS1_RejectsChainIDRedirect(t *testing.T) {
	cd := ws1CallData()
	// Commitment is valid for chainId=1, but the leg is routed to chainId=11155111.
	ep := validCallEP(1, ws1Emitter, big.NewInt(0), cd)
	if legs := ws1Extract(t, ws1Leg("ethereum-sepolia", 11155111, ws1Emitter, ep)); legs != nil {
		t.Errorf("ep.chainId != routed chainId must reject (chain-redirect), got %d legs", len(legs))
	}
}

// RB-SEC-3 (native): an EVM native leg also executes the committed target, not leg.To.
func TestWS1_NativeExecutesCommittedTarget(t *testing.T) {
	recipient := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	val := big.NewInt(1000)
	ep := validCallEP(11155111, recipient, val, []byte{}) // native: empty calldata
	ccd := ws1Leg("ethereum-sepolia", 11155111, "0x000000000000000000000000000000000000dEaD", ep)
	legs := ws1Extract(t, ccd)
	if len(legs) != 1 {
		t.Fatalf("expected 1 leg, got %d", len(legs))
	}
	if legs[0].Target != common.HexToAddress(recipient) || legs[0].Value.Cmp(val) != 0 {
		t.Errorf("native must execute committed target/value, got target=%s value=%s", legs[0].Target.Hex(), legs[0].Value.String())
	}
	if len(legs[0].Data) != 0 {
		t.Errorf("native leg must have empty calldata")
	}
}
