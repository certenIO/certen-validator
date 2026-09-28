package consensus

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// RB-1 / CRITICAL-003 on the batch path (RB3-F40)
// =============================================================================
//
// The per-intent path that was removed enforced, at leg extraction: contract calls only when
// CERTEN_ALLOW_CONTRACT_CALLS is on; a contract call must carry dataHash and executionCommitment;
// keccak256(callData) must equal dataHash; the commitment must be computed for the chain the leg
// executes on and must match (target, value, calldata). The batch path - now the only path -
// decoded calldata and enforced none of it. These tests hold the batch admission to the same rules,
// each failing as a named, permanent refusal.

// packedCommitment is keccak256(abi.encodePacked(uint256 chainId, address target, uint256 value,
// bytes32 keccak256(data))), written out independently of the code under test.
func packedCommitment(chainID int64, target common.Address, value *big.Int, data []byte) common.Hash {
	buf := make([]byte, 0, 116)
	buf = append(buf, common.LeftPadBytes(big.NewInt(chainID).Bytes(), 32)...)
	buf = append(buf, target.Bytes()...)
	buf = append(buf, common.LeftPadBytes(value.Bytes(), 32)...)
	buf = append(buf, crypto.Keccak256(data)...)
	return crypto.Keccak256Hash(buf)
}

type callLeg struct {
	chainID    int64
	target     string
	value      string
	callData   string
	dataHash   string // "" omits the field
	commitment string // "" omits the field
	payloadCID int64
	// events and state are the committed effects (expectedEvents / expectedState); nil omits them.
	events []map[string]interface{}
	state  []map[string]interface{}
}

func callIntent(t *testing.T, l callLeg) *CertenIntent {
	t.Helper()
	ci := batchableIntent(t, "i-call", l.chainID)
	ep := map[string]interface{}{"target": l.target, "value": l.value, "callData": l.callData, "chainId": l.payloadCID}
	if l.dataHash != "" {
		ep["dataHash"] = l.dataHash
	}
	if l.commitment != "" {
		ep["executionCommitment"] = l.commitment
	}
	if l.events != nil {
		ep["expectedEvents"] = l.events
	}
	if l.state != nil {
		ep["expectedState"] = l.state
	}
	legs := []map[string]interface{}{{
		"legId": "leg-0", "chain": "evm", "chainId": l.chainID,
		"from": "0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B", "executionPayload": ep,
		// The chain's live anchor, as the fake names it (declared_anchor.go).
		"anchorContract": map[string]interface{}{"address": testAnchor(l.chainID).Hex(), "functionSelector": BatchAnchorCreateSignature},
	}}
	b, err := json.Marshal(map[string]interface{}{"protocol": "CERTEN", "version": "2.0", "legs": legs})
	if err != nil {
		t.Fatal(err)
	}
	ci.CrossChainData = b
	return ci
}

func goodCallLeg() callLeg {
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")
	data := common.FromHex("0xa9059cbb0000000000000000000000001111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000000a")
	return callLeg{
		chainID: 84532, target: target.Hex(), value: "0", callData: hexOf(data),
		dataHash:   crypto.Keccak256Hash(data).Hex(),
		commitment: packedCommitment(84532, target, big.NewInt(0), data).Hex(),
		payloadCID: 84532,
		// transfer(...) on an ERC-20 emits Transfer(address,address,uint256) from the token.
		events: []map[string]interface{}{{"contract": target.Hex(), "topic0": erc20TransferTopic}},
	}
}

const erc20TransferTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

// RB3-F65: a contract call is admitted only with the effects its success is proven by. Live, intent
// 3b990fe3's note(bytes32) calls committed no event: they were admitted, settled on both chains and paid
// for, then refused at attestation and written back nowhere.
func TestRB1Gate_ContractCallMustCommitProvableEffects(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	for name, mutate := range map[string]func(*callLeg){
		"no committed event":            func(l *callLeg) { l.events = nil },
		"an empty event list":           func(l *callLeg) { l.events = []map[string]interface{}{} },
		"an event with no contract":     func(l *callLeg) { l.events[0]["contract"] = "" },
		"an event with a bad contract":  func(l *callLeg) { l.events[0]["contract"] = "0x1234" },
		"an event with no topic":        func(l *callLeg) { l.events[0]["topic0"] = "" },
		"an event with a short topic":   func(l *callLeg) { l.events[0]["topic0"] = "0xddf252ad" },
		"an event with a bad data hash": func(l *callLeg) { l.events[0]["dataHash"] = "0x01" },
		"a state slot with no account": func(l *callLeg) {
			l.state = []map[string]interface{}{{"account": "", "slot": erc20TransferTopic, "value": erc20TransferTopic}}
		},
		"a state slot with a short value": func(l *callLeg) {
			l.state = []map[string]interface{}{{"account": l.target, "slot": erc20TransferTopic, "value": "0x01"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			l := goodCallLeg()
			mutate(&l)
			err := enqueue(refusalValidator(newFakeEnqueuer()), callIntent(t, l))
			var r *BatchRefusal
			if err == nil || !errors.As(err, &r) || !r.Permanent {
				t.Fatalf("want a permanent refusal before anything is signed, got %v", err)
			}
		})
	}
	// Committed effects well formed - events with a data hash, and a state slot - are admitted.
	l := goodCallLeg()
	l.events[0]["dataHash"] = erc20TransferTopic
	l.state = []map[string]interface{}{{"account": l.target, "slot": erc20TransferTopic, "value": erc20TransferTopic}}
	if err := enqueue(refusalValidator(newFakeEnqueuer()), callIntent(t, l)); err != nil {
		t.Fatalf("a call committing well-formed effects was refused: %v", err)
	}
}

func hexOf(b []byte) string { return "0x" + common.Bytes2Hex(b) }

func planErr(t *testing.T, ci *CertenIntent) error {
	t.Helper()
	_, err := refusalValidator(newFakeEnqueuer()).planBatch(ci, 7)
	return err
}

func wantPermanent(t *testing.T, name string, err error, contains string) {
	t.Helper()
	var r *BatchRefusal
	if !errors.As(err, &r) || !r.Permanent {
		t.Fatalf("%s: want a permanent refusal, got %v", name, err)
	}
	if contains != "" && !strings.Contains(err.Error(), contains) {
		t.Fatalf("%s: refusal %q does not name %q", name, err, contains)
	}
}

func TestRB1Gate_ContractCallAcceptedWithAValidCommitmentWhenEnabled(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	if err := planErr(t, callIntent(t, goodCallLeg())); err != nil {
		t.Fatalf("a correctly committed contract call was refused: %v", err)
	}
}

func TestRB1Gate_ContractCallRefusedWhenNotEnabled(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "")
	wantPermanent(t, "switch off", planErr(t, callIntent(t, goodCallLeg())), "CERTEN_ALLOW_CONTRACT_CALLS")
}

func TestRB1Gate_ContractCallMustCarryItsCommitment(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	l := goodCallLeg()
	l.commitment = ""
	wantPermanent(t, "no commitment", planErr(t, callIntent(t, l)), "executionCommitment")
	l = goodCallLeg()
	l.dataHash = ""
	wantPermanent(t, "no dataHash", planErr(t, callIntent(t, l)), "dataHash")
}

func TestRB1Gate_MutatedCalldataIsRefused(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	l := goodCallLeg()
	l.callData = "0xdeadbeef" + strings.TrimPrefix(l.callData, "0x")[8:] // commitment + dataHash still for the original
	wantPermanent(t, "mutated calldata", planErr(t, callIntent(t, l)), "dataHash")
}

func TestRB1Gate_CommitmentForOtherParametersIsRefused(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	l := goodCallLeg()
	l.value = "5" // the executed value differs from the committed one
	wantPermanent(t, "value changed", planErr(t, callIntent(t, l)), "executionCommitment")
	l = goodCallLeg()
	data := common.FromHex(l.callData)
	l.commitment = packedCommitment(11155111, common.HexToAddress(l.target), big.NewInt(0), data).Hex() // committed for Sepolia
	wantPermanent(t, "commitment for another chain", planErr(t, callIntent(t, l)), "executionCommitment")
}

// A native transfer (no calldata) with a commitment is checked too; without one it is accepted, as
// before - the leaf binds (target, value, empty calldata) either way.
func TestRB1Gate_NativeTransferCommitmentIsCheckedWhenPresent(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "")
	target := common.HexToAddress("0x3333333333333333333333333333333333333333")
	l := callLeg{chainID: 84532, target: target.Hex(), value: "1000", callData: "0x", payloadCID: 84532}
	if err := planErr(t, callIntent(t, l)); err != nil {
		t.Fatalf("a plain native transfer was refused: %v", err)
	}
	l.commitment = packedCommitment(84532, target, big.NewInt(1000), nil).Hex()
	if err := planErr(t, callIntent(t, l)); err != nil {
		t.Fatalf("a native transfer with a correct commitment was refused: %v", err)
	}
	l.commitment = packedCommitment(84532, target, big.NewInt(999), nil).Hex()
	wantPermanent(t, "native wrong commitment", planErr(t, callIntent(t, l)), "executionCommitment")
}

// The commitment the admission checks is the one the member's leaf binds: the shared cross-language
// vectors must hold for the consensus implementation too.
func TestComputeExecutionCommitmentMatchesSharedVectors(t *testing.T) {
	path := ""
	if root := os.Getenv("CERTEN_CONTRACTS_DIR"); root != "" {
		path = filepath.Join(root, "test", "vectors", "execution_commitment_test_vectors.json")
	} else {
		dir, _ := os.Getwd()
		for {
			c := filepath.Join(dir, "certen-contracts", "test", "vectors", "execution_commitment_test_vectors.json")
			if _, err := os.Stat(c); err == nil {
				path = c
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	if path == "" {
		t.Fatal("shared execution-commitment vectors not found (set CERTEN_CONTRACTS_DIR)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		ChainID  int64 `json:"chainId"`
		Expected struct {
			Target, Value, CallData, ExecutionCommitment string
		} `json:"expected"`
	}
	if err := json.Unmarshal(raw, &vs); err != nil || len(vs) == 0 {
		t.Fatalf("vectors: %v (%d)", err, len(vs))
	}
	for _, v := range vs {
		val, ok := new(big.Int).SetString(v.Expected.Value, 10)
		if !ok {
			t.Fatalf("vector value %q", v.Expected.Value)
		}
		got := ComputeExecutionCommitment(v.ChainID, common.HexToAddress(v.Expected.Target), val, common.FromHex(v.Expected.CallData))
		if common.Hash(got).Hex() != common.HexToHash(v.Expected.ExecutionCommitment).Hex() {
			t.Errorf("chain %d: got %x want %s", v.ChainID, got, v.Expected.ExecutionCommitment)
		}
	}
}

// Ported from the removed workstream1_choke_point_test.go (WS1): the batch member executes the
// COMMITTED target from executionPayload, never a leg's top-level "to", for contract calls and
// native transfers alike. (The WS1 dataHash, commitment, empty-commitment and chain-redirect cases
// are the RB1Gate tests above. Its "non-EVM chain name with calldata" case guarded name-based
// routing, which no longer exists: routing is by chain ID only, every leg gets this EVM check, and
// a chain outside the supported three is refused by CheckIntentTargetChains.)
func TestBatchExtraction_ExecutesTheCommittedTarget(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	for _, native := range []bool{false, true} {
		l := goodCallLeg()
		if native {
			target := common.HexToAddress("0x4444444444444444444444444444444444444444")
			l = callLeg{chainID: 84532, target: target.Hex(), value: "7", callData: "0x", payloadCID: 84532,
				commitment: packedCommitment(84532, target, big.NewInt(7), nil).Hex()}
		}
		ci := callIntent(t, l)
		var env map[string]interface{}
		if err := json.Unmarshal(ci.CrossChainData, &env); err != nil {
			t.Fatal(err)
		}
		env["legs"].([]interface{})[0].(map[string]interface{})["to"] = "0x9999999999999999999999999999999999999999"
		ci.CrossChainData, _ = json.Marshal(env)

		legs, _, _, _, err := refusalValidator(newFakeEnqueuer()).batchInputsFromIntentForChain(ci, 84532)
		if err != nil {
			t.Fatalf("native=%v: %v", native, err)
		}
		if got := common.BytesToAddress(legs[0].Target[:]); got != common.HexToAddress(l.target) {
			t.Fatalf("native=%v: executes %s, want the committed target %s (not the top-level to)", native, got.Hex(), l.target)
		}
	}
}
