package main

// The CERTEN intent the live run writes: the same four-blob, memo "CERTEN_INTENT" writeData the scripts
// (scripts/ml_base_only.js, scripts/sl_arb_b.js) submit, with one leg on Base Sepolia. The intent is written to the data
// account governed by the case's key book alone, and approved by that case's key - so what the validators must establish
// about it is exactly "this signature type counts as the book's vote" (RB8, gap G-42).

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/proof"
	"golang.org/x/crypto/sha3"
)

// Target-chain constants for the leg (Base Sepolia, live set recorded in memory project_anchor_admin_eoa: AnchorV8_2).
const (
	baseSepoliaChainID = 84532
	baseSepoliaAnchor  = "0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c"
	intentRecipient    = "0xBe0043Abb10e6DB56b8c6c5cB3F639Bf7fE69251"
	intentAmountWei    = "1"
)

// intentBlobs is the four JSON documents of an intent, in blob order.
type intentBlobs struct {
	IntentID    string
	OperationID string
	Blobs       [4][]byte
}

func keccak(b ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range b {
		h.Write(p)
	}
	return h.Sum(nil)
}

func leftPad32(b []byte) []byte { return append(make([]byte, 32-len(b)), b...) }

// executionCommitment is keccak256(abi.encodePacked(uint256 chainId, address target, uint256 value, bytes32 dataHash)),
// the commitment the scripts compute with ethers.solidityPacked.
func executionCommitment(chainID uint64, target string, valueWei uint64) (commitment, dataHash []byte, err error) {
	addr, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(target), "0x"))
	if err != nil || len(addr) != 20 {
		return nil, nil, fmt.Errorf("target %q is not an address", target)
	}
	cid := make([]byte, 8)
	val := make([]byte, 8)
	for i := 0; i < 8; i++ {
		cid[7-i] = byte(chainID >> (8 * i))
		val[7-i] = byte(valueWei >> (8 * i))
	}
	dataHash = keccak(nil) // value transfer: keccak256(0x)
	return keccak(leftPad32(cid), addr, leftPad32(val), dataHash), dataHash, nil
}

// buildIntent returns the four blobs for one case. from is the CertenAccount of the ADI on the target chain.
func buildIntent(adi string, c liveCase, from string) (*intentBlobs, error) {
	return buildIntentSpec(intentSpec{
		ADI: adi, By: "sigtype-" + c.Tag, Desc: fmt.Sprintf("RB8-D live signature-type run: %s approves 1 wei on Base Sepolia", c.Name),
		Book: c.book(adi), Page: c.page(adi), From: from, Tags: []string{"rb8-d", "sigtype", c.Tag},
	})
}

// intentSpec is what varies between the intents the live runs write: the ADI, who the intent says it was created by, the
// description, the key book and page it declares (the certified key page), the leg's account on the target chain, and the tags.
type intentSpec struct {
	ADI, By, Desc, Book, Page, From string
	Tags                            []string
}

// buildIntentSpec returns the four blobs for spec. The shape is byte-for-byte what buildIntent has always produced.
func buildIntentSpec(sp intentSpec) (*intentBlobs, error) {
	adi, from := sp.ADI, sp.From
	idb := make([]byte, 16)
	if _, err := rand.Read(idb); err != nil {
		return nil, err
	}
	idb[6] = idb[6]&0x0f | 0x40
	idb[8] = idb[8]&0x3f | 0x80
	h := hex.EncodeToString(idb)
	intentID := fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
	now := time.Now().UTC()
	nowMs, nowS := now.UnixMilli(), now.Unix()
	expires := nowS + 3600
	by := sp.By + "-" + intentID[:8]

	commit, dataHash, err := executionCommitment(baseSepoliaChainID, intentRecipient, 1)
	if err != nil {
		return nil, err
	}
	hx := func(b []byte) string { return "0x" + hex.EncodeToString(b) }

	intentData := map[string]any{
		"kind": "CERTEN_INTENT", "version": "2.0", "proof_class": "on_demand",
		"intentType":      "single_leg_cross_chain_transfer",
		"description":     sp.Desc,
		"organizationAdi": adi,
		"initiator":       map[string]any{"adi": adi, "by": by, "role": "organization_operator"},
		"priority":        "normal", "risk_level": "medium", "compliance_required": false,
		"leg_count": 1, "execution_mode": "sequential", "intent_id": intentID, "created_by": by,
		"created_at": now.Format("2006-01-02T15:04:05.000Z"), "intent_class": "financial_transfer",
		"regulatory_jurisdiction": "global", "tags": sp.Tags,
	}
	crossChain := map[string]any{
		"protocol": "CERTEN", "version": "2.0", "operationGroupId": intentID,
		"legs": []any{map[string]any{
			"legId": fmt.Sprintf("leg-base-sepolia-%d-1", baseSepoliaChainID), "role": "payment",
			"chain": "base-sepolia", "chainId": baseSepoliaChainID, "network": "base-sepolia",
			"asset": map[string]any{"symbol": "ETH", "decimals": 18, "native": true, "contract_address": nil, "verified": true},
			"from":  from, "to": intentRecipient, "amountEth": "0.000000000000000001", "amountWei": intentAmountWei,
			"execution_sequence": 1, "conditional_execution": false,
			"rollback_conditions": map[string]any{"timeout_seconds": 3600, "failure_modes": []string{"gas_limit_exceeded", "insufficient_balance"}},
			"anchorContract": map[string]any{
				"type": "evm_contract", "address": baseSepoliaAnchor,
				"functionSelector": "createBatchAnchor(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes32)", "version": "v8.2",
			},
			"gasPolicy": map[string]any{
				"maxFeePerGasGwei": "20", "maxPriorityFeePerGasGwei": "2", "gasLimit": 800000,
				"payer": "from", "gas_estimation_buffer": 1.2,
			},
			"slippage_tolerance": "0.5%", "deadline_timestamp": expires,
			"executionPayload": map[string]any{
				"target": intentRecipient, "value": intentAmountWei, "dataHash": hx(dataHash),
				"chainId": baseSepoliaChainID, "executionCommitment": hx(commit),
			},
		}},
		"execution_mode": "sequential",
		"atomicity":      map[string]any{"mode": "single_leg", "rollback_strategy": "all_or_nothing", "partial_execution_allowed": false},
		"execution_constraints": map[string]any{
			"max_execution_time_seconds": 3600, "required_confirmations": 1, "parallel_execution": false,
		},
		"cross_chain_routing": map[string]any{
			"bridge_type": "certen_anchor_v8", "relay_mechanism": "proof_based", "finality_requirements": "fast",
		},
	}
	book, page := sp.Book, sp.Page
	governance := map[string]any{
		"organizationAdi": adi,
		"authorization": map[string]any{
			"required_key_book": book, "required_key_page": page, "signature_threshold": 1,
			"required_signers":   []string{book},
			"roles":              []any{map[string]any{"role": "DEFAULT_SIGNER", "keyPage": page}},
			"authorization_hash": "",
		},
		"validation_rules": map[string]any{"max_amount": "1.0", "daily_limit": "10.0", "requires_approval": false, "risk_level": "medium"},
		"compliance_checks": map[string]any{
			"aml_required": false, "kyc_verified": true, "sanctions_check": "passed", "jurisdiction": "compliant",
		},
	}
	nb := make([]byte, 16)
	if _, err := rand.Read(nb); err != nil {
		return nil, err
	}
	replay := map[string]any{
		"nonce": fmt.Sprintf("certen_%d_%s", nowMs, hex.EncodeToString(nb)), "created_at": nowS, "expires_at": expires,
		"intent_hash":      "",
		"chain_nonces":     map[string]any{"base-sepolia": "latest", "accumulated": "1"},
		"execution_window": map[string]any{"start_time": nowS, "end_time": expires, "grace_period_minutes": 5, "max_retries": 3},
		"security": map[string]any{
			"double_spending_protection": true, "replay_attack_prevention": true,
			"temporal_validation": "strict", "nonce_validation": "required",
		},
	}

	enc := func(v any) ([]byte, error) { return json.Marshal(v) }
	var blobs [4][]byte
	for i, v := range []any{intentData, crossChain, governance, replay} {
		b, err := enc(v)
		if err != nil {
			return nil, err
		}
		blobs[i] = b
	}
	// The scripts take the operation id over the blobs with the two hash fields still empty, then fill them in.
	_, opHex, err := proof.ComputeCanonical4BlobHash(blobs[0], blobs[1], blobs[2], blobs[3])
	if err != nil {
		return nil, err
	}
	op := "0x" + opHex
	replay["intent_hash"] = op
	governance["authorization"].(map[string]any)["authorization_hash"] = op
	for _, i := range []int{2, 3} {
		v := []any{intentData, crossChain, governance, replay}[i]
		if blobs[i], err = enc(v); err != nil {
			return nil, err
		}
	}
	return &intentBlobs{IntentID: intentID, OperationID: op, Blobs: blobs}, nil
}
