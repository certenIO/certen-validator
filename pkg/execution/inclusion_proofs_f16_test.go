// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// RB5-F16, the settlement gate's side: its transaction and receipt inclusion proofs are built by the one implementation
// (pkg/ethproof) from AGREED reads of the block, and they are byte-identical to the strategy observer's - the proofs the
// signed result hash binds and the chain_execution_results row stores. They used to be built from the gate's own single
// provider (its decoded block, or its raw JSON), and written over the strategy observer's hash list after the fact.

func gateObserver(t *testing.T, urls []string, chainID int64) *ExternalChainObserver {
	t.Helper()
	reader, err := ethrpc.NewAgreeingReader(context.Background(), chainID, urls, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := rpc.Dial(urls[0])
	if err != nil {
		t.Fatal(err)
	}
	return &ExternalChainObserver{ethClient: ethclient.NewClient(rc), rpcClient: rc, finality: reader, chainID: chainID,
		pollingInterval: 5 * time.Millisecond, timeout: 2 * time.Second, requiredConfirmations: 1}
}

func strategyObserver(t *testing.T, urls []string, chainID int64) *chain.EVMObserver {
	t.Helper()
	reader, err := ethrpc.NewAgreeingReader(context.Background(), chainID, urls, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ethclient.Dial(urls[0])
	if err != nil {
		t.Fatal(err)
	}
	o, err := chain.NewEVMObserver(&chain.EVMObserverConfig{Client: client, Finality: reader, ChainID: chainID, ValidatorID: "v",
		RequiredConfirmations: 1, PollingInterval: 5 * time.Millisecond, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// The gate's own provider cannot serve the block's bodies; the other two agree on them. The proofs are the agreed ones.
func TestTheGateProvesTheSettlementFromAgreedReads(t *testing.T) {
	for _, name := range ethprooftest.Settlements {
		t.Run(name, func(t *testing.T) {
			f := ethprooftest.Load(t, name)
			noBodies := func(method string, params []json.RawMessage, res json.RawMessage) json.RawMessage {
				var full bool
				switch {
				case method == "eth_getBlockByHash" && len(params) > 1 && json.Unmarshal(params[1], &full) == nil && full:
					return json.RawMessage("null")
				case method == "eth_getBlockReceipts":
					return json.RawMessage("null")
				}
				return res
			}
			urls := ethprooftest.URLs(t, &ethprooftest.Provider{F: f, Mutate: noBodies}, &ethprooftest.Provider{F: f},
				&ethprooftest.Provider{F: f, NoBlockReceipts: true})
			res, err := gateObserver(t, urls, f.ChainID).ObserveTransaction(context.Background(), f.SettlementTx)
			if err != nil {
				t.Fatal(err)
			}
			if res.TxInclusionProof == nil || !res.TxInclusionProof.Verify() || res.ReceiptInclusionProof == nil || !res.ReceiptInclusionProof.Verify() {
				t.Fatalf("THE regression: the gate built no verifying proofs from the agreeing providers (tx %v, receipt %v)",
					res.TxInclusionProof != nil, res.ReceiptInclusionProof != nil)
			}
			header := f.Header(t)
			if common.Hash(res.TxInclusionProof.ExpectedRoot) != header.TxHash || common.Hash(res.ReceiptInclusionProof.ExpectedRoot) != header.ReceiptHash ||
				common.Hash(res.TxInclusionProof.LeafHash) != f.SettlementTx {
				t.Fatal("the gate's proofs are not the settlement's in its block")
			}
		})
	}
}

// The gate and the strategy observer prove a settlement identically, byte for byte.
func TestTheGateAndTheStrategyObserverProveIdentically(t *testing.T) {
	for _, name := range ethprooftest.Settlements {
		t.Run(name, func(t *testing.T) {
			f := ethprooftest.Load(t, name)
			urls := ethprooftest.URLs(t, &ethprooftest.Provider{F: f}, &ethprooftest.Provider{F: f})
			gate, err := gateObserver(t, urls, f.ChainID).ObserveTransaction(context.Background(), f.SettlementTx)
			if err != nil {
				t.Fatal(err)
			}
			obs, err := strategyObserver(t, urls, f.ChainID).ObserveTransaction(context.Background(), f.SettlementTx)
			if err != nil {
				t.Fatal(err)
			}
			txJSON, _ := json.Marshal(gate.TxInclusionProof)
			rcJSON, _ := json.Marshal(gate.ReceiptInclusionProof)
			if gate.TxInclusionProof == nil || !bytes.Equal(txJSON, obs.MerkleProof) {
				t.Fatalf("THE regression: the strategy observer's transaction proof (%d bytes) is not the gate's (%d bytes)", len(obs.MerkleProof), len(txJSON))
			}
			if gate.ReceiptInclusionProof == nil || !bytes.Equal(rcJSON, obs.ReceiptProof) {
				t.Fatalf("THE regression: the strategy observer's receipt proof (%d bytes) is not the gate's (%d bytes)", len(obs.ReceiptProof), len(rcJSON))
			}
		})
	}
}

// Phase 7 refuses a cycle whose observation does not carry the proofs the gate verified, instead of writing the gate's
// copy over the signed one.
func TestPhase7RefusesProofsTheSignedObservationDoesNotCarry(t *testing.T) {
	f := ethprooftest.Load(t, ethprooftest.BaseSepolia)
	urls := ethprooftest.URLs(t, &ethprooftest.Provider{F: f}, &ethprooftest.Provider{F: f})
	gate, err := gateObserver(t, urls, f.ChainID).ObserveTransaction(context.Background(), f.SettlementTx)
	if err != nil {
		t.Fatal(err)
	}
	obs, err := strategyObserver(t, urls, f.ChainID).ObserveTransaction(context.Background(), f.SettlementTx)
	if err != nil {
		t.Fatal(err)
	}
	verified := verifiedCallProofs{strings.ToLower(strings.TrimPrefix(f.SettlementTx.Hex(), "0x")): gate}
	if err := sameVerifiedProofs([]*chain.ObservationResult{obs}, verified); err != nil {
		t.Fatalf("identical proofs refused: %v", err)
	}
	other := *obs
	other.ReceiptProof = append([]byte(nil), obs.ReceiptProof...)
	other.ReceiptProof[len(other.ReceiptProof)/2] ^= 1
	if err := sameVerifiedProofs([]*chain.ObservationResult{&other}, verified); err == nil {
		t.Fatal("an observation carrying other proofs than the gate verified was accepted")
	}
	if err := gate.VerifyInclusionProofs(); err != nil {
		t.Fatalf("the gate's proofs, bound to the result: %v", err)
	}
	bad := *gate
	bad.TxIndex++
	if err := bad.VerifyInclusionProofs(); err == nil {
		t.Fatal("proofs at another index than the result's transaction verified")
	}
}
