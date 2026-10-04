// Copyright 2026 Certen Protocol

package strategy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// RB5-F16: the strategy observer - whose result hash Phase 8 signs and peers recompute - claimed transaction and receipt
// Merkle inclusion proofs, and built a list of the block's transaction hashes (constructTxMerkleProof), from a block one
// provider served, which go-ethereum could not even decode on Base or Arbitrum. The signed hash did not bind it. These
// tests observe real blocks of the three supported chains through agreeing providers.

// fixtureObserver observes f through providers ps: the first is the observer's own client, all are its agreeing reader.
func fixtureObserver(t *testing.T, ps ...*ethprooftest.Provider) *EVMObserver {
	t.Helper()
	urls := ethprooftest.URLs(t, ps...)
	reader, err := ethrpc.NewAgreeingReader(context.Background(), ps[0].F.ChainID, urls, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ethclient.Dial(urls[0])
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewEVMObserver(&EVMObserverConfig{Client: client, Finality: reader, ChainID: ps[0].F.ChainID, ValidatorID: "validator-4",
		RequiredConfirmations: 1, PollingInterval: 5 * time.Millisecond, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func observeFixture(t *testing.T, name string) (*ethprooftest.Fixture, *ObservationResult) {
	t.Helper()
	f := ethprooftest.Load(t, name)
	o := fixtureObserver(t, &ethprooftest.Provider{F: f}, &ethprooftest.Provider{F: f, NoBlockReceipts: true})
	obs, err := o.ObserveTransaction(context.Background(), f.SettlementTx)
	if err != nil {
		t.Fatalf("%s: observing the real settlement: %v", name, err)
	}
	return f, obs
}

// The observation carries a transaction and a receipt inclusion proof that verify offline against the block they name.
func TestTheStrategyObserverCarriesRealInclusionProofs(t *testing.T) {
	for _, name := range ethprooftest.Settlements {
		t.Run(name, func(t *testing.T) {
			f, obs := observeFixture(t, name)
			var txProof, rcProof ethproof.InclusionProof
			if err := json.Unmarshal(obs.MerkleProof, &txProof); err != nil {
				t.Fatalf("THE regression: the observation's transaction proof is not an inclusion proof (%d bytes): %v", len(obs.MerkleProof), err)
			}
			if err := json.Unmarshal(obs.ReceiptProof, &rcProof); err != nil {
				t.Fatalf("THE regression: the observation carries no receipt proof (%d bytes): %v", len(obs.ReceiptProof), err)
			}
			header := f.Header(t)
			headerRLP, err := rlp.EncodeToBytes(header)
			if err != nil {
				t.Fatal(err)
			}
			if _, receipt, err := ethproof.VerifySettlement(f.BlockHash(), headerRLP, f.SettlementTx, &txProof, &rcProof); err != nil {
				t.Fatalf("THE regression: the observation's proofs do not verify against block %s: %v", f.BlockHash().Hex(), err)
			} else if !receipt.Succeeded() || obs.Status != 1 {
				t.Fatalf("the proven receipt succeeded=%v, the observation states %d", receipt.Succeeded(), obs.Status)
			}
			if common.Hash(obs.TransactionsRoot) != header.TxHash || common.Hash(obs.ReceiptsRoot) != header.ReceiptHash {
				t.Fatal("the observation's roots are not the block's")
			}
			if string(obs.RawReceipt) != string(rcProof.LeafValue) {
				t.Fatal("the observation's raw receipt is not the receipt its proof proves")
			}
			var stated struct {
				From common.Address `json:"from"`
			}
			_ = json.Unmarshal(f.Transactions()[f.SettlementIndex()]["from"], &stated.From)
			if !strings.EqualFold(obs.TxFrom, stated.From.Hex()) {
				t.Fatalf("sender %s, the transaction's is %s", obs.TxFrom, stated.From.Hex())
			}
		})
	}
}

// The result hash - what Phase 8 signs and every peer recomputes - binds the proofs byte for byte.
func TestTheSignedResultHashBindsTheInclusionProofs(t *testing.T) {
	_, obs := observeFixture(t, ethprooftest.Sepolia)
	if computeResultHash(obs) != obs.ResultHash {
		t.Fatal("the observation's result hash is not its own")
	}
	for _, field := range []string{"merkle_proof", "receipt_proof"} {
		tampered := *obs
		switch field {
		case "merkle_proof":
			tampered.MerkleProof = append([]byte(nil), obs.MerkleProof...)
			tampered.MerkleProof[len(tampered.MerkleProof)/2] ^= 1
		case "receipt_proof":
			tampered.ReceiptProof = append([]byte(nil), obs.ReceiptProof...)
			tampered.ReceiptProof[len(tampered.ReceiptProof)/2] ^= 1
		}
		if computeResultHash(&tampered) == obs.ResultHash {
			t.Fatalf("THE regression: the signed result hash does not bind %s - a changed proof signs the same", field)
		}
	}
}

// A settlement whose receipt the providers agree on, but which the block's receiptsRoot does not commit to, is refused:
// the observation never stands without its proofs.
func TestAnUnprovableSettlementIsNotObserved(t *testing.T) {
	f := ethprooftest.Load(t, ethprooftest.Sepolia)
	idx := f.SettlementIndex()
	forge := func(method string, _ []json.RawMessage, res json.RawMessage) json.RawMessage {
		if method != "eth_getBlockReceipts" {
			return res
		}
		var rs []map[string]json.RawMessage
		_ = json.Unmarshal(res, &rs)
		rs[idx]["cumulativeGasUsed"] = json.RawMessage(`"0x1"`)
		out, _ := json.Marshal(rs)
		return out
	}
	o := fixtureObserver(t, &ethprooftest.Provider{F: f, Mutate: forge}, &ethprooftest.Provider{F: f, Mutate: forge})
	obs, err := o.ObserveTransaction(context.Background(), f.SettlementTx)
	if err == nil {
		t.Fatalf("THE regression: a settlement the block's receiptsRoot does not commit to was observed (result %x)", obs.ResultHash)
	}
	if !strings.Contains(err.Error(), "receiptsRoot") {
		t.Fatalf("refused, but not by name: %v", err)
	}
}

// A Nitro system transaction named as the settlement is proven in its block - the encoders cover it - and then refused by
// name, because no relayer signed it and it states no signer or call to observe.
func TestANitroSystemTransactionIsNotObservedAsASettlement(t *testing.T) {
	for _, name := range []string{ethprooftest.ArbitrumRetry, ethprooftest.ArbitrumDeposit, ethprooftest.ArbitrumUnsigned,
		ethprooftest.ArbitrumContract} {
		f := ethprooftest.Load(t, name)
		o := fixtureObserver(t, &ethprooftest.Provider{F: f}, &ethprooftest.Provider{F: f, NoBlockReceipts: true})
		obs, err := o.ObserveTransaction(context.Background(), f.SettlementTx)
		if err == nil {
			t.Fatalf("%s: a system transaction was observed as a settlement (result %x)", name, obs.ResultHash)
		}
		if !strings.Contains(err.Error(), "does not decode") || !strings.Contains(err.Error(), f.SettlementTx.Hex()) {
			t.Fatalf("%s: refused, but not by name: %v", name, err)
		}
	}
}

// What the observation emits verifies from its own bytes, and a tampered copy does not.
func TestAnObservationsProofsVerifyFromItsOwnBytes(t *testing.T) {
	for _, name := range ethprooftest.Settlements {
		_, obs := observeFixture(t, name)
		enc, err := json.Marshal(obs)
		if err != nil {
			t.Fatal(err)
		}
		var back ObservationResult
		if err := json.Unmarshal(enc, &back); err != nil {
			t.Fatal(err)
		}
		if _, _, err := VerifyObservationProofs(&back); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		bad := back
		bad.BlockHeaderRLP = append([]byte(nil), back.BlockHeaderRLP...)
		bad.BlockHeaderRLP[len(bad.BlockHeaderRLP)-1] ^= 1
		if _, _, err := VerifyObservationProofs(&bad); err == nil {
			t.Fatalf("%s: a tampered header verified", name)
		}
		bad = back
		bad.TxHash = common.Hash{1}.Hex()
		if _, _, err := VerifyObservationProofs(&bad); err == nil {
			t.Fatalf("%s: another transaction's hash verified", name)
		}
	}
}

// An observer whose finality reader cannot serve agreed block bodies refuses by name instead of observing unproven.
func TestAnObserverWithoutAgreedBodiesRefusesByName(t *testing.T) {
	f := ethprooftest.Load(t, ethprooftest.BaseSepolia)
	urls := ethprooftest.URLs(t, &ethprooftest.Provider{F: f})
	client, err := ethclient.Dial(urls[0])
	if err != nil {
		t.Fatal(err)
	}
	o, _ := NewEVMObserver(&EVMObserverConfig{Client: client, Finality: client, ChainID: f.ChainID, RequiredConfirmations: 1,
		PollingInterval: 5 * time.Millisecond, Timeout: time.Second})
	if _, err := o.ObserveTransaction(context.Background(), f.SettlementTx); err == nil || !strings.Contains(err.Error(), "cannot serve a block's agreed bodies") {
		t.Fatalf("an observer reading one provider's bodies: %v", err)
	}
}
