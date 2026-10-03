// Copyright 2026 Certen Protocol

package execution

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// RB5-F18 (survey §5 item 7): the write-back's tx_inclusion_proof_valid and receipt_inclusion_proof_valid. They were
// read from the proofs' construction-time Verified flag on a result that never carried proofs, so both were always
// false - and they sat in the transaction body, which is never written, so no write-back stated them at all. They are
// now computed from the settlement gate's verified trie proofs, checked again against the block's roots, and written.

func writtenEntries(t *testing.T, o *UnifiedOrchestrator, c *activeCycle) map[string]string {
	t.Helper()
	bundle, _, err := o.buildAttestationBundleFromCycle(c)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := o.txBuilder.BuildFromBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range tx.Body.DataEntry.ToDoubleHashFormat() {
		k, v, _ := strings.Cut(string(e), "=")
		out[k] = v
	}
	return out
}

// settledWithGateProofs turns the fixture's cycle into a settlement the gate proved: its observation names the
// transaction and the block's roots, and SettlementProof carries the gate's tx and receipt trie proofs.
func settledWithGateProofs(t *testing.T, o *UnifiedOrchestrator) (*activeCycle, *MerkleInclusionProof, *MerkleInclusionProof) {
	t.Helper()
	c := f81NonSettlementCycle(t, o)
	txProof, txRoot := buildTxProof(t, buildTestTxs(5), 2)
	// A second trie stands in for the block's receipts trie: the proof is the same kind and verifies the same way.
	rcProof, rcRoot := buildTxProof(t, buildTestTxs(6), 2)
	settlement := common.HexToHash("0x5e7f1e" + strings.Repeat("ab", 29))
	obs := c.Result.ObservationResults[0]
	obs.TxHash = settlement.Hex()
	obs.Status = 1
	obs.TransactionsRoot, obs.ReceiptsRoot = txRoot, rcRoot
	c.NonSettlement = nil
	c.SettlementTx = settlement.Hex()
	c.SettlementProof = &ExternalChainResult{TxHash: settlement, TxInclusionProof: txProof, ReceiptInclusionProof: rcProof}
	return c, txProof, rcProof
}

func TestTheWriteBackStatesTheSettlementsVerifiedInclusion(t *testing.T) {
	o := f81Orchestrator(nil, "v")
	c, _, _ := settledWithGateProofs(t, o)
	got := writtenEntries(t, o, c)
	if got["tx_inclusion_proof_valid"] != "true" || got["receipt_inclusion_proof_valid"] != "true" {
		t.Fatalf("the gate proved the settlement's tx and receipt in the block, and the write-back states tx=%q receipt=%q",
			got["tx_inclusion_proof_valid"], got["receipt_inclusion_proof_valid"])
	}
}

func TestTheInclusionVerdictsComeFromTheProofsNotTheirFlag(t *testing.T) {
	o := f81Orchestrator(nil, "v")

	// A proof whose trie does not reach the block's root proves nothing about that block, whatever its flag says.
	c, txProof, _ := settledWithGateProofs(t, o)
	c.Result.ObservationResults[0].TransactionsRoot = levelHash("another block's transactions root")
	if !txProof.Verified {
		t.Fatal("precondition: the proof's construction-time flag is set")
	}
	if got := writtenEntries(t, o, c); got["tx_inclusion_proof_valid"] != "false" || got["receipt_inclusion_proof_valid"] != "true" {
		t.Fatalf("a tx proof to another root is stated %q (receipt %q)", got["tx_inclusion_proof_valid"], got["receipt_inclusion_proof_valid"])
	}

	// A tampered proof node fails the walk.
	c, _, rcProof := settledWithGateProofs(t, o)
	rcProof.ProofNodes[0] = append([]byte(nil), rcProof.ProofNodes[0]...)
	rcProof.ProofNodes[0][len(rcProof.ProofNodes[0])-1] ^= 0xff
	if got := writtenEntries(t, o, c); got["receipt_inclusion_proof_valid"] != "false" {
		t.Fatalf("a tampered receipt proof is stated %q", got["receipt_inclusion_proof_valid"])
	}

	// Proofs of another transaction are not this settlement's.
	c, _, _ = settledWithGateProofs(t, o)
	c.SettlementProof.TxHash = common.HexToHash("0x01")
	if got := writtenEntries(t, o, c); got["tx_inclusion_proof_valid"] != "false" || got["receipt_inclusion_proof_valid"] != "false" {
		t.Fatalf("another transaction's proofs were stated for this settlement: %q %q", got["tx_inclusion_proof_valid"], got["receipt_inclusion_proof_valid"])
	}

	// A member that never settled has no transaction and no proof.
	if got := writtenEntries(t, o, f81NonSettlementCycle(t, o)); got["tx_inclusion_proof_valid"] != "false" || got["receipt_inclusion_proof_valid"] != "false" {
		t.Fatalf("a non-settlement states inclusion %q %q", got["tx_inclusion_proof_valid"], got["receipt_inclusion_proof_valid"])
	}
}
