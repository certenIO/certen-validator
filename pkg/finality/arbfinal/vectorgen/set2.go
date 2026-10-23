// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	sw "github.com/certen/independant-validator/pkg/finality/arbfinal/synthworld"
)

// generate2 builds the second published set, finality_arb_final2 (RB11-E1-FIX): the vectors of the three LOW findings of the
// completeness review V-E1-A1. Set 1 and the force set are never written by this path.
func generate2(out string) error {
	mismatches = nil
	g := newGen()
	g.legacy = true
	synthetic3(g)
	if len(mismatches) > 0 {
		return fmt.Errorf("%d vectors disagree with the verifier:\n%s", len(mismatches), strings.Join(mismatches, "\n"))
	}
	return g.write2(out)
}

// nodeIndex is the position of filler in the canonical (ascending by keccak256) NODES order of the evidence.
func nodeIndex(e arbfinal.Evidence, filler []byte) uint64 {
	for i, n := range finality.EncodeNodes(e.Nodes) {
		if bytes.Equal(n, filler) {
			return uint64(i)
		}
	}
	panic("the filler is not in the NODES set")
}

// tooLarge is the literal of a NODES element over max_node_bytes that sits outside the transaction and receipt proof paths.
func tooLarge(w *sw.World, filler []byte) string {
	return st(finality.CodeEvidenceTooLarge, "part", "nodes", "count", uint64(len(filler)), "limit", uint64(4096), "index", nodeIndex(w.Evidence, filler))
}

func synthetic3(g *gen) {
	V := world("valid", nil)
	g.synth("synth_valid_direct", "synthetic", "the Rollup is called with confirmAssertion (the base of the patches of this set)", V, okText(okFields(V, "direct")))
	A := func(name, note string, w *sw.World, expect string) { g.synth(name, "adversarial", note, w, expect) }
	confirmCall := sw.ConfirmCall(sw.SelConfirm)
	walletInput := sw.WalletInput(sw.SelWalletTx, [][]byte{confirmCall}, []common.Address{sw.Rollup})
	txOf := func(w *sw.World) [32]byte { return w.TxHash }

	// ---- L1: the wallet route needs a transaction that has a callee ----
	create := world("create-wallet-input", func(p *sw.Parts) { p.TxCreate, p.TxInput = true, walletInput })
	A("adv_conf_contract_creation_with_wallet_entry_point_bytes", "a contract-creation transaction whose init code begins with the executeTransaction selector and decodes as a call to the Rollup: init code is not calldata",
		create, st(arbfinal.CodeConfirmationUnproof, "reason", arbfinal.ConfirmIndirect, "tx", txOf(create), "l1_block", create.K.Number))
	createTxs := world("create-wallet-txs", func(p *sw.Parts) {
		p.TxCreate, p.TxInput = true, sw.WalletInput(sw.SelWalletTxs, [][]byte{confirmCall}, []common.Address{sw.Rollup})
	})
	A("adv_conf_contract_creation_with_wallet_batch_entry_point_bytes", "the same for executeTransactions(bytes[],address[],uint256[])",
		createTxs, st(arbfinal.CodeConfirmationUnproof, "reason", arbfinal.ConfirmIndirect, "tx", txOf(createTxs), "l1_block", createTxs.K.Number))
	// The route is chosen by the calldata alone: the callee's code is not examined (spec 5.7: wallet addresses and code hashes are not
	// pinned, "indirect" is the state for calldata the verifier does not decode). This vector states that boundary; it is a non-claim.
	callee := world("wallet-callee-unexamined", func(p *sw.Parts) {
		t := common.HexToAddress("0x00000000000000000000000000000000000000cc")
		p.TxTo, p.TxInput = &t, walletInput
	})
	g.synth("synth_valid_wallet_route_callee_code_is_not_examined", "synthetic", "a callee that is not the synthetic ValidatorWallet address takes the wallet route on its calldata alone: the verifier proves the Rollup-side evidence (log set, status, anyTrustFastConfirmer = 0 at K), not the callee's code",
		callee, okText(okFields(callee, "wallet")))

	// ---- L2: the leg's chain ----
	for _, c := range []struct {
		name  string
		chain uint64
	}{{"zero", 0}, {"eth_sepolia", 11155111}, {"base_sepolia", 84532}} {
		leg := V.Leg
		leg.Chain = c.chain
		g.add("adv_leg_chain_is_"+c.name, "adversarial", "the leg names another chain than the container's header (arb-sepolia 421614): Kind.Verify judges it as the registry does",
			leg, "synth.json", V.Pins, V.Container, st(finality.CodeBlockMismatch, "field", "chain", "want", c.chain, "got", finality.ChainArbitrumSepolia))
	}

	// ---- L3: max_node_bytes for every NODES element that is not on the transaction or receipt proof path ----
	fill := func(n int) []byte { return bytes.Repeat([]byte{0x5a}, n) }
	with := func(w *sw.World, filler []byte) *sw.World {
		return edit(w, func(e *arbfinal.Evidence) { e.Nodes = append(e.Nodes, filler) })
	}
	atMax := with(V, fill(4096))
	g.synth("synth_valid_nodes_filler_at_max_node_bytes", "synthetic", "an unreferenced NODES element of exactly max_node_bytes (4096) is carried", atMax, okText(okFields(atMax, "direct")))
	for _, n := range []int{4097, 5200, 100000} {
		w := with(V, fill(n))
		A(fmt.Sprintf("adv_nodes_filler_of_%d_bytes", n), "an unreferenced NODES element over max_node_bytes outside the transaction and receipt proof paths: finality_evidence_too_large", w, tooLarge(w, fill(n)))
	}
	bigTx := world("large-tx-leaf", func(p *sw.Parts) {
		p.TxInput = append(append([]byte(nil), sw.SelConfirm[:]...), bytes.Repeat([]byte{0x33}, 5000)...)
	})
	g.synth("synth_valid_tx_proof_leaf_over_max_node_bytes", "synthetic", "the transaction leaf on the proof path is over 4096 bytes (a calldata-mode transaction): it keeps max_tx_leaf_bytes", bigTx, okText(okFields(bigTx, "direct")))
	bigRc := world("large-receipt-leaf", func(p *sw.Parts) { p.LogDataBytes = 6000 })
	g.synth("synth_valid_receipt_proof_leaf_over_max_node_bytes", "synthetic", "the receipt leaf on the proof path is over 4096 bytes: it keeps max_tx_leaf_bytes", bigRc, okText(okFields(bigRc, "direct")))
	beside := with(bigTx, fill(4097))
	A("adv_nodes_filler_over_max_node_bytes_beside_a_large_tx_leaf", "the exemption is the proof path itself, not the evidence: a 4097-byte filler beside a legitimately large transaction leaf is refused", beside, tooLarge(beside, fill(4097)))
	besideRc := with(bigRc, fill(4097))
	A("adv_nodes_filler_over_max_node_bytes_beside_a_large_receipt_leaf", "the same beside a large receipt leaf", besideRc, tooLarge(besideRc, fill(4097)))
}

// write2 writes the set: vectors.json, the evidence and pins files, the MANIFEST (vectors.json, evidence and pins only) and the
// README, which describes the set and is outside the manifest.
func (g *gen) write2(out string) error {
	if err := os.MkdirAll(filepath.Join(out, "evidence"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(out, "pins"), 0o755); err != nil {
		return err
	}
	files := map[string]string{}
	put := func(rel string, b []byte) error {
		files[rel] = fmt.Sprintf("%x", sha256.Sum256(b))
		return os.WriteFile(filepath.Join(out, filepath.FromSlash(rel)), b, 0o644)
	}
	var names []string
	for k := range g.evidence {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if err := put("evidence/"+k+".bin", g.evidence[k]); err != nil {
			return err
		}
	}
	names = nil
	for k := range g.pins {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if err := put("pins/"+k, g.pins[k]); err != nil {
			return err
		}
	}
	vj, err := json.MarshalIndent(map[string]any{"format": "finality_arb_final2/1", "vectors": g.vecs}, "", " ")
	if err != nil {
		return err
	}
	vj = append(vj, '\n')
	if err := put("vectors.json", vj); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "README.md"), []byte(readme2Text), 0o644); err != nil {
		return err
	}
	mj, _ := json.MarshalIndent(map[string]any{"format": "finality_arb_final2/manifest/1", "files": files}, "", " ")
	mj = append(mj, '\n')
	if err := os.WriteFile(filepath.Join(out, "MANIFEST.json"), mj, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(mj)
	if err := os.WriteFile(filepath.Join(out, "MANIFEST.json.sha256"), []byte(hex.EncodeToString(sum[:])+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %d vectors, %d evidence files, %d pins files; MANIFEST sha256 %x\n", len(g.vecs), len(g.evidence), len(g.pins), sum)
	return nil
}
