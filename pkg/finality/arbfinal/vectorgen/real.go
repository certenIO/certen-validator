// Copyright 2026 Certen Protocol

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// realVectors adds the vectors derived from the live capture of cmd/finalityarbfinalrecord: the real positive and the
// adversarial cases made by editing real bytes. dir holds evidence.bin, leg.json {chain, number, hash, header_hex} and pins.json
// (the embedded pins with the eth_sepolia ledger of the ethl1 v2 set).
func realVectors(g *gen, dir string) error {
	read := func(n string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, n)) }
	ev, err := read("evidence.bin")
	if err != nil {
		return err
	}
	pins, err := read("pins.json")
	if err != nil {
		return err
	}
	lj, err := read("leg.json")
	if err != nil {
		return err
	}
	var l struct {
		Chain     uint64 `json:"chain"`
		Number    uint64 `json:"number"`
		Hash      string `json:"hash"`
		HeaderHex string `json:"header_hex"`
	}
	if err := json.Unmarshal(lj, &l); err != nil {
		return err
	}
	hb, err := hex.DecodeString(strings.TrimPrefix(l.HeaderHex, "0x"))
	if err != nil {
		return err
	}
	var leg finality.BlockRef
	leg.Chain, leg.Number, leg.HeaderRLP = l.Chain, l.Number, hb
	copy(leg.Hash[:], mustHex(l.Hash))

	p, err := finality.ParsePinsOverride(pins)
	if err != nil {
		return err
	}
	v, err := arbfinal.New().Verify(p, leg, ev)
	if err != nil {
		return fmt.Errorf("the live evidence is refused: %v", err)
	}
	g.add("real_valid", "live", "a real confirmed assertion of Arbitrum Sepolia, its honest confirmAssertion transaction, near-head Rollup proofs at S and K, a real L2 header chain and a real Sepolia light-client walk", leg, "real.json", pins, ev, outcome(v, nil))

	c, err := finality.DecodeContainer(ev, finality.DefaultLimits())
	if err != nil {
		return err
	}
	l1p, err := arbfinalL1Pins(p)
	if err != nil {
		return err
	}
	arbPins, err := arbfinal.LoadPins(p)
	if err != nil {
		return err
	}
	e, err := arbfinal.Decode(c.Body, arbfinal.Bounds{Limits: finality.DefaultLimits(), MaxLinks: l1p.MaxLinks, MaxSpineHeaders: l1p.MaxSpineHeaders, MaxHeaderChain: arbPins.MaxHeaderChain})
	if err != nil {
		return err
	}
	re := func(f func(e *arbfinal.Evidence)) []byte {
		x := e
		x.L1Spine, x.L2Spine, x.Nodes = cp2(e.L1Spine), cp2(e.L2Spine), cp2(e.Nodes)
		x.ConfTxRaw, x.ConfReceiptRaw = cp(e.ConfTxRaw), cp(e.ConfReceiptRaw)
		x.LC.FinalUpdate.SSZ, x.LC.AnchorBody.SSZ = cp(e.LC.FinalUpdate.SSZ), cp(e.LC.AnchorBody.SSZ)
		x.LC.Links = append([]ethl1.LB(nil), e.LC.Links...)
		f(&x)
		out, err := arbfinal.BuildContainer(leg, x)
		if err != nil {
			panic(err)
		}
		return out
	}
	hash := func(b []byte) [32]byte { return [32]byte(crypto.Keccak256Hash(b)) }
	add := func(name, note string, ev []byte, expect string) {
		g.add(name, "adversarial", note, leg, "real.json", pins, ev, expect)
	}

	unknownOrProof := func(f func(e *arbfinal.Evidence)) (string, []byte) {
		b := re(f)
		vv, er := arbfinal.New().Verify(p, leg, b)
		return outcome(vv, er), b
	}
	// Edits of the real assertion's preimage: the recomputed assertion is not a node of the Rollup. Which named state follows
	// depends on whether the carried nodes happen to cover the new key's path (assertion_unknown through a complete exclusion
	// proof, or l1_state_proof_invalid{slot} through a missing node); the literal written here is the one the verifier returns
	// for these exact bytes, and it is one of the two.
	for _, c := range []struct {
		name, note string
		f          func(e *arbfinal.Evidence)
	}{
		{"adv_real_after_send_root_altered", "afterState.sendRoot of the real assertion altered", func(e *arbfinal.Evidence) { e.After.SendRoot[0] ^= 1 }},
		{"adv_real_after_inbox_position_altered", "afterState.inboxPosition altered", func(e *arbfinal.Evidence) { e.After.InboxPosition++ }},
		{"adv_real_parent_assertion_hash_altered", "parentAssertionHash altered", func(e *arbfinal.Evidence) { e.ParentAssertionHash[0] ^= 1 }},
		{"adv_real_sequencer_batch_acc_altered", "sequencerBatchAcc altered", func(e *arbfinal.Evidence) { e.SequencerBatchAcc[0] ^= 1 }},
	} {
		exp, b := unknownOrProof(c.f)
		if !strings.Contains(exp, `"code":"assertion_unknown"`) && !strings.Contains(exp, `"code":"l1_state_proof_invalid"`) {
			return fmt.Errorf("%s: unexpected verdict %s", c.name, exp)
		}
		add(c.name, c.note, b, exp)
	}
	add("adv_real_machine_status_errored", "machineStatus 2", re(func(e *arbfinal.Evidence) { e.After.MachineStatus = 2 }), st(arbfinal.CodeMachineNotFinished, "machine_status", uint8(2)))
	add("adv_real_parent_config_confirm_period_altered", "ParentConfig.confirmPeriodBlocks + 1", re(func(e *arbfinal.Evidence) { e.Parent.ConfirmPeriodBlocks++ }),
		st(arbfinal.CodePreimageMismatch, "part", arbfinal.PreimageParentConfig))
	sp := e.L2Spine
	if len(sp) >= 3 {
		top := mustHeaderNumber(sp[0])
		add("adv_real_l2_spine_header_dropped", "an interior header of the real L2 chain removed", re(func(e *arbfinal.Evidence) { e.L2Spine = append([][]byte{e.L2Spine[0]}, e.L2Spine[2:]...) }),
			st(arbfinal.CodeHeaderChainBroken, "spine", "l2", "at_number", top-1, "want_hash", hash(sp[1]), "got_hash", hash(sp[2]), "reason", arbfinal.ReasonParentHash))
		fw := re(func(e *arbfinal.Evidence) { e.L2Spine[1][len(e.L2Spine[1])-1] ^= 1 })
		vv, er := arbfinal.New().Verify(p, leg, fw)
		add("adv_real_l2_spine_header_altered", "one byte of an interior real L2 header altered", fw, outcome(vv, er))
	}
	add("adv_real_l2_spine_leg_dropped", "the leg's own header removed from the real chain", re(func(e *arbfinal.Evidence) { e.L2Spine = e.L2Spine[:len(e.L2Spine)-1] }),
		st(finality.CodeBlockMismatch, "field", "spineLastNumber", "want", leg.Number, "got", leg.Number+1))
	for _, c := range []struct {
		name, note string
		f          func(e *arbfinal.Evidence)
	}{
		{"adv_real_conf_tx_altered", "a byte of the real confirmation transaction altered", func(e *arbfinal.Evidence) { e.ConfTxRaw[len(e.ConfTxRaw)-5] ^= 1 }},
		{"adv_real_conf_receipt_altered", "a byte of the real receipt altered", func(e *arbfinal.Evidence) { e.ConfReceiptRaw[len(e.ConfReceiptRaw)-5] ^= 1 }},
	} {
		exp, b := unknownOrProof(c.f)
		add(c.name, c.note, b, exp)
	}
	exp, b := unknownOrProof(func(e *arbfinal.Evidence) { e.LC.FinalUpdate.SSZ[len(e.LC.FinalUpdate.SSZ)-20] ^= 1 })
	add("adv_real_l1_finality_update_altered", "a byte of the real finality update altered (L1 finality refused, inner code carried)", b, exp)
	exp, b = unknownOrProof(func(e *arbfinal.Evidence) { e.L1Spine[1][len(e.L1Spine[1])-1] ^= 1 })
	add("adv_real_l1_spine_altered", "a byte of a real L1 spine header altered", b, exp)
	exp, b = unknownOrProof(func(e *arbfinal.Evidence) { e.Nodes[len(e.Nodes)/2][0] ^= 1 })
	add("adv_real_node_altered", "a byte of a trie node altered (the set is no longer ascending by hash or the proof breaks)", b, exp)
	return nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		panic(err)
	}
	return b
}

func mustHeaderNumber(raw []byte) uint64 {
	h, err := finality.ReadHeader(raw)
	if err != nil {
		panic(err)
	}
	return h.Number
}

func arbfinalL1Pins(p *finality.Pins) (ethl1.Pins, error) { return arbfinal.EthL1Pins(p) }
