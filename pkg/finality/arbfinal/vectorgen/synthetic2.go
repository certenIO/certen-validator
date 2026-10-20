// Copyright 2026 Certen Protocol

package main

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	sw "github.com/certen/independant-validator/pkg/finality/arbfinal/synthworld"
)

// synthetic2 are the vectors added after the first mutation run over the verifier: each pins a boundary or an error path that
// the first 83 vectors left to the implementation (container framing, the leg's own header, the BoLD genesis boundary, log and
// calldata length boundaries, undecodable leaves, a proof left out of each read).
func synthetic2(g *gen) {
	V := world("valid", nil)
	A := func(name, note string, w *sw.World, expect string) { g.synth(name, "adversarial", note, w, expect) }
	other := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	otherTopic := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000d0")
	confirmCall := sw.ConfirmCall(sw.SelConfirm)
	txOf := func(w *sw.World) [32]byte { return w.TxHash }

	// ---- the BoLD genesis boundary ----
	first := world("first-post-bold", func(p *sw.Parts) { p.Leg = 105880605 })
	g.synth("synth_valid_first_post_bold_block", "synthetic", "the first block after the BoLD genesis block is judged", first, okText(okFields(first, "direct")))
	at := world("bold-genesis", func(p *sw.Parts) { p.Leg = 105880604 })
	A("adv_pre_bold_block_is_the_genesis_block", "the BoLD genesis L2 block itself is pre-BoLD (n <= bold_genesis_l2_block)", at, st(arbfinal.CodePreBold, "n", uint64(105880604), "bold_genesis_l2_block", uint64(105880604)))

	// ---- the container framing and the leg ----
	chainOff := 4 + 4 + len(arbfinal.KindName)
	A("adv_container_truncated_in_header", "the container cut inside its header", mustRaw(V, cp(V.Container)[:chainOff+3]),
		st(finality.CodeEvidenceMalformed, "part", "header.chain", "reason", finality.ReasonTruncated, "got_len", uint64(3), "want_len", uint64(8)))
	badMagic := cp(V.Container)
	badMagic[0] = 'D'
	A("adv_container_bad_magic", "the magic is DFE1", mustRaw(V, badMagic), st(finality.CodeEvidenceUnrecognised, "kind", "", "version", "magic:44464531"))
	hashFlip := cp(V.Container)
	hashFlip[chainOff+17] ^= 1
	want := V.Leg.Hash
	got := want
	got[0] ^= 1
	A("adv_container_block_hash", "header blockHash differs from the leg", mustRaw(V, hashFlip), st(finality.CodeBlockMismatch, "field", "blockHash", "want", want, "got", got))
	badHdr := cp(V.Leg.HeaderRLP)
	badHdr[len(badHdr)-1] ^= 1
	leg := V.Leg
	leg.HeaderRLP = badHdr
	g.add("adv_leg_header_does_not_hash_to_the_leg_hash", "adversarial", "the leg's raw header is not the header of the leg hash", leg, "synth.json", V.Pins, V.Container,
		st(finality.CodeBlockMismatch, "field", "settlementHeaderHash", "want", V.Leg.Hash, "got", [32]byte(crypto.Keccak256Hash(badHdr))))
	legN := V.Leg
	legN.Number++
	g.add("adv_leg_number_is_not_the_header_number", "adversarial", "the leg's number is not the number inside its (hash-consistent) header", legN, "synth.json", V.Pins, mustContainer(legN, V.Evidence),
		st(finality.CodeBlockMismatch, "field", "settlementHeaderNumber", "want", legN.Number, "got", V.Leg.Number))
	noL1 := editPins(V.Pins, nil, "eth_sepolia")
	g.synthPins("adv_pins_without_eth_sepolia_section", "the pins file has no eth_sepolia section: the L1 head cannot be judged", "synth_no_eth_sepolia.json", noL1, V,
		st(finality.CodePinUnknown, "chain", uint64(11155111), "kind", "eth_sepolia"))

	// ---- receipt logs and calldata lengths ----
	extra := world("extra-logs", func(p *sw.Parts) {
		p.Logs = []sw.Log{{Address: sw.Rollup}, {Address: sw.Rollup, Topics: []common.Hash{otherTopic}}, {Address: other, Topics: []common.Hash{sw.TopicConfirm, sw.ThisAssertion}},
			{Address: sw.Rollup, Topics: []common.Hash{sw.TopicConfirm, sw.ThisAssertion}}}
	})
	g.synth("synth_valid_receipt_with_other_logs_first", "synthetic", "logs without topics, with another topic and from another contract precede the confirmation log", extra, okText(okFields(extra, "direct")))
	oneTopic := world("one-topic", func(p *sw.Parts) { p.Logs = []sw.Log{{Address: sw.Rollup, Topics: []common.Hash{sw.TopicConfirm}}} })
	A("adv_conf_log_has_no_assertion_topic", "a Rollup AssertionConfirmed log with one topic only", oneTopic,
		st(arbfinal.CodeConfirmationUnproof, "reason", arbfinal.ConfirmLogMissing, "tx", txOf(oneTopic), "l1_block", oneTopic.K.Number))
	selOnly := world("selector-only", func(p *sw.Parts) { p.TxInput = sw.SelConfirm[:] })
	g.synth("synth_valid_selector_only_input", "synthetic", "the input is exactly the 4-byte confirmAssertion selector", selOnly, okText(okFields(selOnly, "direct")))
	short := world("three-bytes", func(p *sw.Parts) { p.TxInput = sw.SelConfirm[:3] })
	A("adv_conf_three_byte_input", "three bytes of calldata sent to the Rollup", short, st(arbfinal.CodeConfirmationUnproof, "reason", arbfinal.ConfirmIndirect, "tx", txOf(short), "l1_block", short.K.Number))
	wSel := world("wallet-selector-only", func(p *sw.Parts) {
		t := sw.ValidatorW
		p.TxTo, p.TxInput = &t, sw.WalletInput(sw.SelWalletTx, [][]byte{sw.SelConfirm[:]}, []common.Address{sw.Rollup})
	})
	g.synth("synth_valid_wallet_call_is_the_bare_selector", "synthetic", "the wallet's call data is exactly the 4-byte confirmAssertion selector", wSel, okText(okFields(wSel, "wallet")))
	wShort := world("wallet-three-bytes", func(p *sw.Parts) {
		t := sw.ValidatorW
		p.TxTo, p.TxInput = &t, sw.WalletInput(sw.SelWalletTx, [][]byte{sw.SelConfirm[:3]}, []common.Address{sw.Rollup})
	})
	A("adv_conf_wallet_call_data_three_bytes", "the wallet's call data to the Rollup is three bytes", wShort, st(arbfinal.CodeConfirmationUnproof, "reason", arbfinal.ConfirmWalletNoConfirm, "tx", txOf(wShort), "l1_block", wShort.K.Number))
	wLen := world("wallet-length-mismatch", func(p *sw.Parts) {
		t := sw.ValidatorW
		p.TxTo, p.TxInput = &t, sw.WalletInputAmounts([][]byte{confirmCall, confirmCall}, []common.Address{sw.Rollup, sw.Rollup}, 1)
	})
	A("adv_conf_wallet_arrays_of_different_lengths", "executeTransactions with two calls, two targets and one amount", wLen, st(arbfinal.CodeConfirmationUnproof, "reason", arbfinal.ConfirmWalletUndecodable, "tx", txOf(wLen), "l1_block", wLen.K.Number))
	wNoFast := world("wallet-no-fast-proof", func(p *sw.Parts) {
		t := sw.ValidatorW
		p.TxTo, p.TxInput, p.NoFastProof = &t, sw.WalletInput(sw.SelWalletTx, [][]byte{confirmCall}, []common.Address{sw.Rollup}), true
	})
	A("adv_conf_wallet_fast_confirmer_slot_unproven", "a wallet confirmation without the proof of the anyTrustFastConfirmer slot at K", wNoFast, st(arbfinal.CodeStateProofInvalid, "which", "slot"))

	// ---- leaves that are provable but are not what they must be ----
	idxAbsent := edit(V, func(e *arbfinal.Evidence) { e.ConfTxIndex = 3 })
	A("adv_conf_tx_index_absent_from_the_trie", "confTxIndex 3 of a trie of three transactions: a proven absence is not a transaction", idxAbsent, st(arbfinal.CodeTxProofInvalid, "which", "tx"))
	badTx := world("tx-leaf", func(p *sw.Parts) { p.TxLeaf = []byte{0x02, 0xc0} })
	A("adv_conf_tx_leaf_is_not_a_transaction", "the proven leaf at confTxIndex does not decode as a transaction", badTx, st(arbfinal.CodeTxProofInvalid, "which", "tx"))
	badRc := world("rc-leaf", func(p *sw.Parts) { p.RcLeaf = []byte{0x02, 0xc0} })
	A("adv_conf_receipt_leaf_is_not_a_receipt", "the proven leaf at confTxIndex does not decode as a receipt", badRc, st(arbfinal.CodeTxProofInvalid, "which", "receipt"))

	// ---- one proof left out of each read ----
	// S and K hold the same state in these worlds, so a proof is left out of BOTH (a node carried for one would serve the other).
	omit := func(name, note string, what string, expect string) {
		w := world(name, func(p *sw.Parts) { p.OmitS, p.OmitK = []string{what}, []string{what} })
		A("adv_proof_missing_"+name, note, w, expect)
	}
	slotBad, accBad := st(arbfinal.CodeStateProofInvalid, "which", "slot"), st(arbfinal.CodeStateProofInvalid, "which", "account")
	omit("admin_slot", "the proof of the EIP-1967 admin slot is left out", "admin_slot", slotBad)
	omit("user_slot", "the proof of the secondary slot is left out", "user_slot", slotBad)
	omit("admin_account", "the proof of the admin logic account is left out", "admin_account", accBad)
	omit("user_account", "the proof of the user logic account is left out", "user_account", accBad)
	omit("node_slot", "the proof of the assertion node slot is left out", "node_slot", slotBad)
	omit("config_slot", "the proof of the parent config slot is left out", "config_slot", slotBad)
}
