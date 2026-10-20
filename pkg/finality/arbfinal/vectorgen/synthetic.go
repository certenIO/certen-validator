// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	sw "github.com/certen/independant-validator/pkg/finality/arbfinal/synthworld"
)

func cp(b []byte) []byte { return append([]byte(nil), b...) }

func cp2(l [][]byte) [][]byte {
	out := make([][]byte, len(l))
	for i := range l {
		out[i] = cp(l[i])
	}
	return out
}

func clone(w *sw.World) *sw.World {
	c := *w
	e := w.Evidence
	e.L1Spine, e.L2Spine, e.Nodes = cp2(e.L1Spine), cp2(e.L2Spine), cp2(e.Nodes)
	e.ConfTxRaw, e.ConfReceiptRaw = cp(e.ConfTxRaw), cp(e.ConfReceiptRaw)
	e.LC.FinalUpdate.SSZ, e.LC.AnchorBody.SSZ = cp(e.LC.FinalUpdate.SSZ), cp(e.LC.AnchorBody.SSZ)
	c.Evidence = e
	return &c
}

// edit applies f to a copy of w's evidence and re-encodes the container.
func edit(w *sw.World, f func(e *arbfinal.Evidence)) *sw.World {
	c := clone(w)
	f(&c.Evidence)
	if err := c.Rebuild(); err != nil {
		panic(err)
	}
	return c
}

func flip(b []byte, i int) { b[i] ^= 0x01 }

func world(label string, mod func(*sw.Parts)) *sw.World {
	p := sw.NewParts(label)
	if mod != nil {
		mod(&p)
	}
	return sw.Assemble(p)
}

func okFields(w *sw.World, route string) map[string]any {
	m := w.Parts.Leg + uint64(w.Parts.L2Above)
	return map[string]any{
		"assertion": w.Assertion, "m": m, "s_number": w.S.Number, "s_hash": w.S.Hash, "k_number": w.K.Number, "k_hash": w.K.Hash,
		"confirm_period_blocks": uint64(20), "confirmation_path": "honest", "confirmation_route": route, "confirmation_tx": w.TxHash,
	}
}

// editPins returns the pins file with the JSON value at path replaced (keys re-sorted by the encoder).
func editPins(raw []byte, val any, path ...string) []byte {
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		panic(err)
	}
	cur := doc
	for _, k := range path[:len(path)-1] {
		cur = cur[k].(map[string]any)
	}
	if val == nil {
		delete(cur, path[len(path)-1])
	} else {
		cur[path[len(path)-1]] = val
	}
	out, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return out
}

func (g *gen) synth(name, group, note string, w *sw.World, expect string) {
	g.add(name, group, note, w.Leg, "synth.json", w.Pins, w.Container, expect)
}

func (g *gen) synthPins(name, note, pinsName string, pins []byte, w *sw.World, expect string) {
	g.add(name, "adversarial", note, w.Leg, pinsName, pins, w.Container, expect)
}

func synthetic(g *gen) {
	valid := world("valid", nil)
	g.synth("synth_valid_direct", "synthetic", "the Rollup is called with confirmAssertion; K and S distinct covered L1 blocks; the base of the patches", valid, okText(okFields(valid, "direct")))
	same := world("k-is-s", func(p *sw.Parts) { p.KBack = 0 })
	g.synth("synth_valid_k_equals_s", "synthetic", "K = S (allowed: K <= S)", same, okText(okFields(same, "direct")))
	own := world("leg-is-assertion-block", func(p *sw.Parts) { p.L2Above = 0 })
	g.synth("synth_valid_leg_is_assertion_block", "synthetic", "the leg is the assertion's own block: an l2Spine of one header", own, okText(okFields(own, "direct")))
	fastIrr := world("fast-irrelevant", func(p *sw.Parts) { p.FastConfirm = common.HexToAddress("0x00000000000000000000000000000000000fa570") })
	g.synth("synth_valid_direct_fast_confirmer_irrelevant", "synthetic", "a direct confirmAssertion transaction is honest whatever anyTrustFastConfirmer holds (only wallet confirmations read it)", fastIrr, okText(okFields(fastIrr, "direct")))

	confirmCall := sw.ConfirmCall(sw.SelConfirm)
	other := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	wallet := func(label string, input []byte, mod func(*sw.Parts)) *sw.World {
		return world(label, func(p *sw.Parts) {
			t := sw.ValidatorW
			p.TxTo, p.TxInput = &t, input
			if mod != nil {
				mod(p)
			}
		})
	}
	w1 := wallet("wallet-tx", sw.WalletInput(sw.SelWalletTx, [][]byte{confirmCall}, []common.Address{sw.Rollup}), nil)
	g.synth("synth_valid_wallet_execute_transaction", "synthetic", "ValidatorWallet.executeTransaction(bytes,address,uint256) -> Rollup.confirmAssertion; anyTrustFastConfirmer = 0 proven at K", w1, okText(okFields(w1, "wallet")))
	w2 := wallet("wallet-txs", sw.WalletInput(sw.SelWalletTxs, [][]byte{{0x01, 0x02}, confirmCall}, []common.Address{other, sw.Rollup}), nil)
	g.synth("synth_valid_wallet_execute_transactions", "synthetic", "ValidatorWallet.executeTransactions(bytes[],address[],uint256[]): a first call elsewhere, the second call confirms", w2, okText(okFields(w2, "wallet")))
	w3 := wallet("wallet-tx-refund", sw.WalletInput(sw.SelWalletTxR, [][]byte{confirmCall}, []common.Address{sw.Rollup}), nil)
	g.synth("synth_valid_wallet_execute_transaction_with_gas_refunder", "synthetic", "executeTransactionWithGasRefunder(address,bytes,address,uint256)", w3, okText(okFields(w3, "wallet")))
	w4 := wallet("wallet-txs-refund", sw.WalletInput(sw.SelWalletTxsR, [][]byte{confirmCall}, []common.Address{sw.Rollup}), nil)
	g.synth("synth_valid_wallet_execute_transactions_with_gas_refunder", "synthetic", "executeTransactionsWithGasRefunder(address,bytes[],address[],uint256[])", w4, okText(okFields(w4, "wallet")))

	V := valid
	A := func(name, note string, w *sw.World, expect string) { g.synth(name, "adversarial", note, w, expect) }

	// ---- the assertion ----
	A("adv_machine_status_errored", "afterState.machineStatus = 2", edit(V, func(e *arbfinal.Evidence) { e.After.MachineStatus = 2 }),
		st(arbfinal.CodeMachineNotFinished, "machine_status", uint8(2)))
	A("adv_machine_status_running", "afterState.machineStatus = 0", edit(V, func(e *arbfinal.Evidence) { e.After.MachineStatus = 0 }),
		st(arbfinal.CodeMachineNotFinished, "machine_status", uint8(0)))
	unknown := st(arbfinal.CodeAssertionUnknown)
	A("adv_after_send_root_altered", "afterState.sendRoot altered: the recomputed assertion is not a node of the Rollup", edit(V, func(e *arbfinal.Evidence) { e.After.SendRoot[0] ^= 1 }), unknown)
	A("adv_after_inbox_position_altered", "afterState.inboxPosition altered", edit(V, func(e *arbfinal.Evidence) { e.After.InboxPosition++ }), unknown)
	A("adv_after_position_in_message_altered", "afterState.positionInMessage altered", edit(V, func(e *arbfinal.Evidence) { e.After.PositionInMessage++ }), unknown)
	A("adv_after_end_history_root_altered", "afterState.endHistoryRoot altered", edit(V, func(e *arbfinal.Evidence) { e.After.EndHistoryRoot[31] ^= 1 }), unknown)
	A("adv_after_block_hash_altered", "afterState.blockHash altered", edit(V, func(e *arbfinal.Evidence) { e.After.BlockHash[5] ^= 1 }), unknown)
	A("adv_parent_assertion_hash_altered", "parentAssertionHash altered", edit(V, func(e *arbfinal.Evidence) { e.ParentAssertionHash[0] ^= 1 }), unknown)
	A("adv_sequencer_batch_acc_altered", "sequencerBatchAcc altered", edit(V, func(e *arbfinal.Evidence) { e.SequencerBatchAcc[31] ^= 1 }), unknown)
	pending := world("pending", func(p *sw.Parts) { p.Status = 1 })
	A("adv_status_pending", "the node's status byte is 1 (Pending)", pending, st(arbfinal.CodeNotConfirmed, "status", uint64(1)))
	none := world("no-assertion", func(p *sw.Parts) { p.Status = 0 })
	A("adv_status_no_assertion", "the node's status byte is 0 (NoAssertion)", none, unknown)
	three := world("status-3", func(p *sw.Parts) { p.Status = 3 })
	A("adv_status_three", "a status byte outside the enum", three, st(arbfinal.CodeNotConfirmed, "status", uint64(3)))
	cfg := st(arbfinal.CodePreimageMismatch, "part", arbfinal.PreimageParentConfig)
	A("adv_parent_config_confirm_period_altered", "ParentConfig.confirmPeriodBlocks 20 -> 21", edit(V, func(e *arbfinal.Evidence) { e.Parent.ConfirmPeriodBlocks = 21 }), cfg)
	A("adv_parent_config_wasm_module_root_altered", "ParentConfig.wasmModuleRoot altered", edit(V, func(e *arbfinal.Evidence) { e.Parent.WasmModuleRoot[0] ^= 1 }), cfg)
	A("adv_parent_config_required_stake_altered", "ParentConfig.requiredStake altered", edit(V, func(e *arbfinal.Evidence) { e.Parent.RequiredStake[31] ^= 1 }), cfg)
	A("adv_parent_config_challenge_manager_altered", "ParentConfig.challengeManager altered", edit(V, func(e *arbfinal.Evidence) { e.Parent.ChallengeManager[0] ^= 1 }), cfg)
	A("adv_parent_config_next_inbox_position_altered", "ParentConfig.nextInboxPosition altered", edit(V, func(e *arbfinal.Evidence) { e.Parent.NextInboxPosition++ }), cfg)
	forgedCfg := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000c1")
	A("adv_parent_config_slot_other", "the parent config slot on L1 holds another hash", world("cfg-slot", func(p *sw.Parts) { p.ConfigWord = &forgedCfg }), cfg)

	// ---- contract identity under S and under K ----
	bad := crypto.Keccak256Hash([]byte("an unpinned logic contract"))
	idn := func(role string, addr common.Address, code common.Hash, at uint64) string {
		return st(arbfinal.CodeContractIdentity, "role", role, "address", addr[:], "code_hash", code[:], "judged_at", at)
	}
	wAS := world("admin-s", func(p *sw.Parts) { p.AdminCodeS = bad })
	A("adv_admin_logic_not_pinned_under_s", "the admin logic code hash is not in logic_pins at S", wAS, idn(arbfinal.RoleAdminLogic, sw.AdminLogic, bad, wAS.S.Number))
	wUS := world("user-s", func(p *sw.Parts) { p.UserCodeS = bad })
	A("adv_user_logic_not_pinned_under_s", "the secondary user logic code hash is not in logic_pins at S", wUS, idn(arbfinal.RoleUserLogic, sw.UserLogic, bad, wUS.S.Number))
	wAK := world("admin-k", func(p *sw.Parts) { p.AdminCodeK = bad })
	A("adv_admin_logic_not_pinned_under_k", "pinned at S, unpinned at K: an upgrade-confirm-restore path leaves no trace under S [r2:C1]", wAK, idn(arbfinal.RoleAdminLogic, sw.AdminLogic, bad, wAK.K.Number))
	wUK := world("user-k", func(p *sw.Parts) { p.UserCodeK = bad })
	A("adv_user_logic_not_pinned_under_k", "the user logic is unpinned at K only", wUK, idn(arbfinal.RoleUserLogic, sw.UserLogic, bad, wUK.K.Number))
	wSwap := world("role-swap", func(p *sw.Parts) { p.AdminCodeS = sw.UserCode })
	A("adv_admin_slot_holds_user_logic_code", "the admin logic account holds the (pinned) user logic code: the role does not match", wSwap, idn(arbfinal.RoleAdminLogic, sw.AdminLogic, sw.UserCode, wSwap.S.Number))
	ghost := common.HexToAddress("0x00000000000000000000000000000000000000cc")
	gw := common.BytesToHash(append(make([]byte, 12), ghost[:]...))
	wGhost := world("admin-ghost", func(p *sw.Parts) { p.AdminWordS = &gw })
	A("adv_admin_implementation_slot_altered", "the EIP-1967 admin slot names an address with no account", wGhost, idn(arbfinal.RoleAdminLogic, ghost, common.Hash{}, wGhost.S.Number))
	wGhostK := world("user-ghost-k", func(p *sw.Parts) { p.UserWordK = &gw })
	A("adv_user_implementation_slot_altered_under_k", "the secondary slot names an address with no account at K only", wGhostK, idn(arbfinal.RoleUserLogic, ghost, common.Hash{}, wGhostK.K.Number))
	hi := common.BytesToHash(append([]byte{0x01}, append(make([]byte, 11), sw.AdminLogic[:]...)...))
	wHi := world("admin-hi", func(p *sw.Parts) { p.AdminWordS = &hi })
	A("adv_admin_implementation_word_high_bytes", "the admin slot word has a non-zero byte above the 20-byte address", wHi, idn(arbfinal.RoleAdminLogic, sw.AdminLogic, sw.AdminCode, wHi.S.Number))
	wAbs := world("rollup-absent", func(p *sw.Parts) { p.RollupAbsent = true })
	A("adv_rollup_account_absent", "the Rollup account does not exist at S (a verified exclusion proof)", wAbs, idn("rollup", sw.Rollup, common.Hash{}, wAbs.S.Number))
	A("adv_nodes_empty", "no trie node is carried", edit(V, func(e *arbfinal.Evidence) { e.Nodes = nil }), st(arbfinal.CodeStateProofInvalid, "which", "account"))

	// ---- the confirmation path ----
	txh, kn := func(w *sw.World) [32]byte { return w.TxHash }, func(w *sw.World) uint64 { return w.K.Number }
	unp := func(w *sw.World, r arbfinal.ConfirmReason) string {
		return st(arbfinal.CodeConfirmationUnproof, "reason", r, "tx", txh(w), "l1_block", kn(w))
	}
	forceT := func(w *sw.World, path string) string {
		return st(arbfinal.CodeConfirmedByOwner, "path", path, "tx", txh(w), "l1_block", kn(w))
	}
	assertion := sw.ThisAssertion
	otherTopic := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000d0")
	wNoLog := world("no-log", func(p *sw.Parts) { p.NoLogs = true })
	A("adv_conf_receipt_without_log", "the receipt holds no log", wNoLog, unp(wNoLog, arbfinal.ConfirmLogMissing))
	wT0 := world("topic0", func(p *sw.Parts) {
		p.Logs = []sw.Log{{Address: sw.Rollup, Topics: []common.Hash{otherTopic, common.Hash(assertion)}}}
	})
	A("adv_conf_wrong_topic0", "a Rollup log with another event signature", wT0, unp(wT0, arbfinal.ConfirmLogMissing))
	wT1 := world("topic1", func(p *sw.Parts) {
		p.Logs = []sw.Log{{Address: sw.Rollup, Topics: []common.Hash{sw.TopicConfirm, otherTopic}}}
	})
	A("adv_conf_wrong_assertion_topic", "AssertionConfirmed for another assertion hash", wT1, unp(wT1, arbfinal.ConfirmLogMissing))
	wAddr := world("log-address", func(p *sw.Parts) {
		p.Logs = []sw.Log{{Address: other, Topics: []common.Hash{sw.TopicConfirm, common.Hash(assertion)}}}
	})
	A("adv_conf_log_from_other_contract", "the log is not emitted by the Rollup", wAddr, unp(wAddr, arbfinal.ConfirmLogMissing))
	wSt0 := world("status0", func(p *sw.Parts) { p.RcStatus = 0 })
	A("adv_conf_receipt_status_zero", "receipt status 0", wSt0, unp(wSt0, arbfinal.ConfirmReceiptStatus))
	wTo := world("to-other", func(p *sw.Parts) { p.TxTo = &other })
	A("adv_conf_tx_to_other_contract", "tx.to is not the Rollup and the input is not a wallet entry point", wTo, unp(wTo, arbfinal.ConfirmIndirect))
	wForceSel := world("force-selector", func(p *sw.Parts) { p.TxInput = sw.ConfirmCall(sw.SelForce) })
	A("adv_conf_force_selector", "forceConfirmAssertion 0x5bf03833 sent to the Rollup", wForceSel, forceT(wForceSel, "force"))
	both := []sw.Log{{Address: sw.Rollup, Topics: []common.Hash{sw.TopicConfirm, common.Hash(assertion)}}, {Address: sw.Rollup, Topics: []common.Hash{sw.TopicForce, common.Hash(assertion)}}}
	wForceLog := world("force-log", func(p *sw.Parts) { p.Logs = both })
	A("adv_conf_force_log_on_confirm_selector", "a confirmAssertion selector but an AssertionForceConfirmed log in the receipt", wForceLog, forceT(wForceLog, "force"))
	wExec := world("executor-force", func(p *sw.Parts) {
		p.TxTo, p.TxInput, p.Logs = &sw.Executor, []byte{0x1c, 0xff, 0x79, 0xcd, 0x00}, both
	})
	A("adv_conf_owner_force_through_upgrade_executor", "the shape of the 2025-10-13 force-confirm: tx.to = the UpgradeExecutor, receipt with AssertionConfirmed and AssertionForceConfirmed", wExec, forceT(wExec, "force"))
	wFast := world("fast-selector", func(p *sw.Parts) { p.TxInput = sw.ConfirmCall(sw.SelFast) })
	A("adv_conf_fast_confirm_selector", "fastConfirmAssertion 0x6096686d", wFast, forceT(wFast, "fast"))
	wFastNew := world("fast-new-selector", func(p *sw.Parts) { p.TxInput = sw.ConfirmCall(sw.SelFastNew) })
	A("adv_conf_fast_confirm_new_selector", "fastConfirmNewAssertion 0x6420fb9f", wFastNew, forceT(wFastNew, "fast"))
	wOtherSel := world("other-selector", func(p *sw.Parts) { p.TxInput = sw.ConfirmCall([4]byte{0xde, 0xad, 0xbe, 0xef}) })
	A("adv_conf_other_selector_to_rollup", "an unknown selector sent to the Rollup", wOtherSel, unp(wOtherSel, arbfinal.ConfirmIndirect))
	wEmpty := world("empty-input", func(p *sw.Parts) { p.TxInput = []byte{} })
	A("adv_conf_empty_input_to_rollup", "empty calldata", wEmpty, unp(wEmpty, arbfinal.ConfirmIndirect))
	wWOther := wallet("wallet-other-target", sw.WalletInput(sw.SelWalletTx, [][]byte{confirmCall}, []common.Address{other}), nil)
	A("adv_conf_wallet_call_targets_other_contract", "the decoded wallet call has the confirm selector but targets another contract", wWOther, unp(wWOther, arbfinal.ConfirmWalletNoConfirm))
	wWSel := wallet("wallet-other-selector", sw.WalletInput(sw.SelWalletTx, [][]byte{sw.ConfirmCall([4]byte{0xde, 0xad, 0xbe, 0xef})}, []common.Address{sw.Rollup}), nil)
	A("adv_conf_wallet_call_other_selector", "the decoded wallet call targets the Rollup with another selector", wWSel, unp(wWSel, arbfinal.ConfirmWalletNoConfirm))
	wWFast := wallet("wallet-fast", sw.WalletInput(sw.SelWalletTx, [][]byte{sw.ConfirmCall(sw.SelFast)}, []common.Address{sw.Rollup}), nil)
	A("adv_conf_wallet_fast_call", "the wallet calls fastConfirmAssertion", wWFast, forceT(wWFast, "fast"))
	wWForce := wallet("wallet-force", sw.WalletInput(sw.SelWalletTx, [][]byte{sw.ConfirmCall(sw.SelForce)}, []common.Address{sw.Rollup}), nil)
	A("adv_conf_wallet_force_call", "the wallet calls forceConfirmAssertion", wWForce, forceT(wWForce, "force"))
	wWFC := wallet("wallet-fast-confirmer", sw.WalletInput(sw.SelWalletTx, [][]byte{confirmCall}, []common.Address{sw.Rollup}),
		func(p *sw.Parts) { p.FastConfirm = common.HexToAddress("0x00000000000000000000000000000000000fa570") })
	A("adv_conf_wallet_fast_confirmer_nonzero", "a wallet confirmation while anyTrustFastConfirmer is not the zero address at K", wWFC, unp(wWFC, arbfinal.ConfirmFastConfirmerSet))
	wWBad := wallet("wallet-garbage", append(append([]byte(nil), sw.SelWalletTx[:]...), bytes.Repeat([]byte{0xab}, 40)...), nil)
	A("adv_conf_wallet_calldata_undecodable", "executeTransaction selector followed by bytes that are not ABI arguments", wWBad, unp(wWBad, arbfinal.ConfirmWalletUndecodable))
	good := sw.WalletInput(sw.SelWalletTx, [][]byte{confirmCall}, []common.Address{sw.Rollup})
	wWNon := wallet("wallet-noncanonical", append(append([]byte(nil), good...), 0x00), nil)
	A("adv_conf_wallet_calldata_noncanonical", "valid arguments with one trailing byte: the ABI encoding must be canonical", wWNon, unp(wWNon, arbfinal.ConfirmWalletUndecodable))
	A("adv_conf_tx_bytes_altered", "a byte of the carried transaction altered: the leaf is not the proven one", edit(V, func(e *arbfinal.Evidence) { flip(e.ConfTxRaw, len(e.ConfTxRaw)-3) }), st(arbfinal.CodeTxProofInvalid, "which", "tx"))
	A("adv_conf_receipt_bytes_altered", "a byte of the carried receipt altered", edit(V, func(e *arbfinal.Evidence) { flip(e.ConfReceiptRaw, len(e.ConfReceiptRaw)-3) }), st(arbfinal.CodeTxProofInvalid, "which", "receipt"))
	A("adv_conf_tx_index_altered", "confTxIndex names another position of K's transaction trie", edit(V, func(e *arbfinal.Evidence) { e.ConfTxIndex++ }), st(arbfinal.CodeTxProofInvalid, "which", "tx"))

	// ---- the L2 spine ----
	top := V.Parts.Leg + uint64(V.Parts.L2Above)
	hash := func(b []byte) [32]byte { return [32]byte(crypto.Keccak256Hash(b)) }
	sp := V.Evidence.L2Spine
	A("adv_l2_spine_header_dropped", "a header removed from the middle of the l2Spine", edit(V, func(e *arbfinal.Evidence) { e.L2Spine = append([][]byte{e.L2Spine[0]}, e.L2Spine[2:]...) }),
		st(arbfinal.CodeHeaderChainBroken, "spine", "l2", "at_number", top-1, "want_hash", hash(sp[1]), "got_hash", hash(sp[2]), "reason", arbfinal.ReasonParentHash))
	fw := edit(V, func(e *arbfinal.Evidence) { flip(e.L2Spine[1], len(e.L2Spine[1])-1) })
	A("adv_l2_spine_forged_link", "one byte of an interior header altered", fw,
		st(arbfinal.CodeHeaderChainBroken, "spine", "l2", "at_number", top-1, "want_hash", hash(sp[1]), "got_hash", hash(fw.Evidence.L2Spine[1]), "reason", arbfinal.ReasonParentHash))
	skip := world("l2-number-gap", func(p *sw.Parts) { p.L2Skip = 2 })
	ssp := skip.Evidence.L2Spine
	A("adv_l2_spine_number_gap", "a hash-linked chain whose numbers skip one", skip,
		st(arbfinal.CodeHeaderChainBroken, "spine", "l2", "at_number", skip.Parts.Leg+2, "want_hash", hash(ssp[2]), "got_hash", hash(ssp[2]), "reason", arbfinal.ReasonNumberGap))
	topHash := [32]byte(crypto.Keccak256Hash([]byte("an assertion block that is not the top of the spine")))
	wTop := world("l2-top-other", func(p *sw.Parts) { p.AfterHash = &topHash })
	A("adv_l2_spine_top_is_not_the_assertion_block", "the assertion's blockHash is not the hash of l2Spine[0]", wTop,
		st(arbfinal.CodeHeaderChainBroken, "spine", "l2", "at_number", top, "want_hash", topHash, "got_hash", hash(wTop.Evidence.L2Spine[0]), "reason", arbfinal.ReasonParentHash))
	A("adv_l2_spine_leg_header_dropped", "the leg's own header removed: the spine ends one block above it", edit(V, func(e *arbfinal.Evidence) { e.L2Spine = e.L2Spine[:len(e.L2Spine)-1] }),
		st(finality.CodeBlockMismatch, "field", "spineLastNumber", "want", V.Parts.Leg, "got", V.Parts.Leg+1))
	A("adv_l2_spine_empty", "an empty l2Spine", edit(V, func(e *arbfinal.Evidence) { e.L2Spine = nil }),
		st(finality.CodeEvidenceMalformed, "part", "l2Spine", "reason", finality.ReasonSpineEmpty, "got_len", uint64(0), "want_len", uint64(1)))
	bOther := world("another-chain", nil)
	g.add("adv_l2_leg_is_on_another_chain", "adversarial", "a spine of one chain judged for a leg of another chain with the same block number", bOther.Leg, "synth.json", V.Pins,
		mustContainer(bOther.Leg, V.Evidence), st(finality.CodeBlockMismatch, "field", "spineLastHash", "want", bOther.Leg.Hash, "got", V.Leg.Hash))
	bNext := world("next-number", func(p *sw.Parts) { p.Leg++ })
	g.add("adv_l2_leg_number_not_on_spine", "adversarial", "a leg whose number is above the leg the spine ends at", bNext.Leg, "synth.json", V.Pins,
		mustContainer(bNext.Leg, V.Evidence), st(finality.CodeBlockMismatch, "field", "spineLastNumber", "want", bNext.Leg.Number, "got", V.Leg.Number))
	preBold := world("pre-bold", func(p *sw.Parts) { p.Leg = 100_000_000 })
	A("adv_pre_bold_block", "the leg's block number is at or below the BoLD genesis L2 block", preBold, st(arbfinal.CodePreBold, "n", uint64(100_000_000), "bold_genesis_l2_block", uint64(105880604)))
	short := editPins(V.Pins, json.Number("2"), "arb_sepolia", "max_header_chain")
	g.synthPins("adv_l2_spine_exceeds_max_header_chain", "max_header_chain = 2 and a spine of 4 headers", "synth_max_header_chain_2.json", short, V,
		st(arbfinal.CodeHeaderChainExceeds, "needed", uint64(4), "max", uint64(2)))

	// ---- the L1 side ----
	low := V.K.Number - 1
	A("adv_state_block_above_the_spine", "stateBlock above the finalized head", edit(V, func(e *arbfinal.Evidence) { e.StateBlock = V.Parts.F + 1 }),
		st("finality_block_not_covered", "block_number", V.Parts.F+1, "finalized_exec_number", V.Parts.F))
	A("adv_conf_block_below_the_spine", "confBlock below the lowest spine header", edit(V, func(e *arbfinal.Evidence) { e.ConfBlock = low - 1 }),
		st("finality_block_not_covered", "block_number", low-1, "finalized_exec_number", V.Parts.F))
	A("adv_conf_block_above_state_block", "K > S, both on the spine", edit(V, func(e *arbfinal.Evidence) { e.StateBlock, e.ConfBlock = V.K.Number, V.S.Number }),
		st(finality.CodeBlockMismatch, "field", "confBlockAboveStateBlock", "want", V.K.Number, "got", V.S.Number))
	A("adv_l1_signature_flipped", "a byte of the aggregate signature of the finality update flipped: L1 finality is refused and its inner code is carried",
		edit(V, func(e *arbfinal.Evidence) { flip(e.LC.FinalUpdate.SSZ, 496+496+288+64+10) }),
		st(arbfinal.CodeL1FinalityUnproven, "reason", arbfinal.L1FinalityLCRefused, "inner", "finality_signature_invalid"))
	A("adv_l1_spine_link_broken", "an L1 spine header altered: the spine does not reach the finalized head", edit(V, func(e *arbfinal.Evidence) { flip(e.L1Spine[1], len(e.L1Spine[1])-1) }),
		st(arbfinal.CodeL1FinalityUnproven, "reason", arbfinal.L1FinalitySpineRefused, "inner", "finality_header_chain_broken"))
	A("adv_l1_spine_top_is_not_the_finalized_head", "the spine's first header is not the finalized execution head", edit(V, func(e *arbfinal.Evidence) { e.L1Spine = e.L1Spine[1:] }),
		st(arbfinal.CodeL1FinalityUnproven, "reason", arbfinal.L1FinalitySpineRefused, "inner", "finality_header_chain_broken"))
	otherRoot := "0x" + hx(bytes.Repeat([]byte{0x77}, 32))
	otherAnchor := editPins(V.Pins, []any{map[string]any{"period": json.Number("1379"), "committee_root": otherRoot, "wsp_epochs": json.Number("279"), "link_sha256": hx(bytes.Repeat([]byte{0x33}, 32)), "derived_by": []any{"x"}}}, "eth_sepolia", "anchors")
	g.synthPins("adv_l1_anchor_not_the_pinned_committee", "the carried committee is not the ledger's committee for the period", "synth_anchor_other_root.json", otherAnchor, V,
		st(arbfinal.CodeL1FinalityUnproven, "reason", arbfinal.L1FinalityLCRefused, "inner", "finality_pin_mismatch"))

	// ---- the container and the pins ----
	A("adv_container_trailing_byte", "one byte after the container", mustRaw(V, append(cp(V.Container), 0x00)),
		st(finality.CodeEvidenceMalformed, "part", "body", "reason", finality.ReasonTrailingBytes, "got_len", uint64(1), "want_len", uint64(0)))
	kindV2 := cp(V.Container)
	copy(kindV2[4+4+len(arbfinal.KindName)-2:], []byte("v2"))
	A("adv_container_kind_v2", "kind arb-sepolia/finalized/v2", mustRaw(V, kindV2), st(finality.CodeEvidenceUnrecognised, "kind", "arb-sepolia/finalized/v2", "version", ""))
	chainOff := 4 + 4 + len(arbfinal.KindName)
	wrongChain := cp(V.Container)
	wrongChain[chainOff+7] ^= 1
	A("adv_container_chain_id", "header chain 421615", mustRaw(V, wrongChain), st(arbfinal.CodePinMismatch, "field", "chain_id"))
	lvl := cp(V.Container)
	lvl[chainOff+8] = 2
	A("adv_container_level_l1_posted", "header level 2", mustRaw(V, lvl), st(finality.CodeEvidenceMalformed, "part", "header.level", "reason", finality.ReasonLevelNotFinalized, "got_len", uint64(2), "want_len", uint64(3)))
	num := cp(V.Container)
	num[chainOff+8+1+7] ^= 1
	A("adv_container_block_number", "header blockNumber differs from the leg", mustRaw(V, num), st(finality.CodeBlockMismatch, "field", "blockNumber", "want", V.Leg.Number, "got", V.Leg.Number^1))
	noArb := editPins(V.Pins, nil, "arb_sepolia")
	g.synthPins("adv_pins_without_arb_sepolia_section", "the pins file has no arb_sepolia section", "synth_no_arb_sepolia.json", noArb, V,
		st(finality.CodePinUnknown, "chain", uint64(421614), "kind", "arb_sepolia"))
	badLayout := editPins(V.Pins, "nitro-contracts-v9", "arb_sepolia", "layout", "name")
	g.synthPins("adv_pins_layout_unknown", "layout.name is not nitro-contracts-v3.1.0", "synth_layout_unknown.json", badLayout, V, st(arbfinal.CodePinMismatch, "field", "layout"))
}

func mustContainer(leg finality.BlockRef, e arbfinal.Evidence) []byte {
	c, err := arbfinal.BuildContainer(leg, e)
	if err != nil {
		panic(err)
	}
	return c
}

// mustRaw returns a world sharing w's leg and pins whose container is raw (for byte-level container edits).
func mustRaw(w *sw.World, raw []byte) *sw.World {
	c := clone(w)
	c.Container = raw
	return c
}
