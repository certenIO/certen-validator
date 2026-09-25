// Copyright 2026 Certen Protocol
//
// READING A KEY PAGE'S HISTORY OFF ITS MAIN CHAIN, AND CHECKING THE REPLAY.
//
// Every entry on the page's main chain is read in chain order - the order the
// executor applied them - and each one is bound before it is replayed:
//
//   - its receipt starts at the entry and recomputes to its anchor, so the
//     block it names is a block the chain committed it in;
//   - the transaction returned for it hashes to the entry, so the body being
//     replayed is the one the receipt proves;
//   - chain order and block order agree, so "every entry at or before the
//     execution block" is a prefix of the chain.
//
// Nothing is skipped. An entry that cannot be read, bound or classified stops
// the snapshot: a history with a hole in it is not the page's history, and a
// state replayed across the hole is a guess. The ranged "degraded" expand that
// used to stand in for an unreadable entry synthesised its block from the
// entry's `received` field - the block a pending multi-signature transaction
// was RECEIVED, not the one it EXECUTED in - so it could put a mutation on the
// wrong side of the execution block. It is gone; the by-hash expand it stood
// in for answers promptly on the network as it runs today.
//
// The replay is then checked against the chain itself: replayed to the head,
// the page must equal the page the network holds now, on every field that
// decides authority. A replay that disagrees with the present cannot be
// trusted about the past.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// expandAttempts bounds retries of one by-hash expand. A retry asks the same
// question again; it is not a different, weaker question.
const expandAttempts = 3

// collectPageHistory reads, binds and classifies every entry on the page's
// main chain, in chain order.
func (ab *AuthorityBuilder) collectPageHistory(ctx context.Context, entries []map[string]interface{},
	keyPage string) (*GenesisEvent, *protocol.KeyPage, []pageEvent, error) {

	pu := ProofUtilities{}
	var genesis *GenesisEvent
	var genesisPage *protocol.KeyPage
	var events []pageEvent
	var lastBlock int64

	for i, entry := range entries {
		if idx, ok := chainIndexOf(entry); !ok || idx != i {
			return nil, nil, nil, ValidationError{Msg: fmt.Sprintf(
				"main chain record %d reports index %v; the enumeration is not the chain in order", i, idx)}
		}
		entryHash, ok := pu.CaseInsensitiveGet(entry, "entry").(string)
		if !ok || len(entryHash) != 64 {
			return nil, nil, nil, ValidationError{Msg: fmt.Sprintf("main chain record %d carries no entry hash", i)}
		}
		entryHash = strings.ToLower(entryHash)

		expanded, err := ab.expandEntryWithReceipt(ctx, entryHash, keyPage)
		if err != nil {
			return nil, nil, nil, err
		}
		receipt, err := ab.extractReceiptFromEntry(expanded)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("main chain entry %s: %w", short(entryHash), err)
		}
		if !strings.EqualFold(receipt.Start, entryHash) {
			return nil, nil, nil, ValidationError{Msg: fmt.Sprintf(
				"main chain entry %s: its receipt starts at %s", short(entryHash), short(receipt.Start))}
		}
		if err := VerifyReceiptMerkle(receipt, "main chain entry "+short(entryHash)); err != nil {
			return nil, nil, nil, err
		}
		if receipt.LocalBlock <= 0 || receipt.LocalBlock < lastBlock {
			return nil, nil, nil, ValidationError{Msg: fmt.Sprintf(
				"main chain entry %d (%s) is recorded at block %d, after an earlier entry at block %d; "+
					"chain order and block order disagree", i, short(entryHash), receipt.LocalBlock, lastBlock)}
		}
		lastBlock = receipt.LocalBlock

		txn, err := decodeEntryTransaction(expanded, entryHash)
		if err != nil {
			return nil, nil, nil, err
		}

		value := pu.CaseInsensitiveGet(expanded, "value")
		if genesisType, isGenesis := ab.isKeyPageGenesis(value); isGenesis {
			if genesis != nil {
				return nil, nil, nil, ValidationError{Msg: "Multiple genesis events found"}
			}
			if i != 0 {
				return nil, nil, nil, ValidationError{Msg: fmt.Sprintf(
					"the page's genesis (%s) is entry %d of its main chain, not the first", genesisType, i)}
			}
			state, err := ab.parseGenesisState(genesisType, value, keyPage)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to parse genesis key page state: %v", err)
			}
			gp, err := ab.genesisKeyPage(genesisType, value, keyPage, state)
			if err != nil {
				return nil, nil, nil, err
			}
			genesis = &GenesisEvent{
				EntryHash:  entryHash,
				LocalBlock: receipt.LocalBlock,
				Receipt:    receipt,
				TxType:     genesisType,
				PageState:  state,
			}
			genesisPage = gp
			continue
		}
		if genesis == nil {
			return nil, nil, nil, ValidationError{Msg: fmt.Sprintf(
				"main chain entry %d (%v) precedes any genesis of the page", i, txn.Body.Type())}
		}

		ev := pageEvent{Index: i, EntryHash: entryHash, LocalBlock: receipt.LocalBlock, Receipt: receipt, Txn: txn}
		if _, isUpdateKey := txn.Body.(*protocol.UpdateKey); isUpdateKey {
			ev.Initiator, err = ab.initiatorOf(ctx, txn, keyPage)
			if err != nil {
				return nil, nil, nil, err
			}
		}
		events = append(events, ev)
	}

	if genesis == nil {
		return nil, nil, nil, ValidationError{Msg: "No genesis event found for key page"}
	}
	return genesis, genesisPage, events, nil
}

// chainIndexOf reads the index a ranged chain query reports for a record.
func chainIndexOf(entry map[string]interface{}) (int, bool) {
	pu := ProofUtilities{}
	switch v := pu.CaseInsensitiveGet(entry, "index").(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	}
	return -1, false
}

// expandEntryWithReceipt expands one main chain entry by hash, with its
// receipt.
func (ab *AuthorityBuilder) expandEntryWithReceipt(ctx context.Context, entryHash, keyPage string) (map[string]interface{}, error) {
	var last error
	for attempt := 1; attempt <= expandAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		expanded, err := ab.expandSingleEntry(entryHash, keyPage)
		if err == nil {
			return expanded, nil
		}
		last = err
		fmt.Printf("[AUTHORITY] expand of %s failed (attempt %d/%d): %v\n", short(entryHash), attempt, expandAttempts, err)
		time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
	}
	return nil, ValidationError{Msg: fmt.Sprintf("main chain entry %s of %s could not be read with its receipt: %v",
		short(entryHash), keyPage, last)}
}

// genesisKeyPage is the protocol page the genesis transaction created.
//
// For syntheticCreateIdentity the page travels inline and is decoded with
// core's own types - every field it was created with. The existing parser's
// state is required to agree with it: two readings of one object that differ
// mean one of them is wrong.
//
// createKeyBook and createKeyPage do not carry the page; its initial fields
// are the executor's (see authority_genesis.go), and the page is built from
// them.
func (ab *AuthorityBuilder) genesisKeyPage(genesisType string, value interface{}, keyPage string,
	state KeyPageState) (*protocol.KeyPage, error) {

	if genesisType != "syntheticcreateidentity" {
		return pageFromState(normalizeAccURL(keyPage), state)
	}

	body, _, ok := transactionBodyOf(value)
	if !ok {
		return nil, ValidationError{Msg: "genesis entry is not a transaction message"}
	}
	pu := ProofUtilities{}
	accounts, _ := pu.CaseInsensitiveGet(body, "accounts").([]interface{})
	want := normalizeAccURL(keyPage)
	for _, a := range accounts {
		m, ok := a.(map[string]interface{})
		if !ok {
			continue
		}
		u, _ := pu.CaseInsensitiveGet(m, "url").(string)
		if normalizeAccURL(u) != want {
			continue
		}
		page, err := keyPageFromAccountJSON(m)
		if err != nil {
			return nil, fmt.Errorf("genesis key page %s: %w", want, err)
		}
		decoded := stateFromPage(page)
		if decoded.Version != state.Version || decoded.Threshold != state.Threshold ||
			!entriesEqual(decoded.EntrySet(), state.EntrySet()) {
			return nil, ValidationError{Msg: fmt.Sprintf(
				"genesis key page %s: the parsed state (v%d, threshold %d, %d entries) disagrees with the "+
					"page decoded by accumulate's own types (v%d, threshold %d, %d entries)", want,
				state.Version, state.Threshold, len(state.EntrySet()),
				decoded.Version, decoded.Threshold, len(decoded.EntrySet()))}
		}
		return page, nil
	}
	return nil, ValidationError{Msg: "No key page definition found in genesis"}
}

// initiatorOf identifies what initiated a transaction the way core's
// transactionIsInitiated does - the credit payment flagged as initiator - and,
// when the payer is the page itself, the key that signed.
//
// The initiating signature is bound to the transaction: its metadata must hash
// to the initiator the transaction header commits to, and the header is part
// of the transaction hash the chain entry proves.
func (ab *AuthorityBuilder) initiatorOf(ctx context.Context, txn *protocol.Transaction, keyPage string) (*pageInitiator, error) {
	txid := fmt.Sprintf("acc://%x@%s", txn.GetHash(), strings.TrimPrefix(normalizeAccURL(keyPage), "acc://"))
	resp, err := ab.artifactManager.SaveRPCArtifact(ctx, fmt.Sprintf("g1_initiator_%x", txn.GetHash()[:8]),
		ab.client, txid, map[string]interface{}{"queryType": "default"})
	if err != nil {
		return nil, fmt.Errorf("query %s for its initiator: %w", txid, err)
	}
	pu := ProofUtilities{}
	result, err := pu.ExpectResult(resp)
	if err != nil {
		return nil, fmt.Errorf("query %s for its initiator: %w", txid, err)
	}

	type rec struct {
		id  string
		msg map[string]interface{}
	}
	var all []rec
	sets, _ := pu.CaseInsensitiveGet(result, "signatures").(map[string]interface{})
	setRecords, _ := pu.CaseInsensitiveGet(sets, "records").([]interface{})
	for _, s := range setRecords {
		sm, _ := s.(map[string]interface{})
		sigs, _ := pu.CaseInsensitiveGet(sm, "signatures").(map[string]interface{})
		records, _ := pu.CaseInsensitiveGet(sigs, "records").([]interface{})
		for _, r := range records {
			rm, _ := r.(map[string]interface{})
			id, _ := pu.CaseInsensitiveGet(rm, "id").(string)
			msg, _ := pu.CaseInsensitiveGet(rm, "message").(map[string]interface{})
			if msg != nil {
				all = append(all, rec{id: id, msg: msg})
			}
		}
	}

	var payment map[string]interface{}
	for _, r := range all {
		t, _ := pu.CaseInsensitiveGet(r.msg, "type").(string)
		init, _ := pu.CaseInsensitiveGet(r.msg, "initiator").(bool)
		if !strings.EqualFold(t, "creditPayment") || !init {
			continue
		}
		if payment != nil {
			return nil, ValidationError{Msg: fmt.Sprintf("%s records more than one initiating credit payment", txid)}
		}
		payment = r.msg
	}
	if payment == nil {
		return nil, ValidationError{Msg: fmt.Sprintf("%s records no initiating credit payment", txid)}
	}
	payerStr, _ := pu.CaseInsensitiveGet(payment, "payer").(string)
	payer, err := url.Parse(payerStr)
	if err != nil || payerStr == "" {
		return nil, ValidationError{Msg: fmt.Sprintf("%s: the initiating credit payment names no payer", txid)}
	}
	cause, _ := pu.CaseInsensitiveGet(payment, "cause").(string)
	if cause == "" {
		return nil, ValidationError{Msg: fmt.Sprintf("%s: the initiating credit payment names no cause", txid)}
	}

	// The initiating signature: in the same response, or by its own id.
	var sigJSON interface{}
	for _, r := range all {
		if strings.EqualFold(r.id, cause) {
			sigJSON = pu.CaseInsensitiveGet(r.msg, "signature")
			break
		}
	}
	if sigJSON == nil {
		causeResp, err := ab.artifactManager.SaveRPCArtifact(ctx, fmt.Sprintf("g1_initiator_cause_%x", txn.GetHash()[:8]),
			ab.client, cause, map[string]interface{}{"queryType": "default"})
		if err != nil {
			return nil, fmt.Errorf("query initiating signature %s: %w", cause, err)
		}
		causeResult, err := pu.ExpectResult(causeResp)
		if err != nil {
			return nil, fmt.Errorf("query initiating signature %s: %w", cause, err)
		}
		if m, ok := pu.CaseInsensitiveGet(causeResult, "message").(map[string]interface{}); ok {
			sigJSON = pu.CaseInsensitiveGet(m, "signature")
		}
	}
	if sigJSON == nil {
		return nil, ValidationError{Msg: fmt.Sprintf("%s: the initiating signature %s could not be read", txid, cause)}
	}
	b, err := json.Marshal(sigJSON)
	if err != nil {
		return nil, err
	}
	sig, err := protocol.UnmarshalSignatureJSON(b)
	if err != nil {
		return nil, ValidationError{Msg: fmt.Sprintf("%s: decode initiating signature: %v", txid, err)}
	}
	if !bytes.Equal(sig.Metadata().Hash(), txn.Header.Initiator[:]) {
		return nil, ValidationError{Msg: fmt.Sprintf("%s: the signature its credit payment names as initiator "+
			"is not the one the transaction header commits to", txid)}
	}

	init := &pageInitiator{Payer: payer}
	if ks, ok := sig.(protocol.KeySignature); ok {
		init.KeyHash = ks.GetPublicKeyHash()
	}
	return init, nil
}

// liveKeyPage reads the page as the network holds it now.
func (ab *AuthorityBuilder) liveKeyPage(ctx context.Context, keyPage string) (*protocol.KeyPage, error) {
	resp, err := ab.artifactManager.SaveRPCArtifact(ctx, "g1_authority_live_page", ab.client,
		normalizeAccURL(keyPage), map[string]interface{}{"queryType": "default"})
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", keyPage, err)
	}
	pu := ProofUtilities{}
	result, err := pu.ExpectResult(resp)
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", keyPage, err)
	}
	account := pu.CaseInsensitiveGet(result, "account")
	if account == nil {
		return nil, ValidationError{Msg: fmt.Sprintf("query %s returned no account", keyPage)}
	}
	return keyPageFromAccountJSON(account)
}

// checkReplayAgainstLive requires the page replayed to the head of its main
// chain to equal the page the network holds now, and the chain not to have
// grown while it was read.
func (ab *AuthorityBuilder) checkReplayAgainstLive(ctx context.Context, keyPage string, replayed *protocol.KeyPage,
	chainLength int) error {

	live, err := ab.liveKeyPage(ctx, keyPage)
	if err != nil {
		return err
	}
	after, err := ab.getMainChainCount(ctx, normalizeAccURL(keyPage))
	if err != nil {
		return err
	}
	if after != chainLength {
		return ValidationError{Msg: fmt.Sprintf("%s's main chain grew from %d to %d entries while it was being "+
			"read; the replay and the live page describe different moments - retry", keyPage, chainLength, after)}
	}
	if !authorityEqual(replayed, live) {
		return ValidationError{Msg: fmt.Sprintf("%s replayed to the head of its main chain does not match the page "+
			"the network holds: %s. A replay that disagrees with the present cannot be trusted about the past",
			keyPage, describeAuthorityDifference(replayed, live))}
	}
	return nil
}

// noteRulesOf records, for G1's unverifiedPageRules, the thresholds beyond
// acceptance that the page carried at execution.
func (ab *AuthorityBuilder) noteRulesOf(page *protocol.KeyPage) {
	ab.notePageRules(map[string]interface{}{
		"url":               page.Url.String(),
		"rejectThreshold":   page.RejectThreshold,
		"responseThreshold": page.ResponseThreshold,
		"blockThreshold":    page.BlockThreshold,
	})
}
