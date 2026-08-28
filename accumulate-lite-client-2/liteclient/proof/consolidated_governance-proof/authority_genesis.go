// Copyright 2026 Certen Protocol
//
// A KEY PAGE'S GENESIS, for every way Accumulate creates one.
//
// # THE DEFECT, MEASURED
//
// classifyGovernanceEvents recognised exactly one genesis: syntheticCreateIdentity.
// That is how page 1 of an ADI's DEFAULT book comes into existence, and it is
// the only way any page in the corpus or in production ever had — so the
// KPSW-EXEC snapshot worked for every account on record and could not work for
// any other.
//
// Measured on Kermit 2026-08-26, corpus case M
// (acc://certen-p8m.acme/book/2, transaction 54e962f88502aacf):
//
//	[AUTHORITY] Entry b8bcd6363598b918 transaction type: createKeyPage
//	[AUTHORITY] [DEBUG] Skipping non-governance transaction at block 10252537
//	Error: concurrent authority snapshot failed: No genesis event found for key page
//
// The page's genesis was sitting on its own main chain, correctly, and was
// skipped as "non-governance". G1 could not prove ANY transaction signed from a
// page other than a default book's first — which is to say, the moment an
// institution uses a second page or a second book, governance proof stops
// working entirely.
//
// It fails CLOSED, which is the one good thing about it: an error, not a
// confident wrong answer. But an error here reaches an operator as "governance
// proof failed", and Phase 7's rule 8 is that a capability limit must not read
// like a governance rejection.
//
// # THE THREE WAYS A PAGE IS BORN
//
// From accumulate-core, which is the only authority on this — every initial
// value below is quoted from the executor that sets it, not inferred from what
// a page happens to report today:
//
//	syntheticCreateIdentity   page 1 of an ADI's default book. The created
//	                          accounts travel inline in body.accounts[], so the
//	                          page's initial state is read from there.
//
//	createKeyBook             page 1 of a NEW book.
//	                          chain/create_key_book.go: page.Version = 1,
//	                          AcceptThreshold left unset (zero, which
//	                          GetSignatureThreshold reads as one), and
//	                          Keys = [body.publicKeyHash].
//
//	createKeyPage             page N of an EXISTING book.
//	                          chain/create_key_page.go:66-82: page.Version = 1,
//	                          page.AcceptThreshold = 1 ("Require one signature
//	                          from the Key Page"), and one KeySpec per
//	                          body.keys[] entry.
//
// # WHY MATCHING ON THE PAGE'S OWN CHAIN IS SOUND
//
// Neither createKeyPage nor createKeyBook names the page it creates: the page
// number comes from book.PageCount at execution time. What makes this
// unambiguous is WHERE the entry was found — st.Create(page) writes the
// transaction to the CREATED page's main chain, so a createKeyPage on some
// sibling page never appears on this one's. The scan is already walking the
// target page's own chain.
//
// That is an argument, not a guarantee, so it is also CHECKED: the transaction's
// principal must be the target page's own book. A createKeyPage that reached
// this page's chain from another book would be refused rather than parsed into
// a state for a page it did not create.

package main

import (
	"fmt"
	"strings"
)

// genesisTxTypes are the transaction types that bring a key page into being.
var genesisTxTypes = map[string]bool{
	"syntheticcreateidentity": true,
	"createkeybook":           true,
	"createkeypage":           true,
}

// transactionBodyOf digs message.transaction.body out of an expanded chain
// entry's `value`, returning the body map and the transaction map.
//
// Returns ok=false rather than an error for anything that is not a transaction
// message: a key page's main chain legitimately carries other message kinds, and
// those are not malformed, they are simply not this.
func transactionBodyOf(value interface{}) (body, txn map[string]interface{}, ok bool) {
	pu := ProofUtilities{}
	valueMap, ok := value.(map[string]interface{})
	if !ok {
		return nil, nil, false
	}
	messageMap, ok := pu.CaseInsensitiveGet(valueMap, "message").(map[string]interface{})
	if !ok {
		return nil, nil, false
	}
	if t, _ := pu.CaseInsensitiveGet(messageMap, "type").(string); !strings.EqualFold(t, "transaction") {
		return nil, nil, false
	}
	txnMap, ok := pu.CaseInsensitiveGet(messageMap, "transaction").(map[string]interface{})
	if !ok {
		return nil, nil, false
	}
	bodyMap, ok := pu.CaseInsensitiveGet(txnMap, "body").(map[string]interface{})
	if !ok {
		return nil, nil, false
	}
	return bodyMap, txnMap, true
}

// bodyTypeOf returns the lowercased transaction body type, or "".
func bodyTypeOf(value interface{}) string {
	body, _, ok := transactionBodyOf(value)
	if !ok {
		return ""
	}
	pu := ProofUtilities{}
	t, _ := pu.CaseInsensitiveGet(body, "type").(string)
	return strings.ToLower(t)
}

// isKeyPageGenesis reports whether this chain entry is the genesis of keyPage.
func (ab *AuthorityBuilder) isKeyPageGenesis(value interface{}) (string, bool) {
	t := bodyTypeOf(value)
	if t == "" || !genesisTxTypes[t] {
		return "", false
	}
	return t, true
}

// principalOf returns a transaction's header principal.
func principalOf(txn map[string]interface{}) string {
	pu := ProofUtilities{}
	header, ok := pu.CaseInsensitiveGet(txn, "header").(map[string]interface{})
	if !ok {
		return ""
	}
	p, _ := pu.CaseInsensitiveGet(header, "principal").(string)
	return normalizeAccURL(p)
}

// parseGenesisState derives a page's INITIAL state from the transaction that
// created it.
//
// Dispatches on the body type, because the three creations carry the page's
// initial state in three different shapes. Every value comes from the
// accumulate-core executor named in the file header; nothing here is read back
// off the chain, because the point of KPSW-EXEC is to derive the page's history
// rather than to trust what an endpoint reports today.
func (ab *AuthorityBuilder) parseGenesisState(txType string, value interface{},
	keyPage string) (KeyPageState, error) {

	body, txn, ok := transactionBodyOf(value)
	if !ok {
		return KeyPageState{}, ValidationError{Msg: "genesis entry is not a transaction message"}
	}
	pu := ProofUtilities{}
	page := normalizeAccURL(keyPage)
	book := bookOfPage(page)

	switch txType {
	case "syntheticcreateidentity":
		// The created accounts travel inline; the existing parser finds the page
		// among them. Unchanged, so every proof on record parses exactly as it did.
		msgMap, ok := pu.CaseInsensitiveGet(
			value.(map[string]interface{}), "message").(map[string]interface{})
		if !ok {
			return KeyPageState{}, ValidationError{Msg: "genesis message is not an object"}
		}
		return ab.parseGenesisKeyPageState(msgMap, keyPage)

	case "createkeybook":
		// chain/create_key_book.go: page.Version = 1, one key, AcceptThreshold
		// left UNSET. Zero is not "no rule" — GetSignatureThreshold reads it as
		// one — and it is recorded as the zero the chain actually holds so the
		// resolver's own normalisation stays the single place that decides.
		url, _ := pu.CaseInsensitiveGet(body, "url").(string)
		if normalizeAccURL(url) != book {
			return KeyPageState{}, ValidationError{Msg: fmt.Sprintf(
				"createKeyBook creates %s, which is not the book of %s", url, page)}
		}
		if !strings.HasSuffix(page, "/1") {
			return KeyPageState{}, ValidationError{Msg: fmt.Sprintf(
				"createKeyBook creates only page 1, but the target is %s", page)}
		}
		hash, _ := pu.CaseInsensitiveGet(body, "publicKeyHash").(string)
		if hash == "" {
			return KeyPageState{}, ValidationError{Msg: "createKeyBook carries no publicKeyHash"}
		}
		return KeyPageState{
			Version:   1,
			Threshold: 0,
			Keys:      []string{strings.ToLower(hash)},
			Entries:   []KeyPageEntry{{KeyHash: strings.ToLower(hash)}},
		}, nil

	case "createkeypage":
		// chain/create_key_page.go: Version = 1, AcceptThreshold = 1, one
		// KeySpec per body.keys[].
		//
		// The body does not name the page — the number comes from
		// book.PageCount at execution — so the check is that this transaction
		// acted on THIS page's book. Being found on this page's own main chain
		// is what identifies it; this is the corroboration.
		if p := principalOf(txn); p != book {
			return KeyPageState{}, ValidationError{Msg: fmt.Sprintf(
				"createKeyPage acted on %s, not on %s, the book of %s", p, book, page)}
		}
		raw, _ := pu.CaseInsensitiveGet(body, "keys").([]interface{})
		if len(raw) == 0 {
			return KeyPageState{}, ValidationError{Msg: "createKeyPage carries no keys"}
		}
		st := KeyPageState{Version: 1, Threshold: 1}
		for _, item := range raw {
			spec, ok := item.(map[string]interface{})
			if !ok {
				// NEVER SILENTLY SKIP. An entry dropped here understates the
				// page's authority and surfaces later as an unmet threshold,
				// which reads as a governance rejection.
				return KeyPageState{}, ValidationError{
					Msg: "createKeyPage key spec is not an object"}
			}
			h, _ := pu.CaseInsensitiveGet(spec, "keyHash").(string)
			d, _ := pu.CaseInsensitiveGet(spec, "delegate").(string)
			if h == "" && d == "" {
				return KeyPageState{}, ValidationError{
					Msg: "createKeyPage key spec carries neither keyHash nor delegate"}
			}
			e := KeyPageEntry{KeyHash: strings.ToLower(h), Delegate: normalizeAccURL(d)}
			st.Entries = append(st.Entries, e)
			if e.KeyHash != "" {
				st.Keys = append(st.Keys, e.KeyHash)
			}
		}
		return st, nil
	}

	return KeyPageState{}, ValidationError{Msg: "unrecognised genesis transaction type " + txType}
}
