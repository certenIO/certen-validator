// Copyright 2026 Certen Protocol
//
// Roles that depend on the governed transaction, derived from the transaction the evidence carries (docs/proof/G1_CROSS_PARTITION.md
// D1(c), D1(f), D4; RB9 Phase C1b-2).
//
// Until C1b-2 three roles were recorded and listed but never proven, because the facts that justify them were outside the evidence:
// header-authority (the transaction's header), initiator-signer (the transaction's initiating signature) and certified-key-page (the
// intent certificate). The evidence now carries the transaction (Evidence.Transaction) and the signatures of the cause chains
// (VoteHop.Signature), so two of them are derived here exactly as the capture derives them:
//
//   - header-authority: every authority Header.Authorities and the body (Transaction.GetAdditionalAuthorities) name. The book and every
//     page of it carry the role. Proven when the transaction is carried; recorded and Declared when it is not.
//   - initiator-signer: the page the initiating signature paid from (CreditPayment.Payer: the innermost key page, a lite token address
//     paying as its lite identity - sig_user.go sendCreditPayment) and every delegator page in that signature's path. The initiating
//     signature is the one whose metadata hash (or merkle initiator hash) is Header.Initiator (protocol.SignatureDidInitiate). It is
//     found among the carried cause-chain signatures; when it is among them the role is proven exactly (a recorded page that is not
//     derived, or a derived page that is not recorded, is g1_role_mismatch). When the initiating signature is not carried the role
//     stays a recorded fact, listed as Declared, and the report says so by name (g1_initiator_signature_not_carried) - never a
//     verified role shaped like a proven one.
//
// certified-key-page stays Declared in every case: it depends on the key book and page the INTENT declares, a fact that only the
// intent certificate carries; the binding in RB9 Phase C2 (BindProofV2) checks it against the certificate.
package proofv2

import (
	"encoding/hex"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// StateInitiatorSignatureNotCarried: a page records the role initiator-signer but the evidence carries no signature that initiated the
// transaction (or no transaction), so the role is a recorded fact the verifier lists as Declared, not one it proves. It is a named
// state of the report (Report.Unproven), never a refusal: the page is proven, only the reason it is among the proven pages is not.
const StateInitiatorSignatureNotCarried = "g1_initiator_signature_not_carried"

// carriedTransaction decodes the transaction the evidence carries and requires it to be the one the evidence names: its hash TxHash
// and its principal the evidence's account (g1_transaction_mismatch otherwise). nil, nil when none is carried.
func carriedTransaction(ev *Evidence, x xAnchor) (*protocol.Transaction, error) {
	if ev.Transaction == "" {
		return nil, nil
	}
	txn, err := decodeTxn(ev.Transaction)
	if err != nil {
		return nil, refusal21(StateTransactionMismatch, x.id, x.block, "%v", err)
	}
	txHash, _ := hex.DecodeString(ev.TxHash)
	if string(txn.GetHash()) != string(txHash) {
		return nil, refusal21(StateTransactionMismatch, x.id, x.block, "the carried transaction hashes to %x, not the transaction %s", txn.GetHash()[:8], ev.TxHash[:min(16, len(ev.TxHash))])
	}
	if !strings.EqualFold(txn.Header.Principal.String(), ev.Account) {
		return nil, refusal21(StateTransactionMismatch, x.id, x.block, "the carried transaction acts on %v, not %s", txn.Header.Principal, ev.Account)
	}
	return txn, nil
}

// headerAuthorityURLs are the authorities the transaction requires beyond the principal's: Header.Authorities and the authorities its
// body adds, without repeats, in order.
func headerAuthorityURLs(txn *protocol.Transaction) []*url.URL {
	var out []*url.URL
	seen := map[string]bool{}
	for _, a := range append(append([]*url.URL(nil), txn.Header.Authorities...), txn.GetAdditionalAuthorities()...) {
		if a != nil && !seen[lk(a)] {
			seen[lk(a)] = true
			out = append(out, a)
		}
	}
	return out
}

// initiatorPayerURL is the page an initiating key signature paid from: its signer, a lite token address paying as its lite identity
// (the account the initiating CreditPayment names).
func initiatorPayerURL(signer *url.URL) *url.URL {
	if key, _ := protocol.ParseLiteIdentity(signer); key == nil {
		if key, _, _ := protocol.ParseLiteTokenAddress(signer); key != nil {
			return signer.RootIdentity()
		}
	}
	return signer
}

// initiatorPages finds the signature that initiated the transaction and returns the pages it makes initiator-signers: its payer and every
// delegator in its path. found is false when no carried signature initiated the transaction. The signature is the document's member
// InitiatingSignature when it carries one (a separate, non-voting initiator: carriedInitiatorPages proves it completely or refuses the
// document), else it is searched among the cause-chain signatures of the votes. A signature used here is bound first, exactly as the vote
// re-evaluation binds it: it is the message its chain entry holds, and a key signature must sign the transaction (g1_signature_invalid).
func initiatorPages(ev *Evidence, txn *protocol.Transaction, byURL map[string]*provenAcct, tl states, x xAnchor, network string) (pages []*url.URL, found bool, err error) {
	if ev.InitiatingSignature != nil {
		return carriedInitiatorPages(ev, txn, byURL, tl, x, network)
	}
	var none [32]byte
	if txn.Header.Initiator == none {
		return nil, false, nil
	}
	txid := txn.ID()
	seen := map[string]bool{}
	for _, v := range ev.Votes {
		for _, h := range v.allHops() {
			if seen[h.Message] {
				continue
			}
			seen[h.Message] = true
			sig, derr := decodeSig(h.Signature)
			if derr != nil {
				continue // a signature that does not decode initiates nothing; the re-evaluation refuses it by name
			}
			if _, isAuth := sig.(*protocol.AuthoritySignature); isAuth {
				continue
			}
			if ok, _ := protocol.SignatureDidInitiate(sig, txn.Header.Initiator[:], nil); !ok {
				continue
			}
			pa := byURL[strings.ToLower(h.Page)]
			id, blk := "", uint64(0)
			if hp, perr := url.Parse(h.Page); perr == nil {
				if p2, ok := byURL[lk(hp)]; ok {
					pa = p2
				}
			}
			if pa != nil {
				id, blk = pa.anchor.id, pa.anchor.block
			}
			msgHash := (&messaging.SignatureMessage{Signature: sig, TxID: txid}).Hash()
			if hex.EncodeToString(msgHash[:]) != strings.ToLower(h.Message) {
				return nil, false, refusal21(StateSignatureInvalid, id, blk, "the initiating signature on %s is not the message its chain entry holds", h.Page)
			}
			var vs *govsig.Verified
			if pa != nil {
				if vs, err = verifyKeySignature(sig, txn, network, pa, h.Page, h.Block); err != nil {
					return nil, false, err
				}
			} else if _, ok := sig.(protocol.UserSignature); !ok || !protocol.VerifyUserSignature(sig.(protocol.UserSignature), txn) {
				return nil, false, refusal21(StateSignatureInvalid, id, blk, "the initiating signature on %s does not sign the transaction", h.Page)
			}
			var ks protocol.KeySignature
			if vs != nil {
				ks = vs.Inner
			} else {
				inner, _ := unwrapSignature(sig)
				var ok bool
				if ks, ok = inner.(protocol.KeySignature); !ok {
					return nil, false, refusal21(StateSignatureInvalid, id, blk, "the initiating signature on %s carries no key", h.Page)
				}
			}
			pages = append(pages, initiatorPayerURL(ks.GetSigner()))
			pages = append(pages, delegatorPages(sig)...)
			return pages, true, nil
		}
	}
	return nil, false, nil
}

// carriedInitiatorPages proves the initiating signature the document carries (Evidence.InitiatingSignature, DAX-1G) and returns the pages it makes
// initiator-signers: the payer and every delegator of its path. It proves the member COMPLETELY or refuses the document by name; there is no state
// in which a carried signature is only partly proven. Each refusal names the signer page's partition and block (the transaction's when the page is
// not proven at all). In order:
//
//  1. the page the signature is recorded on is a proven page                                   g1_initiator_page_unproven
//  2. the transaction names an initiator                                                        g1_role_mismatch
//  3. the signature decodes and is not an authority signature                                  g1_signature_invalid
//  4. the signature's message hash (messaging.SignatureMessage.Hash(), the signature's own hash) is the member's message  g1_signature_invalid
//  5. the signature is the one the header names as the initiator (SignatureDidInitiate)         g1_role_mismatch
//  6. the message is a member of the page's signature chain as bound at the page's block, and
//     the claimed block is the one its signature-index chain gives (deriveArrival)              g1_block_before_signature, g1_arrival_unproven
//  7. the signature signs this transaction, is of a type the executor version in force there
//     admits, and its delegation is within the depth limit (govsig.Verify)                      g1_signature_invalid, g1_executor_version_unproven, g1_delegation_depth_exceeded
//  8. the key signature's payer is the page it is recorded on                                   g1_signature_invalid
//  9. the page's certified history is carried (folded and replayed by foldTimelines), and a
//     state of the page at the signature's signer version during the arrival block held the key g1_history_unavailable, g1_initiator_key_not_held
//
// Every delegator of the signature is then required to be a proven page by deriveRoles (g1_initiator_page_unproven). What this does NOT prove: that each
// delegation of a delegated initiating signature was admitted by the executor at arrival (the delegator pages' entries naming the delegate book); the
// initiator authorizes nothing, the executor's acceptance of the message is evidenced by its membership in the key page's signature chain (step 6), and
// the vote model re-evaluates delegation for votes only (docs/proof/G1_CROSS_PARTITION.md, initiator-signer).
func carriedInitiatorPages(ev *Evidence, txn *protocol.Transaction, byURL map[string]*provenAcct, tl states, x xAnchor, network string) ([]*url.URL, bool, error) {
	h := ev.InitiatingSignature
	page, perr := url.Parse(h.Page)
	var pa *provenAcct
	if perr == nil {
		pa = byURL[lk(page)]
	}
	if pa == nil {
		return nil, false, refusal21(StateInitiatorPageUnproven, x.id, x.block, "the initiating signature is carried for %s, which is not among the proven pages", h.Page)
	}
	id, blk := pa.anchor.id, pa.anchor.block
	var none [32]byte
	if txn.Header.Initiator == none {
		return nil, false, refusal21(StateRoleMismatch, id, blk, "the transaction names no initiator, so the initiating signature carried for %s claims a role the transaction does not justify", h.Page)
	}
	sig, derr := decodeSig(h.Signature)
	if derr != nil {
		return nil, false, refusal21(StateSignatureInvalid, id, blk, "the initiating signature on %s: %v", h.Page, derr)
	}
	if _, isAuth := sig.(*protocol.AuthoritySignature); isAuth {
		return nil, false, refusal21(StateSignatureInvalid, id, blk, "the initiating signature on %s is an authority signature, which cannot initiate a transaction", h.Page)
	}
	msgHash := (&messaging.SignatureMessage{Signature: sig, TxID: txn.ID()}).Hash()
	if hex.EncodeToString(msgHash[:]) != strings.ToLower(h.Message) {
		return nil, false, refusal21(StateSignatureInvalid, id, blk, "the initiating signature on %s is not the message its chain entry holds", h.Page)
	}
	if ok, _ := protocol.SignatureDidInitiate(sig, txn.Header.Initiator[:], nil); !ok {
		return nil, false, refusal21(StateRoleMismatch, id, blk, "the signature carried for %s is not the one the transaction header names as its initiator: initiator-signer is claimed for it and the transaction does not justify it", h.Page)
	}
	if h.Arrival == nil {
		return nil, false, refusal21(StateArrivalUnproven, id, blk, "the initiating signature on %s carries no arrival proof", h.Page)
	}
	block, aerr := deriveArrival(pa, &ev.Pages[pa.i], "signature", h.Message, h.Receipt, h.Arrival)
	if aerr != nil {
		return nil, false, aerr
	}
	if block != h.Block {
		return nil, false, refusal21(StateArrivalUnproven, id, blk, "the initiating signature on %s was claimed to arrive in block %d, its signature-index chain says %d", h.Page, h.Block, block)
	}
	vs, verr := verifyKeySignature(sig, txn, network, pa, h.Page, block)
	if verr != nil {
		return nil, false, verr
	}
	ks := vs.Inner
	signer := ks.GetSigner()
	if signer == nil || normURL(initiatorPayerURL(signer)) != normURL(page) {
		return nil, false, refusal21(StateSignatureInvalid, id, blk, "the initiating signature recorded on %s is by %v", h.Page, signer)
	}
	st, ok := tl[govvote.CanonicalAccSpelling(h.Page)]
	if !ok {
		return nil, false, refusal21(StateHistoryUnavailable, id, blk, "the initiating signature on %s is carried without the page's certified history, so the key it was made with cannot be judged against the page as it stood when the signature arrived", h.Page)
	}
	if held, _ := govvote.KeyHeldDuring(st, txn.Body.Type(), ks.GetSignerVersion(), int64(block), vs.KeyHash); held == 0 {
		return nil, false, refusal21(StateInitiatorKeyNotHeld, id, blk, "no state of %s at version %d during block %d both held the key of the initiating signature and allowed a %v", h.Page, ks.GetSignerVersion(), block, txn.Body.Type())
	}
	pages := []*url.URL{initiatorPayerURL(signer)}
	pages = append(pages, delegatorPages(sig)...)
	return pages, true, nil
}
