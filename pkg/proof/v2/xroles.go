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

// initiatorPages finds, among the cause-chain signatures the evidence carries, the signature that initiated the transaction and
// returns the pages it makes initiator-signers: its payer and every delegator in its path. found is false when no carried signature
// initiated the transaction. A signature used here is bound first, exactly as the vote re-evaluation binds it: it is the message its
// chain entry holds, and a key signature must sign the transaction (g1_signature_invalid).
func initiatorPages(ev *Evidence, txn *protocol.Transaction, byURL map[string]*provenAcct, network string) (pages []*url.URL, found bool, err error) {
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
