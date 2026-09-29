// Copyright 2026 Certen Protocol

package govvote

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govreceipt"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// EvidenceVersion names this evidence format.
const EvidenceVersion = "certen:govvote-evidence:v1"

// Evidence is everything the authority vote on one transaction read, each item bound to the chain, so the vote can be
// evaluated again OFFLINE by the same model and compared with the record the proof carries (RB4-F66):
//
//   - the governed transaction, binary;
//   - each signature, arrival and recorded vote the model counted or examined: its signature bytes, and the receipt
//     that starts at its message hash on its page's signature chain and names the block it was recorded in;
//   - each page's history: its genesis and every main chain entry, binary, each with the receipt that starts at the
//     entry; UpdateKey entries with their initiating signature;
//   - the principal's authority set at execution, and the account histories it is replayed from.
//
// VerifyEvidence checks every binding, replays every page from its genesis, re-runs the vote and returns it.
type Evidence struct {
	Version        string              `json:"version"`
	Account        string              `json:"account"`
	Transaction    string              `json:"transaction"` // hex of the governed transaction's binary encoding
	Authorities    []AccountAuthority  `json:"authorities"`
	Extra          []string            `json:"extra,omitempty"`
	IgnoreDisabled bool                `json:"ignoreDisabled,omitempty"`
	Signatures     []SignatureEvidence `json:"signatures,omitempty"`
	Arrivals       []ArrivalEvidence   `json:"arrivals,omitempty"`
	Votes          []VoteEvidence      `json:"votes,omitempty"`
	Pages          []PageHistory       `json:"pages"`
	// AuthoritySet is what Authorities is replayed from (account.go); the replay must reach it exactly.
	AuthoritySet *AuthorityEvidence `json:"authoritySet"`
}

// SignatureEvidence is one user signature on the transaction: the fact the model read, the signature, and its receipt
// on the signer page's signature chain.
type SignatureEvidence struct {
	Fact      SigFact            `json:"fact"`
	Signature string             `json:"signature"` // hex of the signature's binary encoding
	Receipt   govreceipt.Receipt `json:"receipt"`
}

// ArrivalEvidence is one delegated vote recorded on the page it was delegated from.
type ArrivalEvidence struct {
	Fact      ArrivalFact        `json:"fact"`
	Signature string             `json:"signature"` // hex of the authority signature's binary encoding
	Receipt   govreceipt.Receipt `json:"receipt"`
}

// VoteEvidence is one of the principal's authorities' votes, recorded on the principal.
type VoteEvidence struct {
	Fact      RecordedVote       `json:"fact"`
	Signature string             `json:"signature"`
	Receipt   govreceipt.Receipt `json:"receipt"`
}

// PageHistory is a key page's main chain: its genesis and every entry after it, in chain order. Entries is the chain's
// length when it was read.
type PageHistory struct {
	Page    string         `json:"page"`
	Entries int            `json:"entries"`
	Genesis HistoryEntry   `json:"genesis"`
	Events  []HistoryEntry `json:"events"`
}

// HistoryEntry is one main chain entry: its transaction, and the receipt that starts at it. Initiator is the
// initiating signature, for an UpdateKey.
type HistoryEntry struct {
	Index       int                `json:"index"`
	EntryHash   string             `json:"entryHash"`
	LocalBlock  int64              `json:"localBlock"`
	Receipt     govreceipt.Receipt `json:"receipt"`
	Transaction string             `json:"transaction"`         // hex of the transaction's binary encoding
	Initiator   string             `json:"initiator,omitempty"` // hex of the initiating signature's binary encoding
}

// VerifyEvidence checks every binding in the evidence and evaluates the vote again from it.
func VerifyEvidence(ctx context.Context, ev *Evidence) (*AccountVote, error) {
	if ev == nil {
		return nil, fmt.Errorf("no vote evidence")
	}
	if ev.Version != EvidenceVersion {
		return nil, fmt.Errorf("vote evidence version %q, not %q", ev.Version, EvidenceVersion)
	}
	txn, err := decodeTransaction(ev.Transaction)
	if err != nil {
		return nil, fmt.Errorf("the governed transaction: %w", err)
	}
	facts := Facts{TxType: txn.Body.Type()}

	for i, s := range ev.Signatures {
		sig, err := decodeSignature(s.Signature)
		if err != nil {
			return nil, fmt.Errorf("signature %d: %w", i, err)
		}
		if err := checkSignatureFact(txn, sig, s.Fact); err != nil {
			return nil, fmt.Errorf("signature %d (%s): %w", i, short(s.Fact.ID), err)
		}
		if err := checkMessageReceipt(txn, sig, s.Fact.ID, s.Fact.Block, s.Receipt); err != nil {
			return nil, fmt.Errorf("signature %d (%s): %w", i, short(s.Fact.ID), err)
		}
		facts.Sigs = append(facts.Sigs, s.Fact)
	}
	for i, a := range ev.Arrivals {
		sig, err := decodeSignature(a.Signature)
		if err != nil {
			return nil, fmt.Errorf("arrival %d: %w", i, err)
		}
		if err := checkArrivalFact(sig, a.Fact); err != nil {
			return nil, fmt.Errorf("arrival %d (%s): %w", i, short(a.Fact.ID), err)
		}
		if err := checkMessageReceipt(txn, sig, a.Fact.ID, a.Fact.Block, a.Receipt); err != nil {
			return nil, fmt.Errorf("arrival %d (%s): %w", i, short(a.Fact.ID), err)
		}
		facts.Arrivals = append(facts.Arrivals, a.Fact)
	}
	for i, v := range ev.Votes {
		sig, err := decodeSignature(v.Signature)
		if err != nil {
			return nil, fmt.Errorf("vote %d: %w", i, err)
		}
		if err := checkVoteFact(sig, v.Fact); err != nil {
			return nil, fmt.Errorf("vote %d (%s): %w", i, short(v.Fact.ID), err)
		}
		if err := checkMessageReceipt(txn, sig, v.Fact.ID, v.Fact.Block, v.Receipt); err != nil {
			return nil, fmt.Errorf("vote %d (%s): %w", i, short(v.Fact.ID), err)
		}
		facts.Votes = append(facts.Votes, v.Fact)
	}

	authorities, decided, err := AuthoritySetAt(ev.AuthoritySet, ev.Account)
	if err != nil {
		return nil, fmt.Errorf("the authority set at execution: %w", err)
	}
	if !authoritiesEqual(authorities, ev.Authorities) {
		return nil, fmt.Errorf("the account histories replay to the authority set %v, not the %v the evidence states",
			authorities, ev.Authorities)
	}
	if !stringsEqual(decided, ev.AuthoritySet.DecidedByLiveState) {
		return nil, fmt.Errorf("the accounts whose set rests on the network's present state are %v, not the %v the "+
			"evidence names", decided, ev.AuthoritySet.DecidedByLiveState)
	}

	timelines := evidenceTimelines{}
	for _, ph := range ev.Pages {
		states, err := replayHistory(ph)
		if err != nil {
			return nil, fmt.Errorf("page %s: %w", ph.Page, err)
		}
		timelines[normalizeAccURL(ph.Page)] = states
	}
	return Evaluate(ctx, facts, timelines, ev.Account, ev.Authorities, ev.Extra, ev.IgnoreDisabled)
}

type evidenceTimelines map[string]States

func (m evidenceTimelines) Timeline(_ context.Context, page string) (Timeline, error) {
	tl, ok := m[normalizeAccURL(page)]
	if !ok {
		return nil, fmt.Errorf("the evidence carries no history for %s", page)
	}
	return tl, nil
}

// replayHistory binds every entry of a page's history and replays it.
func replayHistory(ph PageHistory) (States, error) {
	if ph.Entries != len(ph.Events)+1 {
		return nil, fmt.Errorf("the history carries %d entries of a chain of %d", len(ph.Events)+1, ph.Entries)
	}
	gtx, err := checkHistoryEntry(ph.Genesis, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("genesis: %w", err)
	}
	genesis, err := GenesisPage(ph.Page, gtx)
	if err != nil {
		return nil, fmt.Errorf("genesis: %w", err)
	}
	events := make([]Event, 0, len(ph.Events))
	last := ph.Genesis.LocalBlock
	for i, e := range ph.Events {
		txn, err := checkHistoryEntry(e, i+1, last)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i+1, err)
		}
		last = e.LocalBlock
		ev := Event{EntryHash: strings.ToLower(e.EntryHash), LocalBlock: e.LocalBlock, Txn: txn}
		if _, isUpdateKey := txn.Body.(*protocol.UpdateKey); isUpdateKey {
			sig, err := decodeSignature(e.Initiator)
			if err != nil {
				return nil, fmt.Errorf("entry %d: its initiating signature: %w", i+1, err)
			}
			if ev.Initiator, err = InitiatorOf(txn, sig); err != nil {
				return nil, fmt.Errorf("entry %d: %w", i+1, err)
			}
		}
		events = append(events, ev)
	}
	replayed, _, err := Replay(genesis, ph.Genesis.LocalBlock, events)
	if err != nil {
		return nil, err
	}
	out := make(States, len(replayed))
	for i, r := range replayed {
		out[i] = r.State
	}
	return out, nil
}

// checkHistoryEntry binds one main chain entry: its index, its receipt (starting at the entry, recomputing to its
// anchor, at the entry's block, not before the previous entry's), and its transaction (hashing to the entry).
func checkHistoryEntry(e HistoryEntry, index int, notBefore int64) (*protocol.Transaction, error) {
	if e.Index != index {
		return nil, fmt.Errorf("is chain index %d, not %d", e.Index, index)
	}
	if !strings.EqualFold(e.Receipt.Start, e.EntryHash) {
		return nil, fmt.Errorf("its receipt starts at %s, not at the entry %s", short(e.Receipt.Start), short(e.EntryHash))
	}
	if err := govreceipt.VerifyMerkle(e.Receipt, "entry "+short(e.EntryHash)); err != nil {
		return nil, err
	}
	if e.Receipt.LocalBlock != e.LocalBlock || e.LocalBlock <= 0 || e.LocalBlock < notBefore {
		return nil, fmt.Errorf("is recorded at block %d (receipt %d), after an entry at block %d",
			e.LocalBlock, e.Receipt.LocalBlock, notBefore)
	}
	txn, err := decodeTransaction(e.Transaction)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(hex.EncodeToString(txn.GetHash()), e.EntryHash) {
		return nil, fmt.Errorf("its transaction hashes to %x, not to the entry %s", txn.GetHash()[:8], short(e.EntryHash))
	}
	return txn, nil
}

// checkMessageReceipt binds a signature message to its receipt: the message - the signature on this transaction -
// hashes to the id the fact names and to the receipt's start, the receipt recomputes, and names the fact's block.
func checkMessageReceipt(txn *protocol.Transaction, sig protocol.Signature, id string, block int64, r govreceipt.Receipt) error {
	msg := &messaging.SignatureMessage{Signature: sig, TxID: txn.ID()}
	h := msg.Hash()
	hash := hex.EncodeToString(h[:])
	if !strings.Contains(strings.ToLower(id), hash) {
		return fmt.Errorf("the signature message hashes to %s, which is not the message %s", short(hash), id)
	}
	if !strings.EqualFold(r.Start, hash) {
		return fmt.Errorf("its receipt starts at %s, not at the message %s", short(r.Start), short(hash))
	}
	if err := govreceipt.VerifyMerkle(r, "message "+short(hash)); err != nil {
		return err
	}
	if r.LocalBlock != block || block <= 0 {
		return fmt.Errorf("is recorded at block %d, its receipt names %d", block, r.LocalBlock)
	}
	return nil
}

// checkSignatureFact requires the fact to be what the signature says: a user signature on this transaction, by the
// key and signer version and with the vote the fact records, on the signer and delegation path it records.
func checkSignatureFact(txn *protocol.Transaction, sig protocol.Signature, f SigFact) error {
	us, ok := sig.(protocol.UserSignature)
	if !ok {
		return fmt.Errorf("a %v is not a user signature", sig.Type())
	}
	if !protocol.VerifyUserSignature(us, txn) {
		return fmt.Errorf("the signature does not sign the transaction")
	}
	key, path := innermost(sig)
	ks, ok := key.(protocol.KeySignature)
	if !ok {
		return fmt.Errorf("a %v carries no key", key.Type())
	}
	if !strings.EqualFold(hex.EncodeToString(ks.GetPublicKeyHash()), f.KeyHash) {
		return fmt.Errorf("the signature's key hash %x is not the fact's %s", ks.GetPublicKeyHash(), short(f.KeyHash))
	}
	if ks.GetSignerVersion() != f.Version {
		return fmt.Errorf("the signature is at signer version %d, the fact records %d", ks.GetSignerVersion(), f.Version)
	}
	if normalizeAccURL(ks.GetSigner().String()) != normalizeAccURL(f.Signer) {
		return fmt.Errorf("the signature's signer %v is not the fact's %s", ks.GetSigner(), f.Signer)
	}
	if sig.GetVote() != f.Vote {
		return fmt.Errorf("the signature votes %v, the fact records %v", sig.GetVote(), f.Vote)
	}
	if !pathEqual(path, f.Path) {
		return fmt.Errorf("the signature's delegation path %v is not the fact's %v", path, f.Path)
	}
	return nil
}

// innermost unwraps delegated signatures to the key signature and returns the delegators, outermost wrapper first.
func innermost(sig protocol.Signature) (protocol.Signature, []string) {
	var path []string
	for {
		d, ok := sig.(*protocol.DelegatedSignature)
		if !ok {
			// Read outer wrapper first: the fact's path order, outermost first - the order the CLI's
			// SignatureData.DelegatorChain gives. Core reverses this list (sig_user.go unwrapDelegated), which is why
			// an arrival's delegator[0] is the page nearest the key.
			return sig, path
		}
		path = append(path, normalizeAccURL(d.Delegator.String()))
		sig = d.Signature
	}
}

// checkArrivalFact requires the fact to be what the authority signature says.
func checkArrivalFact(sig protocol.Signature, f ArrivalFact) error {
	a, ok := sig.(*protocol.AuthoritySignature)
	if !ok {
		return fmt.Errorf("a %v is not an authority signature", sig.Type())
	}
	if len(a.Delegator) == 0 || normalizeAccURL(a.Delegator[0].String()) != normalizeAccURL(f.Page) {
		return fmt.Errorf("the delegated vote's first delegator is not the page %s", f.Page)
	}
	beyond := a.Delegator[1:]
	path := make([]string, len(beyond))
	for i := range beyond {
		path[i] = normalizeAccURL(beyond[len(beyond)-1-i].String())
	}
	if !pathEqual(path, f.Path) {
		return fmt.Errorf("the delegated vote's path %v is not the fact's %v", path, f.Path)
	}
	return checkAuthority(a, f.Authority, f.Origin, f.Vote)
}

// checkVoteFact requires the fact to be what the principal's recorded vote says.
func checkVoteFact(sig protocol.Signature, f RecordedVote) error {
	a, ok := sig.(*protocol.AuthoritySignature)
	if !ok {
		return fmt.Errorf("a %v is not an authority signature", sig.Type())
	}
	if len(a.Delegator) != 0 {
		return fmt.Errorf("a recorded vote of the principal's own authority names delegators")
	}
	return checkAuthority(a, f.Authority, f.Origin, f.Vote)
}

func checkAuthority(a *protocol.AuthoritySignature, authority, origin string, vote protocol.VoteType) error {
	if a.Authority == nil || normalizeAccURL(a.Authority.String()) != normalizeAccURL(authority) {
		return fmt.Errorf("the vote is by %v, the fact records %s", a.Authority, authority)
	}
	if a.Origin == nil || normalizeAccURL(a.Origin.String()) != normalizeAccURL(origin) {
		return fmt.Errorf("the vote was cast by %v, the fact records %s", a.Origin, origin)
	}
	if a.Vote != vote {
		return fmt.Errorf("the vote is %v, the fact records %v", a.Vote, vote)
	}
	return nil
}

func decodeTransaction(h string) (*protocol.Transaction, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("the transaction is not hex")
	}
	txn := new(protocol.Transaction)
	if err := txn.UnmarshalBinary(b); err != nil {
		return nil, fmt.Errorf("the transaction does not decode: %w", err)
	}
	if txn.Body == nil || txn.Header.Principal == nil {
		return nil, fmt.Errorf("the transaction has no body or principal")
	}
	return txn, nil
}

func decodeSignature(h string) (protocol.Signature, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("the signature is not hex")
	}
	sig, err := protocol.UnmarshalSignature(b)
	if err != nil {
		return nil, fmt.Errorf("the signature does not decode: %w", err)
	}
	return sig, nil
}

func authoritiesEqual(a, b []AccountAuthority) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if normalizeAccURL(a[i].URL) != normalizeAccURL(b[i].URL) || a[i].Disabled != b[i].Disabled {
			return false
		}
	}
	return true
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
