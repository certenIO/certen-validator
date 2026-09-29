// Copyright 2026 Certen Protocol
//
// THE PRINCIPAL'S AUTHORITY SET AT EXECUTION, REPLAYED FROM ACCOUNT HISTORIES (RB4-F66 E2b).
//
// An account's own authority set is written in exactly two ways, both on its main chain: by the transaction that
// created it, and by UpdateAccountAuth. So it is replayed like a key page: from the creation entry through every
// UpdateAccountAuth, taking the set as of the last one recorded at or before the execution block. The set that
// governed a transaction is the principal's own if it has one, else the nearest identity above it with one (core
// create_utils.go).
//
// Creation, from accumulate-core chain/*.go:
//
//	createDataAccount, createTokenAccount, createToken
//	                          the authorities the body names (setInitialAuthorities)
//	createKeyBook             the book itself, then those the body names
//	createIdentity            the new key book, then those the body names
//	syntheticCreateIdentity   the created accounts travel inline, with their sets
//
// An account created naming no authority starts empty and is governed by its nearest ancestor with a set
// (V2Baikonur); before Baikonur the parent's set was COPIED in at creation (StateManager.SetAuth -> InheritAuth).
// Which rule created an account is not recorded on it, so both are replayed, and a rule survives only if its replay
// reaches the set the network held when the history was read. If the surviving rules disagree at the block, the set
// is not established. When the network's set is what eliminated a rule that would have given a different answer,
// the account is named: that part of the set rests on the network's word for its present state, not on the chain
// alone.
package govvote

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govreceipt"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// AuthorityEvidence is what the principal's authority set at execution is replayed from.
type AuthorityEvidence struct {
	// Block is the execution block, on the principal's partition - where every account of the climb lives.
	Block int64 `json:"block"`
	// Accounts is the main chain history of every account the replay reads: the principal, each identity it climbs
	// to, and each parent a pre-Baikonur creation would have copied from.
	Accounts []AccountHistory `json:"accounts"`
	// DecidedByLiveState names each account whose set at the block rests on the network's present set choosing
	// between the two creation rules (see the package comment). Re-derived by the verifier and required equal.
	DecidedByLiveState []string `json:"decidedByLiveState,omitempty"`
}

// AccountHistory is an account's whole main chain, and its authority set as the network held it when read.
type AccountHistory struct {
	Account string             `json:"account"`
	Entries int                `json:"entries"`
	Events  []AccountEntry     `json:"events"`
	Live    []AccountAuthority `json:"live"`
}

// AccountEntry is one main chain entry: its transaction, compact - the header, and the body; a write-data body
// without its entry, which is committed to by its hash (core transaction_hash.go hashWriteData) - bound to the entry
// hash. The creation entry and every UpdateAccountAuth carry the receipt that names their block; nothing else's
// block matters to the set.
type AccountEntry struct {
	Index         int                 `json:"index"`
	EntryHash     string              `json:"entryHash"`
	Header        string              `json:"header"`
	Body          string              `json:"body"`
	DataEntryHash string              `json:"dataEntryHash,omitempty"`
	LocalBlock    int64               `json:"localBlock,omitempty"`
	Receipt       *govreceipt.Receipt `json:"receipt,omitempty"`
}

// CompactEntry is the evidence form of one main chain transaction.
func CompactEntry(index int, txn *protocol.Transaction) (AccountEntry, error) {
	h, err := txn.Header.MarshalBinary()
	if err != nil {
		return AccountEntry{}, err
	}
	e := AccountEntry{Index: index, EntryHash: hex.EncodeToString(txn.GetHash()), Header: hex.EncodeToString(h)}
	body := txn.Body
	if stripped, entry, ok := withoutDataEntry(body); ok {
		body = stripped
		e.DataEntryHash = strings.Repeat("0", 64)
		if entry != nil {
			e.DataEntryHash = hex.EncodeToString(entry.Hash())
		}
	}
	b, err := body.MarshalBinary()
	if err != nil {
		return AccountEntry{}, err
	}
	e.Body = hex.EncodeToString(b)
	return e, nil
}

// withoutDataEntry is a write-data body with its entry removed, and the entry.
func withoutDataEntry(body protocol.TransactionBody) (protocol.TransactionBody, protocol.DataEntry, bool) {
	switch b := body.(type) {
	case *protocol.WriteData:
		x := b.Copy()
		x.Entry = nil
		return x, b.Entry, true
	case *protocol.WriteDataTo:
		x := b.Copy()
		x.Entry = nil
		return x, b.Entry, true
	case *protocol.SyntheticWriteData:
		x := b.Copy()
		x.Entry = nil
		return x, b.Entry, true
	case *protocol.SystemWriteData:
		x := b.Copy()
		x.Entry = nil
		return x, b.Entry, true
	}
	return nil, nil, false
}

// decodeEntry decodes a compact entry and requires it to hash to its entry hash. A write-data body is returned
// without its entry; nothing about an account's authority reads one.
func decodeEntry(e AccountEntry) (*protocol.Transaction, error) {
	hb, err := hex.DecodeString(e.Header)
	if err != nil {
		return nil, fmt.Errorf("the header is not hex")
	}
	txn := new(protocol.Transaction)
	if err := txn.Header.UnmarshalBinary(hb); err != nil {
		return nil, fmt.Errorf("the header does not decode: %w", err)
	}
	bb, err := hex.DecodeString(e.Body)
	if err != nil {
		return nil, fmt.Errorf("the body is not hex")
	}
	body, err := protocol.UnmarshalTransactionBody(bb)
	if err != nil {
		return nil, fmt.Errorf("the body does not decode: %w", err)
	}
	txn.Body = body

	var got []byte
	if stripped, entry, isData := withoutDataEntry(body); isData {
		if entry != nil {
			return nil, fmt.Errorf("a write-data body is carried with its entry")
		}
		dh, err := hex.DecodeString(e.DataEntryHash)
		if err != nil || len(dh) != 32 {
			return nil, fmt.Errorf("a write-data body without its entry's hash")
		}
		sb, err := stripped.MarshalBinary()
		if err != nil {
			return nil, err
		}
		hasher := new(merkle.Hasher)
		hasher.AddBytes(sb)
		hasher.AddHash((*[32]byte)(dh))
		headerHash := sha256.Sum256(hb)
		sum := sha256.Sum256(append(headerHash[:], hasher.MerkleHash()...))
		got = sum[:]
	} else {
		if e.DataEntryHash != "" {
			return nil, fmt.Errorf("a %v body carries a data entry hash", body.Type())
		}
		got = txn.GetHash()
	}
	if !strings.EqualFold(hex.EncodeToString(got), e.EntryHash) {
		return nil, fmt.Errorf("its transaction hashes to %x, not to the entry %s", got[:8], short(e.EntryHash))
	}
	return txn, nil
}

// needsBlock is whether an entry's block matters to the set: the creation, and every UpdateAccountAuth.
func needsBlock(index int, txn *protocol.Transaction) bool {
	if index == 0 {
		return true
	}
	_, ok := txn.Body.(*protocol.UpdateAccountAuth)
	return ok
}

// NeedsBlock is needsBlock for the reader assembling the evidence.
func NeedsBlock(index int, txn *protocol.Transaction) bool { return needsBlock(index, txn) }

// replayedAccount is an account's history, decoded and bound.
type replayedAccount struct {
	url    *url.URL
	txns   []*protocol.Transaction
	blocks map[int]int64
	live   *protocol.AccountAuth
}

func bindAccount(h AccountHistory) (*replayedAccount, error) {
	u, err := url.Parse(h.Account)
	if err != nil {
		return nil, fmt.Errorf("account %q: %w", h.Account, err)
	}
	if h.Entries != len(h.Events) || h.Entries == 0 {
		return nil, fmt.Errorf("the history carries %d entries of a chain of %d", len(h.Events), h.Entries)
	}
	ra := &replayedAccount{url: u, blocks: map[int]int64{}, live: new(protocol.AccountAuth)}
	var last int64
	for i, e := range h.Events {
		if e.Index != i {
			return nil, fmt.Errorf("entry %d is chain index %d", i, e.Index)
		}
		txn, err := decodeEntry(e)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		if needsBlock(i, txn) {
			if e.Receipt == nil {
				return nil, fmt.Errorf("entry %d (%v) carries no receipt, and its block decides the set", i, txn.Body.Type())
			}
			if !strings.EqualFold(e.Receipt.Start, e.EntryHash) {
				return nil, fmt.Errorf("entry %d: its receipt starts at %s, not at the entry", i, short(e.Receipt.Start))
			}
			if err := govreceipt.VerifyMerkle(*e.Receipt, "account entry "+short(e.EntryHash)); err != nil {
				return nil, err
			}
			if e.Receipt.LocalBlock != e.LocalBlock || e.LocalBlock <= 0 || e.LocalBlock < last {
				return nil, fmt.Errorf("entry %d is recorded at block %d (receipt %d), after an entry at block %d",
					i, e.LocalBlock, e.Receipt.LocalBlock, last)
			}
			last = e.LocalBlock
			ra.blocks[i] = e.LocalBlock
		} else if e.Receipt != nil || e.LocalBlock != 0 {
			return nil, fmt.Errorf("entry %d (%v) carries a block that decides nothing", i, txn.Body.Type())
		}
		ra.txns = append(ra.txns, txn)
	}
	for _, a := range h.Live {
		au, err := url.Parse(a.URL)
		if err != nil {
			return nil, fmt.Errorf("live authority %q: %w", a.URL, err)
		}
		e, isNew := ra.live.AddAuthority(au)
		if !isNew {
			return nil, fmt.Errorf("the live set names %s twice", a.URL)
		}
		e.Disabled = a.Disabled
	}
	return ra, nil
}

// AuthoritySetAt is the set that governed a transaction on principal at ev.Block, replayed from ev alone, and the
// accounts whose part of it rests on the network's present set (sorted).
func AuthoritySetAt(ev *AuthorityEvidence, principal string) ([]AccountAuthority, []string, error) {
	if ev == nil {
		return nil, nil, fmt.Errorf("no authority set evidence")
	}
	accounts := map[string]*replayedAccount{}
	for _, h := range ev.Accounts {
		key := CanonicalAccSpelling(h.Account)
		if _, dup := accounts[key]; dup {
			return nil, nil, fmt.Errorf("the evidence carries %s twice", h.Account)
		}
		ra, err := bindAccount(h)
		if err != nil {
			return nil, nil, fmt.Errorf("the history of %s: %w", h.Account, err)
		}
		accounts[key] = ra
	}
	r := &authReplay{accounts: accounts, decided: map[string]bool{}}
	u, err := url.Parse(normalizeAccURL(principal))
	if err != nil {
		return nil, nil, fmt.Errorf("principal %q: %w", principal, err)
	}
	set, err := r.climb(u, ev.Block)
	if err != nil {
		return nil, nil, err
	}
	var decided []string
	for a := range r.decided {
		decided = append(decided, a)
	}
	sort.Strings(decided)
	return set, decided, nil
}

type authReplay struct {
	accounts map[string]*replayedAccount
	decided  map[string]bool
	depth    int
}

// climb is core's: the account's own set, else the next identity up.
//
// An account whose own set the network's present set chose between the creation rules is named only when the rule
// it eliminated would have made the climb land on a different set. The common case - a data account created naming
// no authority, which pre-Baikonur would have copied its identity's book and post-Baikonur climbs to that same book -
// is not.
func (r *authReplay) climb(u *url.URL, block int64) ([]AccountAuthority, error) {
	r.depth++
	defer func() { r.depth-- }()
	if r.depth > 16 {
		return nil, fmt.Errorf("the authority climb from %v does not terminate", u)
	}
	auth, alternatives, err := r.accountAuthAt(u, block)
	if err != nil {
		return nil, err
	}
	effective, err := r.landOn(u, auth, block)
	if err != nil {
		return nil, err
	}
	for _, alt := range alternatives {
		other, err := r.landOn(u, alt, block)
		if err != nil || !authoritiesEqual(other, effective) {
			r.decided[CanonicalAccSpelling(u.String())] = true
		}
	}
	return effective, nil
}

// landOn is where the climb lands from an account whose own set is auth.
func (r *authReplay) landOn(u *url.URL, auth *protocol.AccountAuth, block int64) ([]AccountAuthority, error) {
	if len(auth.Authorities) > 0 {
		out := make([]AccountAuthority, 0, len(auth.Authorities))
		for _, e := range auth.Authorities {
			out = append(out, AccountAuthority{URL: normalizeAccURL(e.Url.String()), Disabled: e.Disabled})
		}
		return out, nil
	}
	if u.IsRootIdentity() {
		return nil, fmt.Errorf("%v and every identity above it have no authorities", u)
	}
	return r.climb(u.Identity(), block)
}

// accountAuthAt is an account's own set as of a block, by both creation rules (see the package comment), and the
// different set a rule the network's present set eliminated would have given.
func (r *authReplay) accountAuthAt(u *url.URL, block int64) (*protocol.AccountAuth, []*protocol.AccountAuth, error) {
	r.depth++
	defer func() { r.depth-- }()
	if r.depth > 16 {
		return nil, nil, fmt.Errorf("the authority replay of %v does not terminate", u)
	}
	ra, ok := r.accounts[CanonicalAccSpelling(u.String())]
	if !ok {
		return nil, nil, fmt.Errorf("the evidence carries no history for %v", u)
	}
	if ra.blocks[0] > block {
		return nil, nil, fmt.Errorf("%v did not exist at block %d (created at %d)", u, block, ra.blocks[0])
	}

	type outcome struct {
		atBlock, head *protocol.AccountAuth
		err           error
	}
	var candidates []outcome
	for _, inherit := range []bool{false, true} {
		initial, err := r.createdAuth(ra, inherit)
		if err != nil {
			candidates = append(candidates, outcome{err: err})
			continue
		}
		atBlock, head, err := ReplayAccountAuth(u, initial, ra.txns, ra.blocks, block)
		candidates = append(candidates, outcome{atBlock: atBlock, head: head, err: err})
	}

	var survivors, eliminated []outcome
	var why []string
	for _, c := range candidates {
		switch {
		case c.err != nil:
			why = append(why, c.err.Error())
		case !c.head.Equal(ra.live):
			why = append(why, fmt.Sprintf("replayed to the head it is %s, not %s", DescribeAuth(c.head), DescribeAuth(ra.live)))
			eliminated = append(eliminated, c)
		default:
			survivors = append(survivors, c)
		}
	}
	switch {
	case len(survivors) == 0:
		return nil, nil, fmt.Errorf("the authority set of %v could not be replayed to the set the network holds: %s", u,
			strings.Join(why, "; "))
	case len(survivors) == 2 && !survivors[0].atBlock.Equal(survivors[1].atBlock):
		return nil, nil, fmt.Errorf("the authority set of %v at block %d depends on which creation rule applied, and "+
			"both reach the present", u, block)
	}
	var alternatives []*protocol.AccountAuth
	for _, e := range eliminated {
		if !e.atBlock.Equal(survivors[0].atBlock) {
			alternatives = append(alternatives, e.atBlock)
		}
	}
	return survivors[0].atBlock, alternatives, nil
}

// createdAuth is the set the creating transaction gave the account; inherit applies the pre-Baikonur copy.
func (r *authReplay) createdAuth(ra *replayedAccount, inherit bool) (*protocol.AccountAuth, error) {
	u := ra.url
	auth, err := CreatedAuth(u, ra.txns[0])
	if err != nil || len(auth.Authorities) > 0 || !inherit || u.IsRootIdentity() {
		return auth, err
	}
	if _, synthetic := ra.txns[0].Body.(*protocol.SyntheticCreateIdentity); synthetic {
		// Created on another partition with its set already decided: nothing was inherited here.
		return auth, nil
	}
	// Before Baikonur an account naming no authority had its parent's set copied in at creation: the parent's set
	// at the block that created it.
	parent, alternatives, err := r.accountAuthAt(u.Identity(), ra.blocks[0])
	if err != nil {
		return nil, fmt.Errorf("the set %v would have copied from %v at creation: %w", u, u.Identity(), err)
	}
	if len(alternatives) > 0 {
		// What would have been copied rests on the network's present set; named without asking whether it changes
		// where the climb lands - over-naming is safe, under-naming is not.
		r.decided[CanonicalAccSpelling(u.Identity().String())] = true
	}
	return parent.Copy(), nil
}

// CreatedAuth is the set the creating transaction named, without any inheritance.
func CreatedAuth(u *url.URL, txn *protocol.Transaction) (*protocol.AccountAuth, error) {
	auth := new(protocol.AccountAuth)
	var named []*url.URL
	switch body := txn.Body.(type) {
	case *protocol.CreateDataAccount:
		if !body.Url.Equal(u) {
			return nil, fmt.Errorf("the first entry of %v creates %v", u, body.Url)
		}
		named = body.Authorities
	case *protocol.CreateTokenAccount:
		if !body.Url.Equal(u) {
			return nil, fmt.Errorf("the first entry of %v creates %v", u, body.Url)
		}
		named = body.Authorities
	case *protocol.CreateToken:
		if !body.Url.Equal(u) {
			return nil, fmt.Errorf("the first entry of %v creates %v", u, body.Url)
		}
		named = body.Authorities
	case *protocol.CreateKeyBook:
		if !body.Url.Equal(u) {
			return nil, fmt.Errorf("the first entry of %v creates %v", u, body.Url)
		}
		auth.AddAuthority(body.Url)
		named = body.Authorities
	case *protocol.CreateIdentity:
		if !body.Url.Equal(u) {
			return nil, fmt.Errorf("the first entry of %v creates %v", u, body.Url)
		}
		if body.KeyBookUrl != nil {
			auth.AddAuthority(body.KeyBookUrl)
		}
		named = body.Authorities
	case *protocol.SyntheticCreateIdentity:
		for _, a := range body.Accounts {
			if !a.GetUrl().Equal(u) {
				continue
			}
			full, ok := a.(protocol.FullAccount)
			if !ok {
				return nil, fmt.Errorf("%v was created as a %v, which has no authority set", u, a.Type())
			}
			// Created on another partition with its set already decided.
			return full.GetAuth().Copy(), nil
		}
		return nil, fmt.Errorf("the synthetic creation on %v's chain does not create it", u)
	default:
		return nil, fmt.Errorf("%v was created by a %v, which this replay has not been taught", u, txn.Body.Type())
	}
	for _, a := range named {
		auth.AddAuthority(a)
	}
	return auth, nil
}

// ReplayAccountAuth applies every UpdateAccountAuth on the account's chain, and returns the set as of block - after
// the last one recorded at or before it - and after the final entry. blocks holds each UpdateAccountAuth's block.
func ReplayAccountAuth(u *url.URL, initial *protocol.AccountAuth, txns []*protocol.Transaction, blocks map[int]int64,
	block int64) (*protocol.AccountAuth, *protocol.AccountAuth, error) {
	auth := initial.Copy()
	atBlock := auth.Copy()
	for i := 1; i < len(txns); i++ {
		body, ok := txns[i].Body.(*protocol.UpdateAccountAuth)
		if !ok {
			continue
		}
		if !txns[i].Header.Principal.Equal(u) {
			return nil, nil, fmt.Errorf("an updateAccountAuth on %v's chain names %v", u, txns[i].Header.Principal)
		}
		at, known := blocks[i]
		if !known {
			return nil, nil, fmt.Errorf("the updateAccountAuth at entry %d of %v has no block", i, u)
		}
		next := auth.Copy()
		if err := ApplyAccountAuthOps(u, next, body.Operations); err != nil {
			return nil, nil, fmt.Errorf("replay diverges from execution at entry %d of %v: %w - the executor "+
				"applied it without error", i, u, err)
		}
		auth = next
		if at <= block {
			atBlock = auth.Copy()
		}
	}
	return atBlock, auth, nil
}

// ApplyAccountAuthOps mirrors UpdateAccountAuth.Execute, less the checks that can only make it fail (authority
// existence, not-a-page, inheritance).
func ApplyAccountAuthOps(u *url.URL, auth *protocol.AccountAuth, ops []protocol.AccountAuthOperation) error {
	for _, op := range ops {
		switch op := op.(type) {
		case *protocol.EnableAccountAuthOperation:
			e, ok := auth.GetAuthority(op.Authority)
			if !ok {
				return fmt.Errorf("%v is not an authority of %v", op.Authority, u)
			}
			e.Disabled = false
		case *protocol.DisableAccountAuthOperation:
			e, ok := auth.GetAuthority(op.Authority)
			if !ok {
				return fmt.Errorf("%v is not an authority of %v", op.Authority, u)
			}
			e.Disabled = true
		case *protocol.AddAccountAuthorityOperation:
			if _, isNew := auth.AddAuthority(op.Authority); !isNew {
				return fmt.Errorf("duplicate authority %v", op.Authority)
			}
		case *protocol.RemoveAccountAuthorityOperation:
			if !auth.RemoveAuthority(op.Authority) {
				return fmt.Errorf("no such authority %v", op.Authority)
			}
			if len(auth.Authorities) == 0 && u.IsRootIdentity() {
				return fmt.Errorf("removing the last authority from a root account is not allowed")
			}
		default:
			return fmt.Errorf("invalid operation %v", op.Type())
		}
	}
	return nil
}

// DescribeAuth names a set for a reader.
func DescribeAuth(a *protocol.AccountAuth) string {
	if a == nil || len(a.Authorities) == 0 {
		return "[]"
	}
	parts := make([]string, 0, len(a.Authorities))
	for _, e := range a.Authorities {
		s := e.Url.String()
		if e.Disabled {
			s += " (disabled)"
		}
		parts = append(parts, s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
