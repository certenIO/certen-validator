// Copyright 2026 Certen Protocol
//
// Assembling evidence 2.1 from a capture (docs/proof/G1_CROSS_PARTITION.md D3, D4, section 5; RB9 Phase C1b-2).
//
// The capture records the pages as they were at their partition's block (retention-limited) and the facts of the vote. The members that
// make the timeline verifiable - a page's history, the receipt placing a counted signature in its page's signature chain, the
// signature-index entries that fix the block it arrived in, the block that produced a vote - are computed from the chains' entries,
// which are append-only and so are the same whenever they are read: the first n entries now are the first n entries at the block at
// which the (proven) chain root had n. Every receipt built here is checked against the chain root the page proves before it is kept.

package proofv2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// ChainSource reads the chains of accounts. A chain is append-only: the first n entries read now are the first n entries the chain had
// when it held n, whatever it holds today.
type ChainSource interface {
	// Entries returns the first n entries of the named chain of account (an index chain's entries are the padded IndexEntry encodings).
	Entries(ctx context.Context, account *url.URL, chain string, n uint64) ([][]byte, error)
	// History returns the first n entries of the account's main chain as the transactions they name, with the initiating signature of an
	// UpdateKey.
	History(ctx context.Context, account *url.URL, n uint64) ([]HistoryEntry, error)
}

// ChainReceipt returns the receipt of entry p of a chain holding exactly entries, from the entry to the chain's anchor: Accumulate's
// merkle algorithm (merkle.State.AddEntry carrying an entry upward, Anchor folding the peaks) replayed step by step, so it is the receipt
// the chain itself would produce for the chain at that height.
func ChainReceipt(entries [][]byte, p int) (*merkle.Receipt, error) {
	if p < 0 || p >= len(entries) {
		return nil, fmt.Errorf("entry %d of a chain of %d", p, len(entries))
	}
	type node struct {
		hash []byte
		has  bool
	}
	comb := func(left, right []byte) []byte {
		s := sha256.Sum256(append(append([]byte{}, left...), right...))
		return s[:]
	}
	var pending []*node
	r := &merkle.Receipt{Start: entries[p]}
	for i, e := range entries {
		cur := &node{hash: e, has: i == p}
		for lvl := 0; ; lvl++ {
			if lvl == len(pending) {
				pending = append(pending, nil)
			}
			if pending[lvl] == nil {
				pending[lvl] = cur
				break
			}
			left := pending[lvl]
			if left.has {
				r.Entries = append(r.Entries, &merkle.ReceiptEntry{Right: true, Hash: cur.hash})
			}
			if cur.has {
				r.Entries = append(r.Entries, &merkle.ReceiptEntry{Right: false, Hash: left.hash})
			}
			cur = &node{hash: comb(left.hash, cur.hash), has: left.has || cur.has}
			pending[lvl] = nil
		}
	}
	var acc *node
	for _, v := range pending {
		if v == nil {
			continue
		}
		if acc == nil {
			acc = v
			continue
		}
		if acc.has {
			r.Entries = append(r.Entries, &merkle.ReceiptEntry{Right: false, Hash: v.hash})
		}
		if v.has {
			r.Entries = append(r.Entries, &merkle.ReceiptEntry{Right: true, Hash: acc.hash})
		}
		acc = &node{hash: comb(v.hash, acc.hash), has: acc.has || v.has}
	}
	r.Anchor = acc.hash
	return r, nil
}

func rcptHex(r *merkle.Receipt) (string, error) {
	b, err := r.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// chainEntries reads the first count entries of a bound chain and requires them to fold to exactly the chain root the page proves.
func chainEntries(ctx context.Context, src ChainSource, u *url.URL, p *PageState, name string) ([][]byte, error) {
	c := boundChain(p, name)
	if c == nil || c.Count == 0 {
		return nil, fmt.Errorf("%s has no %s chain bound at the block", p.URL, name)
	}
	es, err := src.Entries(ctx, u, name, c.Count)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", p.URL, name, err)
	}
	if uint64(len(es)) != c.Count {
		return nil, fmt.Errorf("%s %s: read %d entries, the chain proves %d", p.URL, name, len(es), c.Count)
	}
	if !foldMatches(es, c) {
		return nil, fmt.Errorf("%s %s: the %d entries read do not fold to the chain root the page proves", p.URL, name, c.Count)
	}
	return es, nil
}

// AttachHistory reads the page's main chain as transactions and its main-index chain, and carries them as the page's History (PROOF_V2
// 5.2 steps 2-3). The verifier folds both to the roots the page proves.
func AttachHistory(ctx context.Context, src ChainSource, p *PageState) error {
	u, err := url.Parse(p.URL)
	if err != nil {
		return err
	}
	main, mainIdx := boundChain(p, "main"), boundChain(p, "main-index")
	if main == nil || mainIdx == nil {
		return fmt.Errorf("%s has no bound main or main-index chain: its history cannot be proven", p.URL)
	}
	he, err := src.History(ctx, u, main.Count)
	if err != nil {
		return fmt.Errorf("%s history: %w", p.URL, err)
	}
	idx, err := chainEntries(ctx, src, u, p, "main-index")
	if err != nil {
		return err
	}
	h := &PageHistory{Entries: he}
	for _, e := range idx {
		h.Index = append(h.Index, hex.EncodeToString(e))
	}
	p.History = h
	return nil
}

// HistoryStates folds and replays a page's carried history exactly as the verifier does and returns every state the page passed through,
// each with the block it began in. The capture uses it to find the delegate books an earlier state of a page named.
func HistoryStates(p *PageState, partition string, block uint64) (govvote.States, error) {
	raw, err := hex.DecodeString(p.State)
	if err != nil {
		return nil, err
	}
	acct, err := protocol.UnmarshalAccount(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.URL, err)
	}
	pa := &provenAcct{acct: acct, anchor: &xAnchor{id: partition, block: block}, chain: PageChain{URL: p.URL, Bound: len(p.Chains) > 0}}
	return replayHistory(pa, p)
}

// EntryProof is a chain entry's receipt into the chain root the page proves, and the block it was written in with the index entries that
// fix it.
type EntryProof struct {
	Receipt  string
	Arrival  Arrival
	Position uint64
	Block    uint64
}

// ProveEntry places the entry msg in the named chain of page p: its receipt to the chain root bound at the block, and the two adjacent
// index entries (<chain>-index) that bracket its position, whose block is the entry's.
func ProveEntry(ctx context.Context, src ChainSource, p *PageState, chain string, msg []byte) (*EntryProof, error) {
	u, err := url.Parse(p.URL)
	if err != nil {
		return nil, err
	}
	es, err := chainEntries(ctx, src, u, p, chain)
	if err != nil {
		return nil, err
	}
	pos := -1
	for i, e := range es {
		if string(e) == string(msg) {
			if pos >= 0 {
				return nil, fmt.Errorf("%s %s holds the entry %x twice", p.URL, chain, msg[:8])
			}
			pos = i
		}
	}
	if pos < 0 {
		return nil, fmt.Errorf("%s %s does not hold the entry %x at the block", p.URL, chain, msg[:8])
	}
	r, err := ChainReceipt(es, pos)
	if err != nil {
		return nil, err
	}
	rh, err := rcptHex(r)
	if err != nil {
		return nil, err
	}
	idx, err := chainEntries(ctx, src, u, p, chain+"-index")
	if err != nil {
		return nil, err
	}
	at := -1
	var atEntry indexEntry
	for j, raw := range idx {
		ie, _, err := decodeIndexEntry(hex.EncodeToString(raw))
		if err != nil {
			return nil, fmt.Errorf("%s %s-index entry %d: %w", p.URL, chain, j, err)
		}
		if ie.source >= uint64(pos) {
			at, atEntry = j, ie
			break
		}
	}
	if at < 0 {
		return nil, fmt.Errorf("%s %s-index records no block for position %d of %d", p.URL, chain, pos, len(es))
	}
	mk := func(j int) (*IndexProof, error) {
		ir, err := ChainReceipt(idx, j)
		if err != nil {
			return nil, err
		}
		ih, err := rcptHex(ir)
		if err != nil {
			return nil, err
		}
		return &IndexProof{Position: uint64(j), Entry: hex.EncodeToString(idx[j]), Receipt: ih}, nil
	}
	a := Arrival{}
	atp, err := mk(at)
	if err != nil {
		return nil, err
	}
	a.At = *atp
	if at > 0 {
		if a.Before, err = mk(at - 1); err != nil {
			return nil, err
		}
	}
	return &EntryProof{Receipt: rh, Arrival: a, Position: uint64(pos), Block: atEntry.block}, nil
}

// Assembly is everything a capture holds that evidence 2.1 needs beyond the layers of the transaction's own proof.
type Assembly struct {
	// Pages are the captured pages (partition, roles and, where captured, history set), each as of its partition's block.
	Pages []*PageState
	// Roots are the state roots the pages are proven into, by the partition URL ("acc://bvn-BVN2.acme") the page names.
	Roots map[string][32]byte
	// Foreign are the anchors of the partitions other than the transaction's, to be proven into the certified root.
	Foreign []*PartitionBlock
	// Votes are the votes as captured: the hops and counted signatures with their message, signature and block; the receipts, the arrival
	// proofs and the production are built here.
	Votes []Vote
	// Sequenced maps a sequenced vote's message to the hash of the SequencedMessage the source partition recorded in its synthetic ledger.
	Sequenced map[string]string
	// Transaction is the governed transaction, binary, hex.
	Transaction string
	Source      ChainSource
}

// ProveMembers builds the members of the votes that need the chains: the receipt of each vote in the principal's signature chain, of
// each hop and counted signature in its page's signature chain with the arrival proof, and the production of each vote. It changes the
// votes in place and returns them.
func (a *Assembly) ProveMembers(ctx context.Context, principal string) ([]Vote, error) {
	byURL := map[string]*PageState{}
	for _, p := range a.Pages {
		byURL[strings.ToLower(p.URL)] = p
	}
	pp, ok := byURL[strings.ToLower(principal)]
	if !ok {
		return nil, fmt.Errorf("the principal %s is not among the captured pages", principal)
	}
	out := make([]Vote, len(a.Votes))
	for vi := range a.Votes {
		v := a.Votes[vi]
		v.Hops = append([]VoteHop(nil), v.Hops...)
		v.Counted = append([]VoteHop(nil), v.Counted...)
		msg, err := hex.DecodeString(v.Message)
		if err != nil || len(msg) != 32 {
			return nil, fmt.Errorf("the vote of %s: message is not 32 bytes of hex", v.Authority)
		}
		vp, err := ProveEntry(ctx, a.Source, pp, "signature", msg)
		if err != nil {
			return nil, fmt.Errorf("the vote of %s: %w", v.Authority, err)
		}
		v.Receipt = vp.Receipt
		prove := func(hs []VoteHop) error {
			for i := range hs {
				h := &hs[i]
				pg, ok := byURL[strings.ToLower(h.Page)]
				if !ok {
					return fmt.Errorf("the signature on %s is not among the captured pages", h.Page)
				}
				hm, err := hex.DecodeString(h.Message)
				if err != nil || len(hm) != 32 {
					return fmt.Errorf("the signature on %s: message is not 32 bytes of hex", h.Page)
				}
				ep, err := ProveEntry(ctx, a.Source, pg, "signature", hm)
				if err != nil {
					return fmt.Errorf("the signature on %s: %w", h.Page, err)
				}
				arr := ep.Arrival
				h.Receipt, h.Arrival, h.Block = ep.Receipt, &arr, ep.Block
			}
			return nil
		}
		if err := prove(v.Hops); err != nil {
			return nil, err
		}
		if err := prove(v.Counted); err != nil {
			return nil, err
		}
		switch v.Transport.Kind {
		case TransportInline:
			arr := vp.Arrival
			v.Produced = &Production{Account: principal, Chain: "signature", Message: v.Message, Receipt: vp.Receipt, Arrival: arr}
		case TransportSequenced:
			seq, ok := a.Sequenced[v.Message]
			if !ok {
				break // the production cannot be established: the verifier reports g1_vote_held for it
			}
			ledger := strings.ToLower(v.Transport.Source) + "/" + protocol.Synthetic
			lp, ok := byURL[ledger]
			if !ok {
				break
			}
			sm, err := hex.DecodeString(seq)
			if err != nil || len(sm) != 32 {
				return nil, fmt.Errorf("the vote of %s: the sequenced message hash is not 32 bytes of hex", v.Authority)
			}
			ep, err := ProveEntry(ctx, a.Source, lp, "main", sm)
			if err != nil {
				return nil, fmt.Errorf("the production of the vote of %s: %w", v.Authority, err)
			}
			v.Produced = &Production{Account: lp.URL, Chain: "main", Message: seq, Receipt: ep.Receipt, Arrival: ep.Arrival}
		}
		out[vi] = v
	}
	return out, nil
}

// StateHistoryUnavailable: a page's history could not be read from the chains, so its signatures cannot be judged against the page as it
// stood when they arrived (the votes are not re-evaluated and the report says so by name).
const StateHistoryUnavailable = "g1_history_unavailable"

// LoadPartitionBlock reads the anchor the Directory executed at position index of a partition's anchor sequence (the position a
// capture recorded), as SelectPartitionBlock would have chosen it.
func LoadPartitionBlock(ctx context.Context, log AnchorLog, partition string, index uint64) (*PartitionBlock, error) {
	return partitionBlockAt(ctx, log, partition, index, index)
}

// StateEvidence21NotInForce: evidence 2.1 can be built and verified, but the rules that accept it in a certificate are not in force
// (design D7), so a proof for an intent's certificate is refused by name. It supersedes StateEvidence21Required, which said the build
// did not exist.
const StateEvidence21NotInForce = "g1_evidence_21_not_in_force"
