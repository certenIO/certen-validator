// Copyright 2026 Certen Protocol
//
// The certified timeline of evidence 2.1 (docs/proof/PROOF_V2.md 5.2 "Refined 2026-10-05" steps 2-5; docs/proof/G1_CROSS_PARTITION.md
// D3; RB9 Phase C1b-1). A page "as of B_Y" can only be the END of the history that judged a counted signature, so for every page
// that carries a PageHistory the verifier
//
//  1. folds the history's main-chain entry hashes to the main chain root proven at B_Y (step 2: no entry inserted, omitted or
//     reordered) and the main-index chain to its proven root, which gives every entry's block;
//  2. replays the entries from the page's genesis with the executor's rules (govvote.Replay) and requires the replay to end in the
//     proven state (step 3);
//  3. derives each counted signature's exact arrival block from the page's signature-index chain (step 4) - never from a claim;
//  4. runs the vote model (govvote) on that certified timeline and requires its result to equal every recorded vote's Origin and
//     Vote, and the principal's authorities to be ready (step 5).
//
// Everything the model needs is recomputed here. Anything it cannot establish is a named state with the partition and block it was
// judged at (design D6): a refusal when the evidence contradicts it, an Unproven entry of the report when the evidence is silent.

package proofv2

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The named states of the certified timeline (design D6, extended by RB9 Phase C1b-1; see docs/proof/G1_CROSS_PARTITION.md).
const (
	// StateHistoryFoldMismatch: a page's history entries (or its main-index entries) do not fold to the chain root proven at B_Y.
	StateHistoryFoldMismatch = "g1_history_fold_mismatch"
	// StateHistoryHeadMismatch: the replay of a page's history does not end in the page proven at B_Y.
	StateHistoryHeadMismatch = "g1_history_head_mismatch"
	// StateHistoryUnreplayable: the replay cannot apply an entry as the executor did (a transaction it has not been taught, or one
	// the executor accepted that the replay cannot). It is the replay declining to guess, never a fact about the page.
	StateHistoryUnreplayable = "g1_history_unreplayable"
	// StateArrivalUnproven: the block a counted signature or vote arrived in cannot be derived from its chain's index chain.
	StateArrivalUnproven = "g1_arrival_unproven"
	// StateVoteNotReproduced: the vote model, run on the certified timeline, does not reach a recorded vote's Origin and Vote - or a
	// recorded fact cannot be reconciled with the page's certified history (the model's own refusal, carried in the detail).
	StateVoteNotReproduced = "g1_vote_not_reproduced"
	// StateAuthorityNotReady: a required authority did not vote accept on the certified timeline, or (every authority disabled) no
	// authority voted.
	StateAuthorityNotReady = "g1_authority_not_ready"
	// StateTransactionMismatch: the carried transaction is not the one TxHash names, or not on the evidence's account.
	StateTransactionMismatch = "g1_transaction_mismatch"
	// StateSignatureInvalid: a carried signature does not sign the transaction, or is not the message its chain entry holds.
	StateSignatureInvalid = "g1_signature_invalid"
)

// ArrivalReport is, for the report, one counted signature or vote and the block the verifier derived for it.
type ArrivalReport struct {
	Kind      string // "signature" (a hop), "produced" (a vote's production)
	Account   string
	Partition string
	Message   string
	Block     uint64
}

// Authorization modes of a report (design D3).
const (
	ModeAuthoritiesRequired    = "authorities_required"
	ModeAllAuthoritiesDisabled = "all_authorities_disabled"
)

func unboundRefusal(pa *provenAcct, p *PageState) error {
	code := StateChainUnboundPending
	if i := strings.Index(pa.chain.Note, ":"); i > 0 && strings.HasPrefix(pa.chain.Note, "g1_") {
		code = pa.chain.Note[:i]
	}
	return refusal21(code, pa.anchor.id, pa.anchor.block, "%s: its chains are not bound at the block (%s)", p.URL, pa.chain.Note)
}

// boundChain returns the named chain among a page's bound chains.
func boundChain(p *PageState, name string) *proof.ChainRoot {
	for i := range p.Chains {
		if p.Chains[i].Name == name {
			return &p.Chains[i]
		}
	}
	return nil
}

// foldMatches folds entries into a merkle state and requires it to be exactly the chain's proven state: the same height and the same
// pending hashes, so no entry was inserted, omitted or reordered.
func foldMatches(entries [][]byte, c *proof.ChainRoot) bool {
	if uint64(len(entries)) != c.Count {
		return false
	}
	st := new(merkle.State)
	for _, e := range entries {
		st.AddEntry(e)
	}
	n := max(len(st.Pending), len(c.Pending))
	for i := 0; i < n; i++ {
		var a, b []byte
		if i < len(st.Pending) {
			a = st.Pending[i]
		}
		if i < len(c.Pending) && c.Pending[i] != nil {
			var err error
			if b, err = hex.DecodeString(*c.Pending[i]); err != nil {
				return false
			}
		}
		if !bytes.Equal(a, b) {
			return false
		}
	}
	return true
}

type indexEntry struct {
	source, block uint64
}

func decodeIndexEntry(h string) (indexEntry, []byte, error) {
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) != 32 {
		return indexEntry{}, nil, fmt.Errorf("an index chain entry is not 32 bytes of hex")
	}
	e := new(protocol.IndexEntry)
	if err := e.UnmarshalBinary(raw); err != nil {
		return indexEntry{}, nil, fmt.Errorf("an index chain entry does not decode: %w", err)
	}
	return indexEntry{source: e.Source, block: e.BlockIndex}, raw, nil
}

func decodeTxn(h string) (*protocol.Transaction, error) {
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("a transaction is not hex")
	}
	txn := new(protocol.Transaction)
	if err := txn.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("a transaction does not decode: %w", err)
	}
	if txn.Body == nil || txn.Header.Principal == nil {
		return nil, fmt.Errorf("a transaction has no body or principal")
	}
	return txn, nil
}

func decodeSig(h string) (protocol.Signature, error) {
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("a signature is not hex")
	}
	sig, err := protocol.UnmarshalSignature(raw)
	if err != nil {
		return nil, fmt.Errorf("a signature does not decode: %w", err)
	}
	return sig, nil
}

// replayHistory folds and replays one page's history (PROOF_V2 5.2 steps 2-3) and returns every state the page's authority passed
// through, each with the block it began in.
func replayHistory(pa *provenAcct, p *PageState) (govvote.States, error) {
	h := p.History
	id, blk := pa.anchor.id, pa.anchor.block
	if !pa.chain.Bound {
		return nil, unboundRefusal(pa, p)
	}
	kp, ok := pa.acct.(*protocol.KeyPage)
	if !ok {
		return nil, fmt.Errorf("%s carries a history but is %T, not a key page", p.URL, pa.acct)
	}
	main, mainIdx := boundChain(p, "main"), boundChain(p, "main-index")
	if main == nil || mainIdx == nil {
		return nil, refusal21(StateHistoryFoldMismatch, id, blk, "%s: no main or main-index chain is bound at the block", p.URL)
	}
	if len(h.Entries) == 0 {
		return nil, refusal21(StateHistoryFoldMismatch, id, blk, "%s: the history carries no entry; the main chain holds %d", p.URL, main.Count)
	}
	txns := make([]*protocol.Transaction, len(h.Entries))
	hashes := make([][]byte, len(h.Entries))
	for i, e := range h.Entries {
		txn, err := decodeTxn(e.Transaction)
		if err != nil {
			return nil, fmt.Errorf("%s: history entry %d: %w", p.URL, i, err)
		}
		txns[i], hashes[i] = txn, txn.GetHash()
	}
	if !foldMatches(hashes, main) {
		return nil, refusal21(StateHistoryFoldMismatch, id, blk,
			"%s: the %d history entries do not fold to the main chain root proven at the block (height %d)", p.URL, len(hashes), main.Count)
	}
	idxRaw := make([][]byte, len(h.Index))
	idx := make([]indexEntry, len(h.Index))
	for i, s := range h.Index {
		e, raw, err := decodeIndexEntry(s)
		if err != nil {
			return nil, fmt.Errorf("%s: main-index entry %d: %w", p.URL, i, err)
		}
		idx[i], idxRaw[i] = e, raw
	}
	if !foldMatches(idxRaw, mainIdx) {
		return nil, refusal21(StateHistoryFoldMismatch, id, blk,
			"%s: the %d main-index entries do not fold to the main-index root proven at the block (height %d)", p.URL, len(idx), mainIdx.Count)
	}
	// Each main chain entry's block: the first index entry whose Source reaches it. The index must be strictly increasing and end at
	// the chain's last entry.
	blocks := make([]uint64, len(hashes))
	k := 0
	for j := range hashes {
		for k < len(idx) && idx[k].source < uint64(j) {
			k++
		}
		if k == len(idx) {
			return nil, refusal21(StateHistoryFoldMismatch, id, blk, "%s: main chain entry %d lies after the main-index chain's last entry", p.URL, j)
		}
		blocks[j] = idx[k].block
	}
	for i := 1; i < len(idx); i++ {
		if idx[i].source <= idx[i-1].source || idx[i].block <= idx[i-1].block {
			return nil, refusal21(StateHistoryFoldMismatch, id, blk, "%s: the main-index chain is not strictly increasing at entry %d", p.URL, i)
		}
	}
	if len(idx) == 0 || idx[len(idx)-1].source != uint64(len(hashes))-1 {
		return nil, refusal21(StateHistoryFoldMismatch, id, blk, "%s: the main-index chain does not end at the main chain's last entry", p.URL)
	}
	if blocks[len(blocks)-1] > blk {
		return nil, refusal21(StateBlockBeforeArrival, id, blk, "%s: a history entry was written in block %d, after the page's block", p.URL, blocks[len(blocks)-1])
	}

	genesis, err := govvote.GenesisPage(p.URL, txns[0])
	if err != nil {
		return nil, refusal21(StateHistoryUnreplayable, id, blk, "%s: genesis: %v", p.URL, err)
	}
	events := make([]govvote.Event, 0, len(txns)-1)
	for i := 1; i < len(txns); i++ {
		ev := govvote.Event{EntryHash: hex.EncodeToString(hashes[i]), LocalBlock: int64(blocks[i]), Txn: txns[i]}
		if _, isUpdateKey := txns[i].Body.(*protocol.UpdateKey); isUpdateKey {
			sig, err := decodeSig(h.Entries[i].Initiator)
			if err != nil {
				return nil, refusal21(StateHistoryUnreplayable, id, blk, "%s: history entry %d: its initiating signature: %v", p.URL, i, err)
			}
			if ev.Initiator, err = govvote.InitiatorOf(txns[i], sig); err != nil {
				return nil, refusal21(StateHistoryUnreplayable, id, blk, "%s: history entry %d: %v", p.URL, i, err)
			}
		}
		events = append(events, ev)
	}
	replayed, head, err := govvote.Replay(genesis, int64(blocks[0]), events)
	if err != nil {
		return nil, refusal21(StateHistoryUnreplayable, id, blk, "%s: %v", p.URL, err)
	}
	if d := AuthorityDiff(head, kp); d != "" {
		return nil, refusal21(StateHistoryHeadMismatch, id, blk, "%s: the replay ends in a page that differs from the proven one: %s", p.URL, d)
	}
	out := make(govvote.States, len(replayed))
	for i, r := range replayed {
		out[i] = r.State
	}
	return out, nil
}

// receiptFlags is the sequence of Right flags a receipt for the entry at position p of a chain of n entries has: the bits of the
// offset inside the entry's perfect subtree (Right when the entry is the left child), then one Right step for the combined smaller
// peaks (if any), then one non-Right step per larger peak (merkle.State.Anchor combines a larger peak on the left).
func receiptFlags(p, n uint64) []bool {
	var heights []uint
	for h := 63; h >= 0; h-- {
		if n>>uint(h)&1 == 1 {
			heights = append(heights, uint(h))
		}
	}
	start := uint64(0)
	for j, h := range heights {
		size := uint64(1) << h
		if p < start+size {
			off := p - start
			out := make([]bool, 0, int(h)+1+j)
			for i := uint(0); i < h; i++ {
				out = append(out, off>>i&1 == 0)
			}
			if j < len(heights)-1 {
				out = append(out, true)
			}
			for i := 0; i < j; i++ {
				out = append(out, false)
			}
			return out
		}
		start += size
	}
	return nil
}

// receiptPositions returns every position p < n whose receipt in a chain of n entries has r's shape. A receipt does not carry its
// entry's position in anything it hashes, but the shape (which side each sibling is on) fixes it given the chain's height; a result
// of more than one position, or none, means the position is not established. The Right flags are decoded directly (receiptFlags
// inverted): a receipt of the entry at offset off inside the perfect subtree of height h that is the j-th largest peak has h flags that
// are the bits of off (Right when the bit is 0), then one Right flag when a smaller peak exists, then j non-Right flags. At most 64
// peaks are tried, so the cost is O(log n) in the chain's height, not linear in it.
func receiptPositions(r *merkle.Receipt, n uint64) []uint64 {
	if n == 0 {
		return nil
	}
	f := make([]bool, len(r.Entries))
	for i, e := range r.Entries {
		f[i] = e.Right
	}
	var heights []uint
	for h := 63; h >= 0; h-- {
		if n>>uint(h)&1 == 1 {
			heights = append(heights, uint(h))
		}
	}
	var out []uint64
	start := uint64(0)
	for j, h := range heights {
		want := int(h) + j
		last := j == len(heights)-1
		if !last {
			want++
		}
		if len(f) == want {
			k := int(h)
			ok := true
			if !last {
				ok = f[k]
				k++
			}
			for i := 0; i < j && ok; i++ {
				ok = !f[k+i]
			}
			if ok {
				off := uint64(0)
				for i := 0; i < int(h); i++ {
					if !f[i] {
						off |= 1 << uint(i)
					}
				}
				out = append(out, start+off)
			}
		}
		start += uint64(1) << h
	}
	return out
}

func rootOf(c *proof.ChainRoot) ([]byte, error) {
	b, err := hex.DecodeString(c.Anchor)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("chain %s has no 32-byte root", c.Name)
	}
	return b, nil
}

// checkIndexProof requires an index entry to be a member of the bound index chain at the position its receipt allows.
func checkIndexProof(ip IndexProof, ir *proof.ChainRoot) (indexEntry, error) {
	e, raw, err := decodeIndexEntry(ip.Entry)
	if err != nil {
		return e, err
	}
	root, err := rootOf(ir)
	if err != nil {
		return e, err
	}
	r, err := decodeReceipt(ip.Receipt)
	if err != nil {
		return e, err
	}
	if !bytes.Equal(r.Start, raw) || !bytes.Equal(r.Anchor, root) || !r.Validate(nil) {
		return e, fmt.Errorf("the index entry %d is not a member of the %s chain bound at the block", ip.Position, ir.Name)
	}
	ps := receiptPositions(r, ir.Count)
	if len(ps) != 1 || ps[0] != ip.Position {
		return e, fmt.Errorf("the receipt of index entry %d allows positions %v in a chain of %d", ip.Position, ps, ir.Count)
	}
	return e, nil
}

// deriveArrival derives the block the entry msgHex (receipt rcptHex into the named chain) was written in, from the chain's index
// chain: the position of the entry is fixed by its receipt; the block is that of the index entry At, which must be the first whose
// Source reaches the position (Before, adjacent to it, must not).
func deriveArrival(pa *provenAcct, p *PageState, chain, msgHex, rcptHex string, a *Arrival) (uint64, error) {
	id, blk := pa.anchor.id, pa.anchor.block
	bad := func(format string, args ...any) error {
		return refusal21(StateArrivalUnproven, id, blk, "%s %s: %s", p.URL, chain, fmt.Sprintf(format, args...))
	}
	if !pa.chain.Bound {
		return 0, unboundRefusal(pa, p)
	}
	cr, ir := boundChain(p, chain), boundChain(p, chain+"-index")
	if cr == nil || ir == nil {
		return 0, bad("no %s or %s-index chain is bound at the block", chain, chain)
	}
	root, err := rootOf(cr)
	if err != nil {
		return 0, err
	}
	if !inChain(rcptHex, msgHex, root) {
		return 0, refusal21(StateBlockBeforeArrival, id, blk, "the entry is not a member of %s's %s chain at the block", p.URL, chain)
	}
	r, _ := decodeReceipt(rcptHex)
	ps := receiptPositions(r, cr.Count)
	if len(ps) != 1 {
		return 0, bad("the entry's receipt allows positions %v in a chain of %d: the position is not established", ps, cr.Count)
	}
	pos := ps[0]
	at, err := checkIndexProof(a.At, ir)
	if err != nil {
		return 0, bad("%v", err)
	}
	if at.source < pos || at.source >= cr.Count {
		return 0, bad("the index entry covers chain entries up to %d, which does not reach position %d of %d", at.source, pos, cr.Count)
	}
	if a.Before == nil {
		if a.At.Position != 0 {
			return 0, bad("no previous index entry is given but the entry is index entry %d", a.At.Position)
		}
	} else {
		before, err := checkIndexProof(*a.Before, ir)
		if err != nil {
			return 0, bad("%v", err)
		}
		if a.Before.Position+1 != a.At.Position {
			return 0, bad("index entries %d and %d are not adjacent", a.Before.Position, a.At.Position)
		}
		if before.source >= pos {
			return 0, bad("the previous index entry already covers position %d (up to %d): the entry arrived earlier", pos, before.source)
		}
		if before.block >= at.block || before.source >= at.source {
			return 0, bad("the index chain is not increasing between entries %d and %d", a.Before.Position, a.At.Position)
		}
	}
	if at.block > blk {
		return 0, refusal21(StateBlockBeforeArrival, id, blk, "%s: the entry arrived in block %d, after the page's block", p.URL, at.block)
	}
	return at.block, nil
}

func normURL(u *url.URL) string { return govvote.CanonicalAccSpelling(u.String()) }

func parseVote(s string) (protocol.VoteType, bool) {
	switch s {
	case "accept":
		return protocol.VoteTypeAccept, true
	case "reject":
		return protocol.VoteTypeReject, true
	case "abstain":
		return protocol.VoteTypeAbstain, true
	case "suggest":
		return protocol.VoteTypeSuggest, true
	}
	return 0, false
}

// unwrapSignature strips delegated-signature wrappers and returns the innermost signature and the delegators, outermost wrapper
// first (the order of govvote.SigFact.Path).
func unwrapSignature(sig protocol.Signature) (protocol.Signature, []string) {
	var path []string
	for {
		d, ok := sig.(*protocol.DelegatedSignature)
		if !ok {
			return sig, path
		}
		path = append(path, normURL(d.Delegator))
		sig = d.Signature
	}
}

// timelineIn is what the timeline needs from the rest of the 2.1 verification.
type timelineIn struct {
	ev     *Evidence
	rep    *Report
	x      xIn
	byURL  map[string]*provenAcct
	auths  []protocol.AuthorityEntry
	anchor map[string]*xAnchor
}

type states map[string]govvote.States

func (s states) Timeline(_ context.Context, page string) (govvote.Timeline, error) {
	st, ok := s[govvote.CanonicalAccSpelling(page)]
	if !ok {
		return nil, fmt.Errorf("the evidence carries no certified history for %s", page)
	}
	return st, nil
}

// foldTimelines replays every history the evidence carries (a carried history is always verified), and returns the states by page.
func foldTimelines(ev *Evidence, byURL map[string]*provenAcct) (states, error) {
	out := states{}
	for i := range ev.Pages {
		p := &ev.Pages[i]
		if p.History == nil {
			continue
		}
		u, err := url.Parse(p.URL)
		if err != nil {
			return nil, err
		}
		pa := byURL[lk(u)]
		st, err := replayHistory(pa, p)
		if err != nil {
			return nil, err
		}
		out[govvote.CanonicalAccSpelling(p.URL)] = st
	}
	return out, nil
}

// timelineEngaged says whether the evidence carries everything the vote re-evaluation needs: the transaction, a history for every
// page a counted signature was recorded on, and the arrival proof of every counted signature. When it does not, the votes are not
// re-evaluated and the report says so by name (the verifier does not guess a weaker answer).
func timelineEngaged(ev *Evidence, tl states) (bool, string) {
	if ev.Transaction == "" {
		return false, "the evidence carries no transaction, so the page blacklist and the required authorities are unknown"
	}
	if len(ev.Votes) == 0 {
		return false, "the evidence carries no vote"
	}
	for _, v := range ev.Votes {
		if len(v.Hops) == 0 {
			return false, fmt.Sprintf("the vote of %s carries no cause chain", v.Authority)
		}
		for _, h := range v.allHops() {
			if h.Arrival == nil {
				return false, fmt.Sprintf("the signature on %s carries no arrival proof", h.Page)
			}
			if _, ok := tl[govvote.CanonicalAccSpelling(h.Page)]; !ok {
				return false, fmt.Sprintf("%s carries no history", h.Page)
			}
		}
	}
	return true, ""
}

// evaluateTimeline is steps 4-5: arrival blocks derived, vote model run on the certified timeline, result compared with every
// recorded vote, readiness required.
func evaluateTimeline(in timelineIn, tl states) error {
	ev, rep := in.ev, in.rep
	txn, err := decodeTxn(ev.Transaction)
	if err != nil {
		return refusal21(StateTransactionMismatch, in.x.x.id, in.x.x.block, "%v", err)
	}
	txHash, _ := hex.DecodeString(ev.TxHash)
	if !bytes.Equal(txn.GetHash(), txHash) {
		return refusal21(StateTransactionMismatch, in.x.x.id, in.x.x.block, "the carried transaction hashes to %x, not the transaction %s", txn.GetHash()[:8], ev.TxHash[:16])
	}
	if !strings.EqualFold(txn.Header.Principal.String(), ev.Account) {
		return refusal21(StateTransactionMismatch, in.x.x.id, in.x.x.block, "the carried transaction acts on %v, not %s", txn.Header.Principal, ev.Account)
	}
	typ := txn.Body.Type()
	txid := txn.ID()

	facts := govvote.Facts{TxType: typ}
	if h := txn.Header.HoldUntil; h != nil && h.MinorBlock != 0 {
		facts.HoldUntil = h.MinorBlock
	}
	seen := map[string]bool{}
	for vi := range ev.Votes {
		v := &ev.Votes[vi]
		vt, ok := parseVote(v.Vote)
		if !ok {
			return fmt.Errorf("vote of %s: %q is not a vote", v.Authority, v.Vote)
		}
		for _, h := range v.allHops() {
			hp, err := url.Parse(h.Page)
			if err != nil {
				return err
			}
			pa := in.byURL[lk(hp)]
			p := &ev.Pages[pa.i]
			block, err := deriveArrival(pa, p, "signature", h.Message, h.Receipt, h.Arrival)
			if err != nil {
				return err
			}
			if block != h.Block {
				return refusal21(StateArrivalUnproven, pa.anchor.id, pa.anchor.block,
					"the signature on %s was claimed to arrive in block %d, its signature-index chain says %d", h.Page, h.Block, block)
			}
			sig, err := decodeSig(h.Signature)
			if err != nil {
				return refusal21(StateSignatureInvalid, pa.anchor.id, pa.anchor.block, "%s: %v", h.Page, err)
			}
			msgHash := (&messaging.SignatureMessage{Signature: sig, TxID: txid}).Hash()
			if hex.EncodeToString(msgHash[:]) != strings.ToLower(h.Message) {
				return refusal21(StateSignatureInvalid, pa.anchor.id, pa.anchor.block, "the signature on %s is not the message its chain entry holds", h.Page)
			}
			rep.Arrivals = append(rep.Arrivals, ArrivalReport{Kind: "signature", Account: h.Page, Partition: pa.anchor.source, Message: h.Message, Block: block})
			if seen[h.Message] {
				continue
			}
			seen[h.Message] = true
			if as, ok := sig.(*protocol.AuthoritySignature); ok {
				if len(as.Delegator) == 0 || normURL(as.Delegator[0]) != govvote.CanonicalAccSpelling(h.Page) {
					return refusal21(StateSignatureInvalid, pa.anchor.id, pa.anchor.block, "the delegated vote recorded on %s does not name it as its first delegator", h.Page)
				}
				beyond := as.Delegator[1:]
				path := make([]string, len(beyond))
				for i := range beyond {
					path[i] = normURL(beyond[len(beyond)-1-i])
				}
				facts.Arrivals = append(facts.Arrivals, govvote.ArrivalFact{ID: h.Message, Page: govvote.CanonicalAccSpelling(h.Page),
					Authority: normURL(as.Authority), Path: path, Block: int64(block), Origin: normURL(as.Origin), Vote: as.Vote})
				continue
			}
			vs, verr := verifyKeySignature(sig, txn, in.x.network, pa, h.Page, block)
			if verr != nil {
				return verr
			}
			ks := vs.Inner
			if normURL(ks.GetSigner()) != govvote.CanonicalAccSpelling(h.Page) {
				return refusal21(StateSignatureInvalid, pa.anchor.id, pa.anchor.block, "the signature on %s is by %v", h.Page, ks.GetSigner())
			}
			_, path := unwrapSignature(sig)
			facts.Sigs = append(facts.Sigs, govvote.SigFact{ID: h.Message, Signer: govvote.CanonicalAccSpelling(h.Page), Path: path,
				Version: ks.GetSignerVersion(), KeyHash: hex.EncodeToString(vs.KeyHash), Vote: sig.GetVote(), Block: int64(block),
				Partition: strings.ToLower(pa.anchor.id)})
		}
		facts.Votes = append(facts.Votes, govvote.RecordedVote{ID: v.Message, Authority: govvote.CanonicalAccSpelling(v.Authority),
			Origin: govvote.CanonicalAccSpelling(v.Origin), Vote: vt, ReleasedAt: releasedAt(in, txn, v)})
	}

	// The authorities the transaction requires (design D1, D3): the principal's enabled authorities (the disabled too when the type
	// requires authorization), plus the header's and the body's.
	require := typ.RequireAuthorization()
	allDisabled := true
	listed := map[string]bool{}
	var auths []govvote.AccountAuthority
	for _, a := range in.auths {
		listed[lk(a.Url)] = true
		if !a.Disabled || require {
			allDisabled = false
			auths = append(auths, govvote.AccountAuthority{URL: normURL(a.Url)})
		}
	}
	allDisabled = allDisabled && !require
	mode := ModeAuthoritiesRequired
	if allDisabled {
		mode = ModeAllAuthoritiesDisabled
	}
	rep.AuthorizationMode = mode
	extra := map[string]bool{}
	var extras []string
	addExtra := func(u *url.URL) error {
		if extra[lk(u)] {
			return nil
		}
		extra[lk(u)] = true
		if _, ok := in.byURL[lk(u)]; !ok {
			return refusal21(StateHeaderAuthorityMissing, in.x.x.id, in.x.x.block, "the transaction requires the authority %v, which has no proven pages", u)
		}
		extras = append(extras, normURL(u))
		return nil
	}
	for _, a := range txn.Header.Authorities {
		if err := addExtra(a); err != nil {
			return err
		}
	}
	for _, a := range txn.GetAdditionalAuthorities() {
		if err := addExtra(a); err != nil {
			return err
		}
	}
	// Every recorded vote is reproduced, whether or not its authority is required: evaluate the voters too.
	evalAuths := append([]govvote.AccountAuthority{}, auths...)
	have := map[string]bool{}
	for _, a := range evalAuths {
		have[a.URL] = true
	}
	for _, e := range extras {
		have[e] = true
	}
	for _, v := range facts.Votes {
		if !have[v.Authority] {
			have[v.Authority] = true
			evalAuths = append(evalAuths, govvote.AccountAuthority{URL: v.Authority})
		}
	}
	res, err := govvote.Evaluate(context.Background(), facts, tl, ev.Account, evalAuths, extras, false)
	if err != nil {
		var vu *govvote.VoteUnevaluable
		if errors.As(err, &vu) {
			return refusal21(StateVoteNotReproduced, in.x.x.id, in.x.x.block, "%v", vu)
		}
		return fmt.Errorf("the vote model: %w", err)
	}
	byAuth := map[string]govvote.BookVote{}
	for _, a := range res.Authorities {
		byAuth[a.Authority] = a.Vote
	}
	for _, v := range facts.Votes {
		bv, ok := byAuth[v.Authority]
		if !ok || !bv.Voted || bv.By != v.Origin || voteNameOf(bv.Vote) != voteNameOf(v.Vote.String()) {
			got := "no vote"
			if ok && bv.Voted {
				got = fmt.Sprintf("%s by %s", bv.Vote, bv.By)
			}
			return refusal21(StateVoteNotReproduced, in.x.x.id, in.x.x.block,
				"the recorded vote of %s (%s by %s) is not reproduced on the certified timeline: %s", v.Authority, v.Vote, v.Origin, got)
		}
		if !listed[strings.ToLower(strings.TrimSuffix(v.Authority, "/"))] && !extra[strings.ToLower(v.Authority)] {
			if !allDisabled {
				return refusal21(StateVoteNotReproduced, in.x.x.id, in.x.x.block, "the recorded vote of %s is by an authority outside the principal's set while other authorities are enabled", v.Authority)
			}
			rep.Disclosures = append(rep.Disclosures, NamedState{Code: StateAuthorityVoterOutsideList, Partition: in.x.x.id, Block: in.x.x.block,
				Detail: fmt.Sprintf("%s voted although every listed authority is disabled; the executor accepts any authority's vote then (sig_common.go:367-369)", v.Authority)})
		}
	}
	// Readiness (transaction.go:194-218): each required authority voted accept; with every authority disabled the executor needs
	// one recorded vote and nothing more.
	for _, a := range auths {
		if bv, ok := byAuth[a.URL]; !ok || !bv.Voted || bv.Vote != protocol.VoteTypeAccept.String() {
			return refusal21(StateAuthorityNotReady, in.x.x.id, in.x.x.block, "the authority %s did not vote accept on the certified timeline", a.URL)
		}
	}
	for _, e := range extras {
		if bv, ok := byAuth[e]; !ok || !bv.Voted || bv.Vote != protocol.VoteTypeAccept.String() {
			return refusal21(StateAuthorityNotReady, in.x.x.id, in.x.x.block, "the authority %s the transaction names did not vote accept on the certified timeline", e)
		}
	}
	if allDisabled && len(facts.Votes) == 0 {
		return refusal21(StateAuthorityNotReady, in.x.x.id, in.x.x.block, "every authority is disabled and no authority voted")
	}
	return nil
}

func voteNameOf(s string) string { return strings.ToLower(s) }

// verifyProductions establishes, for each vote, the block that produced it (design D3, D6): the SequencedMessage's entry in the
// source partition's synthetic ledger main chain (a sequenced vote), or the vote's own entry in the principal's signature chain (an
// inline one). A vote with no production proof is the named state g1_vote_held: a HoldUntil release may have produced it in a block
// the evidence does not establish.
func verifyProductions(in timelineIn) error {
	ev, rep := in.ev, in.rep
	held := false
	if txn, err := carriedTransaction(ev, in.x.x); err == nil && txn != nil {
		held = txn.Header.HoldUntil != nil && txn.Header.HoldUntil.MinorBlock != 0
	}
	for vi := range ev.Votes {
		v := &ev.Votes[vi]
		srcID, srcBlock := in.x.x.id, in.x.x.block
		if v.Transport.Kind == TransportSequenced {
			if a, ok := in.anchor[strings.ToLower(v.Transport.Source)]; ok {
				srcID, srcBlock = a.id, a.block
			}
		}
		if v.Produced == nil {
			// The production is needed to place a vote only when the transaction is held (a HoldUntil release produces the vote in a later block
			// than its signature arrived in). A sequenced vote without a production keeps the name the shipped vectors pin whether or not the
			// transaction is held; an inline vote on a transaction that is not held needs no production to be placed (verifier round VA, (d)).
			if held || v.Transport.Kind == TransportSequenced {
				rep.Unproven = append(rep.Unproven, NamedState{Code: StateVoteHeld, Partition: srcID, Block: srcBlock,
					Detail: fmt.Sprintf("the block that produced the vote of %s is not established (a HoldUntil release may have produced it later than its signature arrived)", v.Authority)})
			}
			continue
		}
		pr := v.Produced
		au, err := url.Parse(pr.Account)
		if err != nil {
			return err
		}
		pa, ok := in.byURL[lk(au)]
		if !ok {
			return refusal21(StateCompletenessUnproven, srcID, srcBlock, "%s records the production of the vote of %s but is not among the proven pages", pr.Account, v.Authority)
		}
		switch v.Transport.Kind {
		case TransportInline:
			if !strings.EqualFold(pr.Account, ev.Account) || pr.Chain != "signature" || !strings.EqualFold(pr.Message, v.Message) {
				return refusal21(StateArrivalUnproven, srcID, srcBlock, "an inline vote is produced where the principal's signature chain records it")
			}
		case TransportSequenced:
			src, ok := in.anchor[strings.ToLower(v.Transport.Source)]
			if !ok {
				return refusal21(StatePartitionAnchorUnavailable, v.Transport.Source, 0, "no anchor for the partition that produced the vote")
			}
			want := protocol.PartitionUrl(src.id).JoinPath(protocol.Synthetic)
			if !strings.EqualFold(pr.Account, want.String()) || pr.Chain != "main" {
				return refusal21(StateArrivalUnproven, src.id, src.block, "a sequenced vote is produced in %v's main chain, not %s %s", want, pr.Account, pr.Chain)
			}
			if _, isLedger := pa.acct.(*protocol.SyntheticLedger); !isLedger {
				return refusal21(StateArrivalUnproven, src.id, src.block, "%s is %T, not a synthetic ledger", pr.Account, pa.acct)
			}
			if pr.Sequenced == "" {
				rep.Disclosures = append(rep.Disclosures, NamedState{Code: StateVoteProductionUnbound, Partition: src.id, Block: src.block,
					Detail: fmt.Sprintf("the production of the vote of %s names the synthetic ledger entry that holds it but the document does not carry the SequencedMessage that entry is the hash of: nothing ties the entry to the vote", v.Authority)})
			} else if err := bindSequenced(pr, v, src); err != nil {
				return err
			}
		}
		block, err := deriveArrival(pa, &ev.Pages[pa.i], pr.Chain, pr.Message, pr.Receipt, &pr.Arrival)
		if err != nil {
			return err
		}
		// A vote is produced after the signature that caused it arrived (the last hop is the vote's cause).
		for _, h := range v.Hops[:min(1, len(v.Hops))] {
			hp, _ := url.Parse(h.Page)
			hpa := in.byURL[lk(hp)]
			if hpa.anchor.id == pa.anchor.id && block < h.Block {
				return refusal21(StateBlockBeforeArrival, pa.anchor.id, pa.anchor.block, "the vote of %s was produced in block %d, before the signature that caused it arrived in block %d", v.Authority, block, h.Block)
			}
		}
		rep.Arrivals = append(rep.Arrivals, ArrivalReport{Kind: "produced", Account: pr.Account, Partition: pa.anchor.source, Message: pr.Message, Block: block})
	}
	return nil
}

// bindSequenced requires a sequenced vote's production to be the vote (RB9 verifier round VA, DEF-4): the carried SequencedMessage hashes
// to the synthetic ledger entry the production proves, wraps the SignatureMessage whose hash is the vote's Message (the entry of the
// principal's signature chain), and names the vote's transport (source, destination, number).
func bindSequenced(pr *Production, v *Vote, src *xAnchor) error {
	bad := func(format string, a ...any) error {
		return refusal21(StateArrivalUnproven, src.id, src.block, format, a...)
	}
	raw, err := hex.DecodeString(pr.Sequenced)
	if err != nil {
		return bad("the production of the vote of %s: the sequenced message is not hex", v.Authority)
	}
	seq := new(messaging.SequencedMessage)
	if err := seq.UnmarshalBinary(raw); err != nil {
		return bad("the production of the vote of %s: the sequenced message does not decode: %v", v.Authority, err)
	}
	if h := seq.Hash(); hex.EncodeToString(h[:]) != strings.ToLower(pr.Message) {
		return bad("the production of the vote of %s: the sequenced message hashes to %x, not to the synthetic ledger entry %s", v.Authority, h[:8], pr.Message)
	}
	sm, ok := seq.Message.(*messaging.SignatureMessage)
	if !ok {
		return bad("the production of the vote of %s: the sequenced message wraps a %T, not a signature message", v.Authority, seq.Message)
	}
	if h := sm.Hash(); hex.EncodeToString(h[:]) != strings.ToLower(v.Message) {
		return bad("the production of the vote of %s: the sequenced message wraps the signature message %x, not the vote %s", v.Authority, h[:8], v.Message)
	}
	if seq.Source == nil || seq.Destination == nil || !strings.EqualFold(seq.Source.String(), v.Transport.Source) ||
		!strings.EqualFold(seq.Destination.String(), v.Transport.Destination) || seq.Number != v.Transport.Number {
		return bad("the production of the vote of %s: the sequenced message is %v -> %v #%d, the vote's transport is %s -> %s #%d", v.Authority,
			seq.Source, seq.Destination, seq.Number, v.Transport.Source, v.Transport.Destination, v.Transport.Number)
	}
	return nil
}

// allHops are the signatures a vote's pages counted: the cause chain, then the other counted signatures.
func (v Vote) allHops() []VoteHop {
	return append(append([]VoteHop{}, v.Hops...), v.Counted...)
}

// releasedAt is the block that produced a held transaction's vote (the release), derived from the vote's production proof, or 0 when the
// transaction is not held or the evidence does not establish it (the vote is then judged as an unheld one, and verifyProductions reports
// or refuses the production by name).
func releasedAt(in timelineIn, txn *protocol.Transaction, v *Vote) int64 {
	if h := txn.Header.HoldUntil; h == nil || h.MinorBlock == 0 || v.Produced == nil {
		return 0
	}
	pr := v.Produced
	au, err := url.Parse(pr.Account)
	if err != nil {
		return 0
	}
	pa, ok := in.byURL[lk(au)]
	if !ok {
		return 0
	}
	block, err := deriveArrival(pa, &in.ev.Pages[pa.i], pr.Chain, pr.Message, pr.Receipt, &pr.Arrival)
	if err != nil {
		return 0
	}
	return int64(block)
}
