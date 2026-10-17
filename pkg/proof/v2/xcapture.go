// Copyright 2026 Certen Protocol
//
// Capturing pages on partitions other than the transaction's (docs/proof/G1_CROSS_PARTITION.md D2, D6; research R9).
//
// A key book on another identity can live on another partition Y, whose block numbering and state root are not the
// transaction's partition X's. Each Y page is read as of ONE Y block B_Y: the latest Y block whose BlockValidatorAnchor the
// Directory executed at or before the Directory block that executed X's anchor for the transaction's block. X can count a
// vote from Y only after the Directory anchored the Y block that produced it, so B_Y is at or after every counted
// signature's arrival block on Y (R9 §4.1). The page's receipt must pass through the StateTreeAnchor of Y's own anchor for
// B_Y, and that anchor is proven into the same certified Directory root as the transaction by AnchorAt.
//
// Nothing here falls back: a block the partition no longer serves, has not yet made servable, or an anchor the Directory has
// not executed is a *NamedState carrying the partition and block it was judged at, never a read of current state.

package proofv2

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	acerrors "gitlab.com/accumulatenetwork/accumulate/pkg/errors"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Retention reports the range of blocks a partition advertises it can still serve account state for.
type Retention interface {
	Retained(ctx context.Context, partition string) (earliest, latest uint64, err error)
}

// ClientRetention reads a partition's advertised retained range from the node behind c (consensus-status.retainedBlocks).
type ClientRetention struct {
	C    *jsonrpc.Client
	mu   sync.Mutex
	node string
}

// Retained implements Retention.
func (r *ClientRetention) Retained(ctx context.Context, partition string) (uint64, uint64, error) {
	st, err := r.status(ctx, partition)
	if err != nil {
		return 0, 0, err
	}
	if st.RetainedBlocks == nil {
		return 0, 0, fmt.Errorf("%s advertises no retained blocks", partition)
	}
	return st.RetainedBlocks.Earliest, st.RetainedBlocks.Latest, nil
}

// Head is the partition's newest committed block as the node reports it.
func (r *ClientRetention) Head(ctx context.Context, partition string) (uint64, error) {
	st, err := r.status(ctx, partition)
	if err != nil {
		return 0, err
	}
	if st.LastBlock == nil {
		return 0, fmt.Errorf("%s reports no last block", partition)
	}
	return uint64(st.LastBlock.Height), nil
}

func (r *ClientRetention) status(ctx context.Context, partition string) (*api.ConsensusStatus, error) {
	r.mu.Lock()
	node := r.node
	r.mu.Unlock()
	if node == "" {
		ni, err := r.C.NodeInfo(ctx, api.NodeInfoOptions{})
		if err != nil {
			return nil, fmt.Errorf("node info: %w", err)
		}
		node = ni.PeerID.String()
		r.mu.Lock()
		r.node = node
		r.mu.Unlock()
	}
	no := false
	st, err := r.C.ConsensusStatus(ctx, api.ConsensusStatusOptions{NodeID: node, Partition: partition, IncludePeers: &no})
	if err != nil {
		return nil, fmt.Errorf("consensus status of %s: %w", partition, err)
	}
	return st, nil
}

type histKind int

const (
	histOther histKind = iota
	histNotReady
	histIncomplete
)

var retainedRange = regexp.MustCompile(`retained range is \[(\d+), (\d+)\]`)

// classifyHistorical says whether err is the executor's refusal to serve a block: notReady (beyond the latest indexed block,
// "not yet") or incompleteChain (below the retained range, or the newest state-changing block whose root is not yet
// recorded). Both are matched by status and by their text, because a JSON-RPC hop can reduce a status to its message.
func classifyHistorical(err error) histKind {
	if err == nil {
		return histOther
	}
	if acerrors.Is(err, acerrors.NotReady) {
		return histNotReady
	}
	if acerrors.Is(err, acerrors.IncompleteChain) {
		return histIncomplete
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "notReady") || strings.Contains(msg, "beyond this node's latest indexed block"):
		return histNotReady
	case strings.Contains(msg, "incompleteChain") || strings.Contains(msg, "no BPT history retained") || strings.Contains(msg, "precedes this node's earliest indexed block"):
		return histIncomplete
	}
	return histOther
}

// PageReader reads accounts as of a block on the partition that holds them, and waits, within the partition's retention
// horizon, for the partition to make the block servable.
type PageReader struct {
	Net       api.Querier
	Q         proof.AccumulateQuerier
	Retention Retention     // optional: the advertised range, which sets the wait and names a block below it
	Poll      time.Duration // between attempts; default 2s
	Budget    time.Duration // how long to wait for a block to become servable; default the advertised span, else 5 minutes

	// Read replaces the page read (tests); the default is the capture CapturePage performs.
	Read func(ctx context.Context, account string, block uint64) (*PageState, error)
}

func (r *PageReader) read(ctx context.Context, account string, block uint64) (*PageState, error) {
	if r.Read != nil {
		return r.Read(ctx, account, block)
	}
	return capturePageWith(ctx, r.Net, r.Q, account, block)
}

// PageAt reads account as of partition's block. The newest state-changing block of a partition is not servable until the
// partition commits another (median 1-2 blocks, up to the longest lull); until then the read is retried. A block below the
// partition's retained range, or one the horizon passes before it is servable, is a named state.
func (r *PageReader) PageAt(ctx context.Context, account, partition string, block uint64) (*PageState, error) {
	budget := r.Budget
	if budget == 0 {
		budget = 5 * time.Minute
		if r.Retention != nil {
			if e, l, err := r.Retention.Retained(ctx, partition); err == nil && l > e {
				// A block stays servable for about the advertised span (one second a height); waiting longer than that for
				// the partition to commit again cannot succeed.
				budget = time.Duration(l-e)*time.Second + 30*time.Second
			}
		}
	}
	poll := r.Poll
	if poll == 0 {
		poll = 2 * time.Second
	}
	rctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for {
		p, err := r.read(rctx, account, block)
		if err == nil {
			return p, nil
		}
		kind := classifyHistorical(err)
		if kind == histOther {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("%s as of %s block %d: %w", account, partition, block, err)
		}
		earliest, latest, known := r.retainedRange(rctx, partition, err)
		if kind == histIncomplete && known && block < earliest {
			return nil, &NamedState{Code: StateHistoricalUnavailable, Partition: partition, Block: block,
				Detail: fmt.Sprintf("%s is below the retained range [%d, %d]: %v", account, earliest, latest, err)}
		}
		if rctx.Err() != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if kind == histIncomplete && !known {
				return nil, &NamedState{Code: StateHistoricalUnavailable, Partition: partition, Block: block,
					Detail: fmt.Sprintf("%s was never served within the %s horizon: %v", account, budget, err)}
			}
			return nil, &NamedState{Code: StateNotReady, Partition: partition, Block: block,
				Detail: fmt.Sprintf("%s: the partition committed no later state-changing block within the %s horizon: %v", account, budget, err)}
		}
		select {
		case <-rctx.Done():
		case <-time.After(poll):
		}
	}
}

// retainedRange returns the partition's retained range from its advertisement, or from the refusal's own text.
func (r *PageReader) retainedRange(ctx context.Context, partition string, err error) (earliest, latest uint64, known bool) {
	if m := retainedRange.FindStringSubmatch(err.Error()); m != nil {
		e, _ := strconv.ParseUint(m[1], 10, 64)
		l, _ := strconv.ParseUint(m[2], 10, 64)
		return e, l, true
	}
	if r.Retention != nil {
		if e, l, rerr := r.Retention.Retained(ctx, partition); rerr == nil {
			return e, l, true
		}
	}
	return 0, 0, false
}

// PartitionBlock is the block B_Y a partition's pages are read at, with the anchor the Directory executed for it.
type PartitionBlock struct {
	Partition string // the partition ID as the routing table spells it ("BVN2")
	Block     uint64 // B_Y
	Index     uint64 // the anchor's position in the Directory's anchor(<partition>)-root chain, which is the partition's anchor sequence
	Latest    uint64 // the position of the latest anchor the Directory executed at or before the limit: the last admissible one
	DNBlock   uint64 // the Directory block that executed the anchor
	Txn       *protocol.Transaction
	Anchor    *protocol.BlockValidatorAnchor
}

// AnchorLog is the Directory's record of one partition's anchors.
type AnchorLog interface {
	// Len is the number of anchors the Directory holds from the partition.
	Len(ctx context.Context, partition string) (uint64, error)
	// DNBlock is the Directory block that executed anchor i.
	DNBlock(ctx context.Context, partition string, i uint64) (uint64, error)
	// Block is the partition block anchor i is for (its MinorBlockIndex); it grows with i.
	Block(ctx context.Context, partition string, i uint64) (uint64, error)
	// Produced is anchor i as the partition produced it, checked against the Directory's copy of its roots.
	Produced(ctx context.Context, partition string, i uint64) (*protocol.Transaction, error)
}

// SelectPartitionBlock chooses B_Y for a partition (design D2). The admissible blocks are those whose anchor the Directory
// executed at or before dnLimit - the Directory block that executed the transaction's partition's anchor - and, since a
// partition's pages must not predate any signature counted on it, at or after bound (the latest arrival block of a counted
// signature on the partition; 0 when none). B_Y is the smallest admissible block; with no bound it is the latest. A bound
// beyond the latest admissible block cannot be satisfied and is named: it means the Directory had not anchored a block the
// signature arrived in when it executed the transaction's own anchor, which an honest network never does.
func SelectPartitionBlock(ctx context.Context, log AnchorLog, partition string, dnLimit, bound uint64) (*PartitionBlock, error) {
	n, err := log.Len(ctx, partition)
	if err != nil {
		return nil, fmt.Errorf("anchors of %s: %w", partition, err)
	}
	unavailable := func(detail string) error {
		return &NamedState{Code: StatePartitionAnchorUnavailable, Partition: partition, Detail: detail}
	}
	if n == 0 {
		return nil, unavailable("the Directory holds no anchor from the partition")
	}
	first, err := log.DNBlock(ctx, partition, 0)
	if err != nil {
		return nil, err
	}
	if first > dnLimit {
		return nil, unavailable(fmt.Sprintf("the first anchor was executed at DN %d, after DN %d", first, dnLimit))
	}
	// hi: the last anchor executed at or before dnLimit (the Directory block never decreases with the sequence).
	lo, hi := uint64(0), n-1 // invariant: DNBlock(lo) <= dnLimit
	for lo < hi {
		mid := lo + (hi-lo+1)/2
		b, err := log.DNBlock(ctx, partition, mid)
		if err != nil {
			return nil, err
		}
		if b <= dnLimit {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	latest := lo
	pick := latest
	if bound > 0 {
		top, err := log.Block(ctx, partition, latest)
		if err != nil {
			return nil, err
		}
		if top < bound {
			return nil, &NamedState{Code: StateBlockBeforeArrival, Partition: partition, Block: top,
				Detail: fmt.Sprintf("the latest block the Directory had anchored by DN %d is %d, before the block %d a counted signature arrived in", dnLimit, top, bound)}
		}
		// The smallest anchor whose block is at or after bound.
		l, h := uint64(0), latest
		for l < h {
			mid := l + (h-l)/2
			bl, err := log.Block(ctx, partition, mid)
			if err != nil {
				return nil, err
			}
			if bl >= bound {
				h = mid
			} else {
				l = mid + 1
			}
		}
		pick = l
	}
	return partitionBlockAt(ctx, log, partition, pick, latest)
}

func partitionBlockAt(ctx context.Context, log AnchorLog, partition string, i, latest uint64) (*PartitionBlock, error) {
	dn, err := log.DNBlock(ctx, partition, i)
	if err != nil {
		return nil, err
	}
	txn, err := log.Produced(ctx, partition, i)
	if err != nil {
		return nil, err
	}
	body, ok := txn.Body.(*protocol.BlockValidatorAnchor)
	if !ok {
		return nil, fmt.Errorf("anchor %d of %s is %v, not a block validator anchor", i, partition, txn.Body.Type())
	}
	if body.Source == nil || !strings.EqualFold(body.Source.String(), protocol.PartitionUrl(partition).String()) {
		return nil, fmt.Errorf("anchor %d of %s names the source %v", i, partition, body.Source)
	}
	return &PartitionBlock{Partition: partition, Block: body.MinorBlockIndex, Index: i, Latest: latest, DNBlock: dn, Txn: txn, Anchor: body}, nil
}

// NextPartitionBlock is the admissible anchor after pb, for when pb's block has left the partition's retention before it was
// read: the smallest servable block. It is a named state when pb was the last admissible one.
func NextPartitionBlock(ctx context.Context, log AnchorLog, pb *PartitionBlock) (*PartitionBlock, error) {
	if pb.Index >= pb.Latest {
		return nil, &NamedState{Code: StateHistoricalUnavailable, Partition: pb.Partition, Block: pb.Block,
			Detail: "no later anchor the Directory executed by the transaction's own is admissible"}
	}
	return partitionBlockAt(ctx, log, pb.Partition, pb.Index+1, pb.Latest)
}

// NetLog reads the Directory's anchor chains and the partitions' anchor sequences through a v3 querier.
type NetLog struct{ Net api.Querier }

func rootChain(partition string) string { return "anchor(" + strings.ToLower(partition) + ")-root" }
func bptChain(partition string) string  { return "anchor(" + strings.ToLower(partition) + ")-bpt" }

func dnPool() *url.URL { return protocol.DnUrl().JoinPath(protocol.AnchorPool) }

// Len implements AnchorLog.
func (l NetLog) Len(ctx context.Context, partition string) (uint64, error) {
	r, err := l.Net.Query(ctx, dnPool(), &api.ChainQuery{Name: rootChain(partition)})
	if err != nil {
		return 0, err
	}
	cr, ok := r.(*api.ChainRecord)
	if !ok {
		return 0, fmt.Errorf("%s: got %T, not a chain", rootChain(partition), r)
	}
	return cr.Count, nil
}

func (l NetLog) entry(ctx context.Context, scope *url.URL, chain string, i uint64, receipt bool) (*api.ChainEntryRecord[api.Record], error) {
	q := &api.ChainQuery{Name: chain, Index: &i}
	if receipt {
		q.IncludeReceipt = &api.ReceiptOptions{ForAny: true}
	}
	r, err := l.Net.Query(ctx, scope, q)
	if err != nil {
		return nil, fmt.Errorf("%v %s[%d]: %w", scope, chain, i, err)
	}
	ce, ok := r.(*api.ChainEntryRecord[api.Record])
	if !ok || ce.Index != i {
		return nil, fmt.Errorf("%v %s[%d]: got %T", scope, chain, i, r)
	}
	return ce, nil
}

// DNBlock implements AnchorLog.
func (l NetLog) DNBlock(ctx context.Context, partition string, i uint64) (uint64, error) {
	ce, err := l.entry(ctx, dnPool(), rootChain(partition), i, true)
	if err != nil {
		return 0, err
	}
	if ce.Receipt == nil || ce.Receipt.LocalBlock == 0 {
		return 0, fmt.Errorf("%s[%d] carries no receipt naming the Directory block", rootChain(partition), i)
	}
	return ce.Receipt.LocalBlock, nil
}

// Block implements AnchorLog: the block anchor i of the partition is for, from the partition's own anchor sequence.
func (l NetLog) Block(ctx context.Context, partition string, i uint64) (uint64, error) {
	src := protocol.PartitionUrl(partition).JoinPath(protocol.AnchorPool)
	ce, err := l.entry(ctx, src, "anchor-sequence", i, false)
	if err != nil {
		return 0, err
	}
	mr, ok := ce.Value.(*api.MessageRecord[messaging.Message])
	if !ok {
		return 0, fmt.Errorf("%v anchor-sequence[%d]: got %T, not a message", src, i, ce.Value)
	}
	tm, ok := mr.Message.(*messaging.TransactionMessage)
	if !ok || tm.Transaction == nil {
		return 0, fmt.Errorf("%v anchor-sequence[%d]: not a transaction", src, i)
	}
	body, ok := tm.Transaction.Body.(*protocol.BlockValidatorAnchor)
	if !ok {
		return 0, fmt.Errorf("%v anchor-sequence[%d] is %v, not a block validator anchor", src, i, tm.Transaction.Body.Type())
	}
	return body.MinorBlockIndex, nil
}

// Produced implements AnchorLog: the anchor as the partition's anchor-sequence chain holds it, required to carry exactly the
// root chain and state tree anchors the Directory's anchor(<partition>)-root and -bpt chains hold at the same position.
func (l NetLog) Produced(ctx context.Context, partition string, i uint64) (*protocol.Transaction, error) {
	src := protocol.PartitionUrl(partition).JoinPath(protocol.AnchorPool)
	ce, err := l.entry(ctx, src, "anchor-sequence", i, false)
	if err != nil {
		return nil, err
	}
	mr, ok := ce.Value.(*api.MessageRecord[messaging.Message])
	if !ok {
		return nil, fmt.Errorf("%v anchor-sequence[%d]: got %T, not a message", src, i, ce.Value)
	}
	tm, ok := mr.Message.(*messaging.TransactionMessage)
	if !ok || tm.Transaction == nil {
		return nil, fmt.Errorf("%v anchor-sequence[%d]: not a transaction", src, i)
	}
	body, ok := tm.Transaction.Body.(*protocol.BlockValidatorAnchor)
	if !ok {
		return nil, fmt.Errorf("%v anchor-sequence[%d] is %v, not a block validator anchor", src, i, tm.Transaction.Body.Type())
	}
	root, err := l.entry(ctx, dnPool(), rootChain(partition), i, false)
	if err != nil {
		return nil, err
	}
	state, err := l.entry(ctx, dnPool(), bptChain(partition), i, false)
	if err != nil {
		return nil, err
	}
	if root.Entry != body.RootChainAnchor || state.Entry != body.StateTreeAnchor {
		return nil, fmt.Errorf("%v anchor-sequence[%d] carries roots (%x, %x), the Directory holds (%x, %x) at that position",
			src, i, body.RootChainAnchor, body.StateTreeAnchor, root.Entry, state.Entry)
	}
	return tm.Transaction, nil
}

// AnchorAt returns the partition's anchor for pb as the Directory executed it, and a receipt from the anchor transaction to
// the Directory root chain at the given height (0: whichever root the node anchors it under). With the height of the root
// the transaction is certified under, this is the evidence that proves pb's StateTreeAnchor into the same certified root.
func AnchorAt(ctx context.Context, net api.Querier, pb *PartitionBlock, height uint64) (PartitionAnchor, [32]byte, error) {
	var none [32]byte
	unavailable := func(format string, a ...any) error {
		return &NamedState{Code: StatePartitionAnchorUnavailable, Partition: pb.Partition, Block: pb.Block, Detail: fmt.Sprintf(format, a...)}
	}
	pool := dnPool()
	// The delivered transaction differs from the produced one only in its principal, and its hash covers the principal's URL as
	// the network stores it, case included.
	r, err := net.Query(ctx, pool, &api.DefaultQuery{})
	if err != nil {
		return PartitionAnchor{}, none, fmt.Errorf("anchor pool %v: %w", pool, err)
	}
	ar, ok := r.(*api.AccountRecord)
	if !ok || ar.Account == nil || !ar.Account.GetUrl().Equal(pool) {
		return PartitionAnchor{}, none, fmt.Errorf("anchor pool %v: got %T", pool, r)
	}
	delivered := pb.Txn.Copy()
	delivered.Header.Principal = ar.Account.GetUrl()
	h := delivered.Hash()

	qr, err := net.Query(ctx, pool, &api.ChainQuery{Name: "main", Entry: h[:], IncludeReceipt: &api.ReceiptOptions{ForAny: true}})
	if err != nil {
		if acerrors.Is(err, acerrors.NotFound) {
			return PartitionAnchor{}, none, unavailable("the Directory has not executed the anchor (%x): %v", h[:8], err)
		}
		return PartitionAnchor{}, none, fmt.Errorf("anchor %x on %v: %w", h[:8], pool, err)
	}
	ce, err := onlyChainEntry(qr, "main", h[:])
	if err != nil {
		return PartitionAnchor{}, none, unavailable("%v", err)
	}
	mr, ok := ce.Value.(*api.MessageRecord[messaging.Message])
	if !ok || mr.Sequence == nil {
		return PartitionAnchor{}, none, unavailable("the Directory's entry is not a delivered, sequenced anchor (%T)", ce.Value)
	}
	if mr.Status != acerrors.Delivered {
		return PartitionAnchor{}, none, unavailable("the anchor's status is %v, not delivered", mr.Status)
	}
	tm, ok := mr.Message.(*messaging.TransactionMessage)
	if !ok {
		return PartitionAnchor{}, none, fmt.Errorf("delivered anchor is %T, not a transaction", mr.Message)
	}
	seq := &messaging.SequencedMessage{
		Message: &messaging.TransactionMessage{Transaction: tm.Transaction},
		Source:  mr.Sequence.Source, Destination: mr.Sequence.Destination, Number: mr.Sequence.Number}
	if seq.Source == nil || !seq.Source.Equal(protocol.PartitionUrl(pb.Partition)) {
		return PartitionAnchor{}, none, &NamedState{Code: StateForeignPartitionMismatch, Partition: pb.Partition, Block: pb.Block,
			Detail: fmt.Sprintf("the anchor the Directory executed is from %v", seq.Source)}
	}
	got, ok := tm.Transaction.Body.(*protocol.BlockValidatorAnchor)
	if !ok || got.MinorBlockIndex != pb.Block || got.StateTreeAnchor != pb.Anchor.StateTreeAnchor || got.RootChainAnchor != pb.Anchor.RootChainAnchor {
		return PartitionAnchor{}, none, fmt.Errorf("the Directory executed a different anchor than block %d of %s", pb.Block, pb.Partition)
	}
	rec := ce.Receipt
	if height > 0 {
		idx := ce.Index
		hr, err := net.Query(ctx, pool, &api.ChainQuery{Name: "main", Index: &idx, IncludeReceipt: &api.ReceiptOptions{ForHeight: height}})
		if err != nil {
			return PartitionAnchor{}, none, fmt.Errorf("anchor of %s block %d at root height %d: %w", pb.Partition, pb.Block, height, err)
		}
		he, ok := hr.(*api.ChainEntryRecord[api.Record])
		if !ok || he.Receipt == nil {
			return PartitionAnchor{}, none, fmt.Errorf("anchor at root height %d: got %T without a receipt", height, hr)
		}
		rec = he.Receipt
	}
	if rec == nil {
		return PartitionAnchor{}, none, fmt.Errorf("the Directory's entry for the anchor carries no receipt")
	}
	if !bytes.Equal(rec.Start, h[:]) || !rec.Receipt.Validate(nil) {
		return PartitionAnchor{}, none, fmt.Errorf("the receipt does not prove the anchor %x into a Directory root", h[:8])
	}
	rb, err := rec.Receipt.MarshalBinary()
	if err != nil {
		return PartitionAnchor{}, none, err
	}
	sb, err := seq.MarshalBinary()
	if err != nil {
		return PartitionAnchor{}, none, err
	}
	return PartitionAnchor{Message: hex.EncodeToString(sb), Receipt: hex.EncodeToString(rb)}, h, nil
}

// onlyChainEntry returns the one entry of the named chain with the given hash.
func onlyChainEntry(r api.Record, chain string, entry []byte) (*api.ChainEntryRecord[api.Record], error) {
	switch r := r.(type) {
	case *api.ChainEntryRecord[api.Record]:
		if r.Name == chain && bytes.Equal(r.Entry[:], entry) {
			return r, nil
		}
	case *api.RecordRange[api.Record]:
		var found *api.ChainEntryRecord[api.Record]
		for _, rec := range r.Records {
			if ce, ok := rec.(*api.ChainEntryRecord[api.Record]); ok && ce.Name == chain && bytes.Equal(ce.Entry[:], entry) {
				if found != nil {
					return nil, fmt.Errorf("%s holds the entry %x more than once", chain, entry[:8])
				}
				found = ce
			}
		}
		if found != nil {
			return found, nil
		}
	}
	return nil, fmt.Errorf("%s does not hold the entry %x", chain, entry[:8])
}

// TxPosition is where the transaction's own partition recorded it: its block, the Directory block that executed the
// partition's anchor for that block, and the partition's state root at it.
type TxPosition struct {
	Block     uint64
	DNBlock   uint64
	StateRoot [32]byte
	RootChain [32]byte
}

// Position reads a transaction's block and the Directory block that executed its partition's anchor for it. label is the
// partition as the Directory's anchor chains name it ("bvn1").
func (b *Builder) Position(ctx context.Context, account, txHash, label string) (*TxPosition, error) {
	l1, err := chained_proof.NewLayer1Builder(b.C, false).Build(ctx, account, txHash)
	if err != nil {
		return nil, err
	}
	l2, err := chained_proof.NewLayer2Builder(b.C, false).Build(ctx, label, l1)
	if err != nil {
		return nil, fmt.Errorf("anchor of %s block %d: %w", label, l1.BVNMinorBlockIndex, err)
	}
	p := &TxPosition{Block: l1.BVNMinorBlockIndex, DNBlock: l2.DNMinorBlockIndex}
	if err := hex32(l2.BVNStateTreeAnchor, p.StateRoot[:]); err != nil {
		return nil, err
	}
	if err := hex32(l1.BVNRootChainAnchor, p.RootChain[:]); err != nil {
		return nil, err
	}
	return p, nil
}

// BindToAnchor requires a captured page's receipt to pass through the StateTreeAnchor of the partition's anchor for the block
// it was captured at, and returns the page trimmed to it. A page served for any other block does not pass through it
// (measured live 2026-10-04: the state as of B-1 or B+1 does not), and is refused by name.
func BindToAnchor(p *PageState, partition string, block uint64, stateRoot [32]byte) (*PageState, error) {
	t, err := trimPage(p, stateRoot[:])
	if err != nil {
		return nil, &NamedState{Code: StatePageBlockMismatch, Partition: partition, Block: block, Detail: err.Error()}
	}
	return t, nil
}

// ChainEntryBlock returns the block of the account's partition at which the named chain recorded the entry (the
// receipt's local block): for a key signature on a signer page's signature chain, the block the signature arrived in.
func ChainEntryBlock(ctx context.Context, net api.Querier, account *url.URL, chain string, entry [32]byte) (uint64, error) {
	r, err := net.Query(ctx, account, &api.ChainQuery{Name: chain, Entry: entry[:], IncludeReceipt: &api.ReceiptOptions{ForAny: true}})
	if err != nil {
		return 0, fmt.Errorf("%v %s entry %x: %w", account, chain, entry[:8], err)
	}
	ce, err := onlyChainEntry(r, chain, entry[:])
	if err != nil {
		return 0, fmt.Errorf("%v: %w", account, err)
	}
	if ce.Receipt == nil || ce.Receipt.LocalBlock == 0 {
		return 0, fmt.Errorf("%v %s entry %x carries no receipt naming its block", account, chain, entry[:8])
	}
	return ce.Receipt.LocalBlock, nil
}

// VerifyPageAt checks one captured page against the state tree root of the block it was read at, as the verifier does for a
// page of the transaction's own partition: the receipt starts at the hash of the state, ends at stateRoot and validates, the
// state decodes to the page's URL, and its chain roots - when captured - bind to the receipt.
func VerifyPageAt(p *PageState, stateRoot [32]byte) (protocol.Account, PageChain, error) {
	return verifyPage(p, stateRoot[:])
}
