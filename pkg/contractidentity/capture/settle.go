// Copyright 2026 Certen Protocol

package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// Item names of the settlement station. A captured result and a Stated result are different items: honest captures of one block are
// byte-identical (canonical sorted node set), Stated results carry each validator's own provider failures and are not.
const (
	ItemSettle       = "settle"
	ItemSettleStated = "settle/stated"
)

// SettleRequest is the trigger of E2: the first observation of the settlement receipt (the same trigger as the S6 capture), plus what the
// capture cannot read from the settlement itself and every validator already holds: the attestation's pubkey commitment (blob word 13 of
// executeComprehensiveProof, the key of A05) and, for link 1, the numbers of H_0 (= B_v) .. H_k whose last element is the block whose
// hash the history slot under the settlement root records.
type SettleRequest struct {
	TxHash     common.Hash
	PKC        common.Hash
	Link       uint8
	HopNumbers []uint64
}

// ErrNotAccountSettlement: the transaction is no direct account settlement (no single LeafConsumed log emitted by its recipient); the
// verifier states the leg not_applicable or unsupported, and there is nothing for E2 to capture.
var ErrNotAccountSettlement = errors.New("capture: the transaction is not a direct account settlement")

// DeriveFacts derives the plan inputs from the settlement transaction and receipt (steps 3 and 14). A calldata that the strict ABI decoder
// refuses leaves the step 14 reads out: the verifier states calldata_undecodable and derives no step 14 read either.
func DeriveFacts(m *ci.Manifest, chain uint64, tx *types.Transaction, rc *types.Receipt, req SettleRequest) (*Facts, error) {
	top, ok := m.Topic("LeafConsumed")
	if !ok {
		return nil, errors.New("capture: the manifest has no LeafConsumed topic")
	}
	t0 := common.HexToHash(top.Topic0)
	var cands []*types.Log
	if tx.To() != nil {
		for _, l := range rc.Logs {
			if l.Address == *tx.To() && len(l.Topics) == 3 && l.Topics[0] == t0 {
				cands = append(cands, l)
			}
		}
	}
	if len(cands) != 1 {
		return nil, fmt.Errorf("%w: %d LeafConsumed logs of the recipient", ErrNotAccountSettlement, len(cands))
	}
	f := &Facts{Chain: chain, Manifest: m, Account: cands[0].Address, AnchorID: cands[0].Topics[1], PKC: req.PKC, Link: req.Link,
		HopNumbers: append([]uint64(nil), req.HopNumbers...)}
	if call, err := ci.DecodeSettlementCall(tx.Data(), ci.DefaultABILimits()); err == nil {
		f.Book, f.Page = common.Hash(call.Proof.AuthorityBook), call.Proof.AuthorityPage
		for _, l := range call.Legs {
			f.Selectors = append(f.Selectors, l.Selector)
		}
	}
	return f, nil
}

// SettleResult is the outcome of E2: the verified nodes and codes, or the Stated part saying why nothing was captured.
type SettleResult struct {
	Chain     uint64
	AnchorID  common.Hash
	Block     ci.BlockRef // the settlement block N
	StateRoot common.Hash
	Codes     []ci.Code // ascending by address
	Nodes     [][]byte  // canonical: ascending by keccak256, unique; exactly the nodes the plan visits
	Stated    *ci.Stated
	Facts     *Facts
}

func hashLess(a, b []byte) bool { return bytes.Compare(crypto.Keccak256(a), crypto.Keccak256(b)) < 0 }

// sortNodes orders nodes ascending by keccak256 and removes duplicates.
func sortNodes(nodes [][]byte) [][]byte {
	type hn struct {
		h common.Hash
		n []byte
	}
	hs := make([]hn, 0, len(nodes))
	seen := map[common.Hash]bool{}
	for _, n := range nodes {
		h := common.BytesToHash(crypto.Keccak256(n))
		if !seen[h] {
			seen[h] = true
			hs = append(hs, hn{h, n})
		}
	}
	sort.Slice(hs, func(i, j int) bool { return bytes.Compare(hs[i].h[:], hs[j].h[:]) < 0 })
	out := make([][]byte, len(hs))
	for i := range hs {
		out[i] = hs[i].n
	}
	return out
}

func sortCodes(m map[common.Address][]byte, keep func(common.Address) bool) []ci.Code {
	var out []ci.Code
	for a, c := range m {
		if keep == nil || keep(a) {
			out = append(out, ci.Code{Address: a, Runtime: c})
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].Address[:], out[j].Address[:]) < 0 })
	return out
}

// CaptureSettle is E2: it reads, at the settlement block N, the account, the factory, the anchor (record and AUTH slots), the verifier chain,
// the owners, the step 14 level slots of every leg, the EIP-2935 slot of the last hop and the codes, and returns exactly the nodes and
// codes the verifier's read plan visits. Nothing is kept unverified: every proof is checked against the agreed state root of N and every
// code against the proven code hash. What no provider can serve within the budget is a Stated part (state_unavailable) carrying the
// block it was judged at and the bounded, redacted provider failures; a chain that contradicts a pin is a PlanError; a cancelled caller
// context is its own error. It spawns no goroutine, holds its gate slot under defer and recovers a panic into a PanicError.
func CaptureSettle(ctx context.Context, cfg Config, req SettleRequest) (res *SettleResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, &PanicError{Value: asciiText(fmt.Sprint(r))}
		}
	}()
	if err := cfg.check(); err != nil {
		return nil, err
	}
	clock := cfg.clock()
	parent := ctx
	ctx, cancel := clock.WithDeadline(ctx, clock.Now().Add(cfg.budget()))
	defer cancel()

	src := cfg.Source
	tx, found, terr := src.TransactionByHash(ctx, req.TxHash)
	if terr != nil || !found || tx == nil {
		return nil, unreadable("settlement transaction", terr)
	}
	rc, rerr := src.TransactionReceipt(ctx, req.TxHash)
	if rerr != nil || rc == nil || rc.BlockNumber == nil {
		return nil, unreadable("settlement receipt", rerr)
	}
	hdr, herr := src.HeaderByNumber(ctx, rc.BlockNumber)
	if herr != nil || hdr == nil {
		return nil, unreadable("settlement block header", herr)
	}
	if hdr.Hash() != rc.BlockHash || hdr.Number.Cmp(rc.BlockNumber) != 0 || tx.Hash() != req.TxHash || rc.TxHash != req.TxHash {
		return nil, errors.New("capture: the agreed header, the receipt and the transaction do not name one block")
	}
	facts, ferr := DeriveFacts(cfg.Manifest, cfg.Chain, tx, rc, req)
	if ferr != nil {
		return nil, ferr
	}
	blk := ci.BlockRef{Number: hdr.Number.Uint64(), Hash: [32]byte(hdr.Hash())}
	res = &SettleResult{Chain: cfg.Chain, AnchorID: facts.AnchorID, Block: blk, StateRoot: hdr.Root, Facts: facts}

	if cfg.Gate != nil {
		release, gerr := cfg.Gate.Acquire(ctx)
		if gerr != nil {
			if parent.Err() != nil {
				return nil, parent.Err()
			}
			res.Stated = stated(ci.StatedCaptureNotAttemptedInWindow, blk, nil, "no capture slot within the budget")
			return res, nil
		}
		defer release()
	}

	col := newCollector(&cfg, map[string]blockAt{StationSettle: {blk.Number, hdr.Root}})
	runErr := col.run(ctx, func(rd Reader) (bool, error) { return RunSettle(rd, facts) })
	var ue *UnavailableError
	switch {
	case runErr == nil:
	case parent.Err() != nil:
		return nil, parent.Err()
	case errors.As(runErr, &ue):
		res.Stated = stated(ci.StatedStateUnavailable, blk, ue.Failures, ue.What)
		return res, nil
	default:
		return nil, runErr
	}

	// The evidence is exactly what a strict re-run of the plan visits over the verified pool: padding and the nodes of reads that were only
	// asked while a prerequisite value was still unknown fall away here.
	pool := make([][]byte, 0, len(col.pool))
	for _, n := range col.pool {
		pool = append(pool, n)
	}
	ns, nerr := ci.NewNodeSet(sortNodes(pool))
	if nerr != nil {
		return nil, nerr
	}
	st := newStrict(ns, map[string]common.Hash{StationSettle: hdr.Root}, sortCodes(col.codes, nil))
	if pending, perr := RunSettle(st, facts); perr != nil || pending {
		return nil, &PlanError{Station: StationSettle, Reason: "verified_pool_does_not_replay", Err: perr}
	}
	res.Nodes = sortNodes(ns.VisitedNodes())
	res.Codes = sortCodes(col.codes, func(a common.Address) bool { return st.proven[a] })
	size := 0
	for _, n := range res.Nodes {
		size += len(n)
	}
	for _, c := range res.Codes {
		size += len(c.Runtime)
	}
	if size > ci.DefaultLimits().MaxContainerBytes {
		return nil, fmt.Errorf("%w: the settlement station alone is %d bytes", ErrTooLarge, size)
	}
	return res, nil
}

func unreadable(what string, err error) error {
	if err == nil {
		err = errors.New("not found or incomplete")
	}
	return &UnavailableError{What: what, Failures: []ci.ProviderFailure{{Host: "agreed", Error: asciiText(ethrpc.RedactError(err).Error())}}, Cause: err}
}

// stated builds a Stated part: the registry code, a builder reason, the block it was judged at, bounded redacted failures and detail.
func stated(reason string, blk ci.BlockRef, fails []ci.ProviderFailure, detail string) *ci.Stated {
	lim := ci.DefaultLimits()
	if len(fails) > lim.MaxFailures {
		fails = fails[:lim.MaxFailures]
	}
	out := make([]ci.ProviderFailure, len(fails))
	for i, f := range fails {
		out[i] = ci.ProviderFailure{Host: asciiText(f.Host), Error: asciiText(f.Error)}
	}
	return &ci.Stated{State: ci.StatedState, Reason: reason, JudgedBlock: blk.Number, JudgedHash: blk.Hash, Failures: out, Detail: asciiText(detail)}
}

// NotAttempted is the Stated result of a settlement first observed too late for a capture to have run at inclusion.
func NotAttempted(chain uint64, anchorID common.Hash, blk ci.BlockRef, detail string) *SettleResult {
	return &SettleResult{Chain: chain, AnchorID: anchorID, Block: blk, Stated: stated(ci.StatedCaptureNotAttemptedInWindow, blk, nil, detail)}
}

// ---- storage: canonical bytes (seven validators writing the same capture write identical rows) ----

const (
	settleMagic  = "CSE1"
	statedMagic  = "CSS1"
	maxStatedLen = 64 << 10
)

type wbuf struct{ b []byte }

func (w *wbuf) u32(v int)    { w.b = binary.BigEndian.AppendUint32(w.b, uint32(v)) }
func (w *wbuf) u64(v uint64) { w.b = binary.BigEndian.AppendUint64(w.b, v) }
func (w *wbuf) raw(p []byte) { w.b = append(w.b, p...) }
func (w *wbuf) lp(p []byte)  { w.u32(len(p)); w.raw(p) }
func (w *wbuf) str(s string) { w.lp([]byte(s)) }

type rbuf struct {
	b   []byte
	err error
}

func (r *rbuf) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.b) {
		if r.err == nil {
			r.err = errors.New("truncated")
		}
		return nil
	}
	p := r.b[:n]
	r.b = r.b[n:]
	return p
}
func (r *rbuf) u32() int {
	p := r.take(4)
	if p == nil {
		return 0
	}
	return int(binary.BigEndian.Uint32(p))
}
func (r *rbuf) u64() uint64 {
	p := r.take(8)
	if p == nil {
		return 0
	}
	return binary.BigEndian.Uint64(p)
}
func (r *rbuf) lp() []byte { return r.take(r.u32()) }

// EncodeSettle is the canonical row of a captured settlement station.
func EncodeSettle(r *SettleResult) ([]byte, error) {
	if r == nil || r.Stated != nil {
		return nil, errors.New("capture: EncodeSettle needs a captured result")
	}
	var w wbuf
	w.raw([]byte(settleMagic))
	w.u64(r.Block.Number)
	w.raw(r.Block.Hash[:])
	w.raw(r.StateRoot[:])
	w.u32(len(r.Codes))
	for i, c := range r.Codes {
		if i > 0 && bytes.Compare(r.Codes[i-1].Address[:], c.Address[:]) >= 0 {
			return nil, errors.New("capture: codes are not ascending and unique")
		}
		w.raw(c.Address[:])
		w.lp(c.Runtime)
	}
	w.u32(len(r.Nodes))
	for i, n := range r.Nodes {
		if i > 0 && !hashLess(r.Nodes[i-1], n) {
			return nil, errors.New("capture: nodes are not ascending by keccak256 and unique")
		}
		w.lp(n)
	}
	if len(w.b) > MaxItemBytes() {
		return nil, ErrItemTooLarge
	}
	return w.b, nil
}

// DecodeSettle is the strict inverse of EncodeSettle (decode then encode returns the input).
func DecodeSettle(raw []byte) (*SettleResult, error) {
	lim := ci.DefaultLimits()
	r := &rbuf{b: raw}
	if string(r.take(4)) != settleMagic {
		return nil, errors.New("capture: not a settle row")
	}
	res := &SettleResult{}
	res.Block.Number = r.u64()
	copy(res.Block.Hash[:], r.take(32))
	copy(res.StateRoot[:], r.take(32))
	nc := r.u32()
	if nc > lim.MaxCodes {
		return nil, errors.New("capture: too many codes")
	}
	for i := 0; i < nc && r.err == nil; i++ {
		var c ci.Code
		copy(c.Address[:], r.take(20))
		c.Runtime = append([]byte(nil), r.lp()...)
		if i > 0 && bytes.Compare(res.Codes[i-1].Address[:], c.Address[:]) >= 0 {
			return nil, errors.New("capture: codes are not ascending and unique")
		}
		res.Codes = append(res.Codes, c)
	}
	nn := r.u32()
	if nn > lim.MaxNodes {
		return nil, errors.New("capture: too many nodes")
	}
	for i := 0; i < nn && r.err == nil; i++ {
		n := append([]byte(nil), r.lp()...)
		if i > 0 && !hashLess(res.Nodes[i-1], n) {
			return nil, errors.New("capture: nodes are not ascending by keccak256 and unique")
		}
		res.Nodes = append(res.Nodes, n)
	}
	if r.err != nil {
		return nil, fmt.Errorf("capture: settle row: %v", r.err)
	}
	if len(r.b) != 0 {
		return nil, errors.New("capture: settle row has trailing bytes")
	}
	return res, nil
}

// EncodeStated is the row of a Stated settlement station.
func EncodeStated(s *ci.Stated) ([]byte, error) {
	if s == nil {
		return nil, errors.New("capture: nil Stated")
	}
	var w wbuf
	w.raw([]byte(statedMagic))
	w.str(s.Reason)
	w.u64(s.JudgedBlock)
	w.raw(s.JudgedHash[:])
	w.u32(len(s.Failures))
	for _, f := range s.Failures {
		w.str(f.Host)
		w.str(f.Error)
	}
	w.str(s.Detail)
	if len(w.b) > maxStatedLen {
		return nil, ErrItemTooLarge
	}
	return w.b, nil
}

// DecodeStated is the strict inverse of EncodeStated.
func DecodeStated(raw []byte) (*ci.Stated, error) {
	r := &rbuf{b: raw}
	if string(r.take(4)) != statedMagic {
		return nil, errors.New("capture: not a stated row")
	}
	s := &ci.Stated{State: ci.StatedState}
	s.Reason = string(r.lp())
	s.JudgedBlock = r.u64()
	copy(s.JudgedHash[:], r.take(32))
	n := r.u32()
	if n > ci.DefaultLimits().MaxFailures {
		return nil, errors.New("capture: too many failures")
	}
	for i := 0; i < n && r.err == nil; i++ {
		s.Failures = append(s.Failures, ci.ProviderFailure{Host: string(r.lp()), Error: string(r.lp())})
	}
	s.Detail = string(r.lp())
	if r.err != nil || len(r.b) != 0 {
		return nil, errors.New("capture: malformed stated row")
	}
	return s, nil
}

// SaveSettle stores a result. A captured result goes to ItemSettle (a conflict there means two honest captures disagreed: it is an alarm
// and is returned), a Stated result to ItemSettleStated (a conflict means another validator stated first: it is returned too, and the
// caller treats ErrCaptureConflict on that item as the benign case).
func SaveSettle(ctx context.Context, st Store, r *SettleResult) error {
	k := Key{Chain: r.Chain, AnchorID: r.AnchorID, BlockHash: r.Block.Hash}
	var raw []byte
	var err error
	if r.Stated != nil {
		k.Item = ItemSettleStated
		raw, err = EncodeStated(r.Stated)
	} else {
		k.Item = ItemSettle
		raw, err = EncodeSettle(r)
	}
	if err != nil {
		return err
	}
	return st.Put(ctx, k, raw)
}

// LoadSettle returns the stored settlement station of (chain, anchor, block): the captured row when there is one, else the Stated row.
func LoadSettle(ctx context.Context, st Store, chain uint64, anchorID, blockHash [32]byte) (*SettleResult, error) {
	k := Key{Chain: chain, AnchorID: anchorID, BlockHash: blockHash, Item: ItemSettle}
	if raw, ok, err := st.Get(ctx, k); err != nil {
		return nil, err
	} else if ok {
		r, err := DecodeSettle(raw)
		if err != nil {
			return nil, err
		}
		r.Chain, r.AnchorID = chain, anchorID
		return r, nil
	}
	k.Item = ItemSettleStated
	raw, ok, err := st.Get(ctx, k)
	if err != nil || !ok {
		return nil, err
	}
	s, err := DecodeStated(raw)
	if err != nil {
		return nil, err
	}
	return &SettleResult{Chain: chain, AnchorID: anchorID, Block: ci.BlockRef{Number: s.JudgedBlock, Hash: s.JudgedHash}, Stated: s}, nil
}
