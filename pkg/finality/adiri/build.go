// Copyright 2026 Certen Protocol

package adiri

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/mr-tron/base58"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
)

// EpochDuration is Adiri's epoch length (tn_getCurrentEpochInfo.epochDuration); the next epoch closes 21,600 s after the
// previous closing block (annex M6/M11: measured error 0 s).
const EpochDuration = 21600 * time.Second

// DefaultOverdueBound is how long past the eta an epoch may stay open before the builder reports epoch_overdue (the source's
// local vote wait is about 65 s plus peer recovery; annex scheduling proposal).
const DefaultOverdueBound = 300 * time.Second

// Prover builds adiri/finalized/v1 evidence for chain 2017 (finality.Prover). The epoch records are read from the public
// endpoints in JSON-RPC batches; they are self-authenticating, so ANY one endpoint's answer is verified end to end and no
// provider agreement is required (annex A8, spec 5.8). The own node (ProofEndpoints) is asked only for eth_getProof at F.
// Every endpoint error passes through ethrpc.RedactError / RedactText before it reaches a state.
type Prover struct {
	Endpoints      []string // public endpoints (tn_epochRecord, tn_getCurrentEpoch, eth_getBlockByNumber)
	ProofEndpoints []string // endpoints that may serve eth_getProof at F (CERTEN's own Adiri node)
	Client         *http.Client
	Pins           *finality.Pins
	Verifier       *Verifier
	Now            func() time.Time
	OverdueBound   time.Duration
	BatchSize      int
}

// Chain implements finality.Prover.
func (p *Prover) Chain() uint64 { return finality.ChainAdiri }

// Ceiling implements finality.Ceilinged: Adiri's top level is finalized.
func (p *Prover) Ceiling() finality.Level { return finality.LevelFinalized }

func (p *Prover) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (p *Prover) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Prover) batchSize() int {
	if p.BatchSize > 0 {
		return p.BatchSize
	}
	return 250
}

func (p *Prover) overdue() time.Duration {
	if p.OverdueBound > 0 {
		return p.OverdueBound
	}
	return DefaultOverdueBound
}

type rpcReq struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcResp struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// errNotFound is tn_epochRecord's -32001 "Not Found." (no record, or no certificate yet).
const rpcNotFound = -32001

// post sends one batch to one endpoint and returns the answers in request order.
func (p *Prover) post(ctx context.Context, url string, reqs []rpcReq) ([]rpcResp, error) {
	body, err := json.Marshal(reqs)
	if err != nil {
		return nil, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/json")
	resp, err := p.client().Do(hr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// the body is the provider's text: it is never echoed into a state, only its status
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out []rpcResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("batch answer does not parse: %v", err)
	}
	byID := make(map[int]rpcResp, len(out))
	for _, r := range out {
		byID[r.ID] = r
	}
	ordered := make([]rpcResp, len(reqs))
	for i, q := range reqs {
		r, ok := byID[q.ID]
		if !ok {
			return nil, fmt.Errorf("batch answer lacks id %d", q.ID)
		}
		ordered[i] = r
	}
	return ordered, nil
}

// endpointNote renders one endpoint failure with the endpoint and the error redacted.
func endpointNote(url string, err error) string {
	return ethrpc.RedactText(url) + ": " + ethrpc.RedactError(err).Error()
}

// call sends the batch to each of urls in turn and returns the first answer in which no request failed with a transport or
// HTTP error. Per-request JSON-RPC errors are returned in the answers (the caller decides which are acceptable). A failure of
// every endpoint is finality_source_unavailable{reason, endpoints} with redacted notes.
func (p *Prover) call(ctx context.Context, urls []string, reason SourceReason, reqs []rpcReq) ([]rpcResp, error) {
	var notes []string
	for _, u := range urls {
		out, err := p.post(ctx, u, reqs)
		if err == nil {
			return out, nil
		}
		notes = append(notes, endpointNote(u, err))
		if ctx.Err() != nil {
			break
		}
	}
	if len(urls) == 0 {
		notes = append(notes, "no endpoint configured")
	}
	return nil, SourceUnavailable(reason, notes)
}

func (p *Prover) one(ctx context.Context, urls []string, reason SourceReason, method string, params ...any) (rpcResp, error) {
	out, err := p.call(ctx, urls, reason, []rpcReq{{JSONRPC: "2.0", ID: 1, Method: method, Params: params}})
	if err != nil {
		return rpcResp{}, err
	}
	return out[0], nil
}

func hexU(n uint64) string { return "0x" + strconv.FormatUint(n, 16) }

// ---- reading the chain ----

type recJSON struct {
	Epoch          uint64   `json:"epoch"`
	Committee      []string `json:"committee"`
	NextCommittee  []string `json:"next_committee"`
	ParentHash     string   `json:"parent_hash"`
	FinalState     nhJSON   `json:"final_state"`
	FinalConsensus struct {
		Number uint64 `json:"number"`
		Hash   string `json:"hash"`
	} `json:"final_consensus"`
}

type certJSON struct {
	EpochHash         string `json:"epoch_hash"`
	Signature         string `json:"signature"`
	SignedAuthorities string `json:"signed_authorities"`
}

// DecodeEpochRecord turns a tn_epochRecord result ([record, certificate]) into its CFA1 parts: the committee and next
// committee as 96-byte keys, the checkpoints, the 48-byte signature and the signer indices of the Roaring bitmap.
func DecodeEpochRecord(result json.RawMessage) (rec recJSON, cert certJSON, committee, next [][]byte, out Record, err error) {
	var pair []json.RawMessage
	if err = json.Unmarshal(result, &pair); err != nil || len(pair) != 2 {
		return rec, cert, nil, nil, out, fmt.Errorf("an epoch record result is [record, certificate]")
	}
	if err = json.Unmarshal(pair[0], &rec); err != nil {
		return
	}
	if err = json.Unmarshal(pair[1], &cert); err != nil {
		return
	}
	dec := func(list []string) ([][]byte, error) {
		keys := make([][]byte, len(list))
		for i, s := range list {
			b, e := base58.Decode(s)
			if e != nil || len(b) != KeyBytes {
				return nil, fmt.Errorf("committee key %d is not a 96-byte base58 key", i)
			}
			keys[i] = b
		}
		return keys, nil
	}
	if committee, err = dec(rec.Committee); err != nil {
		return
	}
	if next, err = dec(rec.NextCommittee); err != nil {
		return
	}
	fsHash, e := hex32(rec.FinalState.Hash)
	if e != nil {
		err = fmt.Errorf("final_state.hash: %v", e)
		return
	}
	fc, e := base58.Decode(rec.FinalConsensus.Hash)
	if e != nil || len(fc) != 32 {
		err = fmt.Errorf("final_consensus.hash is not a 32-byte base58 hash")
		return
	}
	sig, e := base58.Decode(cert.Signature)
	if e != nil || len(sig) != SigBytes {
		err = fmt.Errorf("certificate signature is not a 48-byte base58 value")
		return
	}
	bm, e := base58.Decode(cert.SignedAuthorities)
	if e != nil {
		err = fmt.Errorf("signed_authorities is not base58")
		return
	}
	idx, e := DecodeRoaring(bm)
	if e != nil {
		err = fmt.Errorf("signed_authorities: %v", e)
		return
	}
	out.FinalState = NumHash{rec.FinalState.Number, fsHash}
	out.FinalConsensus.Number = rec.FinalConsensus.Number
	copy(out.FinalConsensus.Hash[:], fc)
	copy(out.Signature[:], sig)
	for _, v := range idx {
		if v > 255 {
			err = fmt.Errorf("signer index %d exceeds 255", v)
			return
		}
		out.Signers = append(out.Signers, uint8(v))
	}
	return
}

// DecodeRoaring reads a portable Roaring bitmap (cookie 12346 or 12347; array, bitmap and run containers) into ascending
// values. It is used by the builder only: the evidence carries explicit signer index lists.
func DecodeRoaring(b []byte) ([]uint32, error) {
	if len(b) < 4 {
		return nil, errors.New("roaring: short")
	}
	cookie := binary.LittleEndian.Uint32(b)
	off := 4
	var size int
	var runBits []byte
	switch {
	case cookie&0xffff == 12347:
		size = int(cookie>>16) + 1
		n := (size + 7) / 8
		if len(b) < off+n {
			return nil, errors.New("roaring: short run bitmap")
		}
		runBits = b[off : off+n]
		off += n
	case cookie == 12346:
		if len(b) < 8 {
			return nil, errors.New("roaring: short")
		}
		size = int(binary.LittleEndian.Uint32(b[4:]))
		off = 8
	default:
		return nil, fmt.Errorf("roaring: unknown cookie %d", cookie)
	}
	if size > 65536 {
		return nil, errors.New("roaring: too many containers")
	}
	if len(b) < off+4*size {
		return nil, errors.New("roaring: short descriptive header")
	}
	keys := make([]uint16, size)
	cards := make([]int, size)
	for i := 0; i < size; i++ {
		keys[i] = binary.LittleEndian.Uint16(b[off:])
		cards[i] = int(binary.LittleEndian.Uint16(b[off+2:])) + 1
		off += 4
	}
	if cookie == 12346 || size >= 4 {
		off += 4 * size // offsets
	}
	var out []uint32
	for i := 0; i < size; i++ {
		hi := uint32(keys[i]) << 16
		isRun := runBits != nil && runBits[i/8]&(1<<(i%8)) != 0
		switch {
		case isRun:
			if len(b) < off+2 {
				return nil, errors.New("roaring: short run container")
			}
			n := int(binary.LittleEndian.Uint16(b[off:]))
			off += 2
			if len(b) < off+4*n {
				return nil, errors.New("roaring: short run container")
			}
			for j := 0; j < n; j++ {
				start := uint32(binary.LittleEndian.Uint16(b[off:]))
				length := uint32(binary.LittleEndian.Uint16(b[off+2:]))
				off += 4
				for v := start; v <= start+length; v++ {
					out = append(out, hi|v)
				}
			}
		case cards[i] > 4096:
			if len(b) < off+8192 {
				return nil, errors.New("roaring: short bitmap container")
			}
			for w := 0; w < 1024; w++ {
				word := binary.LittleEndian.Uint64(b[off+8*w:])
				for bit := 0; bit < 64; bit++ {
					if word&(1<<bit) != 0 {
						out = append(out, hi|uint32(w*64+bit))
					}
				}
			}
			off += 8192
		default:
			if len(b) < off+2*cards[i] {
				return nil, errors.New("roaring: short array container")
			}
			for j := 0; j < cards[i]; j++ {
				out = append(out, hi|uint32(binary.LittleEndian.Uint16(b[off:])))
				off += 2
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// EncodeRoaring is the portable serialisation (cookie 12346, array containers) of ascending values below 65536; it is used
// by the fake JSON-RPC servers of the tests.
func EncodeRoaring(values []uint16) []byte {
	out := binary.LittleEndian.AppendUint32(nil, 12346)
	out = binary.LittleEndian.AppendUint32(out, 1)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(values)-1))
	out = binary.LittleEndian.AppendUint32(out, 16)
	for _, v := range values {
		out = binary.LittleEndian.AppendUint16(out, v)
	}
	return out
}

// tableIndex assigns table indices in first-use order.
type tableIndex struct {
	tables [][][]byte
	idx    map[string]int
}

func (t *tableIndex) of(keys [][]byte) uint8 {
	var k strings.Builder
	for _, key := range keys {
		k.Write(key)
	}
	if t.idx == nil {
		t.idx = map[string]int{}
	}
	if i, ok := t.idx[k.String()]; ok {
		return uint8(i)
	}
	t.idx[k.String()] = len(t.tables)
	t.tables = append(t.tables, keys)
	return uint8(len(t.tables) - 1)
}

// headerRLP rebuilds the raw consensus RLP of a header from eth_getBlockByNumber's JSON and requires it to hash to the hash
// the node reported (annex A5: a Telcoin header re-hashes under go-ethereum).
func headerRLP(raw json.RawMessage) ([]byte, [32]byte, error) {
	var h types.Header
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, [32]byte{}, fmt.Errorf("header JSON does not decode: %v", err)
	}
	var named struct {
		Hash common.Hash `json:"hash"`
	}
	if err := json.Unmarshal(raw, &named); err != nil {
		return nil, [32]byte{}, err
	}
	enc, err := rlp.EncodeToBytes(&h)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if h.Hash() != named.Hash {
		return nil, [32]byte{}, fmt.Errorf("header %d re-hashes to %s, the node reported %s", h.Number.Uint64(), h.Hash().Hex(), named.Hash.Hex())
	}
	return enc, [32]byte(named.Hash), nil
}

// Build implements finality.Prover.
func (p *Prover) Build(ctx context.Context, s *ethproof.Settlement, have finality.LevelSet, target finality.Level) (*finality.Addendum, *finality.PendingState, error) {
	if target != finality.LevelFinalized {
		if target == finality.LevelL1Posted {
			return nil, nil, finality.NotApplicableState(finality.ChainAdiri, target, finality.ReasonNoL1Settlment)
		}
		return nil, nil, finality.NewState(finality.CodeEvidenceUnrecognised, "kind", "level:"+target.String(), "version", "")
	}
	if have.Has(finality.LevelFinalized) {
		return nil, nil, finality.NewState(finality.CodeLevelAlreadyPresent, "chain", finality.ChainAdiri, "level", finality.LevelFinalized)
	}
	if p.Verifier == nil {
		p.Verifier = NewVerifier()
	}
	leg, err := finality.DeriveIncluded(finality.ChainAdiri, s)
	if err != nil {
		return nil, nil, err
	}
	return p.BuildLeg(ctx, leg)
}

// BuildLeg builds the evidence for a leg block already derived at level 1 (Build derives it from the Settlement; the
// vector recorder names it directly).
func (p *Prover) BuildLeg(ctx context.Context, leg finality.BlockRef) (*finality.Addendum, *finality.PendingState, error) {
	if p.Verifier == nil {
		p.Verifier = NewVerifier()
	}
	curResp, err := p.one(ctx, p.Endpoints, SourceEpochRecord, "tn_getCurrentEpoch")
	if err != nil {
		return nil, nil, err
	}
	var cur uint64
	if curResp.Error != nil || json.Unmarshal(curResp.Result, &cur) != nil {
		return nil, nil, SourceUnavailable(SourceEpochRecord, []string{"tn_getCurrentEpoch: " + ethrpc.RedactText(rpcErrText(curResp))})
	}

	// records 0..E, E the smallest epoch whose final_state.number >= N
	var recs []Record
	var tables tableIndex
	var lastRec recJSON
	found := false
	for from := uint64(0); from < cur && !found; from += uint64(p.batchSize()) {
		to := from + uint64(p.batchSize())
		if to > cur {
			to = cur
		}
		reqs := make([]rpcReq, 0, to-from)
		for e := from; e < to; e++ {
			reqs = append(reqs, rpcReq{JSONRPC: "2.0", ID: int(e) + 1, Method: "tn_epochRecord", Params: []any{e}})
		}
		out, err := p.call(ctx, p.Endpoints, SourceEpochRecord, reqs)
		if err != nil {
			return nil, nil, err
		}
		for i, r := range out {
			e := from + uint64(i)
			if r.Error != nil && r.Error.Code == rpcNotFound {
				// a closed epoch whose record or certificate does not exist yet
				return nil, p.pendingCertificate(e, cur, leg), nil
			}
			if r.Error != nil {
				return nil, nil, SourceUnavailable(SourceEpochRecord, []string{fmt.Sprintf("tn_epochRecord(%d): %s", e, ethrpc.RedactText(rpcErrText(r)))}, "epoch", e)
			}
			rj, _, committee, next, rec, derr := DecodeEpochRecord(r.Result)
			if derr != nil {
				return nil, nil, SourceUnavailable(SourceEpochRecordsFail, []string{fmt.Sprintf("tn_epochRecord(%d): %s", e, ethrpc.RedactText(derr.Error()))}, "epoch", e)
			}
			if rj.Epoch != e {
				return nil, nil, SourceUnavailable(SourceEpochRecordsFail, []string{fmt.Sprintf("tn_epochRecord(%d) answered epoch %d", e, rj.Epoch)}, "epoch", e)
			}
			rec.CommitteeIdx = tables.of(committee)
			rec.NextIdx = tables.of(next)
			recs = append(recs, rec)
			lastRec = rj
			if rec.FinalState.Number >= leg.Number {
				found = true
				break
			}
		}
	}
	if !found {
		return nil, p.pendingOpen(ctx, cur, recs, leg), nil
	}
	chain := &CFA1{Tables: tables.tables, Records: recs}
	cfa1, err := chain.Encode()
	if err != nil {
		return nil, nil, err
	}
	F := recs[len(recs)-1].FinalState
	_ = lastRec

	body := Body{CFA1: cfa1}
	// linkKind 2 only when this builder holds eth_getProof at F and the distance fits the ring; else linkKind 1.
	if len(p.ProofEndpoints) > 0 && leg.Number < F.Number && F.Number-leg.Number <= EIP2935Window-1 {
		if b2, ok := p.slotBody(ctx, cfa1, F, leg); ok {
			body = b2
		}
	}
	if body.LinkKind == 0 {
		spine, err := p.spine(ctx, F, leg)
		if err != nil {
			return nil, nil, err
		}
		body.LinkKind = LinkSpine
		body.Spine = spine
	}
	ev, err := BuildContainer(leg, body)
	if err != nil {
		return nil, nil, err
	}
	if _, err := p.Verifier.Verify(p.Pins, leg, ev); err != nil {
		return nil, nil, err
	}
	return &finality.Addendum{Level: finality.LevelFinalized, Chain: finality.ChainAdiri, Kind: Name, Evidence: ev}, nil, nil
}

func rpcErrText(r rpcResp) string {
	if r.Error != nil {
		return fmt.Sprintf("code %d: %s", r.Error.Code, r.Error.Message)
	}
	return "empty result"
}

func (p *Prover) pending(reason string, epoch uint64, eta time.Time, kv ...any) *finality.PendingState {
	j := map[string]any{"epoch": epoch}
	for i := 0; i+1 < len(kv); i += 2 {
		j[fmt.Sprint(kv[i])] = kv[i+1]
	}
	return &finality.PendingState{Chain: finality.ChainAdiri, LevelReached: finality.LevelIncluded, NextLevel: finality.LevelFinalized, Reason: reason, ETA: eta, Judged: j}
}

// pendingCertificate: epoch e is closed (e < current) and no endpoint holds its record with a certificate yet.
func (p *Prover) pendingCertificate(e, cur uint64, leg finality.BlockRef) *finality.PendingState {
	return p.pending(PendingCertPending, e, time.Time{}, "current_epoch", cur, "block_number", leg.Number)
}

// pendingOpen: N is above the last sealed epoch's final block, so it lies in the open epoch `cur`. eta = the previous closing
// block's timestamp + 21,600 s; past eta + bound the epoch is overdue.
func (p *Prover) pendingOpen(ctx context.Context, cur uint64, recs []Record, leg finality.BlockRef) *finality.PendingState {
	var prevClose uint64
	if len(recs) > 0 {
		prevClose = recs[len(recs)-1].FinalState.Number
	}
	var eta time.Time
	if r, err := p.one(ctx, p.Endpoints, SourceHeaders, "eth_getBlockByNumber", hexU(prevClose), false); err == nil && r.Error == nil {
		var hd struct {
			Timestamp string `json:"timestamp"`
		}
		if json.Unmarshal(r.Result, &hd) == nil {
			if ts, ok := new(big.Int).SetString(strings.TrimPrefix(hd.Timestamp, "0x"), 16); ok {
				eta = time.Unix(ts.Int64(), 0).UTC().Add(EpochDuration)
			}
		}
	}
	if !eta.IsZero() && p.now().After(eta.Add(p.overdue())) {
		return p.pending(PendingEpochOverdue, cur, eta, "lag_seconds", uint64(p.now().Sub(eta).Seconds()), "block_number", leg.Number)
	}
	return p.pending(PendingEpochOpen, cur, eta, "block_number", leg.Number, "previous_closing_block", prevClose)
}

// spine reads headers F down to the leg block in batches and returns them descending; h_k is the leg's own header.
func (p *Prover) spine(ctx context.Context, F NumHash, leg finality.BlockRef) ([][]byte, error) {
	count := F.Number - leg.Number + 1
	headers := make([][]byte, count)
	hashes := make([][32]byte, count)
	for from := uint64(0); from < count; from += uint64(p.batchSize()) {
		to := from + uint64(p.batchSize())
		if to > count {
			to = count
		}
		reqs := make([]rpcReq, 0, to-from)
		for i := from; i < to; i++ {
			reqs = append(reqs, rpcReq{JSONRPC: "2.0", ID: int(i) + 1, Method: "eth_getBlockByNumber", Params: []any{hexU(F.Number - i), false}})
		}
		out, err := p.call(ctx, p.Endpoints, SourceHeaders, reqs)
		if err != nil {
			return nil, err
		}
		for j, r := range out {
			i := from + uint64(j)
			n := F.Number - i
			if r.Error != nil || len(r.Result) == 0 || string(r.Result) == "null" {
				return nil, SourceUnavailable(SourceHeaders, []string{fmt.Sprintf("eth_getBlockByNumber(%d): %s", n, ethrpc.RedactText(rpcErrText(r)))}, "block", n)
			}
			enc, h, err := headerRLP(r.Result)
			if err != nil {
				return nil, SourceUnavailable(SourceHeaders, []string{fmt.Sprintf("block %d: %s", n, ethrpc.RedactText(err.Error()))}, "block", n)
			}
			headers[i], hashes[i] = enc, h
		}
	}
	if leg.HeaderRLP != nil && hashes[count-1] == leg.Hash {
		headers[count-1] = append([]byte(nil), leg.HeaderRLP...)
	}
	return headers, nil
}

// slotBody tries to build the linkKind 2 body: the header of F and the EIP-2935 account and slot proofs at F. ok=false means
// the proofs could not be obtained (history_proof_unavailable: the encoding switches to linkKind 1, the level does not).
func (p *Prover) slotBody(ctx context.Context, cfa1 []byte, F NumHash, leg finality.BlockRef) (Body, bool) {
	par, err := ParsePins(p.Pins)
	if err != nil {
		return Body{}, false
	}
	slot := common.BigToHash(new(big.Int).SetUint64(leg.Number % EIP2935Window))
	out, err := p.call(ctx, p.ProofEndpoints, SourceHistoryProof, []rpcReq{
		{JSONRPC: "2.0", ID: 1, Method: "eth_getBlockByNumber", Params: []any{hexU(F.Number), false}},
		{JSONRPC: "2.0", ID: 2, Method: "eth_getProof", Params: []any{par.EIP2935Address.Hex(), []string{slot.Hex()}, hexU(F.Number)}},
	})
	if err != nil || out[0].Error != nil || out[1].Error != nil {
		return Body{}, false
	}
	fh, _, err := headerRLP(out[0].Result)
	if err != nil {
		return Body{}, false
	}
	var pr struct {
		AccountProof []string `json:"accountProof"`
		StorageProof []struct {
			Proof []string `json:"proof"`
		} `json:"storageProof"`
	}
	if json.Unmarshal(out[1].Result, &pr) != nil || len(pr.StorageProof) != 1 {
		return Body{}, false
	}
	var nodes [][]byte
	for _, h := range append(append([]string{}, pr.AccountProof...), pr.StorageProof[0].Proof...) {
		b, err := hex.DecodeString(strings.TrimPrefix(h, "0x"))
		if err != nil {
			return Body{}, false
		}
		nodes = append(nodes, b)
	}
	return Body{CFA1: cfa1, LinkKind: LinkSlot, FinalHeader: fh, Nodes: finality.EncodeNodes(nodes)}, true
}

// HeaderRLPFromJSON rebuilds the raw consensus RLP of an eth_getBlockByNumber result and requires it to hash to the hash the
// node reported.
func HeaderRLPFromJSON(raw json.RawMessage) (rlpBytes []byte, hash [32]byte, err error) {
	return headerRLP(raw)
}

// ReadEpochRecords reads tn_epochRecord(from..to-1) in JSON-RPC batches from the first endpoint that answers.
func (p *Prover) ReadEpochRecords(ctx context.Context, from, to uint64) ([]json.RawMessage, error) {
	var out []json.RawMessage
	for f := from; f < to; f += uint64(p.batchSize()) {
		t := f + uint64(p.batchSize())
		if t > to {
			t = to
		}
		reqs := make([]rpcReq, 0, t-f)
		for e := f; e < t; e++ {
			reqs = append(reqs, rpcReq{JSONRPC: "2.0", ID: int(e) + 1, Method: "tn_epochRecord", Params: []any{e}})
		}
		rs, err := p.call(ctx, p.Endpoints, SourceEpochRecord, reqs)
		if err != nil {
			return nil, err
		}
		for i, r := range rs {
			if r.Error != nil {
				return nil, SourceUnavailable(SourceEpochRecord, []string{fmt.Sprintf("tn_epochRecord(%d): %s", f+uint64(i), ethrpc.RedactText(rpcErrText(r)))})
			}
			out = append(out, r.Result)
		}
	}
	return out, nil
}

// ReadHeaders reads the raw headers of blocks from..to inclusive, ascending.
func (p *Prover) ReadHeaders(ctx context.Context, from, to uint64) ([][]byte, error) {
	var out [][]byte
	for f := from; f <= to; f += uint64(p.batchSize()) {
		t := f + uint64(p.batchSize()) - 1
		if t > to {
			t = to
		}
		reqs := make([]rpcReq, 0, t-f+1)
		for n := f; n <= t; n++ {
			reqs = append(reqs, rpcReq{JSONRPC: "2.0", ID: int(n-f) + 1, Method: "eth_getBlockByNumber", Params: []any{hexU(n), false}})
		}
		rs, err := p.call(ctx, p.Endpoints, SourceHeaders, reqs)
		if err != nil {
			return nil, err
		}
		for i, r := range rs {
			if r.Error != nil || len(r.Result) == 0 || string(r.Result) == "null" {
				return nil, SourceUnavailable(SourceHeaders, []string{fmt.Sprintf("eth_getBlockByNumber(%d): %s", f+uint64(i), ethrpc.RedactText(rpcErrText(r)))})
			}
			enc, _, err := headerRLP(r.Result)
			if err != nil {
				return nil, SourceUnavailable(SourceHeaders, []string{ethrpc.RedactText(err.Error())})
			}
			out = append(out, enc)
		}
	}
	return out, nil
}

// RawCall sends one JSON-RPC request to the endpoints and returns its result (for the recorder's tn_genesis read).
func (p *Prover) RawCall(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	r, err := p.one(ctx, p.Endpoints, SourceEpochRecord, method, params...)
	if err != nil {
		return nil, err
	}
	if r.Error != nil {
		return nil, SourceUnavailable(SourceEpochRecord, []string{method + ": " + ethrpc.RedactText(rpcErrText(r))})
	}
	return r.Result, nil
}
