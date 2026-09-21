package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// =============================================================================
// txSender - the batch lane's transaction sender
// =============================================================================
//
// # WHY IT EXISTS
//
// The batch lane sent every transaction (anchor, quorum verify, member settlement) at ONE gas price,
// fixed when the validator started (NewEthereumContractManager), and then waited for its receipt
// with bind.WaitMined and no bound. Once the network fee rose above that startup price a transaction
// could sit in the mempool for ever: the single on-demand submitter goroutine waited on it for ever,
// so no on-demand intent on any chain settled; and a restart did not clear it, because the stuck
// transaction still held its nonce and every later transaction from the key queued behind it.
//
// # WHAT IT GUARANTEES
//
//   - Every transaction is priced when it is sent, from the chain's current base fee and tip, under
//     the same gas-price and cost ceilings the rest of the executor enforces.
//   - A transaction is recorded in a durable per-key outbox BEFORE it is broadcast, and every hash it
//     is later replaced by is added to the same record. The record outlives the transaction (it is
//     kept, marked resolved, for outboxRetention), so which hashes a nonce went out under can always
//     be answered - including hashes broadcast while no caller was listening (Resume).
//   - A transaction that does not mine is REPLACED at the same nonce, with the identical payload and a
//     higher fee. Replacing (not re-sending at a new nonce) keeps "at most one of these executes":
//     all the hashes share a nonce, so exactly one can ever be mined.
//   - Only a DEFINITIVE rejection (insufficient funds, intrinsic gas too low, ...) is treated as "never
//     reached a mempool". An ambiguous broadcast error - a timeout, a dropped connection - may have
//     been accepted, so that transaction stays in flight and is driven to a result like any other.
//   - Waits are bounded. Running out of time is reported as ChainWaitError - "not yet known" - and
//     never as a failure: the transaction stays in the outbox, and Resume drives it forward (and
//     replaces it when stuck) before this key sends anything new.
//   - "Another transaction took this nonce" (ErrNonceConsumedElsewhere - the payload did not run) is
//     concluded only after every receipt read for the nonce has cleanly said "not found" for the grace
//     period. A read that errors is not evidence of absence.

// senderBackend is what the sender needs from a chain client. *ethclient.Client satisfies it.
type senderBackend interface {
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
	SendTransaction(ctx context.Context, tx *types.Transaction) error
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error)
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
}

// SendRequest is one transaction's payload. The sender owns pricing and signing.
type SendRequest struct {
	Nonce uint64
	To    common.Address
	Data  []byte
	Value *big.Int
	Gas   uint64
	// Label names the transaction in logs and in the outbox ("anchor", "verify", "settle").
	Label string
	// Owner identifies what the transaction is FOR (a member's settlement: its chain and operationID).
	// The outbox's history for a nonce is answered only to its owner, so a nonce given back after a
	// rejected broadcast and reused for someone else's transaction is never read as this one's.
	Owner string
	// OnBroadcast is told of every hash this request is broadcast under during Send - the original
	// and each replacement - before its receipt is awaited, so a caller can record them durably.
	// Hashes broadcast later by Resume are in the outbox's history (hashesAt).
	OnBroadcast func(nonce uint64, hash string)
}

// ChainWaitError is a transaction that was broadcast and whose result was not observed within the
// sender's bound. It is NOT a failure: the transaction may still mine, and it stays in the outbox.
type ChainWaitError struct {
	Label  string
	Nonce  uint64
	Hashes []string
	Err    error
}

func (e *ChainWaitError) Error() string {
	return fmt.Sprintf("%s transaction at nonce %d not mined within the wait (hashes %v): %v",
		e.Label, e.Nonce, e.Hashes, e.Err)
}
func (e *ChainWaitError) Unwrap() error { return e.Err }

// NotBroadcastError is a Send that put nothing in flight: it was refused before broadcast (a fee
// ceiling, a pricing read) or its first broadcast was DEFINITIVELY rejected. The nonce was not used,
// so the caller gives it back. errors.As still reaches the cause, e.g. *ErrGasCeilingExceeded.
type NotBroadcastError struct{ Err error }

func (e *NotBroadcastError) Error() string { return "not broadcast: " + e.Err.Error() }
func (e *NotBroadcastError) Unwrap() error { return e.Err }

// SenderUnavailableError: the sender cannot operate - its outbox cannot be read, or holds an entry it
// cannot decode. It fails CLOSED (nothing is sent, because an unknown in-flight nonce could be
// clobbered), and it is not a failure of any member: members wait until an operator repairs it.
type SenderUnavailableError struct{ Err error }

func (e *SenderUnavailableError) Error() string {
	return "transaction sender unavailable (operator attention needed): " + e.Err.Error()
}
func (e *SenderUnavailableError) Unwrap() error { return e.Err }

// ErrNonceConsumedElsewhere: the nonce was mined by a transaction this sender did not broadcast, so
// none of this request's hashes executed. The payload did not run.
var ErrNonceConsumedElsewhere = errors.New("nonce consumed by a transaction this sender did not broadcast; the payload did not execute")

// feeCeiling decides whether a price may be paid. It returns the error to refuse with (an
// *ErrGasCeilingExceeded or *ErrTxCostCeilingExceeded), or the bid it may pay (possibly clamped).
type feeCeiling func(networkPrice, bid *big.Int, gas uint64) (clampedBid *big.Int, err error)

type txSender struct {
	client  senderBackend
	from    common.Address
	chainID *big.Int
	sign    func(tx *types.Transaction) (*types.Transaction, error)
	ceiling feeCeiling
	outbox  *txOutbox
	logf    func(string, ...interface{})

	// stuckAfter is how long a broadcast may go unmined before it is replaced (measured from its
	// persisted LastSent, so it survives restarts); sendWait bounds a Send; resumeWait bounds each
	// outstanding entry in a Resume; poll is the receipt polling interval.
	stuckAfter time.Duration
	sendWait   time.Duration
	resumeWait time.Duration
	poll       time.Duration
	// grace overrides spentGrace; zero means the default.
	grace time.Duration

	mu sync.Mutex // one send or resume at a time per key: they share the nonce space
}

const (
	defaultSenderStuckAfter = 2 * time.Minute
	defaultSenderSendWait   = 3 * time.Minute
	defaultSenderResumeWait = 30 * time.Second
	defaultSenderPoll       = 3 * time.Second

	// A replacement must raise both the tip and the fee cap by at least 10% or nodes refuse it
	// (txpool ErrReplaceUnderpriced). 12.5% clears that with margin.
	bumpNum = 1125
	bumpDen = 1000
)

// Send prices, signs, records and broadcasts one transaction, replacing it with a higher fee while it
// does not mine, and returns the receipt of whichever of its hashes mined.
//
// A refusal before broadcast, or a definitive rejection of the first broadcast, is *NotBroadcastError
// (the nonce is unused). After a broadcast, running out of time is *ChainWaitError.
func (s *txSender) Send(ctx context.Context, req SendRequest) (*types.Receipt, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, networkPrice, err := s.priceAndSign(ctx, req, nil)
	if err != nil {
		return nil, "", &NotBroadcastError{Err: err}
	}
	entry := &outboxEntry{Nonce: req.Nonce, Label: req.Label, Owner: req.Owner, To: req.To.Hex(),
		Data: "0x" + hex.EncodeToString(req.Data), Value: bigString(req.Value), Gas: req.Gas}
	rejected, err := s.broadcast(ctx, entry, tx, true, req.OnBroadcast)
	if err != nil {
		return nil, "", err
	}
	if rejected != nil {
		return nil, "", &NotBroadcastError{Err: rejected}
	}
	s.logf("[TX-SENDER] %s nonce=%d sent %s (network price %s wei)", req.Label, req.Nonce, tx.Hash().Hex(), networkPrice)
	return s.driveToResult(ctx, entry, tx, req.OnBroadcast, s.sendWait)
}

// Resume drives every transaction this key still has in flight toward a result - replacing a stuck one
// with a higher fee - for up to resumeWait each. It is called before a new nonce sequence begins: a
// new transaction must not be queued behind one that is still stuck, and a nonce left in flight by a
// previous run must not be forgotten.
//
// It returns *ChainWaitError when an outstanding transaction still has no result - the caller must
// not send anything new then - and *SenderUnavailableError when an entry cannot be decoded.
func (s *txSender) Resume(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, entry := range s.outbox.entries() {
		latest, err := s.latestTx(entry)
		if err != nil {
			return &SenderUnavailableError{Err: fmt.Errorf("outbox entry at nonce %d is unreadable: %w", entry.Nonce, err)}
		}
		if _, _, err := s.driveToResult(ctx, entry, latest, nil, s.resumeWait); err != nil {
			// A nonce consumed elsewhere is resolved: it no longer blocks this key. Anything else -
			// still in flight - does.
			if !errors.Is(err, ErrNonceConsumedElsewhere) {
				return err
			}
		}
	}
	return nil
}

// driveToResult waits up to wait for one of entry's hashes to mine, replacing the transaction while it
// does not.
func (s *txSender) driveToResult(ctx context.Context, entry *outboxEntry, latest *types.Transaction,
	onBroadcast func(uint64, string), wait time.Duration) (*types.Receipt, string, error) {

	deadline := time.Now().Add(wait)
	var spentSince time.Time // since when every read has cleanly said "spent, and not ours"
	for {
		clean := true
		for _, h := range entry.Hashes {
			rcpt, err := s.client.TransactionReceipt(ctx, common.HexToHash(h))
			if err == nil && rcpt != nil {
				s.outbox.resolve(entry.Nonce, "mined "+h)
				s.logf("[TX-SENDER] %s nonce=%d mined %s status=%d", entry.Label, entry.Nonce, h, rcpt.Status)
				return rcpt, h, nil
			}
			if err != nil && !errors.Is(err, ethereum.NotFound) {
				// Not an answer - and so not evidence that the hash did not mine.
				clean = false
				s.logf("[TX-SENDER] %s nonce=%d receipt read for %s failed: %v", entry.Label, entry.Nonce, h, err)
			}
		}
		// The nonce is spent but none of our hashes has a receipt. Against a load-balanced RPC the
		// nonce can move before the node answering the receipt query has indexed it, so "consumed
		// elsewhere" - which says the payload did NOT run - needs every receipt read to have been a
		// clean "not found", continuously, for spentGrace.
		mined, nerr := s.client.NonceAt(ctx, s.from, nil)
		if nerr == nil && mined > entry.Nonce && clean {
			if spentSince.IsZero() {
				spentSince = time.Now()
			} else if time.Since(spentSince) >= s.spentGrace() {
				s.outbox.resolve(entry.Nonce, "consumed elsewhere")
				s.logf("[TX-SENDER] %s nonce=%d consumed by a transaction this sender did not send (hashes %v)",
					entry.Label, entry.Nonce, entry.Hashes)
				return nil, "", ErrNonceConsumedElsewhere
			}
		} else {
			spentSince = time.Time{}
		}

		if time.Now().After(deadline) {
			return nil, "", &ChainWaitError{Label: entry.Label, Nonce: entry.Nonce,
				Hashes: append([]string(nil), entry.Hashes...), Err: context.DeadlineExceeded}
		}
		if nerr == nil && mined <= entry.Nonce && time.Since(entry.LastSent) >= s.stuckAfter {
			if next := s.unstick(ctx, entry, latest, mined == entry.Nonce, onBroadcast); next != nil {
				latest = next
			}
		}
		select {
		case <-ctx.Done():
			return nil, "", &ChainWaitError{Label: entry.Label, Nonce: entry.Nonce,
				Hashes: append([]string(nil), entry.Hashes...), Err: ctx.Err()}
		case <-time.After(s.poll):
		}
	}
}

// unstick gets a transaction that is not mining moving again.
//
// A higher fee is offered ONLY when this transaction is the next one the chain will take (next) and
// its price is below what the network charges now: that is the one case a replacement can help. A
// transaction waiting behind a lower nonce, or already priced at the market, is not stuck on price,
// and raising its fee pass after pass would compound without bound. In every other case - and when
// the ceiling will not pay for an acceptable replacement - the latest transaction is re-broadcast
// unchanged, which puts back one a node dropped or evicted. Returns the replacement, or nil.
func (s *txSender) unstick(ctx context.Context, entry *outboxEntry, latest *types.Transaction, next bool,
	onBroadcast func(uint64, string)) *types.Transaction {

	req, err := entry.request()
	if err == nil && next && s.underpriced(ctx, latest) {
		tx, _, perr := s.priceAndSign(ctx, req, latest)
		if perr == nil {
			if _, berr := s.broadcast(ctx, entry, tx, false, onBroadcast); berr == nil {
				s.logf("[TX-SENDER] %s nonce=%d replaced with %s (higher fee)", entry.Label, entry.Nonce, tx.Hash().Hex())
				return tx
			} else {
				s.logf("[TX-SENDER] %s nonce=%d replacement not recorded: %v", entry.Label, entry.Nonce, berr)
			}
		} else {
			s.logf("[TX-SENDER] %s nonce=%d not replaced (%v); re-broadcasting it unchanged", entry.Label, entry.Nonce, perr)
		}
	}
	if err != nil {
		s.logf("[TX-SENDER] %s nonce=%d outbox payload unreadable: %v", entry.Label, entry.Nonce, err)
	}
	if serr := s.client.SendTransaction(ctx, latest); serr != nil && !strings.Contains(strings.ToLower(serr.Error()), "already known") {
		s.logf("[TX-SENDER] %s nonce=%d re-broadcast of %s: %v", entry.Label, entry.Nonce, latest.Hash().Hex(), serr)
	}
	s.outbox.touch(entry.Nonce, time.Now())
	entry.LastSent = time.Now()
	return nil
}

// underpriced reports whether tx pays less than the network charges now: a fee cap below the current
// base fee plus tip, or (on a chain without EIP-1559) a gas price below the suggested price. A read
// that fails is treated as "not known to be underpriced" - it is no reason to raise the fee.
func (s *txSender) underpriced(ctx context.Context, tx *types.Transaction) bool {
	head, err := s.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return false
	}
	if head.BaseFee == nil {
		suggested, err := s.client.SuggestGasPrice(ctx)
		return err == nil && tx.GasPrice().Cmp(suggested) < 0
	}
	tip, err := s.client.SuggestGasTipCap(ctx)
	if err != nil {
		return false
	}
	return tx.GasFeeCap().Cmp(new(big.Int).Add(head.BaseFee, tip)) < 0 || tx.GasTipCap().Cmp(tip) < 0
}

// spentGrace is how long a spent nonce with no receipt of ours must persist before it is concluded
// that another transaction used it: ten receipt polls, and never less than half a minute.
func (s *txSender) spentGrace() time.Duration {
	if s.grace > 0 {
		return s.grace
	}
	if g := 10 * s.poll; g > 30*time.Second {
		return g
	}
	return 30 * time.Second
}

var errReplacementAboveCeiling = errors.New("a replacement fee high enough to be accepted is above the ceiling")

// priceAndSign builds the transaction for req at the current market, or - when prev is set - at the
// higher of the market and prev's fee raised by the replacement margin.
func (s *txSender) priceAndSign(ctx context.Context, req SendRequest, prev *types.Transaction) (*types.Transaction, *big.Int, error) {
	head, err := s.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the head for pricing: %w", err)
	}
	value := req.Value
	if value == nil {
		value = new(big.Int)
	}
	to := req.To

	if head.BaseFee == nil {
		// A chain without EIP-1559: a legacy price.
		suggested, err := s.client.SuggestGasPrice(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("reading the gas price: %w", err)
		}
		price, err := s.ceiling(suggested, suggested, req.Gas)
		if err != nil {
			return nil, nil, err
		}
		if prev != nil {
			min := bumped(prev.GasPrice())
			if price.Cmp(min) < 0 {
				p, err := s.ceiling(suggested, min, req.Gas)
				if err != nil || p.Cmp(min) < 0 {
					return nil, nil, errReplacementAboveCeiling
				}
				price = min
			}
		}
		tx, err := s.sign(types.NewTx(&types.LegacyTx{Nonce: req.Nonce, GasPrice: price, Gas: req.Gas,
			To: &to, Value: value, Data: req.Data}))
		return tx, suggested, err
	}

	tip, err := s.client.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the tip: %w", err)
	}
	// What the network charges now, and a cap that survives the base fee doubling before inclusion.
	network := new(big.Int).Add(head.BaseFee, tip)
	feeCap := new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tip)
	if prev != nil {
		if t := bumped(prev.GasTipCap()); tip.Cmp(t) < 0 {
			tip = t
		}
		if c := bumped(prev.GasFeeCap()); feeCap.Cmp(c) < 0 {
			feeCap = c
		}
		if feeCap.Cmp(tip) < 0 {
			feeCap = new(big.Int).Set(tip)
		}
	}
	clamped, err := s.ceiling(network, feeCap, req.Gas)
	if err != nil {
		return nil, nil, err
	}
	if clamped.Cmp(feeCap) < 0 {
		if prev != nil {
			// A replacement below the required margin would be refused by every node.
			return nil, nil, errReplacementAboveCeiling
		}
		feeCap = clamped
		if tip.Cmp(feeCap) > 0 {
			tip = new(big.Int).Set(feeCap)
		}
	}
	tx, err := s.sign(types.NewTx(&types.DynamicFeeTx{ChainID: s.chainID, Nonce: req.Nonce,
		GasTipCap: tip, GasFeeCap: feeCap, Gas: req.Gas, To: &to, Value: value, Data: req.Data}))
	return tx, network, err
}

// broadcast records tx in the outbox, THEN sends it. Recording first means a crash between the two
// leaves the nonce known, never forgotten. The in-memory entry is updated only once the record is on
// disk, so a failed write leaves no phantom.
//
// rejected is non-nil when a FIRST broadcast was definitively refused: nothing is in flight at this
// nonce, and its record is removed. Every other refusal - a replacement refused, "nonce too low", a
// timeout or dropped connection - leaves the transaction(s) in play for driveToResult to resolve.
func (s *txSender) broadcast(ctx context.Context, entry *outboxEntry, tx *types.Transaction, first bool,
	onBroadcast func(uint64, string)) (rejected error, err error) {

	raw, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	h := tx.Hash().Hex()
	next := *entry
	next.Hashes = append(append([]string(nil), entry.Hashes...), h)
	next.Latest = "0x" + hex.EncodeToString(raw)
	next.LastSent = time.Now()
	if err := s.outbox.put(&next); err != nil {
		if first {
			return nil, &NotBroadcastError{Err: fmt.Errorf("recording %s nonce %d before broadcast: %w", entry.Label, entry.Nonce, err)}
		}
		return nil, fmt.Errorf("recording %s nonce %d replacement: %w", entry.Label, entry.Nonce, err)
	}
	*entry = next
	if onBroadcast != nil {
		onBroadcast(entry.Nonce, h)
	}
	serr := s.client.SendTransaction(ctx, tx)
	if serr == nil {
		return nil, nil
	}
	msg := strings.ToLower(serr.Error())
	if strings.Contains(msg, "already known") {
		return nil, nil
	}
	if first && isDefinitiveRejection(msg) {
		s.outbox.delete(entry.Nonce)
		return fmt.Errorf("broadcasting %s: %w", entry.Label, serr), nil
	}
	s.logf("[TX-SENDER] %s nonce=%d broadcast of %s returned %v - kept in flight until its result is known",
		entry.Label, entry.Nonce, h, serr)
	return nil, nil
}

// isDefinitiveRejection reports whether a node's refusal proves the transaction was NOT accepted into
// its mempool. Anything not listed - timeouts, dropped connections, 5xx, "replacement transaction
// underpriced" (another transaction holds the nonce), "nonce too low" (something mined there) - may
// leave it in flight, and is not treated as a rejection.
func isDefinitiveRejection(msg string) bool {
	if strings.Contains(msg, "replacement transaction underpriced") {
		return false
	}
	for _, s := range []string{
		"insufficient funds",
		"intrinsic gas too low",
		"exceeds block gas limit",
		"gas limit reached",
		"invalid sender",
		"invalid chain id",
		"chain id mismatch",
		"transaction underpriced",
		"fee cap less than block base fee",
		"max fee per gas less than block base fee",
		"max priority fee per gas higher than max fee per gas",
		"tip higher than fee cap",
		"exceeds the configured cap",
		"oversized data",
		"gas uint64 overflow",
		"negative value",
		// The pinned nonce is above the account's next nonce: a sequencer that refuses gaps will
		// never accept it. It is not in flight; the next sequence re-pins from the chain.
		"nonce too high",
		"nonce gap",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

func (s *txSender) latestTx(entry *outboxEntry) (*types.Transaction, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(entry.Latest, "0x"))
	if err != nil {
		return nil, err
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(raw); err != nil {
		return nil, err
	}
	return tx, nil
}

func bumped(v *big.Int) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	out := new(big.Int).Mul(v, big.NewInt(bumpNum))
	out.Div(out, big.NewInt(bumpDen))
	return out.Add(out, big.NewInt(1))
}

func bigString(v *big.Int) string {
	if v == nil {
		return "0"
	}
	return v.String()
}

// =============================================================================
// Outbox - the durable record of this key's transactions, in flight and recently resolved
// =============================================================================

// outboxRetention is how long a resolved entry is kept, so the hashes a nonce went out under can
// still be answered for (hashesAt) after the transaction has mined.
const outboxRetention = 14 * 24 * time.Hour

type outboxEntry struct {
	Nonce  uint64   `json:"nonce"`
	Label  string   `json:"label"`
	Owner  string   `json:"owner,omitempty"`
	To     string   `json:"to"`
	Data   string   `json:"data"`
	Value  string   `json:"value"`
	Gas    uint64   `json:"gas"`
	Hashes []string `json:"hashes"`
	// Latest is the most recently broadcast signed transaction, so a restart can replace it.
	Latest   string    `json:"latest"`
	LastSent time.Time `json:"last_sent"`
	// Resolved: the nonce has a result (Outcome) and is no longer in flight.
	Resolved   bool      `json:"resolved,omitempty"`
	ResolvedAt time.Time `json:"resolved_at,omitempty"`
	Outcome    string    `json:"outcome,omitempty"`
}

func (e *outboxEntry) request() (SendRequest, error) {
	data, err := hex.DecodeString(strings.TrimPrefix(e.Data, "0x"))
	if err != nil {
		return SendRequest{}, err
	}
	v, ok := new(big.Int).SetString(e.Value, 10)
	if !ok {
		return SendRequest{}, fmt.Errorf("outbox value %q", e.Value)
	}
	return SendRequest{Nonce: e.Nonce, To: common.HexToAddress(e.To), Data: data, Value: v, Gas: e.Gas, Label: e.Label}, nil
}

type txOutbox struct {
	mu   sync.Mutex
	path string
	byN  map[uint64]*outboxEntry
	logf func(string, ...interface{})
}

// openTxOutbox loads the outbox at path. An unreadable outbox is an ERROR, not an empty one: treating
// it as empty would forget transactions this key has in flight, which is exactly what it exists to
// prevent.
func openTxOutbox(path string) (*txOutbox, error) {
	o := &txOutbox{path: path, byN: map[uint64]*outboxEntry{}, logf: func(string, ...interface{}) {}}
	blob, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return o, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading tx outbox %s: %w", path, err)
	}
	var list []*outboxEntry
	if err := json.Unmarshal(blob, &list); err != nil {
		return nil, fmt.Errorf("tx outbox %s is corrupt: %w", path, err)
	}
	for _, e := range list {
		o.byN[e.Nonce] = e
	}
	return o, nil
}

// entries returns the entries still in flight, lowest nonce first. Copies: the caller may hold them
// while the outbox changes.
func (o *txOutbox) entries() []*outboxEntry {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]*outboxEntry, 0, len(o.byN))
	for _, e := range o.byN {
		if !e.Resolved {
			cp := *e
			cp.Hashes = append([]string(nil), e.Hashes...)
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Nonce < out[j].Nonce })
	return out
}

// has reports whether a transaction at nonce is still in flight.
func (o *txOutbox) has(nonce uint64) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	e, ok := o.byN[nonce]
	return ok && !e.Resolved
}

// known reports whether this sender has a record at nonce - in flight or resolved.
func (o *txOutbox) known(nonce uint64) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, ok := o.byN[nonce]
	return ok
}

// hashesAt is every hash a transaction at nonce was broadcast under, in flight or resolved - but only
// if that transaction belongs to owner. A nonce can be reused after a definitively rejected first
// broadcast; the entry there is then someone else's, and its hashes say nothing about owner.
func (o *txOutbox) hashesAt(nonce uint64, owner string) []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if e, ok := o.byN[nonce]; ok && owner != "" && e.Owner == owner {
		return append([]string(nil), e.Hashes...)
	}
	return nil
}

// put writes e; the in-memory state changes only if the write succeeds.
func (o *txOutbox) put(e *outboxEntry) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	next := make(map[uint64]*outboxEntry, len(o.byN)+1)
	for k, v := range o.byN {
		next[k] = v
	}
	cp := *e
	cp.Hashes = append([]string(nil), e.Hashes...)
	next[e.Nonce] = &cp
	if err := saveOutbox(o.path, next); err != nil {
		return err
	}
	o.byN = next
	return nil
}

// resolve marks nonce's transaction as having a result. The entry keeps its signed transaction for
// the retention period: it answers which hashes the nonce went out under (hashesAt), and a mined
// transaction that a reorg later drops can still be re-broadcast from it.
func (o *txOutbox) resolve(nonce uint64, outcome string) {
	o.update(nonce, func(e *outboxEntry) {
		e.Resolved, e.ResolvedAt, e.Outcome = true, time.Now(), outcome
	})
}

func (o *txOutbox) touch(nonce uint64, at time.Time) {
	o.update(nonce, func(e *outboxEntry) { e.LastSent = at })
}

// delete forgets an entry whose first broadcast was definitively rejected: nothing was ever in flight.
func (o *txOutbox) delete(nonce uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.byN[nonce]; !ok {
		return
	}
	next := make(map[uint64]*outboxEntry, len(o.byN))
	for k, v := range o.byN {
		if k != nonce {
			next[k] = v
		}
	}
	if err := saveOutbox(o.path, next); err != nil {
		o.logf("[TX-SENDER] outbox write failed removing nonce %d: %v (it will be retried on the next write)", nonce, err)
	}
	o.byN = next
}

func (o *txOutbox) update(nonce uint64, fn func(*outboxEntry)) {
	o.mu.Lock()
	defer o.mu.Unlock()
	cur, ok := o.byN[nonce]
	if !ok {
		return
	}
	cp := *cur
	cp.Hashes = append([]string(nil), cur.Hashes...)
	fn(&cp)
	o.byN[nonce] = &cp
	pruneResolved(o.byN)
	if err := saveOutbox(o.path, o.byN); err != nil {
		// The in-memory record is still right; the next successful write persists it.
		o.logf("[TX-SENDER] outbox write failed updating nonce %d: %v", nonce, err)
	}
}

// pruneResolved drops, in memory, resolved entries past retention - the same ones saveOutbox leaves
// off disk.
func pruneResolved(byN map[uint64]*outboxEntry) {
	cutoff := time.Now().Add(-outboxRetention)
	for n, e := range byN {
		if e.Resolved && e.ResolvedAt.Before(cutoff) {
			delete(byN, n)
		}
	}
}

// saveOutbox writes the outbox atomically - a temp file, fsync'd, renamed over the old one, then the
// directory fsync'd so the rename itself survives a crash - dropping resolved entries past retention.
func saveOutbox(path string, byN map[uint64]*outboxEntry) error {
	cutoff := time.Now().Add(-outboxRetention)
	list := make([]*outboxEntry, 0, len(byN))
	for _, e := range byN {
		if e.Resolved && e.ResolvedAt.Before(cutoff) {
			continue
		}
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Nonce < list[j].Nonce })
	blob, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Directory fsync makes the rename durable on POSIX filesystems. Windows cannot open a directory
	// for syncing and does not need it (MoveFileEx is durable on NTFS), so its error is ignored there.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
