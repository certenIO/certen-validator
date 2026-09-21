package execution

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// txSender against a model chain
// =============================================================================
//
// modelChain implements exactly the node and miner rules the sender depends on, and nothing else:
//
//   - the mempool holds at most one transaction per nonce;
//   - a transaction at an occupied nonce REPLACES it only if its tip and fee cap are both at least
//     10% higher, otherwise it is refused "replacement transaction underpriced" (go-ethereum's
//     txpool rule);
//   - a block includes the account's next-nonce transaction only when its fee cap covers the base
//     fee; an underpriced one stays pending indefinitely, as on a real node;
//   - receipts are served by hash; the account's mined nonce advances with each inclusion.
//
// Failure modes a live node exhibits can be switched on: the base fee it REPORTS can differ from the
// one it charges (how a transaction gets priced below the market and stuck); a broadcast can error
// while having been accepted (a timeout after delivery), or be definitively rejected; receipt reads
// can error; and the mempool can evict a pending transaction.

type modelChain struct {
	mu         sync.Mutex
	chainID    *big.Int
	from       common.Address
	baseFee    *big.Int // what inclusion requires
	reported   *big.Int // what HeaderByNumber reports; nil = the truth
	tip        *big.Int
	mined      uint64                        // the account's mined nonce
	pending    map[uint64]*types.Transaction // mempool, by nonce
	receipts   map[common.Hash]*types.Receipt
	block      uint64
	sendCount  int
	acceptErr  error // returned by SendTransaction AFTER accepting the transaction
	rejectErr  error // returned by SendTransaction INSTEAD of accepting it
	receiptErr error // returned by every receipt read
}

func newModelChain(from common.Address) *modelChain {
	return &modelChain{chainID: big.NewInt(84532), from: from, baseFee: big.NewInt(1_000_000_000),
		tip: big.NewInt(1_000_000), pending: map[uint64]*types.Transaction{}, receipts: map[common.Hash]*types.Receipt{}}
}

func (m *modelChain) HeaderByNumber(context.Context, *big.Int) (*types.Header, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	bf := m.baseFee
	if m.reported != nil {
		bf = m.reported
	}
	return &types.Header{Number: new(big.Int).SetUint64(m.block), BaseFee: new(big.Int).Set(bf)}, nil
}
func (m *modelChain) SuggestGasTipCap(context.Context) (*big.Int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return new(big.Int).Set(m.tip), nil
}
func (m *modelChain) SuggestGasPrice(context.Context) (*big.Int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return new(big.Int).Add(m.baseFee, m.tip), nil
}
func (m *modelChain) SendTransaction(_ context.Context, tx *types.Transaction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendCount++
	if m.rejectErr != nil {
		return m.rejectErr
	}
	if tx.Nonce() < m.mined {
		return errors.New("nonce too low")
	}
	if old, ok := m.pending[tx.Nonce()]; ok {
		if old.Hash() == tx.Hash() {
			return errors.New("already known")
		}
		minTip := new(big.Int).Div(new(big.Int).Mul(old.GasTipCap(), big.NewInt(110)), big.NewInt(100))
		minCap := new(big.Int).Div(new(big.Int).Mul(old.GasFeeCap(), big.NewInt(110)), big.NewInt(100))
		if tx.GasTipCap().Cmp(minTip) < 0 || tx.GasFeeCap().Cmp(minCap) < 0 {
			return errors.New("replacement transaction underpriced")
		}
	}
	m.pending[tx.Nonce()] = tx
	return m.acceptErr
}
func (m *modelChain) TransactionReceipt(_ context.Context, h common.Hash) (*types.Receipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.receiptErr != nil {
		return nil, m.receiptErr
	}
	if r, ok := m.receipts[h]; ok {
		return r, nil
	}
	return nil, ethereum.NotFound
}
func (m *modelChain) NonceAt(context.Context, common.Address, *big.Int) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mined, nil
}
func (m *modelChain) PendingNonceAt(context.Context, common.Address) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.mined
	for {
		if _, ok := m.pending[n]; !ok {
			return n, nil
		}
		n++
	}
}

// mineBlock includes the next-nonce transaction if its fee cap covers the base fee.
func (m *modelChain) mineBlock() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.block++
	tx, ok := m.pending[m.mined]
	if !ok || tx.GasFeeCap().Cmp(m.baseFee) < 0 {
		return
	}
	delete(m.pending, m.mined)
	m.mined++
	m.receipts[tx.Hash()] = &types.Receipt{Status: types.ReceiptStatusSuccessful, TxHash: tx.Hash(),
		BlockNumber: new(big.Int).SetUint64(m.block), GasUsed: 21000}
}

func (m *modelChain) set(fn func(m *modelChain)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(m)
}

type senderRig struct {
	t     *testing.T
	key   *ecdsa.PrivateKey
	chain *modelChain
	path  string
}

func newSenderRig(t *testing.T) *senderRig {
	t.Helper()
	key, _ := crypto.GenerateKey()
	r := &senderRig{t: t, key: key, chain: newModelChain(crypto.PubkeyToAddress(key.PublicKey)),
		path: filepath.Join(t.TempDir(), "outbox.json")}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
				r.chain.mineBlock()
			}
		}
	}()
	t.Cleanup(func() { close(stop); <-done })
	return r
}

func (r *senderRig) sender(ceiling feeCeiling) *txSender {
	outbox, err := openTxOutbox(r.path)
	if err != nil {
		r.t.Fatal(err)
	}
	if ceiling == nil {
		ceiling = func(_, bid *big.Int, _ uint64) (*big.Int, error) { return bid, nil }
	}
	signer := types.LatestSignerForChainID(r.chain.chainID)
	return &txSender{
		client:  r.chain,
		from:    r.chain.from,
		chainID: r.chain.chainID,
		sign: func(tx *types.Transaction) (*types.Transaction, error) {
			return types.SignTx(tx, signer, r.key)
		},
		ceiling:    ceiling,
		outbox:     outbox,
		logf:       func(f string, a ...interface{}) { r.t.Logf(f, a...) },
		stuckAfter: 100 * time.Millisecond,
		sendWait:   5 * time.Second,
		resumeWait: 5 * time.Second,
		poll:       10 * time.Millisecond,
		grace:      150 * time.Millisecond,
	}
}

func (r *senderRig) pendingNonce() uint64 {
	n, _ := r.chain.PendingNonceAt(context.Background(), r.chain.from)
	return n
}

func (r *senderRig) minedNonce() uint64 {
	n, _ := r.chain.NonceAt(context.Background(), r.chain.from, nil)
	return n
}

func payload(nonce uint64) SendRequest {
	return SendRequest{Nonce: nonce, To: common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
		Data: []byte{0xca, 0xfe}, Value: big.NewInt(0), Gas: 60000, Label: "settle", Owner: testOwner}
}

const testOwner = "settle:84532|member-a"

func TestTxSenderMinesAtTheMarketPrice(t *testing.T) {
	r := newSenderRig(t)
	s := r.sender(nil)
	rcpt, h, err := s.Send(context.Background(), payload(r.pendingNonce()))
	if err != nil || rcpt == nil || rcpt.Status != types.ReceiptStatusSuccessful || h == "" {
		t.Fatalf("send: rcpt=%v hash=%q err=%v", rcpt, h, err)
	}
	if n := len(s.outbox.entries()); n != 0 {
		t.Fatalf("%d entries still in flight after the transaction mined", n)
	}
	if got := s.outbox.hashesAt(0, testOwner); len(got) != 1 || !strings.EqualFold(got[0], h) {
		t.Fatalf("history at nonce 0 = %v; the mined hash must stay answerable", got)
	}
}

// THE defect: a transaction priced below what the chain charges used to wait for ever. It is
// replaced at the same nonce with a higher fee, and the replacement mines.
func TestTxSenderReplacesAStuckTransactionAtTheSameNonce(t *testing.T) {
	r := newSenderRig(t)
	s := r.sender(nil)
	r.chain.set(func(m *modelChain) { m.reported = big.NewInt(1) }) // reports a base fee far below the real one

	var mu sync.Mutex
	var seen []string
	nonce := r.pendingNonce()
	req := payload(nonce)
	req.OnBroadcast = func(n uint64, h string) {
		mu.Lock()
		defer mu.Unlock()
		if n != nonce {
			t.Errorf("broadcast at nonce %d, want %d", n, nonce)
		}
		seen = append(seen, h)
		r.chain.set(func(m *modelChain) { m.reported = nil }) // the market is visible for the replacement
	}
	rcpt, h, err := s.Send(context.Background(), req)
	if err != nil || rcpt == nil || rcpt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("send: rcpt=%v err=%v", rcpt, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) < 2 || strings.EqualFold(h, seen[0]) {
		t.Fatalf("broadcasts %v, mined %s; want the underpriced original replaced and a replacement mined", seen, h)
	}
	if r.minedNonce() != nonce+1 {
		t.Fatalf("mined nonce %d, want %d: exactly one transaction at the nonce", r.minedNonce(), nonce+1)
	}
}

// The market moves after the send (the base fee rises well above the fee cap) while the suggested tip
// stays where it was. The replacement must still raise the TIP by the node's margin as well as the
// cap, or the node refuses it; the model chain enforces that rule, so mining proves it was met.
func TestTxSenderReplacementClearsTheNodesReplacementRule(t *testing.T) {
	r := newSenderRig(t)
	s := r.sender(nil)
	r.chain.set(func(m *modelChain) { m.reported = big.NewInt(1_000_000_000) }) // priced from 1 gwei
	req := payload(r.pendingNonce())
	req.OnBroadcast = func(uint64, string) {
		r.chain.set(func(m *modelChain) {
			m.reported = nil
			m.baseFee = big.NewInt(5_000_000_000) // the market is now 5 gwei; the tip is unchanged
		})
	}
	if rcpt, _, err := s.Send(context.Background(), req); err != nil || rcpt == nil {
		t.Fatalf("a replacement that clears the 10%% rule must be accepted and mine: %v", err)
	}
}

// A bound that runs out is "not yet known", never a failure. The transaction stays in the outbox on
// disk; a restarted sender drives it forward, and a replacement it makes while no caller is listening
// is in the nonce's history - the record that lets that settlement be attributed later.
func TestTxSenderBoundedWaitIsResumedAfterARestartAndItsHistoryKept(t *testing.T) {
	r := newSenderRig(t)
	s := r.sender(nil)
	s.sendWait = 300 * time.Millisecond
	s.stuckAfter = time.Hour // no replacement inside the bound
	r.chain.set(func(m *modelChain) { m.reported = big.NewInt(1) })

	nonce := r.pendingNonce()
	_, _, err := s.Send(context.Background(), payload(nonce))
	var cwe *ChainWaitError
	if !errors.As(err, &cwe) || cwe.Nonce != nonce || len(cwe.Hashes) != 1 {
		t.Fatalf("err = %v; want *ChainWaitError at nonce %d carrying its hash", err, nonce)
	}
	if !isTransientSendError(err) || !keyBusy(err) {
		t.Fatal("a bounded-out wait was classified as a failure, or not as a busy key")
	}
	original := cwe.Hashes[0]

	r.chain.set(func(m *modelChain) { m.reported = nil })
	resumed := r.sender(nil) // a restart: a new sender over the same outbox file
	resumed.stuckAfter = 50 * time.Millisecond
	if !resumed.outbox.has(nonce) {
		t.Fatal("the in-flight transaction was not persisted across the restart")
	}
	if err := resumed.Resume(context.Background()); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if resumed.outbox.has(nonce) || r.minedNonce() != nonce+1 {
		t.Fatal("resume left the transaction outstanding")
	}
	hist := resumed.outbox.hashesAt(nonce, testOwner)
	if len(hist) < 2 || !strings.EqualFold(hist[0], original) {
		t.Fatalf("history at nonce %d = %v; want the original and the replacement Resume made", nonce, hist)
	}
}

// Resume is bounded and says so: while an old transaction is still stuck, nothing new may be sent.
func TestTxSenderResumeReportsAStillStuckTransaction(t *testing.T) {
	r := newSenderRig(t)
	s := r.sender(nil)
	s.sendWait, s.resumeWait, s.stuckAfter = 150*time.Millisecond, 150*time.Millisecond, time.Hour
	r.chain.set(func(m *modelChain) { m.reported = big.NewInt(1) })
	if _, _, err := s.Send(context.Background(), payload(r.pendingNonce())); err == nil {
		t.Fatal("an underpriced transaction mined")
	}
	start := time.Now()
	var cwe *ChainWaitError
	if err := s.Resume(context.Background()); !errors.As(err, &cwe) {
		t.Fatalf("resume = %v; want *ChainWaitError while the transaction is still stuck", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("resume took %s; it must return at its own short bound", time.Since(start))
	}
}

// Another transaction took the nonce: none of this request's hashes ran, and that is reported as
// such - not a success, not a revert - once it has held for the grace period.
func TestTxSenderReportsANonceConsumedElsewhere(t *testing.T) {
	r := newSenderRig(t)
	s := r.sender(nil)
	s.stuckAfter = time.Hour
	r.chain.set(func(m *modelChain) { m.reported = big.NewInt(1) })
	nonce := r.pendingNonce()

	errc := make(chan error, 1)
	go func() {
		_, _, err := s.Send(context.Background(), payload(nonce))
		errc <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for !s.outbox.has(nonce) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	signer := types.LatestSignerForChainID(r.chain.chainID)
	other, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{ChainID: r.chain.chainID, Nonce: nonce,
		GasTipCap: big.NewInt(1_000_000_000), GasFeeCap: big.NewInt(50_000_000_000), Gas: 21000,
		To: &r.chain.from, Value: big.NewInt(1)}), signer, r.key)
	if err := r.chain.SendTransaction(context.Background(), other); err != nil {
		t.Fatalf("sending the other transaction: %v", err)
	}
	if err := <-errc; !errors.Is(err, ErrNonceConsumedElsewhere) {
		t.Fatalf("err = %v; want ErrNonceConsumedElsewhere", err)
	}
	if s.outbox.has(nonce) {
		t.Fatal("a nonce resolved as consumed elsewhere is still in flight")
	}
}

// A receipt read that ERRORS is not evidence of absence. Our transaction mines while every receipt
// read fails; the sender must not conclude "consumed elsewhere" - it waits, and when reads recover
// it finds its own receipt.
func TestTxSenderReadErrorsAreNotEvidenceOfAbsence(t *testing.T) {
	r := newSenderRig(t)
	s := r.sender(nil)
	r.chain.set(func(m *modelChain) { m.receiptErr = errors.New("429 too many requests") })
	go func() {
		time.Sleep(600 * time.Millisecond) // four grace periods of failing reads
		r.chain.set(func(m *modelChain) { m.receiptErr = nil })
	}()
	rcpt, _, err := s.Send(context.Background(), payload(r.pendingNonce()))
	if err != nil || rcpt == nil {
		t.Fatalf("err = %v; a transaction that mined behind failing reads must be found, not declared consumed elsewhere", err)
	}
}

// A broadcast that ERRORS may still have been accepted (a timeout after delivery). It is kept in
// flight and driven to its result - never forgotten, and its nonce never handed out again.
func TestTxSenderKeepsAnAmbiguouslyBroadcastTransactionInFlight(t *testing.T) {
	r := newSenderRig(t)
	s := r.sender(nil)
	r.chain.set(func(m *modelChain) { m.acceptErr = errors.New("context deadline exceeded") })
	rcpt, _, err := s.Send(context.Background(), payload(r.pendingNonce()))
	if err != nil || rcpt == nil {
		t.Fatalf("err = %v; an accepted-but-errored broadcast must be driven to its receipt", err)
	}
}

// A DEFINITIVE rejection means nothing reached a mempool: the send is NotBroadcast, nothing is left
// in the outbox, and the nonce stays free.
func TestTxSenderDefinitiveRejectionLeavesNothingInFlight(t *testing.T) {
	r := newSenderRig(t)
	s := r.sender(nil)
	r.chain.set(func(m *modelChain) { m.rejectErr = errors.New("insufficient funds for gas * price + value") })
	nonce := r.pendingNonce()
	_, _, err := s.Send(context.Background(), payload(nonce))
	var nb *NotBroadcastError
	if !errors.As(err, &nb) || s.outbox.has(nonce) || len(s.outbox.hashesAt(nonce, testOwner)) != 0 {
		t.Fatalf("err = %v in flight=%t; want NotBroadcast and nothing recorded", err, s.outbox.has(nonce))
	}
}

// A transaction the mempool drops is put back, even when the ceiling will not pay for a replacement.
func TestTxSenderRebroadcastsAnEvictedTransaction(t *testing.T) {
	r := newSenderRig(t)
	var calls int
	var mu sync.Mutex
	ceiling := func(_, bid *big.Int, _ uint64) (*big.Int, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls > 1 {
			return nil, &ErrGasCeilingExceeded{ChainID: 84532, SuggestedGwei: 9, CeilingGwei: 1}
		}
		return bid, nil
	}
	s := r.sender(ceiling)
	nonce := r.pendingNonce()
	// Evict on the first broadcast, before any block can include it.
	r.chain.set(func(m *modelChain) { m.baseFee = big.NewInt(1 << 62) })
	errc := make(chan error, 1)
	go func() {
		_, _, err := s.Send(context.Background(), payload(nonce))
		errc <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for !s.outbox.has(nonce) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	r.chain.set(func(m *modelChain) {
		delete(m.pending, nonce)              // the node evicts it
		m.baseFee = big.NewInt(1_000_000_000) // and the market returns
	})
	if err := <-errc; err != nil {
		t.Fatalf("err = %v; an evicted transaction must be re-broadcast and mine", err)
	}
}

// A ceiling refusal sends nothing: no broadcast, no outbox entry, and the nonce is left unused.
func TestTxSenderCeilingRefusalSendsNothing(t *testing.T) {
	r := newSenderRig(t)
	refuse := func(_, _ *big.Int, _ uint64) (*big.Int, error) {
		return nil, &ErrGasCeilingExceeded{ChainID: 84532, SuggestedGwei: 999, CeilingGwei: 1}
	}
	s := r.sender(refuse)
	nonce := r.pendingNonce()
	_, _, err := s.Send(context.Background(), payload(nonce))
	var nb *NotBroadcastError
	var gasCeil *ErrGasCeilingExceeded
	if !errors.As(err, &nb) || !errors.As(err, &gasCeil) {
		t.Fatalf("err = %v; want a NotBroadcastError carrying the ceiling refusal", err)
	}
	r.chain.mu.Lock()
	sent := r.chain.sendCount
	r.chain.mu.Unlock()
	if s.outbox.has(nonce) || sent != 0 || r.pendingNonce() != nonce {
		t.Fatal("a refused send left something in flight")
	}
}

// A replacement the ceiling will not pay for is not sent; the original keeps waiting (and is
// re-broadcast as it is).
func TestTxSenderDoesNotReplaceAboveTheCeiling(t *testing.T) {
	r := newSenderRig(t)
	var calls int
	var mu sync.Mutex
	ceiling := func(_, bid *big.Int, _ uint64) (*big.Int, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls > 1 {
			return big.NewInt(2), nil // clamps below any acceptable replacement
		}
		return bid, nil
	}
	s := r.sender(ceiling)
	s.sendWait = 400 * time.Millisecond
	r.chain.set(func(m *modelChain) { m.reported = big.NewInt(1) })
	_, _, err := s.Send(context.Background(), payload(r.pendingNonce()))
	var cwe *ChainWaitError
	if !errors.As(err, &cwe) || len(cwe.Hashes) != 1 {
		t.Fatalf("err = %v; want a ChainWaitError with only the original hash (no over-ceiling replacement)", err)
	}
}

// An outbox that cannot be read is an error, never an empty outbox: an empty one would forget the
// transactions this key has in flight.
func TestTxOutboxRefusesACorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openTxOutbox(path); err == nil {
		t.Fatal("a corrupt outbox was opened as empty")
	}
}

// A failed write leaves no phantom: the in-memory outbox changes only when the disk does.
func TestTxOutboxFailedWriteLeavesNoPhantom(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := &txOutbox{path: filepath.Join(blocker, "outbox.json"), byN: map[uint64]*outboxEntry{}, logf: func(string, ...interface{}) {}}
	if err := o.put(&outboxEntry{Nonce: 5, Hashes: []string{"0xaa"}}); err == nil {
		t.Fatal("a write into a path under a file succeeded")
	}
	if o.has(5) || len(o.hashesAt(5, "")) != 0 {
		t.Fatal("a failed write left an in-flight entry in memory")
	}
}

// Rewinding gives back EXACTLY the nonce that was handed out, and only if it is still the last one;
// decrementing past a nonce another send holds would issue it twice.
func TestRewindNonceGivesBackOnlyTheLastNonce(t *testing.T) {
	ecm := &EthereumContractManager{nonceActive: true, nonceSeq: 10}
	a, _ := ecm.takeNonce() // 10
	b, _ := ecm.takeNonce() // 11
	ecm.rewindNonce(a)      // not the last: ignored
	if n, _ := ecm.takeNonce(); n != 12 {
		t.Fatalf("after rewinding a non-last nonce the next is %d, want 12", n)
	}
	ecm.rewindNonce(12)
	if n, _ := ecm.takeNonce(); n != 12 {
		t.Fatalf("after rewinding the last nonce the next is %d, want 12", n)
	}
	_ = b
}

// A nonce given back after a definitively rejected broadcast can carry another member's transaction.
// Its history is answered only to its owner, so it is never read as the first member's settlement.
func TestTxOutboxHistoryIsAnsweredOnlyToItsOwner(t *testing.T) {
	r := newSenderRig(t)
	s := r.sender(nil)
	nonce := r.pendingNonce()
	r.chain.set(func(m *modelChain) { m.rejectErr = errors.New("max fee per gas less than block base fee") })
	if _, _, err := s.Send(context.Background(), payload(nonce)); err == nil {
		t.Fatal("a rejected broadcast succeeded")
	}
	r.chain.set(func(m *modelChain) { m.rejectErr = nil })
	other := payload(nonce) // the same nonce, reused for another member's transaction
	other.Owner, other.Data = "settle:84532|member-b", []byte{0xbe, 0xef}
	if _, _, err := s.Send(context.Background(), other); err != nil {
		t.Fatalf("the reused nonce's send: %v", err)
	}
	if got := s.outbox.hashesAt(nonce, testOwner); len(got) != 0 {
		t.Fatalf("member-a reads %v at the reused nonce; that transaction is member-b's", got)
	}
	if got := s.outbox.hashesAt(nonce, other.Owner); len(got) != 1 {
		t.Fatalf("member-b reads %v at its own nonce; want its one hash", got)
	}
}

// A transaction waiting behind a LOWER nonce, or already priced at the market, is not stuck on price:
// its fee is not raised, however long it waits. Only re-broadcast.
func TestTxSenderDoesNotEscalateFeesWhenPriceIsNotTheCause(t *testing.T) {
	r := newSenderRig(t)
	s := r.sender(nil)
	s.sendWait = 600 * time.Millisecond
	s.stuckAfter = 20 * time.Millisecond
	nonce := r.pendingNonce()
	// A gap: something at nonce-0 is missing, so our transaction at nonce+1 can never be next.
	req := payload(nonce + 1)
	var broadcasts int
	var mu sync.Mutex
	req.OnBroadcast = func(uint64, string) { mu.Lock(); broadcasts++; mu.Unlock() }
	_, _, err := s.Send(context.Background(), req)
	var cwe *ChainWaitError
	if !errors.As(err, &cwe) {
		t.Fatalf("err = %v; want a ChainWaitError while the gap is open", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if broadcasts != 1 || len(cwe.Hashes) != 1 {
		t.Fatalf("%d broadcasts (%d hashes) while waiting behind a gap; the fee must not be raised", broadcasts, len(cwe.Hashes))
	}
}
