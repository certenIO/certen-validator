// Copyright 2026 Certen Protocol
//
// Quorum-attested non-settlement: the failure record of a member that never settled.

package execution

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// Non-settlement
// =============================================================================
//
// A member that never reached its chain - dropped from its batch, or past its deadline before it
// could be sent - has no transaction to observe, and its failure used to be recorded nowhere: the
// record was a proof cycle with no transaction, which the adapter refused (RB3-F49).
//
// Its failure is now a result like any other, attested by a quorum and written back. What the quorum
// attests is a CHAIN FACT every validator can check for itself: at a finalized block past the member's
// deadline, the member's leaf is not consumed on its account. Each peer computes the leaf, the account
// and the deadline from ITS OWN copy of the member - the same data it co-signs batches from - so a
// requester cannot pass off an unrelated, trivially unspent leaf as an intent's failure.
//
// Past the deadline an honest settlement can no longer execute - its proof's expiresAt is the
// deadline and the account enforces it (settlementExpiry) - so "not consumed after the deadline" is
// the member's outcome, not a snapshot of one still in flight. (A key holder writing its own
// expiresAt could still spend an attested leaf late; that closes only on chain, design §7.)

// nonSettlementFinality is how far past the member's deadline the observed block must be: a settlement
// broadcast before the deadline has had time to be mined, or to revert on its expiry.
const nonSettlementFinality = 2 * time.Minute

// NonSettlementClaim is what a non-settlement attestation states (defined beside the message it rides in).
type NonSettlementClaim = attestation.NonSettlementClaim

// nonSettlementResultHash is the result a non-settlement attestation signs - domain-separated from any
// settlement's result hash, over the facts a peer re-derives. The cause is the requester's account of
// why; it is in the signed message but not in the result, since no peer can observe it on chain.
func nonSettlementResultHash(c *NonSettlementClaim) [32]byte {
	h := sha256.New()
	h.Write([]byte("certen:nonsettlement:v1"))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(c.ChainID))
	h.Write(b[:])
	for _, s := range []string{c.Account, c.OperationID, c.Leaf, c.BlockHash} {
		h.Write([]byte(strings.ToLower(s)))
		h.Write([]byte{0})
	}
	for _, n := range []int64{c.Deadline, int64(c.Block), c.BlockTime} {
		binary.BigEndian.PutUint64(b[:], uint64(n))
		h.Write(b[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// NonSettlementFacts is what a non-settlement is about: one member's identity on its chain, its
// account, its leaf and its deadline - computed from the member, never taken from a request.
type NonSettlementFacts struct {
	IntentID    string         `json:"intent_id"`
	ChainID     int64          `json:"chain_id"`
	OperationID [32]byte       `json:"operation_id"`
	Account     common.Address `json:"account"`
	Leaf        [32]byte       `json:"leaf"`
	Deadline    time.Time      `json:"deadline"`
}

// memberFacts computes a member's non-settlement facts.
func memberFacts(p *PendingBatchIntent) (NonSettlementFacts, error) {
	if p == nil {
		return NonSettlementFacts{}, fmt.Errorf("no member")
	}
	d, ok := p.Deadline()
	if !ok {
		return NonSettlementFacts{}, fmt.Errorf("member %s on chain %d has no deadline; its non-settlement can never be final",
			p.IntentID, p.ChainID)
	}
	leaf, err := p.Leaf()
	if err != nil {
		return NonSettlementFacts{}, err
	}
	return NonSettlementFacts{IntentID: p.IntentID, ChainID: p.ChainID, OperationID: p.OperationID,
		Account: p.Account, Leaf: leaf, Deadline: d}, nil
}

// NonSettlementChain reads what a non-settlement rests on.
type NonSettlementChain interface {
	// FinalizedHeader is the chain's latest finalized block header.
	FinalizedHeader(ctx context.Context, chainID int64) (*types.Header, error)
	// HeaderAt is the header of block number.
	HeaderAt(ctx context.Context, chainID int64, number uint64) (*types.Header, error)
	// LeafConsumedAt reads the account's isLeafConsumed(leaf) as of block number.
	LeafConsumedAt(ctx context.Context, chainID int64, account common.Address, leaf [32]byte, number uint64) (bool, error)
}

// NonSettlementChainFromResolver reads through the batch path's chain managers.
func NonSettlementChainFromResolver(chains EVMChainResolver) NonSettlementChain {
	return resolverNonSettlementChain{chains}
}

type resolverNonSettlementChain struct{ chains EVMChainResolver }

func (r resolverNonSettlementChain) client(chainID int64) (*EthereumContractManager, error) {
	ecm, _, err := r.chains.ManagerForChain(chainID)
	if err != nil {
		return nil, err
	}
	if ecm == nil || ecm.client == nil {
		return nil, fmt.Errorf("no chain client for chain %d", chainID)
	}
	return ecm, nil
}

// clock is the chain's clock (chain_clock.go): a non-settlement's and a predecessor's time is read there (T-6..T-8).
func (r resolverNonSettlementChain) clock(chainID int64) (*ChainClock, error) {
	ecm, err := r.client(chainID)
	if err != nil {
		return nil, err
	}
	primary := ""
	if ecm.config != nil {
		primary = ecm.config.EthereumRPC
	}
	return chainClockFor(chainID, primary), nil
}

func (r resolverNonSettlementChain) FinalizedHeader(ctx context.Context, chainID int64) (*types.Header, error) {
	c, err := r.clock(chainID)
	if err != nil {
		return nil, err
	}
	return c.Finalized(ctx)
}

func (r resolverNonSettlementChain) HeaderAt(ctx context.Context, chainID int64, number uint64) (*types.Header, error) {
	c, err := r.clock(chainID)
	if err != nil {
		return nil, err
	}
	return c.HeaderAt(ctx, number)
}

func (r resolverNonSettlementChain) LeafConsumedAt(ctx context.Context, chainID int64, account common.Address, leaf [32]byte, number uint64) (bool, error) {
	ecm, err := r.client(chainID)
	if err != nil {
		return false, err
	}
	return leafConsumedAt(ctx, ecm.client, account, leaf, number)
}

// leafChain is what reading a leaf needs: the account's state, headers and logs.
type leafChain interface {
	bind.ContractBackend
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
}

// leafConsumedAt answers whether the account had consumed leaf as of block number.
//
// A consumed leaf stays consumed, and every consumption emits LeafConsumed(anchorId, leaf, operationID). So the leaf
// was consumed as of number exactly when it is consumed at the chain's head and no LeafConsumed for it was emitted
// after number. That needs contract state only at the head and logs for the blocks since: it used to be an eth_call
// AT number, and a node that keeps no state that old - Arbitrum Sepolia's finalized block trails its head by ~4,500
// blocks - failed every read ("historical state … is not available"), so a sequential successor whose predecessor
// was on Arbitrum waited forever (RB4-F65).
//
// An account with no code at the head has consumed nothing (RB3-F63: it used to be a failed read). Any other failure
// - the head, the call, the logs - stays a read error, which decides nothing.
func leafConsumedAt(ctx context.Context, c leafChain, account common.Address, leaf [32]byte, number uint64) (bool, error) {
	head, err := c.HeaderByNumber(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("reading the chain head: %w", err)
	}
	latest := head.Number.Uint64()
	if number > latest {
		return false, fmt.Errorf("block %d is past the chain head %d", number, latest)
	}
	acct, err := contracts.NewCertenAccountV7_2(account, c)
	if err != nil {
		return false, err
	}
	consumed, err := acct.IsLeafConsumed(&bind.CallOpts{Context: ctx, BlockNumber: new(big.Int).SetUint64(latest)}, leaf)
	if errors.Is(err, bind.ErrNoCode) {
		return false, nil
	}
	if err != nil || !consumed || number == latest {
		return consumed, err
	}
	q := ethereum.FilterQuery{
		Addresses: []common.Address{account},
		Topics:    [][]common.Hash{{leafConsumedTopic}, nil, {common.Hash(leaf)}},
	}
	after, err := filterLogsSplitting(ctx, c, q, number+1, latest)
	if err != nil {
		return false, fmt.Errorf("reading LeafConsumed for leaf %x after block %d: %w", leaf[:8], number, err)
	}
	return len(after) == 0, nil
}

// Outcomes of looking for a non-settlement that are not a failure of the look.
var (
	// errNotYetAttestable: the chain's finalized time is not yet past the member's deadline.
	errNotYetAttestable = errors.New("non-settlement not attestable yet: the finalized chain is not past the member's deadline")
	// errMemberSettled: the member's leaf IS consumed - it settled, and has no non-settlement.
	errMemberSettled = errors.New("the member's leaf is consumed: it settled")
)

// observeNonSettlement establishes a member's non-settlement at the chain's latest finalized block.
func observeNonSettlement(ctx context.Context, rd NonSettlementChain, f NonSettlementFacts, cause string) (*NonSettlementClaim, *chain.ObservationResult, error) {
	return observeNonSettlementAt(ctx, rd, f, cause, 0)
}

// observeNonSettlementAt is observeNonSettlement at a pinned block: once a non-settlement was first observed at block
// pinned, every later attempt claims it at that same block (0: not pinned yet - the latest finalized block). It waits
// until this node's view of the chain has finalized the pinned block.
//
// RB5-F46: the claim used to move to the requester's newest finalized block on every attempt. The validators read one
// load-balanced endpoint whose backends disagree on the finalized head by minutes, so peers behind the requester's
// backend refused each claim as "not finalized here" (intent bb72e258, 2026-10-02: claim at 47608254, peers finalized at
// 47608085) - and the next attempt chased a newer block again. Pinned, the peers reach the block and the quorum forms.
func observeNonSettlementAt(ctx context.Context, rd NonSettlementChain, f NonSettlementFacts, cause string, pinned uint64) (*NonSettlementClaim, *chain.ObservationResult, error) {
	account, leaf, deadline := f.Account, f.Leaf, f.Deadline
	head, err := rd.FinalizedHeader(ctx, f.ChainID)
	if err != nil {
		return nil, nil, readErr(fmt.Errorf("reading the finalized block of chain %d: %w", f.ChainID, err))
	}
	if pinned != 0 {
		if head.Number.Uint64() < pinned {
			return nil, nil, fmt.Errorf("%w (the claim is pinned at block %d; finalized here %d)", errNotYetAttestable,
				pinned, head.Number.Uint64())
		}
		if head, err = rd.HeaderAt(ctx, f.ChainID, pinned); err != nil {
			return nil, nil, readErr(fmt.Errorf("reading the pinned block %d of chain %d: %w", pinned, f.ChainID, err))
		}
	}
	if int64(head.Time) <= deadline.Add(nonSettlementFinality).Unix() {
		// Blocked only because no finalized block is past the horizon yet: on a chain whose blocks stop when idle, the
		// clock's heartbeat makes one (RB7 T-6, rule 10). The block decides, by this same predicate.
		awaitChainTime(f.ChainID, fmt.Sprintf("the non-settlement of %s", f.IntentID), uint64(deadline.Add(nonSettlementFinality).Unix()))
		return nil, nil, fmt.Errorf("%w (finalized %s, deadline %s)", errNotYetAttestable,
			time.Unix(int64(head.Time), 0).UTC().Format(time.RFC3339), deadline.Format(time.RFC3339))
	}
	consumed, err := rd.LeafConsumedAt(ctx, f.ChainID, account, leaf, head.Number.Uint64())
	if err != nil {
		return nil, nil, readErr(fmt.Errorf("reading isLeafConsumed at block %d: %w", head.Number.Uint64(), err))
	}
	if consumed {
		return nil, nil, errMemberSettled
	}
	claim := &NonSettlementClaim{
		ChainID: f.ChainID, Account: account.Hex(), OperationID: common.Hash(f.OperationID).Hex(),
		Leaf: common.Hash(leaf).Hex(), Deadline: deadline.Unix(), Block: head.Number.Uint64(),
		BlockHash: head.Hash().Hex(), BlockTime: int64(head.Time), Cause: cause,
	}
	obs := &chain.ObservationResult{
		BlockNumber: claim.Block, BlockHash: claim.BlockHash, BlockTimestamp: time.Unix(claim.BlockTime, 0).UTC(),
		IsFinalized: true, ResultHash: nonSettlementResultHash(claim),
	}
	return claim, obs, nil
}

// verifyNonSettlementClaim is a peer's independent check of a requester's claim, from the peer's own
// copy of the member and its own reads of the chain. It returns nil only when the peer reproduces
// the claim's result hash exactly.
func verifyNonSettlementClaim(ctx context.Context, rd NonSettlementChain, own *PendingBatchIntent, msg *attestation.AttestationMessage) error {
	if msg.NonSettlement == nil {
		return fmt.Errorf("no non-settlement claim")
	}
	f, err := memberFacts(own)
	if err != nil {
		return err
	}
	return verifyNonSettlementFacts(ctx, rd, f, msg)
}

// verifyNonSettlementFacts is verifyNonSettlementClaim from this validator's own facts of the member: its queued copy,
// or the tree it kept and signed (keptMemberFacts).
func verifyNonSettlementFacts(ctx context.Context, rd NonSettlementChain, f NonSettlementFacts, msg *attestation.AttestationMessage) error {
	c := msg.NonSettlement
	if c == nil {
		return fmt.Errorf("no non-settlement claim")
	}
	account, leaf, deadline := f.Account, f.Leaf, f.Deadline
	if !strings.EqualFold(c.Account, account.Hex()) || !strings.EqualFold(c.Leaf, common.Hash(leaf).Hex()) ||
		c.Deadline != deadline.Unix() || c.ChainID != f.ChainID ||
		!strings.EqualFold(c.OperationID, common.Hash(f.OperationID).Hex()) {
		return fmt.Errorf("the claim's member (account %s, leaf %s, deadline %d) is not this validator's member (account %s, leaf %s, deadline %d)",
			c.Account, c.Leaf, c.Deadline, account.Hex(), common.Hash(leaf).Hex(), deadline.Unix())
	}
	fin, err := rd.FinalizedHeader(ctx, c.ChainID)
	if err != nil {
		return readErr(fmt.Errorf("reading the finalized block: %w", err))
	}
	if c.Block > fin.Number.Uint64() {
		return fmt.Errorf("block %d is not finalized here (finalized %d): %w", c.Block, fin.Number.Uint64(), ErrNotYetFinalized)
	}
	hdr, err := rd.HeaderAt(ctx, c.ChainID, c.Block)
	if err != nil {
		return readErr(fmt.Errorf("reading block %d: %w", c.Block, err))
	}
	if !strings.EqualFold(hdr.Hash().Hex(), c.BlockHash) || int64(hdr.Time) != c.BlockTime {
		return fmt.Errorf("block %d is %s at %d here, the claim says %s at %d", c.Block, hdr.Hash().Hex(), hdr.Time, c.BlockHash, c.BlockTime)
	}
	if c.BlockTime <= deadline.Add(nonSettlementFinality).Unix() {
		return fmt.Errorf("block %d (time %d) is not past the member's deadline %d with its finality margin", c.Block, c.BlockTime, deadline.Unix())
	}
	consumed, err := rd.LeafConsumedAt(ctx, c.ChainID, account, leaf, c.Block)
	if err != nil {
		return readErr(fmt.Errorf("reading isLeafConsumed at block %d: %w", c.Block, err))
	}
	if consumed {
		return fmt.Errorf("the member's leaf is consumed at block %d: it settled", c.Block)
	}
	if want := nonSettlementResultHash(c); want != msg.ResultHash {
		return fmt.Errorf("result hash %x does not match the claim's %x", msg.ResultHash[:8], want[:8])
	}
	return nil
}
