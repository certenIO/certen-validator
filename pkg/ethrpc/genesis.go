package ethrpc

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/supportedchains"
)

// =============================================================================
// The genesis pin: which chain of a chain id a provider serves (RB7 D8)
// =============================================================================
//
// A testnet that is reset keeps its chain id: Telcoin's Adiri (2017) has had more than one incarnation. A provider's
// chain id therefore says which NETWORK it serves, not which chain: after a reset every CERTEN contract, settlement and
// leaf on the old chain is gone, and the same addresses and heights on the new chain mean something else. A chain the
// catalogue pins (supportedchains.Chain.PinnedGenesis) is read only from providers whose block 0 is the pinned one:
//
//   - at construction (verifyOne), beside the chain id: a provider serving another genesis refuses the reader outright,
//     like one serving another chain id, and one whose genesis cannot be read is not verified (it is asked for nothing);
//   - on every read: before a provider's answer is counted, its genesis is read again whenever the last reading is older
//     than GenesisRecheck. A provider found on another genesis fails the whole read by name (ErrGenesisMismatch) - the
//     chain as served is no longer the pinned chain, and nothing read from it is a fact of that chain;
//   - the client a validator SENDS through is checked at boot (execution.VerifySettlementAnchors) and before every
//     batch-lane send (execution sendBatchTx, the same GenesisRecheck bound): nothing is sent to another incarnation.
//
// A chain that is not pinned is never asked for block 0: its reads are exactly what they were.

// ErrGenesisMismatch: a provider serves a chain whose block 0 is not the pinned genesis - a reset testnet, or a provider
// for another incarnation. It is a refusal, not an outage: it does not resolve by waiting, only by changing the pin
// (supportedchains.Chain.PinnedGenesis) once the operators have decided the new chain is to be settled on.
var ErrGenesisMismatch = errors.New("the provider serves another genesis than the chain is pinned to")

// GenesisRecheck bounds how old a provider's genesis reading may be when one of its answers is counted.
const GenesisRecheck = 30 * time.Second

// genesisRecheck is the bound in force; tests shorten it.
var genesisRecheck = GenesisRecheck

// PinnedGenesis is the genesis hash chainID is pinned to, and whether it is pinned (supportedchains.PinnedGenesisOf).
func PinnedGenesis(chainID int64) (common.Hash, bool, error) {
	h, ok, err := supportedchains.PinnedGenesisOf(chainID)
	if err != nil || !ok {
		return common.Hash{}, false, err
	}
	return common.HexToHash(h), true, nil
}

// headerByNumber is what reading a genesis needs.
type headerByNumber interface {
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
}

// genesisOf reads a provider's block 0 and returns its hash, computed from the header it serves: a provider cannot name
// a hash its header does not hash to.
func genesisOf(ctx context.Context, c headerByNumber) (common.Hash, error) {
	h, err := c.HeaderByNumber(ctx, new(big.Int))
	if err != nil {
		return common.Hash{}, err
	}
	if h == nil || h.Number == nil || h.Number.Sign() != 0 {
		return common.Hash{}, fmt.Errorf("its block 0 read back as another block")
	}
	return h.Hash(), nil
}

// genesisMismatch names a provider serving another genesis.
func genesisMismatch(chainID int64, host string, got, pin common.Hash) error {
	return fmt.Errorf("%w: chain %d provider %s serves genesis %s, the chain is pinned to %s (%s) - a reset or another "+
		"incarnation of chain %d is not the chain CERTEN settles on; re-pin it only by changing %s on every validator",
		ErrGenesisMismatch, chainID, host, got.Hex(), pin.Hex(), pinSource(chainID), chainID, supportedchains.GenesisEnvFor(chainID))
}

func pinSource(chainID int64) string {
	if c, ok := supportedchains.Lookup(chainID); ok {
		if _, set := os.LookupEnv(c.GenesisEnv()); set {
			return c.GenesisEnv()
		}
	}
	return "the chain catalogue"
}

// CheckGenesis refuses, by name, a client serving another genesis than chainID is pinned to. A chain that is not pinned
// is not read. It is the boot check of a single client (the sender's), whose reads are not agreed.
func CheckGenesis(ctx context.Context, chainID int64, host string, c headerByNumber) error {
	pin, pinned, err := PinnedGenesis(chainID)
	if err != nil {
		return err
	}
	if !pinned {
		return nil
	}
	got, err := genesisOf(ctx, c)
	if err != nil {
		return fmt.Errorf("chain %d provider %s: reading its genesis to check it against the pin %s: %w", chainID, host, pin.Hex(), err)
	}
	if got != pin {
		return genesisMismatch(chainID, host, got, pin)
	}
	return nil
}

// genesisGuard is one provider's genesis reading, refreshed when older than genesisRecheck. Nil for a chain that is not
// pinned.
type genesisGuard struct {
	chainID int64
	host    string
	pin     common.Hash

	mu        sync.Mutex
	checkedAt time.Time
}

// newGenesisGuard is the guard of chainID's provider host: nil when the chain is not pinned.
func newGenesisGuard(chainID int64, host string) (*genesisGuard, error) {
	pin, pinned, err := PinnedGenesis(chainID)
	if err != nil || !pinned {
		return nil, err
	}
	return &genesisGuard{chainID: chainID, host: host, pin: pin}, nil
}

// ensure returns nil when the provider served the pinned genesis within genesisRecheck, reading it again otherwise. A
// read that fails leaves the provider unable to answer this read (it is not counted); another genesis is
// ErrGenesisMismatch.
func (g *genesisGuard) ensure(ctx context.Context, c headerByNumber) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.checkedAt.IsZero() && time.Since(g.checkedAt) < genesisRecheck {
		return nil
	}
	got, err := genesisOf(ctx, c)
	if err != nil {
		return fmt.Errorf("reading its genesis: %w", err)
	}
	if got != g.pin {
		g.checkedAt = time.Time{}
		return genesisMismatch(g.chainID, g.host, got, g.pin)
	}
	g.checkedAt = time.Now()
	return nil
}

// genesisRefusal is the first ErrGenesisMismatch among a read's answers: one provider on another genesis refuses the
// whole read.
func genesisRefusal[T any](as []answer[T]) error {
	for _, a := range as {
		if errors.Is(a.err, ErrGenesisMismatch) {
			return a.err
		}
	}
	return nil
}
