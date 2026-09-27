package execution

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// locatorChain is a chain of blocks with timestamps, one anchor record and the create logs it holds.
type locatorChain struct {
	times  []uint64 // times[n] is block n's timestamp
	pruned uint64   // headers below this are not served
	record AnchorOnChainState
	logs   []types.Log
	reads  int
	asked  [2]uint64
}

func (c *locatorChain) AnchorRecord(context.Context, common.Address, [32]byte) (AnchorOnChainState, error) {
	return c.record, nil
}

func (c *locatorChain) BlockTime(_ context.Context, n uint64) (uint64, error) {
	c.reads++
	if n < c.pruned {
		return 0, errors.New("pruned history unavailable")
	}
	if n >= uint64(len(c.times)) {
		return 0, errors.New("no such block")
	}
	return c.times[n], nil
}

func (c *locatorChain) CreateLogs(_ context.Context, _ common.Address, from, to uint64, _, _ [32]byte, _ common.Address) ([]types.Log, error) {
	c.asked = [2]uint64{from, to}
	var out []types.Log
	for _, l := range c.logs {
		if l.BlockNumber >= from && l.BlockNumber <= to {
			out = append(out, l)
		}
	}
	return out, nil
}

// An Arbitrum-like chain: four blocks per second, so a timestamp names a run of blocks.
func newLocatorChain(blocks int) *locatorChain {
	c := &locatorChain{times: make([]uint64, blocks)}
	for i := range c.times {
		c.times[i] = 1_000_000 + uint64(i/4)
	}
	return c
}

var (
	locBundle = [32]byte{0xb1}
	locRoot   = [32]byte{0x0e}
	locAnchor = common.HexToAddress("0x00000000000000000000000000000000000a1c40")
	locBy     = common.HexToAddress("0xd4a3dbbae0c04d4307c5e00a5e05b66acc289f5d")
)

func TestLocateAnchorCreateFindsTheOneCreateLogAtTheAnchorsTime(t *testing.T) {
	c := newLocatorChain(4000)
	created := uint64(2_222) // the creating block
	c.record = AnchorOnChainState{Valid: true, MerkleRoot: locRoot, CreatedAt: c.times[created], Validator: locBy}
	createTx := common.HexToHash("0xc0ffee")
	c.logs = []types.Log{{BlockNumber: created, TxHash: createTx}}

	got, err := LocateAnchorCreate(context.Background(), c, locAnchor, locBundle, locRoot, 3_500)
	if err != nil {
		t.Fatal(err)
	}
	if got.TxHash != createTx.Hex() || got.Block != created || got.Validator != locBy {
		t.Fatalf("located %+v", got)
	}
	// Exactly the blocks sharing the anchor's timestamp are searched - no guessed window.
	if c.asked != [2]uint64{2_220, 2_223} {
		t.Fatalf("searched blocks %v, want the four with the anchor's timestamp", c.asked)
	}
	if c.reads > 30 {
		t.Fatalf("%d header reads for 4000 blocks; the search is not logarithmic", c.reads)
	}
}

// Production, 2026-09-27: sepolia.base.org serves no header below block 46,000,000. A search that starts
// from genesis never reaches the anchor; one that works back from the verify block does not need to.
func TestLocateAnchorCreateNeedsNoHistoryBeforeTheAnchor(t *testing.T) {
	c := newLocatorChain(4000)
	c.pruned = 3_000
	c.record = AnchorOnChainState{Valid: true, MerkleRoot: locRoot, CreatedAt: c.times[3_301], Validator: locBy}
	c.logs = []types.Log{{BlockNumber: 3_301, TxHash: common.HexToHash("0x0b")}}
	got, err := LocateAnchorCreate(context.Background(), c, locAnchor, locBundle, locRoot, 3_320)
	if err != nil || got.Block != 3_301 {
		t.Fatalf("(%+v, %v)", got, err)
	}
}

func TestLocateAnchorCreateRefusesWhatTheChainDoesNotSayExactly(t *testing.T) {
	base := func() *locatorChain {
		c := newLocatorChain(400)
		c.record = AnchorOnChainState{Valid: true, MerkleRoot: locRoot, CreatedAt: c.times[200], Validator: locBy}
		c.logs = []types.Log{{BlockNumber: 200, TxHash: common.HexToHash("0x01")}}
		return c
	}
	cases := map[string]struct {
		edit     func(*locatorChain)
		notAfter uint64
		want     string
	}{
		"an anchor that does not exist": {func(c *locatorChain) { c.record.Valid = false }, 300, "does not exist"},
		"an anchor of another root":     {func(c *locatorChain) { c.record.MerkleRoot = [32]byte{9} }, 300, "holds root"},
		"no creator recorded":           {func(c *locatorChain) { c.record.Validator = common.Address{} }, 300, "no creation time or creator"},
		"created after the bound":       {func(*locatorChain) {}, 150, "after block"},
		"no block at the creation time": {func(c *locatorChain) { c.record.CreatedAt = c.times[200]*10 + 1; c.times[399] = c.record.CreatedAt + 5 }, 399, "no block has"},
		"no create log":                 {func(c *locatorChain) { c.logs = nil }, 300, "0 BatchAnchorCreated"},
		"two create logs": {func(c *locatorChain) {
			c.logs = append(c.logs, types.Log{BlockNumber: 201, TxHash: common.HexToHash("0x02")})
		}, 300, "2 BatchAnchorCreated"},
		"only a removed log": {func(c *locatorChain) { c.logs[0].Removed = true }, 300, "0 BatchAnchorCreated"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := base()
			tc.edit(c)
			got, err := LocateAnchorCreate(context.Background(), c, locAnchor, locBundle, locRoot, tc.notAfter)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("(%+v, %v), want an error saying %q", got, err, tc.want)
			}
		})
	}
}
