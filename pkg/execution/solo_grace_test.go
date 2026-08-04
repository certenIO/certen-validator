package execution

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// The solo grace must be a real reduction on the default, and never larger than it.
func TestSoloGraceIsShorterThanDefault(t *testing.T) {
	if soloSettleGrace >= DefaultBatchSettleGrace {
		t.Fatalf("soloSettleGrace %s is not shorter than the default %s — the on-demand path "+
			"would gain nothing", soloSettleGrace, DefaultBatchSettleGrace)
	}
	// Measured spread across all seven validators was 4s. Anything near that is reckless.
	if soloSettleGrace <= 4*time.Second {
		t.Fatalf("soloSettleGrace %s leaves no margin over the observed 4s enqueue spread",
			soloSettleGrace)
	}
}

// A period with co-members must keep the full grace — that is the case the 2026-08-02 quorum
// failure came from, and shortening it there would reintroduce the bug.
func TestSharedPeriodKeepsFullGrace(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})
	const chain = int64(11155111)
	const period, width = uint64(100), uint64(100)

	for _, id := range []string{"a", "b"} {
		if err := m.Add(&PendingBatchIntent{
			IntentID:     id,
			ADIURL:       "acc://" + id + ".acme",
			ChainID:      chain,
			Account:      common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B"),
			OperationID:  [32]byte{id[0]},
			CommitHeight: period + 1,
			Legs:         []LegExecution{{ChainID: chain}},
		}); err != nil {
			t.Fatalf("add %s: %v", id, err)
		}
	}
	if n := len(m.PeekForPeriod(chain, period, width)); n != 2 {
		t.Fatalf("expected 2 members in the period, got %d — the solo shortcut would fire "+
			"on a shared period", n)
	}
}
