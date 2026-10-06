package execution

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
)

// =============================================================================
// Which chains can prove a committed storage slot at all
// =============================================================================
//
// A committed storage-slot effect (expectedState) is proven with eth_getProof at the settlement's FINALIZED block. A
// public node keeps only a short window of state, and a chain's finality lags its head by 75 blocks (Sepolia) to 4,300
// (Arbitrum Sepolia): measured 2026-10-06, no configured provider served a proof at finalized depth on Arbitrum Sepolia,
// so the first intent committing a slot there would have looped as "proven neither present nor absent" until its
// deadline, its member never resolving (RB7 Task 5, T5-7).
//
// Each settlement chain's providers are therefore probed at boot, and again periodically: the finality lag is measured
// (head minus finalized), and every verified provider is asked eth_getProof for the chain's anchor at that depth and at
// that depth plus StateProofProbeMargin blocks (the room a retry or a repair hours later needs). The window each provider
// serves is logged. A chain where NO provider serves finalized depth refuses an expectedState leg by name before anything
// is signed - STATE_PROOF_WINDOW_UNAVAILABLE, a condition of CERTEN's deployment (ErrBatchUnavailable), retried and never
// held against the intent, so it resolves the moment a provider that keeps the state is added.

// ErrStateProofWindowUnavailable is the refusal's name.
var ErrStateProofWindowUnavailable = errors.New("STATE_PROOF_WINDOW_UNAVAILABLE")

// StateProofProbeMargin is how many blocks beyond the finality lag a provider is also asked, to log how long a retry or
// a repair of a proof can wait. A provider serving the lag but not the margin still qualifies: it resolves a proof while
// the settlement is fresh, and a later read gets the named read error.
const StateProofProbeMargin = 10000

// StateProofProbeEvery is how often a chain's providers are probed again.
const StateProofProbeEvery = 30 * time.Minute

type stateProofWindow struct {
	servable bool
	detail   string // each provider's window, by host
}

var stateProofWindows sync.Map // chain id -> stateProofWindow

// StateProofServable is nil when some provider of chainID serves eth_getProof at the chain's finalized depth. Otherwise it
// is the named refusal: ErrStateProofWindowUnavailable wrapped in ErrBatchUnavailable.
func StateProofServable(chainID int64) error {
	v, ok := stateProofWindows.Load(chainID)
	if !ok {
		return fmt.Errorf("%w: %w: chain %d's providers have not been probed for state proofs yet", ErrBatchUnavailable,
			ErrStateProofWindowUnavailable, chainID)
	}
	if w := v.(stateProofWindow); !w.servable {
		return fmt.Errorf("%w: %w: no provider of chain %d serves eth_getProof at its finalized depth (%s); add a provider that "+
			"keeps state that deep", ErrBatchUnavailable, ErrStateProofWindowUnavailable, chainID, w.detail)
	}
	return nil
}

// probeStateProofWindow measures chainID's finality lag and which providers serve eth_getProof that deep, records the
// result for admission and logs it. account is any account the chain holds (its anchor).
func probeStateProofWindow(ctx context.Context, chainID int64, reader *ethrpc.AgreeingReader, account common.Address, logf func(string, ...interface{})) error {
	head, err := reader.HeaderByNumber(ctx, big.NewInt(int64(rpc.LatestBlockNumber)))
	if err != nil {
		return fmt.Errorf("reading the agreed head: %w", err)
	}
	fin, err := reader.HeaderByNumber(ctx, big.NewInt(int64(rpc.FinalizedBlockNumber)))
	if err != nil {
		return fmt.Errorf("reading the agreed finalized block: %w", err)
	}
	if fin.Number.Cmp(head.Number) > 0 {
		return fmt.Errorf("the agreed finalized block %s is past the head %s", fin.Number, head.Number)
	}
	lag := new(big.Int).Sub(head.Number, fin.Number)
	servable := false
	var parts []string
	for _, p := range reader.Locators() {
		at := func(extra int64) error {
			depth := new(big.Int).Add(lag, big.NewInt(extra))
			if depth.Cmp(head.Number) > 0 {
				depth = new(big.Int).Set(head.Number)
			}
			block := new(big.Int).Sub(head.Number, depth)
			_, err := p.GetProof(ctx, account, []string{}, "0x"+block.Text(16))
			return err
		}
		switch {
		case at(0) != nil:
			parts = append(parts, p.Host+": no state at the finalized depth")
		case at(StateProofProbeMargin) != nil:
			servable = true
			parts = append(parts, fmt.Sprintf("%s: serves the finalized depth, not %d blocks beyond it", p.Host, StateProofProbeMargin))
		default:
			servable = true
			parts = append(parts, fmt.Sprintf("%s: serves at least %d blocks beyond the finalized depth", p.Host, StateProofProbeMargin))
		}
	}
	detail := fmt.Sprintf("finality lag %s blocks; %s", lag, strings.Join(parts, "; "))
	stateProofWindows.Store(chainID, stateProofWindow{servable: servable, detail: detail})
	if servable {
		logf("🔎 [STATE-PROOF] chain %d can prove committed storage slots: %s", chainID, detail)
	} else {
		logf("⚠️ [STATE-PROOF] chain %d CANNOT prove committed storage slots (%v): %s", chainID, ErrStateProofWindowUnavailable, detail)
	}
	return nil
}

// startStateProofWindowProbe probes this orchestrator's chain now and every StateProofProbeEvery. Until the first probe
// finishes, an expectedState leg is retried, not refused for good (StateProofServable).
func (o *BatchOrchestrator) startStateProofWindowProbe(chainID int64) {
	if o.ecm == nil || o.ecm.config == nil {
		return
	}
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			reader, err := o.agreedReader(ctx, chainID)
			if err == nil {
				err = probeStateProofWindow(ctx, chainID, reader, o.anchorV7, o.logf)
			}
			cancel()
			wait := StateProofProbeEvery
			if err != nil {
				o.logf("⚠️ [STATE-PROOF] chain %d's providers could not be probed for state proofs: %v", chainID, err)
				wait = time.Minute
			}
			time.Sleep(wait)
		}
	}()
}
