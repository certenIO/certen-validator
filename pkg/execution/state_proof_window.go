package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
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
// (head minus finalized), and every verified provider is asked eth_getProof for the chain's anchor that deep plus
// StateProofProbeMargin blocks. The margin is what makes an instant-finality chain (Telcoin's Adiri, a lag of 0) honest:
// its public endpoints answer only at the head, so asked at depth 0 alone they would all pass, the chain would admit an
// expectedState leg, and the proof read would then fail and loop. The window each provider serves is logged. A chain where
// NO provider serves the finalized depth plus the margin refuses an expectedState leg by name before anything
// is signed - STATE_PROOF_WINDOW_UNAVAILABLE, a condition of CERTEN's deployment (ErrBatchUnavailable), retried and never
// held against the intent, so it resolves the moment a provider that keeps the state is added.

// ErrStateProofWindowUnavailable is the refusal's name.
var ErrStateProofWindowUnavailable = errors.New("STATE_PROOF_WINDOW_UNAVAILABLE")

// StateProofProbeMargin is how many blocks beyond the finality lag a provider must serve to qualify: room for a retry
// of the proof read after the finalized block has moved on. It is small on purpose; a chain's own finality lag, not a
// fixed depth, sets how far back a proof is needed. (Owner 2026-10-06: the earlier 10,000 was far too high.)
const StateProofProbeMargin = 64

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
//
// A probe that cannot complete clears the stored result: admission then answers "not probed yet" (retried), never the
// earlier "servable", which the chain's providers may no longer deserve.
func probeStateProofWindow(ctx context.Context, chainID int64, reader *ethrpc.AgreeingReader, account common.Address, logf func(string, ...interface{})) (err error) {
	defer func() {
		if err != nil {
			stateProofWindows.Delete(chainID)
		}
	}()
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
	depth := new(big.Int).Add(lag, big.NewInt(StateProofProbeMargin))
	if depth.Cmp(head.Number) > 0 {
		depth = new(big.Int).Set(head.Number)
	}
	block := new(big.Int).Sub(head.Number, depth)
	// The state root an answer is checked against is the AGREED header's, the one a real proof read is checked against.
	probed, err := reader.HeaderByNumber(ctx, block)
	if err != nil {
		return fmt.Errorf("reading the agreed block %s to check a proof against: %w", block, err)
	}
	servable := false
	var parts []string
	for _, p := range reader.Locators() {
		raw, err := p.GetProof(ctx, account, []string{}, "0x"+block.Text(16))
		if err != nil {
			parts = append(parts, fmt.Sprintf("%s: no state %s blocks back (the finalized depth plus %d)", p.Host, depth, StateProofProbeMargin))
			continue
		}
		if !accountProofVerifies(raw, probed.Root, account) {
			parts = append(parts, fmt.Sprintf("%s: answered %s blocks back, but not with a proof that verifies against the agreed state root", p.Host, depth))
			continue
		}
		servable = true
		parts = append(parts, fmt.Sprintf("%s: serves %s blocks back (the finalized depth plus %d)", p.Host, depth, StateProofProbeMargin))
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

// accountProofVerifies is true when the eth_getProof answer holds a valid account proof of account against stateRoot.
func accountProofVerifies(raw []byte, stateRoot common.Hash, account common.Address) bool {
	var res EthGetProofResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return false
	}
	nodes := make([][]byte, 0, len(res.AccountProof))
	for _, h := range res.AccountProof {
		n, err := hexutil.Decode(h)
		if err != nil {
			return false
		}
		nodes = append(nodes, n)
	}
	return verifyAccountProof(stateRoot, account, nodes)
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
				stateProofWindows.Delete(chainID) // a probe that cannot run leaves no stale "servable" behind
				o.logf("⚠️ [STATE-PROOF] chain %d's providers could not be probed for state proofs: %v", chainID, err)
				wait = time.Minute
			}
			time.Sleep(wait)
		}
	}()
}
