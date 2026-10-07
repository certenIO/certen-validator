package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

// RB7 Task 5 T5-7: a state proof is asked of every verified provider, not only the primary. A public node keeps a short
// window of state, so at a finalized block the primary may refuse ("exceeds maximum proof window") while another provider
// holds it; a proof is self-verifying against the agreed state root, so one provider that has it is enough.

const stateProofTestChain = 31337

type proofProvider struct {
	mu     sync.Mutex
	asked  int
	answer func() (any, string) // result, or an error message
	depth  int64                // when set, the blocks of state it keeps: eth_getProof deeper than this is refused
	// instant makes the chain's finalized block its head (a lag of 0, as on Telcoin's Adiri), not 1000 blocks behind.
	instant bool
	// stateRoot is the state root every header it serves carries (the probe verifies the account proof against it);
	// noHeaders makes it refuse header reads, so that the chain's head cannot be agreed.
	stateRoot common.Hash
	noHeaders bool
}

func (p *proofProvider) serve(t *testing.T, host string) string {
	t.Helper()
	ln, err := net.Listen("tcp", host+":0")
	if err != nil {
		t.Skipf("cannot listen on %s: %v", host, err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "eth_chainId":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":"%s"}`, req.ID, hexutil.EncodeUint64(stateProofTestChain))
		case "eth_getBlockByNumber":
			// The agreed head and finalized headers, for the probe: head 100000, finalized 99000 (a lag of 1000).
			n := int64(100000)
			if len(req.Params) > 0 && string(req.Params[0]) == `"finalized"` && !p.instant {
				n = 99000
			}
			if p.noHeaders {
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"headers unavailable"}}`, req.ID)
				return
			}
			b, _ := json.Marshal(&types.Header{Number: big.NewInt(n), Difficulty: big.NewInt(0), Time: uint64(n), Root: p.stateRoot})
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, b)
		case "eth_getProof":
			if p.depth != 0 && len(req.Params) == 3 {
				// A provider that keeps only p.depth blocks of state: asked for a block older than that, it has none.
				var blk string
				_ = json.Unmarshal(req.Params[2], &blk)
				if n, err := hexutil.DecodeUint64(blk); err == nil && int64(100000)-int64(n) > p.depth {
					fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"exceeds maximum proof window"}}`, req.ID)
					return
				}
			}
			p.mu.Lock()
			p.asked++
			p.mu.Unlock()
			res, msg := p.answer()
			if msg != "" {
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":%q}}`, req.ID, msg)
				return
			}
			b, _ := json.Marshal(res)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, b)
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no such method"}}`, req.ID)
		}
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.URL
}

func (p *proofProvider) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.asked
}

// getProofJSON is sp as a provider answers eth_getProof.
func getProofJSON(sp *StateProof) map[string]any {
	hexes := func(ns [][]byte) []string {
		out := make([]string, len(ns))
		for i, n := range ns {
			out[i] = hexutil.Encode(n)
		}
		return out
	}
	return map[string]any{
		"accountProof": hexes(sp.AccountProof),
		"storageHash":  sp.StorageHash,
		"storageProof": []map[string]any{{
			"key":   sp.Slot.Hex(),
			"value": hexutil.EncodeBig(sp.Value.Big()),
			"proof": hexes(sp.StorageProof),
		}},
	}
}

func proofObserver(t *testing.T, primary, second *proofProvider) *ExternalChainObserver {
	t.Helper()
	urls := []string{primary.serve(t, "127.0.0.1"), second.serve(t, "127.0.0.2")}
	r, err := ethrpc.NewAgreeingReader(context.Background(), stateProofTestChain, urls, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return &ExternalChainObserver{finality: r, chainID: stateProofTestChain, logger: nil}
}

func TestAStateProofIsReadFromTheSecondProviderWhenThePrimaryHasNoStateThatDeep(t *testing.T) {
	sp, root := buildStateWithSlot(t, rb5Account, rb5Slot, big.NewInt(42))
	primary := &proofProvider{answer: func() (any, string) { return nil, "exceeds maximum proof window" }}
	second := &proofProvider{answer: func() (any, string) { return getProofJSON(sp), "" }}
	o := proofObserver(t, primary, second)

	got := o.fetchStateProofs(context.Background(), big.NewInt(100), root,
		[]ExpectedStateSlot{{Account: rb5Account, Slot: rb5Slot, Value: common.BigToHash(big.NewInt(42))}})
	if len(got) != 1 || !got[0].Verify(root) || got[0].Value != common.BigToHash(big.NewInt(42)) {
		t.Fatalf("the second provider's verifying proof was not returned: %v", got)
	}
	if primary.calls() != 1 || second.calls() != 1 {
		t.Fatalf("the providers were asked %d and %d times; want once each, primary first", primary.calls(), second.calls())
	}
}

// A provider that answers with a proof for another state is never believed: a proof is accepted only when it verifies
// against the state root already agreed on.
func TestAStateProofThatDoesNotMatchTheStateRootIsRejected(t *testing.T) {
	good, root := buildStateWithSlot(t, rb5Account, rb5Slot, big.NewInt(42))
	forged, _ := buildStateWithSlot(t, rb5Account, rb5Slot, big.NewInt(43)) // a proof of another state
	primary := &proofProvider{answer: func() (any, string) { return getProofJSON(forged), "" }}
	second := &proofProvider{answer: func() (any, string) { return getProofJSON(good), "" }}
	o := proofObserver(t, primary, second)
	slots := []ExpectedStateSlot{{Account: rb5Account, Slot: rb5Slot, Value: common.BigToHash(big.NewInt(42))}}

	got := o.fetchStateProofs(context.Background(), big.NewInt(100), root, slots)
	if len(got) != 1 || got[0].Value != common.BigToHash(big.NewInt(42)) {
		t.Fatalf("the forged proof was not passed over for the verifying one: %v", got)
	}

	// With no provider holding a verifying proof there is none: the caller names the slot, nothing is assumed.
	only := &proofProvider{answer: func() (any, string) { return getProofJSON(forged), "" }}
	o = proofObserver(t, only, &proofProvider{answer: func() (any, string) { return nil, "exceeds maximum proof window" }})
	if got := o.fetchStateProofs(context.Background(), big.NewInt(100), root, slots); len(got) != 0 {
		t.Fatalf("a proof that does not verify against the state root was returned: %v", got)
	}
	holds, err := slotsHoldAt(nil, root, slots)
	if err == nil || !strings.Contains(err.Error(), "no verifying state proof") {
		t.Fatalf("an unproven slot was not named: %v %v", holds, err)
	}
}

// The boot probe asks each provider for a proof at the finality lag plus StateProofProbeMargin blocks (room for a retry). A chain where no provider
// serves the finalized depth cannot prove a committed slot, and says so by name; one that has a provider that does can.
func probeWith(t *testing.T, chainID int64, depths ...int64) error {
	t.Helper()
	return probeWithFinality(t, chainID, false, depths...)
}

func probeWithFinality(t *testing.T, chainID int64, instant bool, depths ...int64) error {
	t.Helper()
	// Each provider answers with the REAL account proof of the state its headers name: the probe verifies it.
	sp, root := buildStateWithSlot(t, rb5Account, rb5Slot, big.NewInt(42))
	real := func() (any, string) { return getProofJSON(sp), "" }
	return probeWithAnswer(t, chainID, instant, root, real, depths...)
}

// probeWithAnswer probes a chain whose providers (keeping depths[i] blocks of state) name stateRoot in their headers and
// answer eth_getProof with answer.
func probeWithAnswer(t *testing.T, chainID int64, instant bool, stateRoot common.Hash, answer func() (any, string), depths ...int64) error {
	t.Helper()
	var urls []string
	for i, d := range depths {
		p := &proofProvider{answer: answer, depth: d, instant: instant, stateRoot: stateRoot}
		urls = append(urls, p.serve(t, fmt.Sprintf("127.0.0.%d", i+1)))
	}
	r, err := ethrpc.NewAgreeingReader(context.Background(), stateProofTestChain, urls, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	stateProofWindows.Delete(chainID)
	if err := probeStateProofWindow(context.Background(), chainID, r, rb5Account, t.Logf); err != nil {
		t.Fatal(err)
	}
	return StateProofServable(chainID)
}

// A provider that answers eth_getProof with no error is not thereby serving a proof: an empty or null answer, or a proof
// of another state, does not verify against the agreed header's state root, and a chain whose providers only answer
// that way cannot prove a committed slot.
func TestAProbeAnswerThatDoesNotVerifyAgainstTheStateRootDoesNotMakeAChainServable(t *testing.T) {
	_, root := buildStateWithSlot(t, rb5Account, rb5Slot, big.NewInt(42))
	forged, _ := buildStateWithSlot(t, rb5Account, rb5Slot, big.NewInt(43))
	otherAccountState, _ := buildStateWithSlot(t, common.HexToAddress("0x00000000000000000000000000000000000000c9"), rb5Slot, big.NewInt(1))
	cases := map[string]func() (any, string){
		"an empty account proof": func() (any, string) {
			return map[string]any{"accountProof": []string{}, "storageHash": common.Hash{}, "storageProof": []any{}}, ""
		},
		"a null answer":                 func() (any, string) { return nil, "" },
		"a proof of another state root": func() (any, string) { return getProofJSON(forged), "" },
		"a proof of another account":    func() (any, string) { return getProofJSON(otherAccountState), "" },
	}
	i := int64(920000)
	for name, answer := range cases {
		i++
		err := probeWithAnswer(t, i, false, root, answer, 5000, 5000)
		if err == nil || !errors.Is(err, ErrStateProofWindowUnavailable) {
			t.Errorf("%s made the chain servable (or the probe did not name the refusal): %v", name, err)
		}
	}
}

// A probe that fails later must not leave the earlier "servable" in place: admission stops passing on a stale result
// and is retried (the chain's providers have not been probed), never refused for good and never admitted blind.
func TestAFailedProbeClearsTheStoredWindow(t *testing.T) {
	chainID := int64(920100)
	if err := probeWith(t, chainID, 5000, 5000); err != nil {
		t.Fatalf("setup: a chain with two deep providers was refused: %v", err)
	}
	broken := &proofProvider{noHeaders: true, answer: func() (any, string) { return nil, "" }}
	other := &proofProvider{noHeaders: true, answer: func() (any, string) { return nil, "" }}
	urls := []string{broken.serve(t, "127.0.0.1"), other.serve(t, "127.0.0.2")}
	r, err := ethrpc.NewAgreeingReader(context.Background(), stateProofTestChain, urls, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := probeStateProofWindow(context.Background(), chainID, r, rb5Account, t.Logf); err == nil {
		t.Fatal("a probe whose headers cannot be read succeeded")
	}
	err = StateProofServable(chainID)
	if err == nil || !errors.Is(err, ErrBatchUnavailable) || !strings.Contains(err.Error(), "have not been probed") {
		t.Fatalf("a failed probe left the earlier result in place: %v", err)
	}
}

func TestAChainWithNoProviderThatKeepsStateThatDeepRefusesExpectedStateByName(t *testing.T) {
	// Finality lags by 1000 blocks; the two providers keep 3 and 127 blocks of state, as publicnode does.
	err := probeWith(t, 910001, 3, 127)
	if err == nil || !errors.Is(err, ErrStateProofWindowUnavailable) || !errors.Is(err, ErrBatchUnavailable) {
		t.Fatalf("want STATE_PROOF_WINDOW_UNAVAILABLE wrapping ErrBatchUnavailable, got %v", err)
	}
}

func TestAChainWithAProviderThatKeepsStateAtTheFinalizedDepthCanProve(t *testing.T) {
	// One provider keeps 3 blocks, the other 1,500: it serves the finalized depth (1000) plus the 64-block margin.
	if err := probeWith(t, 910002, 3, 1500); err != nil {
		t.Fatalf("a chain with a provider serving the finalized depth was refused: %v", err)
	}
}

func TestAChainNotProbedYetIsRetriedNotRefusedForGood(t *testing.T) {
	stateProofWindows.Delete(int64(910003))
	err := StateProofServable(910003)
	if !errors.Is(err, ErrBatchUnavailable) || !errors.Is(err, ErrStateProofWindowUnavailable) {
		t.Fatalf("an unprobed chain: %v", err)
	}
}

// Telcoin's Adiri finalizes instantly (a lag of 0) and its public endpoints answer eth_getProof only at the head. Probed at
// depth 0 alone they would pass, the chain would admit an expectedState leg, and the proof read would then fail and loop.
// The probe asks lag + StateProofProbeMargin deep, so a head-only provider is refused and a node that keeps state is not.
func TestAnInstantFinalityChainWithOnlyHeadOnlyProvidersRefusesExpectedStateByName(t *testing.T) {
	err := probeWithFinality(t, 910004, true, 1, 1)
	if err == nil || !errors.Is(err, ErrStateProofWindowUnavailable) || !errors.Is(err, ErrBatchUnavailable) {
		t.Fatalf("head-only providers on an instant-finality chain must be refused by name, got %v", err)
	}
}

func TestAnInstantFinalityChainWithANodeThatKeepsStateCanProve(t *testing.T) {
	if err := probeWithFinality(t, 910005, true, 1, StateProofProbeMargin+1000); err != nil {
		t.Fatalf("a chain with a node that keeps state past the margin was refused: %v", err)
	}
}

// The threshold is exactly the finality lag plus the margin: no 10,000-block room is asked for, and none less than the margin.
func TestTheProbeThresholdIsTheFinalityLagPlusTheMargin(t *testing.T) {
	const lag = 1000
	if StateProofProbeMargin != 64 {
		t.Fatalf("the margin is 64 blocks, got %d", StateProofProbeMargin)
	}
	if err := probeWith(t, 910006, lag+StateProofProbeMargin-1, lag+StateProofProbeMargin-1); err == nil {
		t.Fatal("a provider keeping one block less than lag + margin qualified")
	}
	if err := probeWith(t, 910007, lag+StateProofProbeMargin, lag+StateProofProbeMargin); err != nil {
		t.Fatalf("a provider keeping exactly lag + margin was refused: %v", err)
	}
}
