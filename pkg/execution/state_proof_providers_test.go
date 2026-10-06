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
			if len(req.Params) > 0 && string(req.Params[0]) == `"finalized"` {
				n = 99000
			}
			b, _ := json.Marshal(&types.Header{Number: big.NewInt(n), Difficulty: big.NewInt(0), Time: uint64(n)})
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

// The boot probe measures each provider's window at the finality lag and 10,000 blocks beyond it. A chain where no provider
// serves the finalized depth cannot prove a committed slot, and says so by name; one that has a provider that does can.
func probeWith(t *testing.T, chainID int64, depths ...int64) error {
	t.Helper()
	empty := func() (any, string) {
		return map[string]any{"accountProof": []string{}, "storageHash": common.Hash{}, "storageProof": []any{}}, ""
	}
	var urls []string
	for i, d := range depths {
		p := &proofProvider{answer: empty, depth: d}
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

func TestAChainWithNoProviderThatKeepsStateThatDeepRefusesExpectedStateByName(t *testing.T) {
	// Finality lags by 1000 blocks; the two providers keep 3 and 127 blocks of state, as publicnode does.
	err := probeWith(t, 910001, 3, 127)
	if err == nil || !errors.Is(err, ErrStateProofWindowUnavailable) || !errors.Is(err, ErrBatchUnavailable) {
		t.Fatalf("want STATE_PROOF_WINDOW_UNAVAILABLE wrapping ErrBatchUnavailable, got %v", err)
	}
}

func TestAChainWithAProviderThatKeepsStateAtTheFinalizedDepthCanProve(t *testing.T) {
	// One provider keeps 3 blocks, the other 1,500: it serves the finalized depth (1000) but not 10,000 beyond it.
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
