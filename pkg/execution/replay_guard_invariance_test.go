// Copyright 2026 Certen Protocol

package execution

import (
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB10 activation freeze: the S6 replay guard rides BESIDE the settlement (ExternalChainResult.ReplayGuard) and beside
// the outcome leaf (OutcomeMemberEvidence.ReplayGuard). The result hash every validator compares and signs, and the
// outcome leaf hash under the registry's outcome root, are byte-identical with and without it, pinned to the values
// computed at 6811172; and nothing consensus-reachable names it.

func invarianceResult() *ExternalChainResult {
	return &ExternalChainResult{ResultID: [32]byte{0x01}, PreviousResultHash: [32]byte{0x02}, AnchorProofHash: [32]byte{0x03},
		SequenceNumber: 7, Chain: "sepolia", ChainID: 11155111, TxHash: common.HexToHash("0x9b1f"), BlockNumber: big.NewInt(9_412_007),
		BlockHash: common.HexToHash("0x4f6c"), TransactionsRoot: common.HexToHash("0x22"), ReceiptsRoot: common.HexToHash("0x33"),
		StateRoot: common.HexToHash("0x11"), Status: 1, TxIndex: 3, TxGasUsed: 81_234,
		Logs: []LogEntry{{Address: common.HexToAddress("0xaa"), Topics: []common.Hash{{0xe1}}, Data: []byte("paid")}}}
}

func invarianceReplayGuard() *ethproof.ReplayGuardEvidence {
	return &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, Proof: &ethproof.ReplayGuardProof{
		Version: ethproof.ReplayGuardDomain, ChainID: 11155111, Generation: ethproof.AccountGenerationV7_3,
		Contract:          common.HexToAddress("0x1019dbd51aaDAb221fEB6D7b6ffc96D4e5e321AC"),
		Slot:              ethproof.ReplaySlot{Key: common.HexToHash("0xab"), Base: 4, Derivation: ethproof.ReplayDerivation, Slot: ethproof.ReplaySlotFor(common.HexToHash("0xab"), 4)},
		After:             ethproof.SlotProof{Value: common.BigToHash(common.Big1)},
		BeforeUnavailable: &ethproof.ReplayBeforeUnavailable{Reason: "state_unavailable"}}}
}

const (
	goldenExternalResultHash = "fd2e2560295a2329591349ea1e9f9e9808f1b65c3c5dafd97806c804f84b05e4"
	goldenAttestationHashL4  = "0d74488c7d9d5eceeda3c6ca84c51b4e16176f610342bce2e89db954056a30fd"
	goldenOutcomeLeafHash    = "5ef3a3b5c9a26307af29421b6c7796e2f4144cb4b77a6521783192db8d582b8c"
)

func TestTheReplayGuardIsNoInputOfAnyResultOrOutcomeHash(t *testing.T) {
	plain, carrying := invarianceResult(), invarianceResult()
	carrying.ReplayGuard = invarianceReplayGuard()
	h0, h1 := plain.ComputeResultHash(), carrying.ComputeResultHash()
	if h0 != h1 {
		t.Fatalf("ExternalChainResult.ComputeResultHash moved with the replay guard: %x vs %x", h1, h0)
	}
	if got := hex.EncodeToString(h0[:]); got != goldenExternalResultHash {
		t.Errorf("ExternalChainResult.ComputeResultHash = %s, pinned at 6811172 as %s", got, goldenExternalResultHash)
	}

	msg := func(r *ExternalChainResult) [32]byte {
		m := &attestation.AttestationMessage{IntentID: "intent-rb10", ResultHash: r.ComputeResultHash(), AnchorTxHash: "0xanchor",
			BlockNumber: r.BlockNumber.Uint64(), TargetChain: r.Chain, ChainID: "11155111", Timestamp: 1_790_000_100,
			BundleID: [32]byte{0xb1}, OperationCommitment: [32]byte{0xc1}, ExecutionTxHash: r.TxHash.Hex()}
		h, err := m.Hash()
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	if a0, a1 := msg(plain), msg(carrying); a0 != a1 {
		t.Fatalf("the attestation message hash moved with the replay guard: %x vs %x", a1, a0)
	} else if got := hex.EncodeToString(a0[:]); got != goldenAttestationHashL4 {
		t.Errorf("AttestationMessage.Hash = %s, pinned at 6811172 as %s", got, goldenAttestationHashL4)
	}

	// The outcome leaf a member's evidence states, decoded with and without the replay guard beside it.
	m := newSynthMember(t, nil)
	m.settle(synthSettlement(t, m.chainID, 100, 1000, common.Hash{}, common.HexToAddress(m.ev.Account), 1,
		[]*types.Log{m.consumedLog(m.anchor.bundleID)}), OutcomeExecuted, CommittedEffectsHash(nil, nil))
	if err := m.verify(); err != nil {
		t.Fatal(err)
	}
	leafHash := func(ev OutcomeMemberEvidence) [32]byte {
		leaf, err := ev.Leaf.decode(m.chainID, m.anchor.bundleID)
		if err != nil {
			t.Fatal(err)
		}
		h, err := leaf.Hash()
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	with := m.ev
	with.ReplayGuard = invarianceReplayGuard()
	l0, l1 := leafHash(m.ev), leafHash(with)
	if l0 != l1 {
		t.Fatalf("OutcomeLeaf.Hash moved with the replay guard: %x vs %x", l1, l0)
	}
	if got := hex.EncodeToString(l0[:]); got != goldenOutcomeLeafHash {
		t.Errorf("OutcomeLeaf.Hash = %s, pinned at 6811172 as %s", got, goldenOutcomeLeafHash)
	}
}

// No hashed or signed structure can hold a replay guard: none of their types reaches ethproof.ReplayGuardEvidence.
func TestNoHashedOrSignedStructureCanHoldAReplayGuard(t *testing.T) {
	target := reflect.TypeOf(ethproof.ReplayGuardEvidence{})
	var reaches func(reflect.Type, map[reflect.Type]bool) bool
	reaches = func(ty reflect.Type, seen map[reflect.Type]bool) bool {
		if ty == target {
			return true
		}
		if seen[ty] {
			return false
		}
		seen[ty] = true
		switch ty.Kind() {
		case reflect.Ptr, reflect.Slice, reflect.Array, reflect.Map:
			return reaches(ty.Elem(), seen)
		case reflect.Struct:
			for i := 0; i < ty.NumField(); i++ {
				if reaches(ty.Field(i).Type, seen) {
					return true
				}
			}
		}
		return false
	}
	for _, ty := range []reflect.Type{reflect.TypeOf(attestation.AttestationMessage{}), reflect.TypeOf(OutcomeLeaf{}),
		reflect.TypeOf(OutcomeLeafEvidence{})} {
		if reaches(ty, map[reflect.Type]bool{}) {
			t.Fatalf("%s can hold a replay guard", ty)
		}
	}
	// The carriers do (the test would be vacuous otherwise).
	for _, ty := range []reflect.Type{reflect.TypeOf(ExternalChainResult{}), reflect.TypeOf(OutcomeMemberEvidence{})} {
		if !reaches(ty, map[reflect.Type]bool{}) {
			t.Fatalf("%s carries no replay guard", ty)
		}
	}
}

// pkg/consensus and pkg/proof/v2 (the certificate, the spine, the rules) never name the replay guard.
func TestConsensusAndProofV2NeverNameTheReplayGuard(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no source path")
	}
	root := filepath.Join(filepath.Dir(self), "..")
	for _, dir := range []string{"consensus", filepath.Join("proof", "v2")} {
		files := 0
		err := filepath.Walk(filepath.Join(root, dir), func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") {
				return err
			}
			files++
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, word := range []string{"ReplayGuard", "replayGuard", "replay_guard", "s6-replay", "ReplaySlot", "ReplayLayout"} {
				if strings.Contains(string(b), word) {
					t.Errorf("%s names %q", p, word)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if files == 0 {
			t.Fatalf("no Go files under pkg/%s", dir)
		}
	}
}
