// Copyright 2026 Certen Protocol

package strategy

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB10 activation freeze: the S6 replay guard rides on the observation BESIDE the settlement. What validators compare
// (ResultHash = computeResultHash) and what they sign (the AttestationMessage hash) are byte-identical with and without
// it, and pinned to the values computed at 6811172, so no validator's ResultHash or attestation can differ by what its
// provider still served.

func invarianceObservation() *ObservationResult {
	return &ObservationResult{
		TxHash: "0x9b1f0c4d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e", BlockNumber: 9_412_007,
		BlockHash: "0x4f6c2e1d0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d", BlockTimestamp: time.Unix(1_790_000_000, 0).UTC(),
		Status: 1, Confirmations: 64, RequiredConfirmations: 12, IsFinalized: true,
		StateRoot: common.HexToHash("0x11"), TransactionsRoot: common.HexToHash("0x22"), ReceiptsRoot: common.HexToHash("0x33"),
		MerkleProof: []byte{0xf8, 0x51, 0x80}, ReceiptProof: []byte{0xf9, 0x01, 0x11, 0xa0}, BlockHeaderRLP: []byte{0xf9, 0x02, 0x1a},
		ChainName: "sepolia", ChainIDNumeric: 11155111,
	}
}

func populatedReplayGuard() *ethproof.ReplayGuardEvidence {
	return &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, Proof: &ethproof.ReplayGuardProof{
		Version: ethproof.ReplayGuardDomain, ChainID: 11155111, Generation: ethproof.AccountGenerationV7_3,
		Contract: common.HexToAddress("0x1019dbd51aaDAb221fEB6D7b6ffc96D4e5e321AC"),
		Slot:     ethproof.ReplaySlot{Key: common.HexToHash("0xab"), Base: 4, Derivation: ethproof.ReplayDerivation, Slot: ethproof.ReplaySlotFor(common.HexToHash("0xab"), 4)},
		After:    ethproof.SlotProof{AccountProof: nil, Value: common.BigToHash(common.Big1)},
		BeforeUnavailable: &ethproof.ReplayBeforeUnavailable{Reason: "state_unavailable",
			Providers: []ethproof.ReplayProviderFailure{{Host: "rpc.example", Error: "missing trie node"}}}}}
}

const (
	goldenResultHash      = "614bb572128b7191e78867df3202a045375eea5d24d05238375d5381e5c42920"
	goldenAttestationHash = "339884747528b46d83a8322b4cb4249f0f44f9deb1c8b061c041c0c583e489d7"
)

func TestTheReplayGuardIsNoInputOfTheResultHashOrTheAttestation(t *testing.T) {
	plain, carrying := invarianceObservation(), invarianceObservation()
	carrying.ReplayGuard = populatedReplayGuard()
	named := invarianceObservation()
	named.ReplayGuard = &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: &ethproof.ReplayNamedState{
		State: ethproof.ReplayUnproven, Reason: ethproof.ReasonStateUnavailable, ChainID: 11155111, BlockNumber: 9_412_007}}

	h0 := computeResultHash(plain)
	for name, r := range map[string]*ObservationResult{"a proof": carrying, "a named state": named} {
		if h := computeResultHash(r); h != h0 {
			t.Fatalf("with %s the result hash is %x, without it %x", name, h, h0)
		}
	}
	if got := hex.EncodeToString(h0[:]); got != goldenResultHash {
		t.Errorf("computeResultHash = %s, pinned at 6811172 as %s", got, goldenResultHash)
	}

	msg := func(r *ObservationResult) [32]byte {
		m := &attestation.AttestationMessage{IntentID: "intent-rb10", ResultHash: computeResultHash(r), AnchorTxHash: "0xanchor",
			BlockNumber: r.BlockNumber, TargetChain: "sepolia", ChainID: "11155111", Timestamp: 1_790_000_100, CycleID: "cycle-1",
			BundleID: [32]byte{0xb1}, OperationCommitment: [32]byte{0xc1}, ExecutionTxHash: r.TxHash}
		h, err := m.Hash()
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	a0 := msg(plain)
	if a1, a2 := msg(carrying), msg(named); a1 != a0 || a2 != a0 {
		t.Fatalf("the attestation message hash moved with the replay guard: %x %x vs %x", a1, a2, a0)
	}
	if got := hex.EncodeToString(a0[:]); got != goldenAttestationHash {
		t.Errorf("AttestationMessage.Hash = %s, pinned at 6811172 as %s", got, goldenAttestationHash)
	}
}
