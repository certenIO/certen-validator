// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethproof"
)

func raw(sp ethproof.SlotProof) (acc, sto [][]byte) {
	for _, n := range sp.AccountProof {
		acc = append(acc, n)
	}
	for _, n := range sp.StorageProof {
		sto = append(sto, n)
	}
	return
}

func TestVerifyStorage_PresentSlot(t *testing.T) {
	st := buildState(t, account{addr: testOther}, account{addr: testContract, code: testCode, storage: map[common.Hash]*big.Int{common.BigToHash(big.NewInt(4)): big.NewInt(1)}})
	slot := common.BigToHash(big.NewInt(4))
	acc, sto := raw(st.prove(testContract, slot))
	res, err := ethproof.VerifyStorage(st.root, testContract, acc, slot, sto)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Account.Exists || res.Value != common.BigToHash(big.NewInt(1)) || !res.Account.HasCode() {
		t.Fatalf("got %+v", res)
	}
}

func TestVerifyStorage_AbsentSlotIsZero(t *testing.T) {
	st := buildState(t, account{addr: testContract, code: testCode, storage: map[common.Hash]*big.Int{common.BigToHash(big.NewInt(4)): big.NewInt(1)}})
	slot := common.BigToHash(big.NewInt(9))
	acc, sto := raw(st.prove(testContract, slot))
	res, err := ethproof.VerifyStorage(st.root, testContract, acc, slot, sto)
	if err != nil || res.Value != (common.Hash{}) {
		t.Fatalf("an absent slot must verify as 0: %v %+v", err, res)
	}
}

// R10 Q7: an account with no storage has the empty storage root and no storage node; the opt-in path refused it.
func TestVerifyStorage_EmptyStorageRootNeedsNoNode(t *testing.T) {
	st := buildState(t, account{addr: testOther}, account{addr: testContract, code: testCode})
	slot := common.BigToHash(big.NewInt(4))
	sp := st.prove(testContract, slot)
	acc, sto := raw(sp)
	if len(sto) != 0 {
		t.Fatalf("an empty storage trie yields %d proof nodes", len(sto))
	}
	res, err := ethproof.VerifyStorage(st.root, testContract, acc, slot, sto)
	if err != nil || res.Value != (common.Hash{}) || res.Account.StorageRoot != types.EmptyRootHash {
		t.Fatalf("empty storage must verify as 0: %v %+v", err, res)
	}
	// With the empty node 0x80 the same.
	if _, err := ethproof.VerifyStorage(st.root, testContract, acc, slot, [][]byte{{0x80}}); err != nil {
		t.Fatalf("the empty node: %v", err)
	}
	// Anything else against the empty root is refused.
	if _, err := ethproof.VerifyStorage(st.root, testContract, acc, slot, [][]byte{{0xc0}}); !errors.Is(err, ethproof.ErrStorageProofInvalid) {
		t.Fatalf("a node against the empty root must be refused: %v", err)
	}
}

// An exclusion proof: the account is not in the state, so it holds no storage and the slot is 0.
func TestVerifyStorage_AbsentAccount(t *testing.T) {
	st := buildState(t, account{addr: testOther})
	slot := common.BigToHash(big.NewInt(4))
	acc, sto := raw(st.prove(testContract, slot))
	res, err := ethproof.VerifyStorage(st.root, testContract, acc, slot, sto)
	if err != nil || res.Account.Exists || res.Value != (common.Hash{}) {
		t.Fatalf("an absent account must verify as absent with value 0: %v %+v", err, res)
	}
	// A storage proof offered in a proven absence is refused.
	if _, err := ethproof.VerifyStorage(st.root, testContract, acc, slot, [][]byte{{0x80}}); !errors.Is(err, ethproof.ErrStorageProofInvalid) {
		t.Fatalf("storage claimed in an absent account must be refused: %v", err)
	}
}

func TestVerifyStorage_Refusals(t *testing.T) {
	st := buildState(t, account{addr: testOther}, account{addr: testContract, code: testCode, storage: map[common.Hash]*big.Int{common.BigToHash(big.NewInt(4)): big.NewInt(1)}})
	slot := common.BigToHash(big.NewInt(4))
	acc, sto := raw(st.prove(testContract, slot))
	bad := st.root
	bad[0] ^= 0xff
	if _, err := ethproof.VerifyStorage(bad, testContract, acc, slot, sto); !errors.Is(err, ethproof.ErrStorageProofInvalid) {
		t.Errorf("another state root: %v", err)
	}
	tampered := append([][]byte(nil), sto...)
	tampered[len(tampered)-1] = append([]byte(nil), tampered[len(tampered)-1]...)
	tampered[len(tampered)-1][len(tampered[len(tampered)-1])-1] ^= 0x01
	if _, err := ethproof.VerifyStorage(st.root, testContract, acc, slot, tampered); !errors.Is(err, ethproof.ErrStorageProofInvalid) {
		t.Errorf("a tampered storage node: %v", err)
	}
	if _, err := ethproof.VerifyStorage(st.root, testContract, nil, slot, sto); !errors.Is(err, ethproof.ErrStorageProofInvalid) {
		t.Errorf("no account proof: %v", err)
	}
	if _, err := ethproof.VerifyStorage(st.root, testContract, acc, slot, nil); !errors.Is(err, ethproof.ErrStorageProofInvalid) {
		t.Errorf("no storage proof for a non-empty storage root: %v", err)
	}
	// Another account's proof does not prove this account.
	other, osto := raw(st.prove(testOther, slot))
	if res, err := ethproof.VerifyStorage(st.root, testContract, other, slot, osto); err == nil && res.Account.Exists {
		t.Errorf("another account's proof was taken for the contract's: %+v", res)
	}
}

// R10 Q2/M5: the slot formula, against the value measured on Base Sepolia (cast index bytes32 <leaf> 4).
func TestReplaySlotFor_MatchesTheChain(t *testing.T) {
	cases := []struct{ leaf, slot string }{
		{"0x11d861d3506473d80b34fbb0ab1ff2c680efafa2132cbe3e0ac4a442f3c5b0bb", "0x282ecf3311eb8918d1e78cdd2d0bf2f2c4313d25bf867d058157373b8655610f"},
		{"0x0000000000000000000000000000000000000000000000000000000000003039", "0x768c2ef7a283b6388a264912cb94197ab30efa9b151723b04c330733c3da9d5f"},
	}
	for _, c := range cases {
		if got := ethproof.ReplaySlotFor(common.HexToHash(c.leaf), 4); got != common.HexToHash(c.slot) {
			t.Errorf("slot of %s = %s, the chain's is %s", c.leaf, got.Hex(), c.slot)
		}
	}
	if ethproof.LeafConsumedTopic != common.HexToHash("0xf65d46899882fe56bab13370dcd464db22e179625c161992c07d962286f7ea73") {
		t.Errorf("LeafConsumed topic %s", ethproof.LeafConsumedTopic.Hex())
	}
}
