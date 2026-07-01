package execution

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// RB-5: storage-slot state-proof tests.
//
// Build a real account+storage Merkle-Patricia state, produce eth_getProof-style proofs,
// and assert StateProof.Verify accepts a valid proof against the true stateRoot and
// rejects a wrong value, a wrong stateRoot, and a tampered node. Also exercise the
// VerifyAgainstResult gate: a committed slot must be proven to the committed value.

// buildStateWithSlot builds a single-account state where `account` has storage
// slot=value, and returns a fully-populated StateProof plus the block stateRoot.
func buildStateWithSlot(t *testing.T, account common.Address, slot common.Hash, value *big.Int) (*StateProof, common.Hash) {
	t.Helper()

	// Storage trie: key = keccak256(slot), value = rlp(trimmed big-endian value).
	storageTrie := trie.NewEmpty(nil)
	stoKey := crypto.Keccak256(slot.Bytes())
	trimmed := common.TrimLeftZeroes(common.BigToHash(value).Bytes())
	stoVal, _ := rlp.EncodeToBytes(trimmed)
	storageTrie.Update(stoKey, stoVal)
	storageHash := storageTrie.Hash()

	// Account leaf with Root = storageHash.
	acc := ethAccount{
		Nonce:    1,
		Balance:  big.NewInt(0),
		Root:     storageHash,
		CodeHash: crypto.Keccak256(nil),
	}
	accRLP, err := rlp.EncodeToBytes(&acc)
	if err != nil {
		t.Fatalf("encode account: %v", err)
	}

	// State trie: key = keccak256(account), value = accountRLP.
	stateTrie := trie.NewEmpty(nil)
	accKey := crypto.Keccak256(account.Bytes())
	stateTrie.Update(accKey, accRLP)
	// Add a second unrelated account so the trie has real branch structure.
	other := common.HexToAddress("0x00000000000000000000000000000000000000ff")
	otherAcc := ethAccount{Nonce: 0, Balance: big.NewInt(5), Root: common.Hash{}, CodeHash: crypto.Keccak256(nil)}
	otherRLP, _ := rlp.EncodeToBytes(&otherAcc)
	stateTrie.Update(crypto.Keccak256(other.Bytes()), otherRLP)
	stateRoot := stateTrie.Hash()

	// Account proof.
	accCollector := NewMerkleProofCollector()
	if err := stateTrie.Prove(accKey, accCollector); err != nil {
		t.Fatalf("prove account: %v", err)
	}
	// Storage proof.
	stoCollector := NewMerkleProofCollector()
	if err := storageTrie.Prove(stoKey, stoCollector); err != nil {
		t.Fatalf("prove storage: %v", err)
	}

	sp := &StateProof{
		Account:      account,
		Slot:         slot,
		Value:        common.BigToHash(value),
		AccountProof: accCollector.GetNodes(),
		StorageHash:  storageHash,
		StorageProof: stoCollector.GetNodes(),
	}
	return sp, stateRoot
}

var (
	rb5Account = common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	rb5Slot    = common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000007")
)

func TestRB5_ValidStateProofVerifies(t *testing.T) {
	sp, root := buildStateWithSlot(t, rb5Account, rb5Slot, big.NewInt(42))
	if !sp.Verify(root) {
		t.Fatal("valid state proof must verify against the true stateRoot")
	}
}

func TestRB5_WrongStateRootRejected(t *testing.T) {
	sp, root := buildStateWithSlot(t, rb5Account, rb5Slot, big.NewInt(42))
	bad := root
	bad[0] ^= 0xFF
	if sp.Verify(bad) {
		t.Error("state proof must fail against a wrong stateRoot")
	}
}

func TestRB5_TamperedAccountNodeRejected(t *testing.T) {
	sp, root := buildStateWithSlot(t, rb5Account, rb5Slot, big.NewInt(42))
	n := len(sp.AccountProof) - 1
	sp.AccountProof[n] = append([]byte(nil), sp.AccountProof[n]...)
	sp.AccountProof[n][len(sp.AccountProof[n])-1] ^= 0xFF
	if sp.Verify(root) {
		t.Error("state proof must fail when an account proof node is tampered")
	}
}

func TestRB5_TamperedStorageNodeRejected(t *testing.T) {
	sp, root := buildStateWithSlot(t, rb5Account, rb5Slot, big.NewInt(42))
	n := len(sp.StorageProof) - 1
	sp.StorageProof[n] = append([]byte(nil), sp.StorageProof[n]...)
	sp.StorageProof[n][len(sp.StorageProof[n])-1] ^= 0xFF
	if sp.Verify(root) {
		t.Error("state proof must fail when a storage proof node is tampered")
	}
}

func TestRB5_WrongClaimedValueRejected(t *testing.T) {
	sp, root := buildStateWithSlot(t, rb5Account, rb5Slot, big.NewInt(42))
	// Claim a different value than what the storage proof proves.
	sp.Value = common.BigToHash(big.NewInt(43))
	if sp.Verify(root) {
		t.Error("state proof must fail when the claimed value != the proven slot value")
	}
}

func TestRB5_MismatchedStorageHashRejected(t *testing.T) {
	sp, root := buildStateWithSlot(t, rb5Account, rb5Slot, big.NewInt(42))
	// Claim a storageHash that doesn't match the account's actual storageRoot.
	sp.StorageHash[0] ^= 0xFF
	if sp.Verify(root) {
		t.Error("state proof must fail when StorageHash != account.storageRoot")
	}
}

// TestRB5_GateEnforcesCommittedState drives the VerifyAgainstResult-level gate.
func TestRB5_GateEnforcesCommittedState(t *testing.T) {
	sp, root := buildStateWithSlot(t, rb5Account, rb5Slot, big.NewInt(42))
	result := &ExternalChainResult{StateRoot: root, StateProofs: []*StateProof{sp}}

	// Committed value matches ⇒ pass.
	c := &ExecutionCommitment{ExpectedState: []ExpectedStateSlot{{Account: rb5Account, Slot: rb5Slot, Value: common.BigToHash(big.NewInt(42))}}}
	if !c.verifyExpectedState(result) {
		t.Error("gate must accept a correctly-proven committed slot value")
	}

	// Committed a different value ⇒ reject (proof proves 42, commit says 43).
	cBad := &ExecutionCommitment{ExpectedState: []ExpectedStateSlot{{Account: rb5Account, Slot: rb5Slot, Value: common.BigToHash(big.NewInt(43))}}}
	if cBad.verifyExpectedState(result) {
		t.Error("gate must reject when committed value != proven value")
	}

	// No proof present for the committed slot ⇒ reject.
	cMissing := &ExecutionCommitment{ExpectedState: []ExpectedStateSlot{{Account: rb5Account, Slot: common.HexToHash("0x09"), Value: common.BigToHash(big.NewInt(1))}}}
	if cMissing.verifyExpectedState(result) {
		t.Error("gate must reject when no state proof is present for the committed slot")
	}
}
