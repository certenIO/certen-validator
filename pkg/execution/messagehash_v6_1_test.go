// Phase 3/4 A++ messageHash + validatorSetRoot golden-vector tests for V6.1.
//
// These tests pin the EXACT byte layout that CertenAnchorV6_1.sol::_verifyBLSProof
// and ::_recomputeValidatorSetRoot consume. Any drift in the Go encoding
// (slot order, padding, domain bytes) will fail here BEFORE we ship a
// validator that produces signatures the contract rejects.
//
// Spec references:
//   - CertenAnchorV6_1.sol _verifyBLSProof (6-field abi.encode)
//   - CertenAnchorV6_1.sol _recomputeValidatorSetRoot (sorted abi.encode)
//   - test/CertenAnchorV6_1.t.sol (Solidity-side equivalent)
package execution

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// computeEvmMessageHashV6_1 — six 32-byte slots, keccak256 over 192 bytes.
// =============================================================================

func TestEvmMessageHashV6_1_PreimageLayout(t *testing.T) {
	// Fixed test inputs (also used in the Solidity-side test).
	ecm := &EthereumContractManager{
		config: &CertenContractConfig{ChainID: 11155111}, // Sepolia
	}
	anchorId := bytes32From("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	execCommit := bytes32From("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	operationID := bytes32From("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	setRoot := bytes32From("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")

	got := ecm.computeEvmMessageHashV6_1(anchorId, execCommit, operationID, setRoot)

	// Hand-build the expected preimage exactly per the contract:
	//   bytes32("certen:bls:v1:pre") || uint256(chainId) || anchorId ||
	//   executionCommitment || operationID || validatorSetRoot
	expectedPreimage := make([]byte, 0, 6*32)
	var domain [32]byte
	copy(domain[:], []byte("certen:bls:v1:pre"))
	expectedPreimage = append(expectedPreimage, domain[:]...)
	var chainIDBE [32]byte
	big.NewInt(11155111).FillBytes(chainIDBE[:])
	expectedPreimage = append(expectedPreimage, chainIDBE[:]...)
	expectedPreimage = append(expectedPreimage, anchorId[:]...)
	expectedPreimage = append(expectedPreimage, execCommit[:]...)
	expectedPreimage = append(expectedPreimage, operationID[:]...)
	expectedPreimage = append(expectedPreimage, setRoot[:]...)
	if len(expectedPreimage) != 192 {
		t.Fatalf("expected 192-byte preimage, got %d", len(expectedPreimage))
	}

	var want [32]byte
	copy(want[:], crypto.Keccak256(expectedPreimage))

	if got != want {
		t.Fatalf("messageHash V6.1 mismatch\n  got:  %x\n  want: %x", got, want)
	}
}

func TestEvmMessageHashV6_1_DomainSlotPaddedRight(t *testing.T) {
	// "certen:bls:v1:pre" is 17 bytes; the bytes32 slot pads zeros on the
	// right (least-significant bytes). Solidity bytes32("...") works the same
	// way. This test pins the domain bytes so any future "what does bytes32
	// of a short string look like" question is answered by the test, not
	// argued.
	var domain [32]byte
	copy(domain[:], []byte("certen:bls:v1:pre"))

	expected := [32]byte{
		'c', 'e', 'r', 't', 'e', 'n', ':', 'b', 'l', 's', ':', 'v', '1', ':', 'p', 'r',
		'e', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	if !bytes.Equal(domain[:], expected[:]) {
		t.Fatalf("domain bytes32 layout drift\n  got:  %x\n  want: %x", domain, expected)
	}
}

func TestEvmMessageHashV6_1_ChainIDChangesHash(t *testing.T) {
	// Two ECMs with different chain IDs but everything else identical must
	// produce different hashes — proves chain binding is real.
	a := &EthereumContractManager{config: &CertenContractConfig{ChainID: 1}}
	b := &EthereumContractManager{config: &CertenContractConfig{ChainID: 11155111}}
	x := bytes32From("0x1111111111111111111111111111111111111111111111111111111111111111")
	h1 := a.computeEvmMessageHashV6_1(x, x, x, x)
	h2 := b.computeEvmMessageHashV6_1(x, x, x, x)
	if h1 == h2 {
		t.Fatalf("chain-binding broken: same hash across chains %x", h1)
	}
}

func TestEvmMessageHashV6_1_EveryFieldMatters(t *testing.T) {
	// Flipping any of the 4 input bytes32 fields (with chainId fixed) must
	// change the output. Defense against accidental slot-reuse bugs.
	ecm := &EthereumContractManager{config: &CertenContractConfig{ChainID: 1287}}
	base := func() [32]byte {
		return ecm.computeEvmMessageHashV6_1(
			bytes32From("0x01"), bytes32From("0x02"),
			bytes32From("0x03"), bytes32From("0x04"),
		)
	}
	original := base()

	flipAnchor := ecm.computeEvmMessageHashV6_1(
		bytes32From("0xff"), bytes32From("0x02"),
		bytes32From("0x03"), bytes32From("0x04"))
	if flipAnchor == original {
		t.Fatal("flipping anchorId must change hash")
	}
	flipExec := ecm.computeEvmMessageHashV6_1(
		bytes32From("0x01"), bytes32From("0xff"),
		bytes32From("0x03"), bytes32From("0x04"))
	if flipExec == original {
		t.Fatal("flipping executionCommitment must change hash")
	}
	flipOpID := ecm.computeEvmMessageHashV6_1(
		bytes32From("0x01"), bytes32From("0x02"),
		bytes32From("0xff"), bytes32From("0x04"))
	if flipOpID == original {
		t.Fatal("flipping operationID must change hash")
	}
	flipSetRoot := ecm.computeEvmMessageHashV6_1(
		bytes32From("0x01"), bytes32From("0x02"),
		bytes32From("0x03"), bytes32From("0xff"))
	if flipSetRoot == original {
		t.Fatal("flipping validatorSetRoot must change hash")
	}
}

// =============================================================================
// deriveV6_1BundleID — bundleId now includes operationID
// =============================================================================

func TestDeriveV6_1BundleID_OperationIDChangesBundle(t *testing.T) {
	ecm := &EthereumContractManager{config: &CertenContractConfig{ChainID: 11155111}}
	commit := stubCommitment()
	adi := bytes32From("0xaa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00")
	height := uint64(12345)

	bidA := ecm.deriveV6_1BundleID(adi, commit, bytes32From("0xa1"), height)
	bidB := ecm.deriveV6_1BundleID(adi, commit, bytes32From("0xa2"), height)
	if bidA == bidB {
		t.Fatalf("different operationIDs must yield different bundleIds (got equal: %x)", bidA)
	}
}

func TestDeriveV6_1BundleID_DifferentFromV6(t *testing.T) {
	// Same inputs, V6 vs V6.1 must produce different bundleIds since V6.1
	// adds operationID and a new domain tag ("certen:bundleid:v1.1").
	ecm := &EthereumContractManager{config: &CertenContractConfig{ChainID: 1}}
	commit := stubCommitment()
	adi := bytes32From("0x01")
	height := uint64(42)

	v6 := ecm.deriveV6BundleID(adi, commit, height)
	v6_1 := ecm.deriveV6_1BundleID(adi, commit, bytes32From("0x02"), height)
	if v6 == v6_1 {
		t.Fatalf("V6 and V6.1 bundleIds must differ (got equal: %x)", v6)
	}
}

// =============================================================================
// ComputeValidatorSetRootV6_1 — sorted abi.encode of (addrs, powers, num, den)
// =============================================================================

func TestValidatorSetRoot_SortIsInsertionOrderIndependent(t *testing.T) {
	// Same set, two different input orderings → identical root after sort.
	a := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	b := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	c := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")

	addrs1 := []common.Address{a, b, c}
	powers1 := []*big.Int{big.NewInt(100), big.NewInt(200), big.NewInt(300)}
	s1Addrs, s1Powers := SortValidatorsForSetRoot(addrs1, powers1)
	r1, err := ComputeValidatorSetRootV6_1(s1Addrs, s1Powers, big.NewInt(2), big.NewInt(3))
	if err != nil {
		t.Fatal(err)
	}

	addrs2 := []common.Address{c, a, b}
	powers2 := []*big.Int{big.NewInt(300), big.NewInt(100), big.NewInt(200)}
	s2Addrs, s2Powers := SortValidatorsForSetRoot(addrs2, powers2)
	r2, err := ComputeValidatorSetRootV6_1(s2Addrs, s2Powers, big.NewInt(2), big.NewInt(3))
	if err != nil {
		t.Fatal(err)
	}
	if r1 != r2 {
		t.Fatalf("set root must be insertion-order independent\n  r1: %x\n  r2: %x", r1, r2)
	}
}

func TestValidatorSetRoot_ChangesOnMembershipAdd(t *testing.T) {
	a := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	b := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	c := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")

	sa, sp := SortValidatorsForSetRoot(
		[]common.Address{a, b},
		[]*big.Int{big.NewInt(100), big.NewInt(100)},
	)
	r2, _ := ComputeValidatorSetRootV6_1(sa, sp, big.NewInt(2), big.NewInt(3))

	sa3, sp3 := SortValidatorsForSetRoot(
		[]common.Address{a, b, c},
		[]*big.Int{big.NewInt(100), big.NewInt(100), big.NewInt(100)},
	)
	r3, _ := ComputeValidatorSetRootV6_1(sa3, sp3, big.NewInt(2), big.NewInt(3))

	if r2 == r3 {
		t.Fatalf("adding a validator must change set root")
	}
}

func TestValidatorSetRoot_ChangesOnThresholdChange(t *testing.T) {
	a := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	b := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	sa, sp := SortValidatorsForSetRoot(
		[]common.Address{a, b},
		[]*big.Int{big.NewInt(100), big.NewInt(100)},
	)
	r23, _ := ComputeValidatorSetRootV6_1(sa, sp, big.NewInt(2), big.NewInt(3))
	r12, _ := ComputeValidatorSetRootV6_1(sa, sp, big.NewInt(1), big.NewInt(2))
	if r23 == r12 {
		t.Fatalf("changing threshold must change set root")
	}
}

func TestValidatorSetRoot_LengthMismatchRejected(t *testing.T) {
	_, err := ComputeValidatorSetRootV6_1(
		[]common.Address{common.HexToAddress("0xaaaa")},
		[]*big.Int{big.NewInt(1), big.NewInt(2)}, // mismatched len
		big.NewInt(2), big.NewInt(3),
	)
	if err == nil {
		t.Fatal("expected error on length mismatch")
	}
}

// =============================================================================
// helpers
// =============================================================================

func bytes32From(s string) [32]byte {
	var out [32]byte
	// Accept "0x..." (full or partial) — right-pad with zeros on the right
	// of the SOURCE bytes (so the high-order bytes carry the supplied data).
	// This matches how Solidity bytes32 literals work for short hex.
	hexStr := s
	if len(hexStr) >= 2 && hexStr[0] == '0' && (hexStr[1] == 'x' || hexStr[1] == 'X') {
		hexStr = hexStr[2:]
	}
	// Decode left-aligned: "0xff" → out[0] = 0xff, rest zero.
	for i := 0; i < len(hexStr) && (i/2) < 32; i += 2 {
		hi := hexNibble(hexStr[i])
		var lo byte
		if i+1 < len(hexStr) {
			lo = hexNibble(hexStr[i+1])
		}
		out[i/2] = (hi << 4) | lo
	}
	return out
}

func hexNibble(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return 10 + c - 'a'
	case 'A' <= c && c <= 'F':
		return 10 + c - 'A'
	}
	return 0
}

func stubCommitment() contracts.CommitmentData {
	return contracts.CommitmentData{
		OperationCommitment:  bytes32From("0x01"),
		CrossChainCommitment: bytes32From("0x02"),
		GovernanceRoot:       bytes32From("0x03"),
		ExecutionCommitment:  bytes32From("0x04"),
	}
}
