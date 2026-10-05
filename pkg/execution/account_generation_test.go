package execution

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// RB5-F57: the calldata of a settlement names its account generation, and a chain accepts only its own.

func f57V4Member(t *testing.T, legs int) (*PendingBatchIntent, *BatchTree) {
	t.Helper()
	withAccountLeafVersions(t, "84532=v4")
	p := f57Member("gen", 950+uint64(legs), time.Unix(1_790_000_000, 0).Add(20*time.Minute), legs)
	return p, f57Tree(t, 84532, p)
}

// The settlement a v4 chain sends decodes - in every decoder that judges settlements - as a CertenAccountV7_3 call with
// the member's window; a v3 chain's as before.
func TestASettlementDecodesAsItsGeneration(t *testing.T) {
	for _, legs := range []int{1, 2} {
		p, tree := f57V4Member(t, legs)
		in, _ := p.LeafInput()
		data := f57SettlementCalldata(t, p, tree, nil)
		exec, err := decodeAccountExecution(data)
		if err != nil {
			t.Fatal(err)
		}
		if exec.Generation != AccountLeafV4 || exec.NotBefore != in.NotBefore || exec.NotAfter != in.NotAfter ||
			exec.Batch != (legs > 1) || len(exec.Calls) != legs || exec.AnchorID != tree.BundleID {
			t.Fatalf("%d leg(s): decoded %+v", legs, exec)
		}
		proof, ok := settlementProofOf(data)
		if !ok || proof.Generation != AccountLeafV4 || proof.NotAfter != in.NotAfter || proof.NotBefore != in.NotBefore ||
			proof.AnchorId != tree.BundleID {
			t.Fatalf("%d leg(s): settlementProofOf %+v %t", legs, proof, ok)
		}
		if err := requireChainGeneration(84532, exec); err != nil {
			t.Fatal(err)
		}
	}
	// The same member on the v3 default: a CertenAccountV7_2 call with no window.
	withAccountLeafVersions(t, "")
	p := f57Member("gen3", 960, time.Unix(1_790_000_000, 0).Add(20*time.Minute), 1)
	data := f57SettlementCalldata(t, p, f57Tree(t, 84532, p), nil)
	exec, err := decodeAccountExecution(data)
	if err != nil || exec.Generation != AccountLeafV3 || exec.NotAfter != 0 {
		t.Fatalf("v3: %+v %v", exec, err)
	}
}

// No cross-version fallback: an execution of the other generation is no member's execution on this chain, either way.
func TestAnExecutionOfTheOtherGenerationIsRefused(t *testing.T) {
	withAccountLeafVersions(t, "84532=v4")
	if err := requireChainGeneration(84532, &accountExecution{Generation: AccountLeafV3}); err == nil ||
		!strings.Contains(err.Error(), "CertenAccountV7_2") {
		t.Fatalf("a v3 execution on a v4 chain: %v", err)
	}
	if err := requireChainGeneration(11155111, &accountExecution{Generation: AccountLeafV4}); err == nil {
		t.Fatal("a v4 execution on a v3 chain was accepted")
	}
	if err := requireChainGeneration(1, &accountExecution{Generation: AccountLeafV3}); !errors.Is(err, ErrNoAccountLeafVersion) {
		t.Fatalf("a chain on no version: %v", err)
	}
	// Each generation's binding refuses the other's leaf shape.
	if _, err := (accountV7_2{}).MemberLeaf(nil, BatchLeafInput{NotBefore: 1, NotAfter: 2}); err == nil {
		t.Fatal("a v3 account took a window")
	}
	if _, err := (accountV7_3{}).MemberLeaf(nil, BatchLeafInput{}); !errors.Is(err, ErrNoMemberWindow) {
		t.Fatalf("a v4 account without a window: %v", err)
	}
}

// A v4 settlement mined outside its leaf's window reverted on the window, not on the intent - whatever its expiresAt.
func TestTimingRevertJudgesTheLeafWindow(t *testing.T) {
	p := settlementProof{AccountProofV7_2: contracts.AccountProofV7_2{Timestamp: big.NewInt(100), ExpiresAt: big.NewInt(10_000)},
		Generation: AccountLeafV4, NotBefore: 120, NotAfter: 200}
	for _, c := range []struct {
		at   uint64
		want bool
	}{{110, true}, {120, false}, {200, false}, {201, true}, {9_999, true}} {
		if got, why := timingRevert(p, c.at); got != c.want {
			t.Fatalf("mined at %d: timing=%t (%s), want %t", c.at, got, why, c.want)
		}
	}
}

// attemptFake answers what checkAuthorizedAttempt reads for one v4 attempt whose leaf is in an attested anchor.
type attemptFake struct {
	attemptChain
	anchor common.Address
	signed [32]byte // the leaf the anchor's root holds
	mined  uint64
}

var attemptFakeABI = func() abi.ABI {
	a, err := abi.JSON(strings.NewReader(strings.TrimSuffix(accountAttemptV7_3ABIJSON, "]") + "," +
		strings.TrimPrefix(anchorAttemptABIJSON, "[")))
	if err != nil {
		panic(err)
	}
	return a
}()

func (f *attemptFake) CallContract(_ context.Context, msg ethereum.CallMsg, _ *big.Int) ([]byte, error) {
	if string(msg.Data[:4]) == string(contracts.AnchorsCallData([32]byte{})[:4]) {
		out := make([]byte, 17*32)
		out[9*32+31] = 1                    // timestamp: created at time 1, as every real anchor records its creation
		out[11*32+31], out[12*32+31] = 1, 1 // valid, proofExecuted
		return out, nil
	}
	m, err := attemptFakeABI.MethodById(msg.Data[:4])
	if err != nil {
		return nil, err
	}
	args, err := m.Inputs.Unpack(msg.Data[4:])
	if err != nil {
		return nil, err
	}
	switch m.Name {
	case "anchorContract":
		return m.Outputs.Pack(f.anchor)
	case "computeSingleCommitment", "computeBatchCommitment":
		return m.Outputs.Pack([32]byte{0xc0})
	case "computeLeaf": // the account's leaf over everything it is given, the window included
		return m.Outputs.Pack([32]byte(ethcrypto.Keccak256Hash(msg.Data[4:])))
	case "isLeafConsumed":
		return m.Outputs.Pack(false)
	case "verifyProof":
		return m.Outputs.Pack(args[2].([32]byte) == f.signed)
	}
	return nil, errors.New("unexpected call " + m.Name)
}

func (f *attemptFake) FilterLogs(context.Context, ethereum.FilterQuery) ([]types.Log, error) {
	return []types.Log{{BlockNumber: 1}}, nil // attested long before the attempt
}

func (f *attemptFake) HeaderByNumber(context.Context, *big.Int) (*types.Header, error) {
	return &types.Header{Time: f.mined, Number: big.NewInt(5000)}, nil
}

// A reverted v4 attempt counts as the member's failure only when it was mined inside the window its leaf binds: mined
// after notAfter, it reverted LeafExpired - the deadline, not the execution - whatever expiresAt the sender chose.
func TestAnAttemptOutsideItsLeafWindowIsNotTheMembersFailure(t *testing.T) {
	account := common.HexToAddress("0xfa96ed9b2bc7139fa671e1faf53f901adeea5b32")
	exec := &accountExecution{Generation: AccountLeafV4, NotBefore: 1000, NotAfter: 2000,
		Calls:    []CommittedCall{{Target: dst, Value: big.NewInt(0)}},
		AnchorID: [32]byte{9}, OperationID: [32]byte{7}, AuthorityBook: [32]byte{1}, AuthorityPage: 1, proofDecodedOK: true,
		Timestamp: big.NewInt(0), ExpiresAt: big.NewInt(1 << 40), AdiURLLen: 16}
	abiJSON, _ := accountAttemptABIFor(AccountLeafV4)
	acctABI, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		t.Fatal(err)
	}
	leafCall, err := acctABI.Pack("computeLeaf", [32]byte{0xc0}, exec.OperationID, exec.AuthorityBook, exec.AuthorityPage,
		exec.NotBefore, exec.NotAfter)
	if err != nil {
		t.Fatal(err)
	}
	signed := [32]byte(ethcrypto.Keccak256Hash(leafCall[4:]))
	tx := types.NewTx(&types.DynamicFeeTx{To: &account, Value: big.NewInt(0), Gas: 500000})
	receipt := &types.Receipt{Status: 0, BlockNumber: big.NewInt(5000)}

	inside := &attemptFake{anchor: common.HexToAddress("0xa1"), signed: signed, mined: 1500}
	if err := checkAuthorizedAttempt(context.Background(), inside, tx, receipt, exec, account); err != nil {
		t.Fatalf("an attempt inside its window: %v", err)
	}
	late := &attemptFake{anchor: common.HexToAddress("0xa1"), signed: signed, mined: 2001}
	if err := checkAuthorizedAttempt(context.Background(), late, tx, receipt, exec, account); err == nil ||
		!strings.Contains(err.Error(), "outside its leaf's window") {
		t.Fatalf("an attempt after notAfter: %v", err)
	}
	early := &attemptFake{anchor: common.HexToAddress("0xa1"), signed: signed, mined: 999}
	if err := checkAuthorizedAttempt(context.Background(), early, tx, receipt, exec, account); err == nil {
		t.Fatal("an attempt before notBefore was accepted as the member's failure")
	}
}
