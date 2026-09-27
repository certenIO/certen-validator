package execution

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/proof"
)

// The live failure of 2026-09-20, as data: the four user-signed blobs of intent 5a2ebba0 as
// written to Accumulate (tx aad58e15…@orchid-logistics-tcl1.acme/data), and the calldata of its
// settlement, which reverted on Base Sepolia in tx 0x54562d54… with FDBUSD InsufficientBalance.
// A peer holds exactly this when asked to attest the failure.
func liveIntentBlobs(t *testing.T) [][]byte {
	t.Helper()
	var blobs [][]byte
	for i := 0; i < 4; i++ {
		b, err := os.ReadFile(filepath.Join("testdata", "intent_5a2ebba0", "blob"+string(rune('0'+i))+".json"))
		if err != nil {
			t.Fatalf("read blob %d: %v", i, err)
		}
		blobs = append(blobs, b)
	}
	return blobs
}

// A peer binds the reverted transaction to the signed intent: the operationID it derives from the
// blobs is the one the settlement was authorised under, and the call the intent committed to is
// the call the settlement executed.
func TestRevertedSettlementBindsToTheSignedIntent(t *testing.T) {
	blobs := liveIntentBlobs(t)
	opBytes, _, err := proof.ComputeCanonical4BlobHash(blobs[0], blobs[1], blobs[2], blobs[3])
	if err != nil {
		t.Fatalf("operationID: %v", err)
	}
	if got := hex.EncodeToString(opBytes); got != "8f57121501d6a592cb54f3eb6e73dd856b39909348fcbb8c1df4f9b8acf07941" {
		t.Fatalf("operationID from the signed blobs %s", got)
	}

	legs := parseCommittedCallLegs(blobs[1])
	if len(legs) != 1 {
		t.Fatalf("committed call legs %d, want 1", len(legs))
	}
	call, ok := legs[0].committedCall()
	if !ok {
		t.Fatal("the committed FDBUSD call cannot be bound")
	}

	input, _ := hex.DecodeString(liveRevertedSettlementInput)
	exec, err := decodeAccountExecution(input)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := matchCommittedCalls(exec.Calls, []CommittedCall{call}); err != nil {
		t.Fatalf("the live settlement is the committed call: %v", err)
	}
	var opID [32]byte
	copy(opID[:], opBytes)
	if exec.OperationID != opID {
		t.Fatalf("settlement operationID 0x%x, intent 0x%x", exec.OperationID[:8], opID[:8])
	}

	// Anything else is not this intent's failure.
	tampered := call
	tampered.Data = append([]byte{}, call.Data...)
	tampered.Data[len(tampered.Data)-1] ^= 1
	if err := matchCommittedCalls(exec.Calls, []CommittedCall{tampered}); err == nil {
		t.Fatal("bound a transaction that executed different calldata")
	}
	other := call
	other.Target = common.HexToAddress("0x1111111111111111111111111111111111111111")
	if err := matchCommittedCalls(exec.Calls, []CommittedCall{other}); err == nil {
		t.Fatal("bound a transaction that called a different target")
	}
	if err := matchCommittedCalls(exec.Calls, nil); err == nil {
		t.Fatal("bound a transaction to no commitment at all")
	}
}

// The executor's commitment carries the committed calldata, so its gate can bind a revert too; a
// commitment without it cannot be bound, and the gate then refuses rather than guessing.
func TestRBCallLegCarriesTheCommittedCall(t *testing.T) {
	legs := parseRBContractCallLegs([]interface{}{map[string]interface{}{
		"chainKey": "base-sepolia", "target": "0x2d9e724dE974A81E97ee553B3482cAFA6d5Fe46b",
		"value": "0", "callData": "0xe2233eb8", "execTxHash": "0x01",
	}})
	if len(legs) != 1 {
		t.Fatalf("legs %d", len(legs))
	}
	c, ok := legs[0].committedCall()
	if !ok || c.Target != common.HexToAddress("0x2d9e724dE974A81E97ee553B3482cAFA6d5Fe46b") ||
		hex.EncodeToString(c.Data) != "e2233eb8" || c.Value.Sign() != 0 {
		t.Fatalf("committed call %+v, %v", c, ok)
	}
	old := parseRBContractCallLegs([]interface{}{map[string]interface{}{"chainKey": "base-sepolia", "target": "0x2d9e724dE974A81E97ee553B3482cAFA6d5Fe46b"}})
	if _, ok := old[0].committedCall(); ok {
		t.Fatal("a leg without calldata was treated as bindable")
	}
}

func TestCycleOperationID(t *testing.T) {
	if cycleOperationID(map[string]interface{}{}) != nil {
		t.Fatal("absent operationID must be nil")
	}
	op := cycleOperationID(map[string]interface{}{"operationID": "0x8f57121501d6a592cb54f3eb6e73dd856b39909348fcbb8c1df4f9b8acf07941"})
	if op == nil || op[0] != 0x8f {
		t.Fatalf("got %v", op)
	}
}

// liveRevertedSettlementInput is the calldata of Base Sepolia transaction 0x54562d54…, the reverted
// settlement of intent 5a2ebba0 (2026-09-20).
const liveRevertedSettlementInput = "5b1264bc0000000000000000000000002d9e724de974a81e97ee553b3482cafa6d5fe46b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000064e2233eb8000000000000000000000000e66e6f40f1d7a1c06abace493f38c03800ac565a00000000000000000000000000000000000000000000000000000000000257490b935dd95dacddaa87e656aaffda057424de50244ca1bcb071ade6ea5c361ab10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001805f8e6490594525e574ecad9bbe1a6047f2c395c96f130c0fb1f325bc76f55fd200000000000000000000000000000000000000000000000000000000000001c08f57121501d6a592cb54f3eb6e73dd856b39909348fcbb8c1df4f9b8acf0794100000000000000000000000000000000000000000000000000000000000001e000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000006ab06ab4000000000000000000000000000000000000000000000000000000006ab0790000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000206163633a2f2f6f72636869642d6c6f676973746963732d74636c312e61636d6500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
