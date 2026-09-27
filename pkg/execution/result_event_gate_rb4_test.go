package execution

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// RB-4: a contract call "succeeds" only if the event it committed to is among the settlement's
// inclusion-proven logs - status 1 is necessary, not sufficient. The member gate (VerifyExecutedCall)
// and the shortfall proof apply eventPresent to every committed event; a contract call committing no
// event is refused before either runs (TestMemberLegsAreTheSignedMemberOnTheChain).

var (
	rb4Target = common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	rb4Topic0 = crypto.Keccak256Hash([]byte("Completed(bytes32)"))
	rb4Order  = common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
)

func rb4Logs() []LogEntry {
	return []LogEntry{{Address: rb4Target, Topics: []common.Hash{rb4Topic0, rb4Order}, Data: []byte{7}}}
}

func TestRB4_CallWithCommittedEvent_Passes(t *testing.T) {
	if !eventPresent(rb4Logs(), ExpectedEvent{Contract: rb4Target, Topic0: rb4Topic0}) {
		t.Error("the committed event is in the logs")
	}
}

func TestRB4_CallMissingEvent_Rejected(t *testing.T) {
	if eventPresent(nil, ExpectedEvent{Contract: rb4Target, Topic0: rb4Topic0}) {
		t.Error("no logs: the committed event is absent")
	}
}

func TestRB4_CallWrongTopic_Rejected(t *testing.T) {
	if eventPresent(rb4Logs(), ExpectedEvent{Contract: rb4Target, Topic0: crypto.Keccak256Hash([]byte("Other()"))}) {
		t.Error("another event from the committed contract is not the committed event")
	}
}

func TestRB4_CallWrongContract_Rejected(t *testing.T) {
	if eventPresent(rb4Logs(), ExpectedEvent{Contract: common.HexToAddress("0x01"), Topic0: rb4Topic0}) {
		t.Error("the committed topic from another contract is not the committed event")
	}
}

func TestRB4_DataHashBinding(t *testing.T) {
	if !eventPresent(rb4Logs(), ExpectedEvent{Contract: rb4Target, Topic0: rb4Topic0, DataHash: [32]byte(crypto.Keccak256Hash([]byte{7}))}) {
		t.Error("a log whose data matches the committed hash is the committed event")
	}
	if eventPresent(rb4Logs(), ExpectedEvent{Contract: rb4Target, Topic0: rb4Topic0, DataHash: [32]byte(crypto.Keccak256Hash([]byte{8}))}) {
		t.Error("a log whose data does not match the committed hash is not the committed event")
	}
}

func TestRB4_TopiclessLogIsNotAnEvent(t *testing.T) {
	if eventPresent([]LogEntry{{Address: rb4Target}}, ExpectedEvent{Contract: rb4Target, Topic0: common.Hash{}}) {
		t.Error("a log with no topics matches no committed event")
	}
}
