package intentcert

import (
	"encoding/hex"
	"testing"
)

func vecInputs() MessageInputs {
	w := func(b byte) (out [32]byte) {
		for i := range out {
			out[i] = b
		}
		return
	}
	return MessageInputs{CertenChainID: "certen-testnet", OperationID: w(1), GovRootV2: w(2), AccumulateSetRoot: w(3),
		Incarnation: w(4), GovernanceCommitment: w(5), CertenSetRoot: w(6)}
}

// Pinned against an independent computation (Python, pycryptodome keccak over the eight concatenated words).
func TestTheIntentMessageIsPinned(t *testing.T) {
	got, err := Message(vecInputs())
	if err != nil {
		t.Fatal(err)
	}
	if want := "c5bec2169ab34b84a24ae73f084d788857d503271d7e3a0edd99882775a061fb"; hex.EncodeToString(got[:]) != want {
		t.Fatalf("intent message %x, want %s", got, want)
	}
}

// Every input is bound, and none may be missing.
func TestEveryIntentInputIsBoundAndRequired(t *testing.T) {
	base, _ := Message(vecInputs())
	for name, mut := range map[string]func(*MessageInputs){
		"chain":       func(m *MessageInputs) { m.CertenChainID = "certen-mainnet" },
		"operation":   func(m *MessageInputs) { m.OperationID[0] ^= 1 },
		"govRoot":     func(m *MessageInputs) { m.GovRootV2[0] ^= 1 },
		"acc set":     func(m *MessageInputs) { m.AccumulateSetRoot[0] ^= 1 },
		"incarnation": func(m *MessageInputs) { m.Incarnation[0] ^= 1 },
		"governance":  func(m *MessageInputs) { m.GovernanceCommitment[0] ^= 1 },
		"certen set":  func(m *MessageInputs) { m.CertenSetRoot[0] ^= 1 },
	} {
		in := vecInputs()
		mut(&in)
		if got, err := Message(in); err != nil || got == base {
			t.Errorf("%s: not bound (%v)", name, err)
		}
	}
	for name, mut := range map[string]func(*MessageInputs){
		"no chain":       func(m *MessageInputs) { m.CertenChainID = "" },
		"no operation":   func(m *MessageInputs) { m.OperationID = [32]byte{} },
		"no govRoot":     func(m *MessageInputs) { m.GovRootV2 = [32]byte{} },
		"no acc set":     func(m *MessageInputs) { m.AccumulateSetRoot = [32]byte{} },
		"no incarnation": func(m *MessageInputs) { m.Incarnation = [32]byte{} },
		"no governance":  func(m *MessageInputs) { m.GovernanceCommitment = [32]byte{} },
		"no certen set":  func(m *MessageInputs) { m.CertenSetRoot = [32]byte{} },
	} {
		in := vecInputs()
		mut(&in)
		if _, err := Message(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
