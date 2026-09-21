package consensus

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

var (
	pinAccount = common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B")
	pinAnchor  = common.HexToAddress("0xEA9eeeE42a7971792B11Fd2f682C9c1172490272")
	pinRogue   = common.HexToAddress("0x000000000000000000000000000000000000dEaD")
)

type pinPolicy map[int64]common.Address

func (p pinPolicy) AllowedAccountAnchor(chainID int64, a common.Address) bool { return p[chainID] == a }

func setAnchorCall(a common.Address) []byte {
	return append(append([]byte{}, setAnchorContractSelector...), common.LeftPadBytes(a.Bytes(), 32)...)
}

// The selector CertenAccountV7 compiles setAnchorContract(address) to, from the contract's own build
// artifact (certen-contracts evm/out/CertenAccountV7.sol, methodIdentifiers).
func TestSetAnchorContractSelector(t *testing.T) {
	if got := hex.EncodeToString(setAnchorContractSelector); got != "575652c2" {
		t.Fatalf("selector %s, want 575652c2", got)
	}
}

func TestCheckAccountAnchorCall(t *testing.T) {
	policy := pinPolicy{84532: pinAnchor}
	other := common.HexToAddress("0x1111111111111111111111111111111111111111")
	dirty := setAnchorCall(pinAnchor)
	dirty[5] = 1 // non-zero padding: not a canonical address argument
	for _, c := range []struct {
		name    string
		policy  AccountAnchorPolicy
		target  common.Address
		data    []byte
		refused bool
	}{
		{"a call to another contract", policy, other, setAnchorCall(pinRogue), false},
		{"a transfer", policy, pinAccount, nil, false},
		{"another admin call to itself", policy, pinAccount, []byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3}, false},
		{"to a CERTEN anchor", policy, pinAccount, setAnchorCall(pinAnchor), false},
		{"to a foreign anchor", policy, pinAccount, setAnchorCall(pinRogue), true},
		{"to a CERTEN anchor of another chain", pinPolicy{1: pinAnchor}, pinAccount, setAnchorCall(pinAnchor), true},
		{"with no policy wired", nil, pinAccount, setAnchorCall(pinAnchor), true},
		{"truncated", policy, pinAccount, setAnchorCall(pinAnchor)[:20], true},
		{"with trailing bytes", policy, pinAccount, append(setAnchorCall(pinAnchor), 0), true},
		{"with dirty padding", policy, pinAccount, dirty, true},
	} {
		err := CheckAccountAnchorCall(c.policy, 84532, pinAccount, c.target, c.data)
		if c.refused != (err != nil) || (err != nil && !errors.Is(err, ErrAnchorRepointRefused)) {
			t.Errorf("%s: err=%v, want refused=%t", c.name, err, c.refused)
		}
	}
}

func pinIntent(t *testing.T, legs ...map[string]interface{}) *CertenIntent {
	t.Helper()
	raw, err := json.Marshal(map[string]interface{}{"protocol": "CERTEN", "version": "2.0", "legs": legs})
	if err != nil {
		t.Fatal(err)
	}
	return &CertenIntent{IntentID: "pin", CrossChainData: raw}
}

func pinLeg(from, target common.Address, data []byte) map[string]interface{} {
	return map[string]interface{}{"legId": "l", "chainId": 84532, "from": from.Hex(),
		"executionPayload": map[string]interface{}{"target": target.Hex(), "callData": "0x" + hex.EncodeToString(data), "chainId": 84532}}
}

// The rule applies to the legs as the user signed them, one bad leg refusing the whole intent.
func TestCheckIntentAccountAnchors(t *testing.T) {
	policy := pinPolicy{84532: pinAnchor}
	transfer := pinLeg(pinAccount, common.HexToAddress("0x1111111111111111111111111111111111111111"), nil)
	if err := CheckIntentAccountAnchors(policy, pinIntent(t, transfer, pinLeg(pinAccount, pinAccount, setAnchorCall(pinAnchor)))); err != nil {
		t.Fatalf("a migration to a CERTEN anchor was refused: %v", err)
	}
	err := CheckIntentAccountAnchors(policy, pinIntent(t, transfer, pinLeg(pinAccount, pinAccount, setAnchorCall(pinRogue))))
	if !errors.Is(err, ErrAnchorRepointRefused) {
		t.Fatalf("a repoint to a foreign anchor was allowed: %v", err)
	}
	bad := pinLeg(pinAccount, pinAccount, setAnchorCall(pinRogue))
	bad["from"] = "not-an-address"
	if err := CheckIntentAccountAnchors(policy, pinIntent(t, bad)); !errors.Is(err, ErrAnchorRepointRefused) {
		t.Fatalf("a setAnchorContract leg with an unreadable source was allowed: %v", err)
	}
	if err := CheckIntentAccountAnchors(policy, pinIntent(t, transfer)); err != nil {
		t.Fatalf("an ordinary intent was refused: %v", err)
	}
}

// The refusal must come before the intent is queued for batching or sent by the per-intent path, on
// every validator: after either, a signature or a transaction may already exist.
func TestAnchorPinRunsBeforeAnythingIsQueuedOrSent(t *testing.T) {
	raw, err := os.ReadFile("bft_integration.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	pin := strings.Index(src, "CheckIntentAccountAnchors(anchorPolicy, certenIntent)")
	enqueue := strings.Index(src, "batchQueued = bv.enqueueForBatch(")
	if pin < 0 || enqueue < 0 || pin > enqueue {
		t.Fatalf("anchor pin at %d, enqueue at %d: the pin must run first", pin, enqueue)
	}
}
