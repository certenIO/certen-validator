// Copyright 2026 Certen Protocol

package execution

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// RB3-F64: a validator whose sending key is not its registered identity does not start. Live, validator
// 4 (identity 0x16ab…) sent with validator 1's key (0xd4a3…) and claimed validator 1's settlements.
func TestSendingKeyMustBeTheRegisteredIdentity(t *testing.T) {
	v1 := common.HexToAddress("0xd4a3dbbae0c04d4307c5e00a5e05b66acc289f5d")
	v4 := "0x16ab06f3634218a8f1f3b01dcdd32ddfbdc8a69d"

	err := sendersMatchIdentity(map[int64]common.Address{11155111: v1, 84532: v1, 421614: v1}, v4)
	if err == nil || !strings.Contains(err.Error(), v1.Hex()) || !strings.Contains(err.Error(), "84532") {
		t.Fatalf("validator 4 sending with validator 1's key must be refused, naming the sender and chains: %v", err)
	}
	// One chain wrong is enough.
	own := common.HexToAddress(v4)
	if err := sendersMatchIdentity(map[int64]common.Address{11155111: own, 84532: v1, 421614: own}, v4); err == nil {
		t.Fatal("a single chain sending as another validator must be refused")
	}
	if err := sendersMatchIdentity(map[int64]common.Address{11155111: own, 84532: own, 421614: own}, strings.ToUpper(v4[2:])); err != nil {
		t.Fatalf("its own key on every chain, identity in any case: %v", err)
	}
	for name, id := range map[string]string{"no identity": "", "not an address": "validator-4"} {
		if err := sendersMatchIdentity(map[int64]common.Address{11155111: own}, id); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
	if err := sendersMatchIdentity(nil, v4); err == nil {
		t.Fatal("no chain to check must be refused")
	}
}
