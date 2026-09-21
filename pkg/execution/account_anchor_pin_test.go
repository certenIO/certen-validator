package execution

import (
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/consensus"
)

var pinAnchorV8 = common.HexToAddress("0xEA9eeeE42a7971792B11Fd2f682C9c1172490272")

func repointData(a common.Address) []byte {
	return append(crypto.Keccak256([]byte("setAnchorContract(address)"))[:4], common.LeftPadBytes(a.Bytes(), 32)...)
}

func pinnedStack(t *testing.T) *BatchStack {
	s := stackForChain(t, 84532)
	s.Orchestrators[84532] = &BatchOrchestrator{anchorV7: pinAnchorV8}
	return s
}

func TestParseAccountAnchorAllowlist(t *testing.T) {
	got, err := parseAccountAnchorAllowlist(" 84532:0xEA9eeeE42a7971792B11Fd2f682C9c1172490272 , 11155111:0x000000000000000000000000000000000000bEEF,")
	if err != nil || len(got[84532]) != 1 || got[84532][0] != pinAnchorV8 || len(got[11155111]) != 1 {
		t.Fatalf("parsed %v err %v", got, err)
	}
	for _, bad := range []string{"84532", "x:0xEA9eeeE42a7971792B11Fd2f682C9c1172490272", "84532:0x12"} {
		if _, err := parseAccountAnchorAllowlist(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// The anchor a chain is configured with is allowed; so is one the allowlist adds for the upgrade;
// nothing else - and a malformed allowlist adds nothing.
func TestAllowedAccountAnchor(t *testing.T) {
	s := pinnedStack(t)
	next := common.HexToAddress("0x000000000000000000000000000000000000bEEF")
	if !s.AllowedAccountAnchor(84532, pinAnchorV8) || s.AllowedAccountAnchor(84532, next) {
		t.Fatal("only the configured anchor is allowed without an allowlist")
	}
	t.Setenv(AccountAnchorAllowlistEnv, "84532:"+next.Hex())
	if !s.AllowedAccountAnchor(84532, next) || s.AllowedAccountAnchor(11155111, next) {
		t.Fatal("the allowlist adds its anchor for its chain only")
	}
	t.Setenv(AccountAnchorAllowlistEnv, "84532:"+next.Hex()+",garbage")
	if s.AllowedAccountAnchor(84532, next) || !s.AllowedAccountAnchor(84532, pinAnchorV8) {
		t.Fatal("a malformed allowlist must add nothing, and must not remove the configured anchor")
	}
	if s.AllowedAccountAnchor(84532, common.Address{}) {
		t.Fatal("the zero address is never an anchor")
	}
}

// A validator never queues - and so never signs for - a member that repoints its account away.
func TestEnqueueRefusesAForeignAnchorRepoint(t *testing.T) {
	s := pinnedStack(t)
	account := acct(7)
	self := [20]byte(common.BytesToAddress(account[:]))
	rogue := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	legs := []mirrorLeg{{LegID: "l0", ChainID: 84532, Target: self, Value: big.NewInt(0), Data: repointData(rogue)}}
	err := s.EnqueueOnDemand("i", "acc://a.acme", 84532, account, opid(1), legs, "att", 100, "", time.Time{}, "0xaccum")
	if !errors.Is(err, consensus.ErrAnchorRepointRefused) {
		t.Fatalf("err %v; want the repoint refused", err)
	}
	if n := len(s.Mempool.PendingOnDemand(84532)); n != 0 {
		t.Fatalf("%d member(s) queued", n)
	}
	legs[0].Data = repointData(pinAnchorV8)
	if err := s.EnqueueOnDemand("i", "acc://a.acme", 84532, account, opid(1), legs, "att", 100, "", time.Time{}, "0xaccum"); err != nil {
		t.Fatalf("a repoint to CERTEN's own anchor was refused: %v", err)
	}
}

// A member already in a pool from before the rule (restored from disk) is refused at signing.
func TestPeerRefusesToSignForAForeignAnchorRepoint(t *testing.T) {
	s := pinnedStack(t)
	m := odMember(1, 84532, 100)
	m.Legs = []LegExecution{{LegID: "l0", ChainID: 84532, Target: m.Account, Value: big.NewInt(0),
		Data: repointData(common.HexToAddress("0x000000000000000000000000000000000000dEaD"))}}
	if err := checkMemberAnchorPin(s, m); !errors.Is(err, consensus.ErrAnchorRepointRefused) {
		t.Fatalf("err %v; want refused", err)
	}
	if err := checkMemberAnchorPin(orchestratorAnchorPolicy{s.Orchestrators[84532]}, m); !errors.Is(err, consensus.ErrAnchorRepointRefused) {
		t.Fatalf("leader screen err %v; want refused", err)
	}
}
