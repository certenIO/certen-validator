package ethrpc

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

// RB5 D4: an outcome peer reads contract state (an anchor, the outcome registry, an account's isLeafConsumed) only as
// independent providers agree on it, at a recent block every one of them holds.

func callProvider(final []byte) *stubProvider {
	p := provider(11155111, header(testHeight, "final"))
	p.callResult = final
	p.latest = testHeight + RecentStateDepth
	return p
}

func TestAgreedCallReturnsWhatEveryAnsweringProviderReturns(t *testing.T) {
	r := reader(t, callProvider([]byte{1, 2, 3}), callProvider([]byte{1, 2, 3}))
	at, err := r.RecentAgreedHeader(context.Background())
	if err != nil || at.Number.Uint64() != testHeight {
		t.Fatalf("recent agreed header %v, %v; want height %d", at, err, testHeight)
	}
	to := common.HexToAddress("0x01")
	got, err := r.CallContractAtHash(context.Background(), ethereum.CallMsg{To: &to}, at.Hash())
	if err != nil || string(got) != string([]byte{1, 2, 3}) {
		t.Fatalf("(%x, %v)", got, err)
	}
	code, err := r.CodeAtHash(context.Background(), to, at.Hash())
	if err != nil || len(code) != 3 {
		t.Fatalf("code (%x, %v)", code, err)
	}
}

func TestALyingProviderBlocksAnAgreedCall(t *testing.T) {
	r := reader(t, callProvider([]byte{1}), callProvider([]byte{2}))
	to := common.HexToAddress("0x01")
	if _, err := r.CallContractAtHash(context.Background(), ethereum.CallMsg{To: &to}, common.Hash{1}); !errors.Is(err, ErrProvidersDisagree) {
		t.Fatalf("a provider answering differently was outvoted or ignored: %v", err)
	}
}

func TestAProviderWithoutTheStateLeavesTheCallUnestablished(t *testing.T) {
	r := reader(t, callProvider([]byte{1}), callProvider(nil))
	to := common.HexToAddress("0x01")
	if _, err := r.CallContractAtHash(context.Background(), ethereum.CallMsg{To: &to}, common.Hash{1}); !errors.Is(err, ErrTooFewProviders) {
		t.Fatalf("one provider's state was taken as the chain's: %v", err)
	}
}

func TestLocatorsNameEveryProvider(t *testing.T) {
	r := reader(t, callProvider(nil), callProvider(nil))
	if ls := r.Locators(); len(ls) != 2 || ls[0].Client == nil || ls[0].Host == ls[1].Host {
		t.Fatalf("locators %+v", ls)
	}
}
