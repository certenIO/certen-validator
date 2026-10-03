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

// A throttled provider is asked again within the read's bound, not counted out: free providers throttle a burst of reads
// (measured 2026-10-03 on tenderly's public gateways: HTTP 429 at about the twelfth call), and counting them out left
// every fact unestablished. One that never stops throttling still establishes nothing.
func TestAThrottledProviderIsAskedAgainNotCountedOut(t *testing.T) {
	throttled := callProvider([]byte{1})
	throttled.throttle = 2
	r := reader(t, callProvider([]byte{1}), throttled)
	to := common.HexToAddress("0x01")
	if got, err := r.CallContractAtHash(context.Background(), ethereum.CallMsg{To: &to}, common.Hash{1}); err != nil || len(got) != 1 {
		t.Fatalf("a provider that throttled twice was counted out: (%x, %v)", got, err)
	}
	stuck := callProvider([]byte{1})
	stuck.throttle = 1000
	r = reader(t, callProvider([]byte{1}), stuck)
	if _, err := r.CallContractAtHash(context.Background(), ethereum.CallMsg{To: &to}, common.Hash{1}); !errors.Is(err, ErrTooFewProviders) {
		t.Fatalf("a provider that never answers was taken as agreeing: %v", err)
	}
}
