package ethrpc

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/supportedchains"
)

// RB7 D8: a reset testnet keeps its chain id. A chain the catalogue pins is read only from providers whose block 0 is the
// pinned genesis: at construction, and on every read.

// adiriGenesisJSON is Adiri's block 0 as https://rpc.telcoin.network served it on 2026-10-05 (eth_getBlockByNumber
// "0x0"; identical on adiri.tel and node1-4.telcoin.network).
const adiriGenesisJSON = `{"hash":"0x3577ee7223cf0d9a1da1293fd12a47e0e45bb97afcd0427bccd4954cb704baef","parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","miner":"0x0000000000000000000000000000000000000000","stateRoot":"0x0eecd2892fe819ad315aa6adbfe965378cbc63659b091539a7e7ea9362aea224","transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logsBloom":"0x` +
	`00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000` +
	`","difficulty":"0x0","number":"0x0","gasLimit":"0x1c9c380","gasUsed":"0x0","timestamp":"0x69fceea7","extraData":"0x","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000","baseFeePerGas":"0x7","withdrawalsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","blobGasUsed":"0x0","excessBlobGas":"0x0","parentBeaconBlockRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","requestsHash":"0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`

func adiriGenesis(t *testing.T) *types.Header {
	t.Helper()
	var h types.Header
	if err := json.Unmarshal([]byte(adiriGenesisJSON), &h); err != nil {
		t.Fatal(err)
	}
	return &h
}

// The compiled pin is the hash go-ethereum computes for the genesis header Adiri serves (and, recorded in the catalogue,
// for the block core.Genesis.ToBlock builds from the published telcoin-network@5736cc30 genesis.yaml).
func TestTheAdiriPinIsItsServedGenesisReHashed(t *testing.T) {
	pin, pinned, err := PinnedGenesis(2017)
	if err != nil || !pinned {
		t.Fatalf("Adiri is not pinned: %v", err)
	}
	if got := adiriGenesis(t).Hash(); got != pin {
		t.Fatalf("Adiri's served genesis hashes to %s; the pin is %s", got.Hex(), pin.Hex())
	}
}

// adiriProvider is a chain-2017 provider whose block 0 is genesis and whose block testHeight is final.
func adiriProvider(genesis, final *types.Header) *stubProvider {
	p := provider(2017, final)
	p.headers[0] = genesis
	return p
}

func TestAProviderOnAnotherGenesisRefusesThePinnedReader(t *testing.T) {
	shortenVerification(t)
	final := header(testHeight, "final")
	reset := header(0, "the next incarnation")
	urls := urlsOf(t, adiriProvider(adiriGenesis(t), final), adiriProvider(reset, final))
	r, err := NewAgreeingReader(context.Background(), 2017, urls, 2*time.Second)
	if err == nil {
		t.Fatalf("THE regression: a provider of another genesis was verified (hosts %v)", r.Hosts())
	}
	if !errors.Is(err, ErrGenesisMismatch) || !strings.Contains(err.Error(), reset.Hash().Hex()) ||
		!strings.Contains(err.Error(), supportedchains.GenesisEnvFor(2017)) {
		t.Fatalf("refused, but not by name: %v", err)
	}
}

// A reset while the validator runs: the next read is refused by name, not answered from the new chain.
func TestAResetChainIsRefusedOnTheNextRead(t *testing.T) {
	shortenVerification(t)
	old := genesisRecheck
	genesisRecheck = 0
	t.Cleanup(func() { genesisRecheck = old })
	final := header(testHeight, "final")
	a, b := adiriProvider(adiriGenesis(t), final), adiriProvider(adiriGenesis(t), final)
	r, err := NewAgreeingReader(context.Background(), 2017, urlsOf(t, a, b), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.HeaderByNumber(context.Background(), big.NewInt(testHeight)); err != nil {
		t.Fatalf("before the reset: %v", err)
	}
	for _, p := range []*stubProvider{a, b} {
		p.mu.Lock()
		p.headers[0] = header(0, "the next incarnation")
		p.mu.Unlock()
	}
	_, err = r.HeaderByNumber(context.Background(), big.NewInt(testHeight))
	if !errors.Is(err, ErrGenesisMismatch) {
		t.Fatalf("THE regression: a read after the reset returned %v", err)
	}
	// Every agreed read is gated, not only headers.
	if _, err := r.TransactionReceipt(context.Background(), a.tx); !errors.Is(err, ErrGenesisMismatch) {
		t.Fatalf("receipt after the reset: %v", err)
	}
}

// A provider that cannot serve block 0 (a pruned node) cannot show its genesis: it is not verified and is asked for
// nothing, by name. With two others verified the reader starts on them.
func TestAProviderWithoutBlockZeroIsNotVerifiedOnAPinnedChain(t *testing.T) {
	shortenVerification(t)
	final := header(testHeight, "final")
	pruned := provider(2017, final) // no block 0
	r, err := NewAgreeingReader(context.Background(), 2017,
		urlsOf(t, adiriProvider(adiriGenesis(t), final), adiriProvider(adiriGenesis(t), final), pruned), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Hosts()) != 2 {
		t.Fatalf("hosts %v: the provider without block 0 was verified", r.Hosts())
	}
	if _, err := NewAgreeingReader(context.Background(), 2017, urlsOf(t, adiriProvider(adiriGenesis(t), final), pruned), 2*time.Second); err == nil {
		t.Fatal("a reader started with one provider whose genesis was shown")
	}
}

// The configured pin is the one checked: re-pinning after a reset admits the new chain, and only it.
func TestARePinnedChainIsReadOnItsNewGenesis(t *testing.T) {
	shortenVerification(t)
	final := header(testHeight, "final")
	next := header(0, "the next incarnation")
	t.Setenv(supportedchains.GenesisEnvFor(2017), next.Hash().Hex())
	if _, err := NewAgreeingReader(context.Background(), 2017, urlsOf(t, adiriProvider(next, final), adiriProvider(next, final)), 2*time.Second); err != nil {
		t.Fatalf("the re-pinned chain: %v", err)
	}
	if _, err := NewAgreeingReader(context.Background(), 2017, urlsOf(t, adiriProvider(adiriGenesis(t), final), adiriProvider(adiriGenesis(t), final)), 2*time.Second); !errors.Is(err, ErrGenesisMismatch) {
		t.Fatalf("the old incarnation after re-pinning: %v", err)
	}
}

// A chain that is not pinned is never asked for block 0: its reads are what they were.
func TestAnUnpinnedChainIsNeverAskedForItsGenesis(t *testing.T) {
	final := header(testHeight, "final")
	a, b := provider(11155111, final), provider(11155111, final)
	r := reader(t, a, b)
	if _, err := r.HeaderByNumber(context.Background(), big.NewInt(testHeight)); err != nil {
		t.Fatal(err)
	}
	for _, p := range []*stubProvider{a, b} {
		if n := p.callsOf("eth_getBlockByNumber"); n != 1 {
			t.Fatalf("an unpinned chain's provider was asked eth_getBlockByNumber %d times for one read", n)
		}
	}
}

// The sender's own client is checked at boot (VerifySettlementAnchors).
func TestCheckGenesisRefusesTheSendersClientOnAnotherGenesis(t *testing.T) {
	final := header(testHeight, "final")
	good := urlsOf(t, adiriProvider(adiriGenesis(t), final))[0]
	c, _, err := dialProvider(context.Background(), "a", good, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckGenesis(context.Background(), 2017, "a", c); err != nil {
		t.Fatalf("the pinned genesis: %v", err)
	}
	bad := urlsOf(t, adiriProvider(header(0, "another"), final))[0]
	c2, _, err := dialProvider(context.Background(), "b", bad, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckGenesis(context.Background(), 2017, "b", c2); !errors.Is(err, ErrGenesisMismatch) {
		t.Fatalf("another genesis: %v", err)
	}
	if err := CheckGenesis(context.Background(), 84532, "b", c2); err != nil {
		t.Fatalf("an unpinned chain is not checked: %v", err)
	}
}
