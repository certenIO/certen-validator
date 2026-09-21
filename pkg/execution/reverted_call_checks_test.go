package execution

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// A reverted transaction is accepted as a member's failure only when it is an honest settlement
// attempt: anyone may relay the account's execution, so a copy built to fail - starved of gas,
// sent to the wrong account, sent before the anchor was attested - must not be written back as the
// intent failing.
func TestAuthorizedAttemptRefusesADoomedCopy(t *testing.T) {
	account := common.HexToAddress("0xfa96ed9b2bc7139fa671e1faf53f901adeea5b32")
	other := common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B")
	honest := func() *accountExecution {
		return &accountExecution{Calls: []CommittedCall{{Target: other, Value: big.NewInt(0)}},
			RequiredLevel: AuthorityOperator, proofDecodedOK: true, AdiURLLen: 32}
	}
	plain := func(to common.Address, value *big.Int, gas uint64) *types.Transaction {
		return types.NewTx(&types.DynamicFeeTx{To: &to, Value: value, Gas: gas})
	}
	reverted := &types.Receipt{Status: 0, GasUsed: 140142, BlockNumber: big.NewInt(1)}
	zero := big.NewInt(0)
	cases := map[string]func() error{
		"another account": func() error {
			return checkAuthorizedAttempt(context.Background(), nil, plain(other, zero, 500000), reverted, honest(), account)
		},
		"not a revert": func() error {
			return checkAuthorizedAttempt(context.Background(), nil, plain(account, zero, 500000),
				&types.Receipt{Status: 1, BlockNumber: big.NewInt(1)}, honest(), account)
		},
		"value to a non-payable call": func() error {
			return checkAuthorizedAttempt(context.Background(), nil, plain(account, big.NewInt(1), 500000), reverted, honest(), account)
		},
		"authority level below the legs'": func() error {
			e := honest()
			e.RequiredLevel = 0
			return checkAuthorizedAttempt(context.Background(), nil, plain(account, zero, 500000), reverted, e, account)
		},
		"garbage sub-proofs": func() error {
			e := honest()
			e.HasSubProofs = true
			return checkAuthorizedAttempt(context.Background(), nil, plain(account, zero, 500000), reverted, e, account)
		},
		"starved by the limit": func() error {
			return checkAuthorizedAttempt(context.Background(), nil, plain(account, zero, 300000), reverted, honest(), account)
		},
		"starved by an access list": func() error {
			list := make(types.AccessList, 190)
			tx := types.NewTx(&types.DynamicFeeTx{To: &account, Value: zero, Gas: 500000, AccessList: list})
			return checkAuthorizedAttempt(context.Background(), nil, tx, reverted, honest(), account)
		},
		"starved by padding the ignored fields": func() error {
			e := honest()
			e.ValidatorSignaturesLen = 20000
			return checkAuthorizedAttempt(context.Background(), nil, plain(account, zero, 500000), reverted, e, account)
		},
		"an unusual transaction type": func() error {
			tx := types.NewTx(&types.AccessListTx{To: &account, Value: zero, Gas: 500000})
			return checkAuthorizedAttempt(context.Background(), nil, tx, reverted, honest(), account)
		},
	}
	for name, run := range cases {
		if err := run(); err == nil {
			t.Errorf("%s: a doomed copy was accepted as the intent failing", name)
		}
	}
}

// The attestation must precede the attempt: an attempt sent before the quorum proof reverts on
// authorisation, and the anchor reads attested a moment later.
func TestAnchorAttestedBeforeTheAttempt(t *testing.T) {
	anchor := common.HexToAddress("0xEA9eeeE42a7971792B11Fd2f682C9c1172490272")
	id := [32]byte{0x5f}
	receipt := &types.Receipt{BlockNumber: big.NewInt(5000), TransactionIndex: 3}
	chain := &logChain{logs: []types.Log{{BlockNumber: 4990}}}
	if ok, err := anchorAttestedBefore(context.Background(), chain, anchor, id, receipt); err != nil || !ok {
		t.Fatalf("attested 10 blocks earlier: %v %v", ok, err)
	}
	chain = &logChain{logs: []types.Log{{BlockNumber: 5000, TxIndex: 7}}}
	if ok, _ := anchorAttestedBefore(context.Background(), chain, anchor, id, receipt); ok {
		t.Fatal("an attestation later in the same block was taken as preceding the attempt")
	}
	chain = &logChain{logs: []types.Log{{BlockNumber: 5000, TxIndex: 1}}}
	if ok, _ := anchorAttestedBefore(context.Background(), chain, anchor, id, receipt); !ok {
		t.Fatal("an attestation earlier in the same block was missed")
	}
	chain = &logChain{}
	if ok, _ := anchorAttestedBefore(context.Background(), chain, anchor, id, receipt); ok {
		t.Fatal("no attestation at all was taken as one")
	}
	if chain.calls < 2 {
		t.Fatalf("searched %d chunk(s); the search must walk back in chunks", chain.calls)
	}
}

type logChain struct {
	attemptChain
	logs  []types.Log
	calls int
}

func (c *logChain) FilterLogs(_ context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	c.calls++
	var out []types.Log
	for _, l := range c.logs {
		if l.BlockNumber >= q.FromBlock.Uint64() && l.BlockNumber <= q.ToBlock.Uint64() {
			out = append(out, l)
		}
	}
	return out, nil
}
