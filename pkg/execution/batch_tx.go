package execution

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"
)

// =============================================================================
// Batch-lane transactions go through the manager's txSender
// =============================================================================

// txOutboxDir is where each key's outbox lives, beside the validator's other durable state.
func txOutboxDir() string {
	if d := strings.TrimSpace(os.Getenv("CERTEN_TX_OUTBOX_DIR")); d != "" {
		return d
	}
	return filepath.Join("data", "tx_outbox")
}

// batchSender returns this manager's sender, creating it on first use. An outbox that exists but
// cannot be read is an error, not an empty outbox: see openTxOutbox.
func (ecm *EthereumContractManager) batchSender() (*txSender, error) {
	ecm.senderOnce.Do(func() {
		path := filepath.Join(txOutboxDir(),
			fmt.Sprintf("%d_%s.json", ecm.config.ChainID, strings.ToLower(ecm.auth.From.Hex())))
		outbox, err := openTxOutbox(path)
		if err != nil {
			ecm.senderErr = &SenderUnavailableError{Err: err}
			fmt.Printf("🚨 [TX-SENDER] chain %d: the transaction outbox %s cannot be read (%v). NOTHING will be "+
				"sent from %s until it is repaired: an unreadable outbox may hold transactions in flight, and "+
				"sending blind could clobber their nonces. Members wait; none is failed.\n",
				ecm.config.ChainID, path, err, ecm.auth.From.Hex())
			return
		}
		outbox.logf = func(f string, a ...interface{}) { fmt.Printf(f+"\n", a...) }
		ecm.sender = &txSender{
			client:  ecm.client,
			from:    ecm.auth.From,
			chainID: big.NewInt(ecm.config.ChainID),
			sign: func(tx *types.Transaction) (*types.Transaction, error) {
				return ecm.auth.Signer(ecm.auth.From, tx)
			},
			ceiling:    ecm.feeCeiling,
			outbox:     outbox,
			logf:       func(f string, a ...interface{}) { fmt.Printf(f+"\n", a...) },
			stuckAfter: defaultSenderStuckAfter,
			sendWait:   defaultSenderSendWait,
			resumeWait: defaultSenderResumeWait,
			poll:       defaultSenderPoll,
		}
	})
	return ecm.sender, ecm.senderErr
}

// feeCeiling applies this deployment's gas-price and transaction-cost ceilings - the same rules as
// evaluateGasPrice and refreshGasPrice - to a price the sender is about to pay.
//
// networkPrice is what the network charges now; a network price above the ceiling is a breach and
// refuses the send. bid is the cap the sender wants to offer; bidding above the ceiling while the
// network is below it is not a breach, so the bid is clamped to the ceiling. The cost ceiling is
// checked on the clamped bid: under EIP-1559 the fee cap is the most the transaction can cost.
//
// With enforcement off (CERTEN_GAS_CEILING_ENFORCE=false) there is no ceiling at all and the bid is
// paid as is. Clamping there would sign a transaction priced below the network - one guaranteed to
// sit in the mempool and block the key.
func (ecm *EthereumContractManager) feeCeiling(networkPrice, bid *big.Int, gas uint64) (*big.Int, error) {
	enforce := gasCeilingEnforced()
	if !enforce {
		return new(big.Int).Set(bid), nil
	}
	maxWei := new(big.Int).Mul(big.NewInt(ecm.config.MaxGasPriceGwei), big.NewInt(1e9))
	if maxWei.Sign() > 0 && networkPrice.Cmp(maxWei) > 0 {
		gwei, _ := new(big.Float).Quo(new(big.Float).SetInt(networkPrice), big.NewFloat(1e9)).Float64()
		return nil, &ErrGasCeilingExceeded{ChainID: ecm.config.ChainID, SuggestedGwei: gwei,
			CeilingGwei: ecm.config.MaxGasPriceGwei}
	}
	out := new(big.Int).Set(bid)
	if maxWei.Sign() > 0 && out.Cmp(maxWei) > 0 {
		out = maxWei
	}
	if err := checkTxCostCeiling(gas, out, nativeUSDMicro(), maxTxCostMicroUSD(), ecm.config.ChainID); err != nil {
		return nil, err
	}
	return out, nil
}

// takeNonce hands out the next nonce of the pinned sequence. False when no sequence is active: the
// batch lane only ever sends inside one (beginNonceSequence).
func (ecm *EthereumContractManager) takeNonce() (uint64, bool) {
	ecm.nonceMu.Lock()
	defer ecm.nonceMu.Unlock()
	if !ecm.nonceActive {
		return 0, false
	}
	n := ecm.nonceSeq
	ecm.nonceSeq++
	return n, true
}

// sendBatchTx sends one batch-lane transaction through the sender and returns the receipt of the hash
// that mined.
//
// build receives a COPY of the manager's transactor with the nonce and gas set and sending disabled;
// it only has to produce the call (the contract binding does the ABI encoding). The sender prices,
// signs, records and broadcasts it. Building on a copy also stops concurrent callers from racing on
// the shared transactor's nonce and gas fields.
func (ecm *EthereumContractManager) sendBatchTx(
	ctx context.Context,
	label string,
	owner string,
	gas uint64,
	build func(opts *bind.TransactOpts) (*types.Transaction, error),
	onBroadcast func(nonce uint64, hash string),
) (*types.Receipt, string, error) {
	sender, err := ecm.batchSender()
	if err != nil {
		return nil, "", err
	}
	nonce, ok := ecm.takeNonce()
	if !ok {
		return nil, "", fmt.Errorf("%s: no nonce sequence is pinned; batch-lane sends must run inside one", label)
	}
	opts := *ecm.auth
	opts.Context = ctx
	opts.NoSend = true
	opts.Nonce = new(big.Int).SetUint64(nonce)
	opts.GasLimit = gas
	call, err := build(&opts)
	if err != nil {
		ecm.rewindNonce(nonce)
		return nil, "", fmt.Errorf("%s: building the call: %w", label, err)
	}
	if call.To() == nil {
		ecm.rewindNonce(nonce)
		return nil, "", fmt.Errorf("%s: a contract call has no destination", label)
	}
	rcpt, hash, err := sender.Send(ctx, SendRequest{
		Nonce: nonce, To: *call.To(), Data: call.Data(), Value: call.Value(), Gas: gas,
		Label: label, Owner: owner, OnBroadcast: onBroadcast,
	})
	if err != nil {
		var nb *NotBroadcastError
		if errors.As(err, &nb) {
			// Nothing is in flight at this nonce; give it back, or every later send queues behind a
			// gap the chain never fills.
			ecm.rewindNonce(nonce)
		}
		return nil, "", err
	}
	return rcpt, hash, nil
}

// isTransientSendError reports whether a batch-lane send ended without a result that says anything
// about the payload: still in flight, refused on price before broadcast, or its nonce taken by
// another transaction (so the payload did not run). None of these is a failure of the member.
//
// *SenderUnavailableError is included: the sender failing closed must never turn into members'
// failures. It is logged loudly where it arises (batchSender, Resume).
func isTransientSendError(err error) bool {
	var cwe *ChainWaitError
	var nb *NotBroadcastError
	var su *SenderUnavailableError
	var fp *ForeignPendingError
	return errors.As(err, &cwe) || errors.As(err, &nb) || errors.As(err, &su) || errors.As(err, &fp) ||
		errors.Is(err, ErrNonceConsumedElsewhere) || errors.Is(err, ErrSequenceBusy)
}

// ForeignPendingError: the key has transactions in flight that this sender did not send, ahead of
// anything it would send now. Not a failure of any member; the key is busy until they resolve.
type ForeignPendingError struct{ Nonces []uint64 }

func (e *ForeignPendingError) Error() string {
	return fmt.Sprintf("transactions this sender did not send are in flight at nonces %v", e.Nonces)
}

// ErrSequenceBusy: another lane holds this key's nonce sequence right now (the period flush and the
// on-demand submitter share one key per chain). Not a failure; the caller tries this chain again on
// its next pass instead of blocking every other chain behind this one.
var ErrSequenceBusy = errors.New("this key's nonce sequence is held by another lane")

// ErrAttestedByAnother: this node's quorum attestation reverted because another validator's
// attestation of the same anchor landed first. The root IS attested - but not by this node: the
// transaction and quorum evidence are the other validator's, and so is the settlement.
var ErrAttestedByAnother = errors.New("the anchor was attested by another validator's transaction")

// keyBusy reports whether err says this key cannot send right now - a transaction still in flight,
// or the sender unavailable. Nothing else on this chain can be sent this pass either.
func keyBusy(err error) bool {
	var cwe *ChainWaitError
	var su *SenderUnavailableError
	var fp *ForeignPendingError
	return errors.As(err, &cwe) || errors.As(err, &su) || errors.As(err, &fp) || errors.Is(err, ErrSequenceBusy)
}

// AnchorConfirmUnreadError: this node's quorum attestation MINED, and reading back whether it set the
// anchor's proofExecuted flag failed. The attestation may well have landed; this is "not observed",
// never "rejected".
type AnchorConfirmUnreadError struct {
	BundleID [32]byte
	VerifyTx string
	Err      error
}

func (e *AnchorConfirmUnreadError) Error() string {
	return fmt.Sprintf("could not confirm anchor 0x%x attestation (tx %s) — the attestation may have "+
		"landed and was NOT observed: %v", e.BundleID[:8], e.VerifyTx, e.Err)
}
func (e *AnchorConfirmUnreadError) Unwrap() error { return e.Err }

func isAnchorConfirmUnread(err error) bool {
	var cu *AnchorConfirmUnreadError
	return errors.As(err, &cu)
}

// verifyBroadcast reports whether err is a quorum attestation this node BROADCAST without observing
// its result - it may land - and the attestation's most recent hash.
func verifyBroadcast(err error) (string, bool) {
	var cwe *ChainWaitError
	if errors.As(err, &cwe) && cwe.Label == "verify" {
		if n := len(cwe.Hashes); n > 0 {
			return cwe.Hashes[n-1], true
		}
		return "", true
	}
	var cu *AnchorConfirmUnreadError
	if errors.As(err, &cu) {
		return cu.VerifyTx, true
	}
	return "", false
}
