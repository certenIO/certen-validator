package execution

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// Proving a settlement REVERTED
// =============================================================================
//
// # WHY A REVERT NEEDS ITS OWN PROOF
//
// The RB contract-call gate (VerifyExecutedCall) proves a SUCCESS: the call is included in the
// block and every committed event appears in its inclusion-proven receipt. A reverted call has no
// events, so the gate refused it — "executed call tx … failed (status=0)" — and the refusal aborted
// the whole proof cycle at Phase 7. Nothing was attested and nothing was written back, so a payment
// that reverted on chain was recorded nowhere. Observed live 2026-09-20 on intent 5a2ebba0: the
// FDBUSD transfer reverted with InsufficientBalance in tx 0x54562d54…, the cycle died at the gate,
// and the ADI's intent stayed in 'anchoring'.
//
// A revert is an outcome, not a verification failure. What must hold for it to be attested is
// what makes it THIS intent's failure rather than any failed transaction someone points at:
//
//   - RB-2: the transaction and its receipt are included in the block, against the header roots,
//     and the inclusion-proven receipt says status 0;
//   - binding: the transaction is a CertenAccountV7 execution whose calls are exactly the calls
//     the intent committed to (target, value and calldata), under the intent's operationID.
//
// Both ends run this: the executor before it attests, and every peer independently, from the
// user-signed intent it fetches from Accumulate. The attestation binds the observed status through
// the result hash, so a revert can never be passed off as a success or the reverse.

// CommittedCall is one call an intent committed to execute.
type CommittedCall struct {
	Target common.Address
	// Value is the committed value; nil means the commitment does not state one.
	Value *big.Int
	Data  []byte
}

// accountExecution is a decoded CertenAccountV7 execution call.
type accountExecution struct {
	Batch       bool
	Calls       []CommittedCall
	AnchorID    [32]byte
	OperationID [32]byte
	MerkleProof [][32]byte
	Timestamp   *big.Int
	ExpiresAt   *big.Int
	// RequiredLevel and the three optional sub-proofs, which an honest settlement sends as the
	// legs' level and empty respectively.
	RequiredLevel  uint8
	HasSubProofs   bool
	proofDecodedOK bool
	// The two fields the contract ignores, whose only effect on an attempt is the calldata - and
	// so the gas - they take up.
	AdiURLLen              int
	ValidatorSignaturesLen int
}

// decodeAccountExecution decodes executeGovernanceProofDirect / batchExecuteGovernanceProofDirect.
func decodeAccountExecution(input []byte) (*accountExecution, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("no calldata")
	}
	if certenAccountV7ABIErr != nil {
		return nil, fmt.Errorf("account ABI unavailable: %w", certenAccountV7ABIErr)
	}
	m, err := certenAccountV7ABI.MethodById(input[:4])
	if err != nil {
		return nil, fmt.Errorf("not a CertenAccountV7 call")
	}
	args, err := m.Inputs.Unpack(input[4:])
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", m.Name, err)
	}
	if len(args) < 4 {
		return nil, fmt.Errorf("unexpected %s arg count (%d)", m.Name, len(args))
	}
	out := &accountExecution{}
	switch m.Name {
	case "executeGovernanceProofDirect":
		target, okT := args[0].(common.Address)
		value, okV := args[1].(*big.Int)
		data, okD := args[2].([]byte)
		if !okT || !okV || !okD {
			return nil, fmt.Errorf("unexpected %s argument types", m.Name)
		}
		out.Calls = []CommittedCall{{Target: target, Value: value, Data: data}}
	case "batchExecuteGovernanceProofDirect":
		out.Batch = true
		targets, okT := args[0].([]common.Address)
		values, okV := args[1].([]*big.Int)
		datas, okD := args[2].([][]byte)
		if !okT || !okV || !okD || len(targets) != len(values) || len(targets) != len(datas) {
			return nil, fmt.Errorf("unexpected %s argument types", m.Name)
		}
		for i := range targets {
			out.Calls = append(out.Calls, CommittedCall{Target: targets[i], Value: values[i], Data: datas[i]})
		}
	default:
		return nil, fmt.Errorf("%s is not a settlement call", m.Name)
	}
	proof := reflect.ValueOf(args[3])
	if proof.Kind() != reflect.Struct {
		return nil, fmt.Errorf("unexpected proof type %T", args[3])
	}
	af, of := proof.FieldByName("AnchorId"), proof.FieldByName("OperationID")
	if !af.IsValid() || !of.IsValid() {
		return nil, fmt.Errorf("proof tuple lacks anchorId/operationID")
	}
	a, okA := af.Interface().([32]byte)
	op, okO := of.Interface().([32]byte)
	if !okA || !okO {
		return nil, fmt.Errorf("proof tuple anchorId/operationID have unexpected types")
	}
	out.AnchorID, out.OperationID = a, op
	if f := proof.FieldByName("MerkleProof"); f.IsValid() {
		if mp, ok := f.Interface().([][32]byte); ok {
			out.MerkleProof = mp
		}
	}
	if f := proof.FieldByName("Timestamp"); f.IsValid() {
		out.Timestamp, _ = f.Interface().(*big.Int)
	}
	if f := proof.FieldByName("ExpiresAt"); f.IsValid() {
		out.ExpiresAt, _ = f.Interface().(*big.Int)
	}
	if f := proof.FieldByName("RequiredLevel"); f.IsValid() {
		if lvl, ok := f.Interface().(uint8); ok {
			out.RequiredLevel = lvl
			out.proofDecodedOK = true
		}
	}
	if f := proof.FieldByName("AdiURL"); f.IsValid() {
		if u, ok := f.Interface().(string); ok {
			out.AdiURLLen = len(u)
		}
	}
	if f := proof.FieldByName("ValidatorSignatures"); f.IsValid() {
		if b, ok := f.Interface().([]byte); ok {
			out.ValidatorSignaturesLen = len(b)
		}
	}
	for _, name := range []string{"KeyBookProof", "RoleProof", "ThresholdProof"} {
		if f := proof.FieldByName(name); f.IsValid() {
			if b, ok := f.Interface().([]byte); ok && len(b) > 0 {
				out.HasSubProofs = true
			}
		}
	}
	return out, nil
}

// attemptChain is what checkAuthorizedAttempt reads. *ethclient.Client in production.
type attemptChain interface {
	bind.ContractCaller
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
}

// chainReadError is a failure to READ the chain while verifying an attempt, as opposed to a verdict
// that the attempt is not the member's failure. A caller must not treat it as a verdict: it says
// nothing about the attempt, and the answer may be different a moment later.
type chainReadError struct{ err error }

func (e *chainReadError) Error() string { return e.err.Error() }
func (e *chainReadError) Unwrap() error { return e.err }

func readErr(err error) error { return &chainReadError{err: err} }

// IsChainReadError reports whether err is a failed chain read rather than a verdict.
func IsChainReadError(err error) bool {
	var r *chainReadError
	return errors.As(err, &r)
}

// maxSettlementADIURLLen bounds the advisory adiURL an attempt may carry. Accumulate URLs are short;
// the bound only stops the field being used as calldata padding.
const maxSettlementADIURLLen = 256

// honestSettlementGas is the gas limit the batch orchestrator sends a settlement with. An attempt
// sent with less could have been starved on purpose; one sent with this much and still reverting
// is how an honest settlement fails.
func honestSettlementGas(exec *accountExecution) uint64 {
	if exec.Batch {
		return 400000 + uint64(len(exec.Calls))*250000
	}
	return 500000
}

// proofExecutedTopic is keccak256("ProofExecuted(bytes32,bytes32,bool,bool,bool,uint256)").
var proofExecutedTopic = crypto.Keccak256Hash([]byte("ProofExecuted(bytes32,bytes32,bool,bool,bool,uint256)"))

// proofExecutedLookback bounds how far before an attempt its anchor's attestation is searched
// for, in chunks a public RPC will serve.
const (
	proofExecutedLookback = 60000
	proofExecutedChunk    = 2000
)

// anchorAttestedBefore reports whether the anchor's ProofExecuted event precedes the attempt: in an
// earlier block, or earlier in the same block. The anchor's CURRENT state cannot answer this - an
// attempt sent before the quorum proof landed reverts on "anchor proof not executed", and the
// anchor reads attested a moment later.
func anchorAttestedBefore(ctx context.Context, chain attemptChain, anchor common.Address, anchorID [32]byte, receipt *types.Receipt) (bool, error) {
	if receipt.BlockNumber == nil {
		return false, fmt.Errorf("receipt has no block")
	}
	to := receipt.BlockNumber.Uint64()
	floor := uint64(0)
	if to > proofExecutedLookback {
		floor = to - proofExecutedLookback
	}
	for hi := to; ; {
		lo := floor
		if hi > proofExecutedChunk && hi-proofExecutedChunk+1 > floor {
			lo = hi - proofExecutedChunk + 1
		}
		logs, err := chain.FilterLogs(ctx, ethereum.FilterQuery{
			FromBlock: new(big.Int).SetUint64(lo),
			ToBlock:   new(big.Int).SetUint64(hi),
			Addresses: []common.Address{anchor},
			Topics:    [][]common.Hash{{proofExecutedTopic}, {common.Hash(anchorID)}},
		})
		if err != nil {
			return false, readErr(fmt.Errorf("ProofExecuted logs %d-%d: %w", lo, hi, err))
		}
		for _, l := range logs {
			if l.BlockNumber < to || (l.BlockNumber == to && l.TxIndex < receipt.TransactionIndex) {
				return true, nil
			}
		}
		if lo <= floor || lo == 0 {
			return false, nil
		}
		hi = lo - 1
	}
}

const accountAttemptABIJSON = `[` +
	`{"type":"function","name":"anchorContract","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},` +
	`{"type":"function","name":"computeLeaf","stateMutability":"view","inputs":[{"type":"bytes32"},{"type":"bytes32"}],"outputs":[{"type":"bytes32"}]},` +
	`{"type":"function","name":"computeSingleCommitment","stateMutability":"view","inputs":[{"type":"address"},{"type":"uint256"},{"type":"bytes"}],"outputs":[{"type":"bytes32"}]},` +
	`{"type":"function","name":"computeBatchCommitment","stateMutability":"view","inputs":[{"type":"address[]"},{"type":"uint256[]"},{"type":"bytes[]"}],"outputs":[{"type":"bytes32"}]},` +
	`{"type":"function","name":"isLeafConsumed","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"bool"}]}]`

const anchorAttemptABIJSON = `[` +
	`{"type":"function","name":"verifyProof","stateMutability":"view","inputs":[{"type":"bytes32"},{"type":"bytes32[]"},{"type":"bytes32"}],"outputs":[{"type":"bool"}]}]`

// checkAuthorizedAttempt reports whether a REVERTED execution was an attempt the account would have
// AUTHORISED - so that what reverted was the execution itself, not an authorisation check.
//
// Without this, "the committed calldata under the intent's operationID, and it reverted" can be
// manufactured by anyone: send it with a bogus anchor, an expired window, or too little gas, and it
// reverts - and a quorum that believed it would attest an intent as failed that nobody genuinely
// tried to execute. So the attempt must pass exactly what CertenAccountV7._verifyAnchorUsable and
// _authorizeLeaf check: sent to the member's account, under an anchor that exists with its proof
// executed, carrying a branch that proves the member's leaf in that anchor's root, inside its
// validity window at the block it mined in, with the leaf still unconsumed, after the anchor's
// attestation. And it must have the shape of an honest settlement - no value, the legs' authority
// level, no optional sub-proofs, the orchestrator's gas limit - because each of those can otherwise
// be chosen to make a copy revert for a reason that says nothing about the intent.
func checkAuthorizedAttempt(
	ctx context.Context,
	chain attemptChain,
	tx *types.Transaction,
	receipt *types.Receipt,
	exec *accountExecution,
	account common.Address,
) error {
	if tx == nil {
		return fmt.Errorf("no transaction")
	}
	to, value, gasLimit := tx.To(), tx.Value(), tx.Gas()
	// The GAS the execution receives, not only the limit. Intrinsic gas comes off the limit before
	// execution starts, and an access list, an authorization list or padded calldata raises it - a
	// copy sent with the honest limit and a few hundred access-list entries reaches the call starved.
	// An honest settlement is a plain transaction with no access list, an empty validatorSignatures
	// and the member's ADI URL; anything else is refused.
	switch tx.Type() {
	case types.LegacyTxType, types.DynamicFeeTxType:
	default:
		return fmt.Errorf("transaction type %d is not how a settlement is sent", tx.Type())
	}
	if len(tx.AccessList()) > 0 {
		return fmt.Errorf("carries an access list, which eats the execution's gas")
	}
	if exec.ValidatorSignaturesLen > 0 || exec.AdiURLLen > maxSettlementADIURLLen {
		return fmt.Errorf("carries padding in fields the account ignores, which eats the execution's gas")
	}
	if to == nil || *to != account {
		return fmt.Errorf("not addressed to the member's account %s", account.Hex())
	}
	if receipt == nil || receipt.Status != 0 {
		return fmt.Errorf("receipt does not record a revert")
	}
	if value != nil && value.Sign() != 0 {
		return fmt.Errorf("sent with value to a non-payable function; that reverts before any authorisation")
	}
	// The shape of an HONEST settlement: the legs' own authority level, no optional sub-proofs, and
	// the gas the orchestrator sends. Anything else can be made to revert on purpose - a level
	// below what the account requires, a sub-proof that does not decode, a limit too small for the
	// target - and none of those is the intent failing.
	legs := make([]LegExecution, 0, len(exec.Calls))
	for _, c := range exec.Calls {
		legs = append(legs, LegExecution{Target: c.Target, Value: c.Value, Data: c.Data})
	}
	if !exec.proofDecodedOK || exec.RequiredLevel < requiredLevelForLegs(legs) {
		return fmt.Errorf("authorised at level %d, below the %d the legs require", exec.RequiredLevel, requiredLevelForLegs(legs))
	}
	if exec.HasSubProofs {
		return fmt.Errorf("carries optional sub-proofs an honest settlement does not send")
	}
	if want := honestSettlementGas(exec); gasLimit < want {
		return fmt.Errorf("sent with gas limit %d, below the %d a settlement is sent with", gasLimit, want)
	}
	accountABI, err := abi.JSON(strings.NewReader(accountAttemptABIJSON))
	if err != nil {
		return err
	}
	anchorABI, err := abi.JSON(strings.NewReader(anchorAttemptABIJSON))
	if err != nil {
		return err
	}
	acct := bind.NewBoundContract(account, accountABI, chain, nil, nil)
	call := func(c *bind.BoundContract, method string, args ...interface{}) (interface{}, error) {
		var out []interface{}
		if err := c.Call(&bind.CallOpts{Context: ctx}, &out, method, args...); err != nil {
			return nil, readErr(fmt.Errorf("%s: %w", method, err))
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%s returned nothing", method)
		}
		return out[0], nil
	}

	anchorOut, err := call(acct, "anchorContract")
	if err != nil {
		return err
	}
	anchorAddr, _ := anchorOut.(common.Address)
	var commitmentOut interface{}
	if exec.Batch {
		targets := make([]common.Address, len(exec.Calls))
		values := make([]*big.Int, len(exec.Calls))
		datas := make([][]byte, len(exec.Calls))
		for i, c := range exec.Calls {
			targets[i], values[i], datas[i] = c.Target, c.Value, c.Data
		}
		commitmentOut, err = call(acct, "computeBatchCommitment", targets, values, datas)
	} else if len(exec.Calls) == 1 {
		c := exec.Calls[0]
		commitmentOut, err = call(acct, "computeSingleCommitment", c.Target, c.Value, c.Data)
	} else {
		return fmt.Errorf("no executed call")
	}
	if err != nil {
		return err
	}
	commitment, _ := commitmentOut.([32]byte)
	leafOut, err := call(acct, "computeLeaf", commitment, exec.OperationID)
	if err != nil {
		return err
	}
	leaf, _ := leafOut.([32]byte)

	if consumedOut, err := call(acct, "isLeafConsumed", leaf); err != nil {
		return err
	} else if consumed, _ := consumedOut.(bool); consumed {
		return fmt.Errorf("the leaf is consumed: the intent executed")
	}

	anchor := bind.NewBoundContract(anchorAddr, anchorABI, chain, nil, nil)
	if okOut, err := call(anchor, "verifyProof", exec.AnchorID, exec.MerkleProof, leaf); err != nil {
		return err
	} else if ok, _ := okOut.(bool); !ok {
		return fmt.Errorf("anchor 0x%x does not hold the member's leaf; the attempt was not authorised", exec.AnchorID[:8])
	}
	anchorsABI, err := abiFromJSON(anchorsABIJSON)
	if err != nil {
		return err
	}
	var fields []interface{}
	if err := bind.NewBoundContract(anchorAddr, anchorsABI, chain, nil, nil).
		Call(&bind.CallOpts{Context: ctx}, &fields, "anchors", exec.AnchorID); err != nil {
		return readErr(fmt.Errorf("anchors: %w", err))
	}
	const validIndex, proofExecutedIndex = 11, 12
	if len(fields) <= proofExecutedIndex {
		return fmt.Errorf("anchors() returned %d fields", len(fields))
	}
	valid, _ := fields[validIndex].(bool)
	executed, _ := fields[proofExecutedIndex].(bool)
	if !valid || !executed {
		return fmt.Errorf("anchor 0x%x is not attested; the attempt was not authorised", exec.AnchorID[:8])
	}
	// Attested BEFORE the attempt, not merely by now.
	if before, err := anchorAttestedBefore(ctx, chain, anchorAddr, exec.AnchorID, receipt); err != nil {
		return err
	} else if !before {
		return fmt.Errorf("anchor 0x%x was not attested before the attempt; it reverted on authorisation", exec.AnchorID[:8])
	}

	header, err := chain.HeaderByNumber(ctx, receipt.BlockNumber)
	if err != nil {
		return readErr(fmt.Errorf("header %v: %w", receipt.BlockNumber, err))
	}
	ts := new(big.Int).SetUint64(header.Time)
	if exec.Timestamp == nil || exec.ExpiresAt == nil || ts.Cmp(exec.Timestamp) < 0 || ts.Cmp(exec.ExpiresAt) > 0 {
		return fmt.Errorf("mined outside the proof's validity window; the attempt was not authorised")
	}
	return nil
}

// matchCommittedCalls reports whether every committed call is among the executed ones.
func matchCommittedCalls(executed, committed []CommittedCall) error {
	if len(committed) == 0 {
		return fmt.Errorf("no committed call to bind the transaction to")
	}
	for i, c := range committed {
		found := false
		for _, e := range executed {
			if e.Target != c.Target || !bytes.Equal(e.Data, c.Data) {
				continue
			}
			if c.Value != nil && (e.Value == nil || e.Value.Cmp(c.Value) != 0) {
				continue
			}
			found = true
			break
		}
		if !found {
			return fmt.Errorf("committed call %d (target %s) is not what the transaction executed", i, c.Target.Hex())
		}
	}
	return nil
}

// ParseCommittedCall builds a CommittedCall from the intent's hex/decimal string forms.
func ParseCommittedCall(target, value, callData string) (CommittedCall, error) {
	var c CommittedCall
	t := strings.TrimSpace(target)
	if !common.IsHexAddress(t) {
		return c, fmt.Errorf("target %q is not an address", target)
	}
	c.Target = common.HexToAddress(t)
	if v := strings.TrimSpace(value); v != "" {
		n, ok := new(big.Int).SetString(strings.TrimPrefix(v, "0x"), 10)
		if !ok {
			if n, ok = new(big.Int).SetString(strings.TrimPrefix(v, "0x"), 16); !ok {
				return c, fmt.Errorf("value %q does not parse", value)
			}
		}
		c.Value = n
	}
	d, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(callData), "0x"), "0X"))
	if err != nil {
		return c, fmt.Errorf("callData does not decode: %w", err)
	}
	c.Data = d
	return c, nil
}

// VerifyRevertedCall proves that txHash is the committed execution, that it was an attempt the
// member's account authorised, and that it reverted.
//
// opID, when non-nil, must equal the operationID the execution was authorised under. account is the
// member's account - the source the intent committed to - which the transaction must be sent to.
func (o *ExternalChainObserver) VerifyRevertedCall(
	ctx context.Context,
	txHash common.Hash,
	committed []CommittedCall,
	opID *[32]byte,
	account common.Address,
) (*ExternalChainResult, error) {
	if account == (common.Address{}) {
		return nil, fmt.Errorf("no member account to bind the reverted call to")
	}
	result, err := o.ObserveTransaction(ctx, txHash, nil)
	if err != nil {
		return nil, fmt.Errorf("observe reverted call tx %s: %w", txHash.Hex(), err)
	}
	if result.Status != 0 {
		return nil, fmt.Errorf("tx %s did not revert (status=%d)", txHash.Hex(), result.Status)
	}
	// RB-2: the receipt that says status 0 is the one committed in the block.
	if result.TxInclusionProof == nil || !result.TxInclusionProof.Verify() {
		return nil, fmt.Errorf("RB-2: tx inclusion proof failed to verify for %s", txHash.Hex())
	}
	if result.ReceiptInclusionProof == nil || !result.ReceiptInclusionProof.Verify() {
		return nil, fmt.Errorf("RB-2: receipt inclusion proof failed to verify for %s", txHash.Hex())
	}

	tx, _, err := o.ethClient.TransactionByHash(ctx, txHash)
	if err != nil || tx == nil {
		return nil, fmt.Errorf("fetch reverted tx %s: %v", txHash.Hex(), err)
	}
	exec, err := decodeAccountExecution(tx.Data())
	if err != nil {
		return nil, fmt.Errorf("reverted tx %s is not an account execution: %w", txHash.Hex(), err)
	}
	if err := matchCommittedCalls(exec.Calls, committed); err != nil {
		return nil, fmt.Errorf("reverted tx %s: %w", txHash.Hex(), err)
	}
	if opID != nil && exec.OperationID != *opID {
		return nil, fmt.Errorf("reverted tx %s carries operationID 0x%x, not the intent's 0x%x",
			txHash.Hex(), exec.OperationID[:8], opID[:8])
	}
	receipt, err := o.ethClient.TransactionReceipt(ctx, txHash)
	if err != nil {
		return nil, fmt.Errorf("receipt of %s: %w", txHash.Hex(), err)
	}
	if err := checkAuthorizedAttempt(ctx, o.ethClient, tx, receipt, exec, account); err != nil {
		return nil, fmt.Errorf("reverted tx %s: %w", txHash.Hex(), err)
	}
	return result, nil
}
