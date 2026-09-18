package execution

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/consensus"
)

// ChainBackfillReader is the live BackfillChain: the same RPC endpoints and the same anchor addresses
// the batch path itself uses, so the backfill sees exactly what the validator sees.
//
// It holds a READ-ONLY resolver. The backfill issues nothing but eth_call, eth_getTransactionByHash,
// eth_getTransactionReceipt and eth_getBlockByNumber, and ReadOnlyChains cannot sign because it has
// nothing to sign with — previously this path went through EthereumContractManager, whose constructor
// demands a parseable private key, so a read-only tool had to be handed a throwaway signing key.
type ChainBackfillReader struct {
	chains *ReadOnlyChains
}

// NewChainBackfillReader builds a reader over a read-only chain resolver.
func NewChainBackfillReader(chains *ReadOnlyChains) *ChainBackfillReader {
	return &ChainBackfillReader{chains: chains}
}

// The `anchors(bytes32)` layout comes from anchorsABIJSON in batch_proof_submitter.go — one transcription
// of the deployed struct, checked against a DEPLOYED anchor by TestAnchorsTupleLayoutMatchesDeployedContract.
// A second copy here would be a second thing to get wrong.

// VerifyTransaction reads a mined transaction's calldata and receipt status.
func (r *ChainBackfillReader) VerifyTransaction(
	ctx context.Context,
	chainID int64,
	txHash string,
) ([]byte, uint64, bool, error) {
	client, _, err := r.chains.ClientForChain(chainID)
	if err != nil {
		return nil, 0, false, err
	}
	if !strings.HasPrefix(txHash, "0x") || len(txHash) != 66 {
		return nil, 0, false, fmt.Errorf("%q is not a transaction hash", txHash)
	}
	hash := common.HexToHash(txHash)

	tx, pending, err := client.TransactionByHash(ctx, hash)
	if err != nil {
		return nil, 0, false, fmt.Errorf("fetching %s: %w", txHash, err)
	}
	if pending {
		// A pending transaction has proven nothing yet.
		return nil, 0, false, fmt.Errorf("%s is still pending", txHash)
	}
	receipt, err := client.TransactionReceipt(ctx, hash)
	if err != nil {
		// "THE CHAIN SAYS NO" AND "THIS ENDPOINT CANNOT ANSWER" ARE DIFFERENT FACTS.
		//
		// A pruning endpoint returns the transaction body happily and then `not found` for its receipt.
		// That is indistinguishable from a transaction that does not exist unless it is said out loud —
		// and the first backfill run reported 84 candidates as unexaminable data problems when in truth
		// the configured RPC simply had no receipts older than its retention window. Every one of them
		// was a real, mined, successful transaction.
		//
		// So: if the body exists and the receipt does not, the endpoint is the problem, not the chain.
		if isNotFound(err) {
			return nil, 0, false, fmt.Errorf(
				"%s: this endpoint returned the transaction but not its receipt, which means it is pruning "+
					"history rather than that the transaction is missing — point this chain at an archive "+
					"endpoint and re-run: %w", txHash, err)
		}
		return nil, 0, false, fmt.Errorf("fetching receipt for %s: %w", txHash, err)
	}
	return tx.Data(), receipt.BlockNumber.Uint64(), receipt.Status == 1, nil
}

// isNotFound reports whether an RPC error is "no such object" rather than a transport or server failure.
//
// go-ethereum returns ethereum.NotFound for a missing object, but a pruning node may also answer with a
// null result that surfaces as a plain error string, so both shapes are matched. A false negative here
// only costs a less specific message; a false positive would claim an endpoint is pruning when the chain
// really has nothing, so the match is kept narrow.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ethereum.NotFound) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}

// AnchorState reads the anchor's own record of a bundle.
func (r *ChainBackfillReader) AnchorState(
	ctx context.Context,
	chainID int64,
	bundleID [32]byte,
) (AnchorOnChainState, error) {
	client, anchorAddr, err := r.chains.ClientForChain(chainID)
	if err != nil {
		return AnchorOnChainState{}, err
	}
	parsed, err := abiFromJSON(anchorsABIJSON)
	if err != nil {
		return AnchorOnChainState{}, err
	}
	bound := bind.NewBoundContract(anchorAddr, parsed, client, client, client)

	var out []interface{}
	if err := bound.Call(&bind.CallOpts{Context: ctx}, &out, "anchors", bundleID); err != nil {
		return AnchorOnChainState{}, fmt.Errorf("reading anchor 0x%x: %w", bundleID[:8], err)
	}
	return decodeAnchorState(out)
}

// decodeAnchorState maps the anchors() tuple onto the fields the backfill checks.
//
// Split out and tested against a REAL response (see the golden vector in the tests) because the field
// INDEXES are the part that was wrong in production: a batch anchor binds operationID at index 7, while
// index 3, operationCommitment, stays empty. Reading the wrong one refuses every genuine anchor.
func decodeAnchorState(out []interface{}) (AnchorOnChainState, error) {
	if len(out) < 15 {
		return AnchorOnChainState{}, fmt.Errorf(
			"anchors() returned %d fields, expected 15 — the Anchor struct layout changed", len(out))
	}
	state := AnchorOnChainState{}
	var ok bool
	if state.MerkleRoot, ok = out[1].([32]byte); !ok {
		return AnchorOnChainState{}, fmt.Errorf("merkleRoot has an unexpected type")
	}
	if state.OperationCommitment, ok = out[3].([32]byte); !ok {
		return AnchorOnChainState{}, fmt.Errorf("operationCommitment has an unexpected type")
	}
	// Index 7. A batch anchor binds here, not at index 3 — see AnchorOnChainState.
	if state.OperationID, ok = out[7].([32]byte); !ok {
		return AnchorOnChainState{}, fmt.Errorf("operationID has an unexpected type")
	}
	if state.ExecutionCommitment, ok = out[6].([32]byte); !ok {
		return AnchorOnChainState{}, fmt.Errorf("executionCommitment has an unexpected type")
	}
	if ts, tsOK := out[9].(*big.Int); tsOK && ts != nil && ts.Sign() > 0 {
		state.Timestamp = time.Unix(ts.Int64(), 0).UTC()
	}
	if state.Valid, ok = out[11].(bool); !ok {
		return AnchorOnChainState{}, fmt.Errorf("valid has an unexpected type")
	}
	if state.ProofExecuted, ok = out[12].(bool); !ok {
		return AnchorOnChainState{}, fmt.Errorf("proofExecuted has an unexpected type")
	}
	return state, nil
}

// ValidatorRegistry reads the anchor's registry, refusing a partial one — see ReadValidatorRegistry.
func (r *ChainBackfillReader) ValidatorRegistry(
	ctx context.Context,
	chainID int64,
) (map[string]consensus.ValidatorRegistryEntry, error) {
	client, anchorAddr, err := r.chains.ClientForChain(chainID)
	if err != nil {
		return nil, err
	}
	return ReadValidatorRegistryWith(ctx, client, anchorAddr)
}

// BlockTime returns a block's timestamp.
func (r *ChainBackfillReader) BlockTime(ctx context.Context, chainID int64, blockNumber uint64) (time.Time, error) {
	client, _, err := r.chains.ClientForChain(chainID)
	if err != nil {
		return time.Time{}, err
	}
	header, err := client.HeaderByNumber(ctx, new(big.Int).SetUint64(blockNumber))
	if err != nil {
		return time.Time{}, fmt.Errorf("reading block %d: %w", blockNumber, err)
	}
	return time.Unix(int64(header.Time), 0).UTC(), nil
}
