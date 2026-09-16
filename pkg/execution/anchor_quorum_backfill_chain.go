package execution

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/consensus"
)

// ChainBackfillReader is the live BackfillChain: the same RPC endpoints and the same anchor addresses
// the batch path itself uses, so the backfill sees exactly what the validator sees.
type ChainBackfillReader struct {
	chains EVMChainResolver
}

// NewChainBackfillReader builds a reader over an existing chain resolver.
func NewChainBackfillReader(chains EVMChainResolver) *ChainBackfillReader {
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
	ecm, _, err := r.chains.ManagerForChain(chainID)
	if err != nil {
		return nil, 0, false, err
	}
	if !strings.HasPrefix(txHash, "0x") || len(txHash) != 66 {
		return nil, 0, false, fmt.Errorf("%q is not a transaction hash", txHash)
	}
	hash := common.HexToHash(txHash)

	tx, pending, err := ecm.client.TransactionByHash(ctx, hash)
	if err != nil {
		return nil, 0, false, fmt.Errorf("fetching %s: %w", txHash, err)
	}
	if pending {
		// A pending transaction has proven nothing yet.
		return nil, 0, false, fmt.Errorf("%s is still pending", txHash)
	}
	receipt, err := ecm.client.TransactionReceipt(ctx, hash)
	if err != nil {
		return nil, 0, false, fmt.Errorf("fetching receipt for %s: %w", txHash, err)
	}
	return tx.Data(), receipt.BlockNumber.Uint64(), receipt.Status == 1, nil
}

// AnchorState reads the anchor's own record of a bundle.
func (r *ChainBackfillReader) AnchorState(
	ctx context.Context,
	chainID int64,
	bundleID [32]byte,
) (AnchorOnChainState, error) {
	ecm, anchorAddr, err := r.chains.ManagerForChain(chainID)
	if err != nil {
		return AnchorOnChainState{}, err
	}
	parsed, err := abiFromJSON(anchorsABIJSON)
	if err != nil {
		return AnchorOnChainState{}, err
	}
	bound := bind.NewBoundContract(anchorAddr, parsed, ecm.client, ecm.client, ecm.client)

	var out []interface{}
	if err := bound.Call(&bind.CallOpts{Context: ctx}, &out, "anchors", bundleID); err != nil {
		return AnchorOnChainState{}, fmt.Errorf("reading anchor 0x%x: %w", bundleID[:8], err)
	}
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
	ecm, anchorAddr, err := r.chains.ManagerForChain(chainID)
	if err != nil {
		return nil, err
	}
	return ReadValidatorRegistry(ctx, ecm, anchorAddr)
}

// BlockTime returns a block's timestamp.
func (r *ChainBackfillReader) BlockTime(ctx context.Context, chainID int64, blockNumber uint64) (time.Time, error) {
	ecm, _, err := r.chains.ManagerForChain(chainID)
	if err != nil {
		return time.Time{}, err
	}
	header, err := ecm.client.HeaderByNumber(ctx, new(big.Int).SetUint64(blockNumber))
	if err != nil {
		return time.Time{}, fmt.Errorf("reading block %d: %w", blockNumber, err)
	}
	return time.Unix(int64(header.Time), 0).UTC(), nil
}
