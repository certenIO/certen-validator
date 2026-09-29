package execution

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/execution/contracts"
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
	st, err := ReadAnchorState(ctx, client, anchorAddr, bundleID, nil)
	if err != nil {
		return AnchorOnChainState{}, err
	}
	return decodeAnchorState(st)
}

// decodeAnchorState maps an anchor record (either generation, ReadAnchorState) onto the fields the backfill and the
// create locator check. A batch anchor binds its operation id at operationID, while operationCommitment stays empty:
// reading the wrong one refused every genuine anchor in production.
func decodeAnchorState(st *contracts.AnchorState) (AnchorOnChainState, error) {
	if st == nil {
		return AnchorOnChainState{}, fmt.Errorf("no anchor record")
	}
	if st.Timestamp == nil || !st.Timestamp.IsUint64() {
		return AnchorOnChainState{}, fmt.Errorf("timestamp has an unexpected value")
	}
	state := AnchorOnChainState{
		MerkleRoot: st.MerkleRoot, OperationCommitment: st.OperationCommitment, OperationID: st.OperationID,
		ExecutionCommitment: st.ExecutionCommitment, Validator: st.Validator, Valid: st.Valid, ProofExecuted: st.ProofExecuted,
		Version: st.Version, AccumulateSetRoot: st.AccumulateSetRoot, Incarnation: st.Incarnation,
	}
	if st.Timestamp.Sign() > 0 {
		state.CreatedAt = st.Timestamp.Uint64()
		state.Timestamp = time.Unix(st.Timestamp.Int64(), 0).UTC()
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

// LatestBlock reports the head this endpoint will serve.
func (r *ChainBackfillReader) LatestBlock(ctx context.Context, chainID int64) (uint64, error) {
	client, _, err := r.chains.ClientForChain(chainID)
	if err != nil {
		return 0, err
	}
	head, err := client.BlockNumber(ctx)
	if err != nil {
		return 0, fmt.Errorf("chain %d: reading head: %w", chainID, err)
	}
	return head, nil
}

// ScanProofExecuted returns the anchors this chain reports as proven in a block range.
//
// The topic comes from the parsed ABI rather than a stored constant: the hand-maintained topic table in
// pkg/anchor was computed with sha256 for the life of the file, which matches no log any node emits. A
// scanner that silently returns nothing is indistinguishable from a chain with nothing to backfill, so
// this derives the value it filters on from the same ABI it decodes with.
func (r *ChainBackfillReader) ScanProofExecuted(
	ctx context.Context,
	chainID int64,
	fromBlock, toBlock uint64,
) ([]ProofExecutedLog, error) {
	client, anchorAddr, err := r.chains.ClientForChain(chainID)
	if err != nil {
		return nil, err
	}
	event, ok := anchorEventsABI.Events["ProofExecuted"]
	if !ok {
		return nil, fmt.Errorf("the anchor event ABI declares no ProofExecuted event")
	}

	logs, err := client.FilterLogs(ctx, ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(fromBlock),
		ToBlock:   new(big.Int).SetUint64(toBlock),
		Addresses: []common.Address{anchorAddr},
		Topics:    [][]common.Hash{{event.ID}},
	})
	if err != nil {
		return nil, fmt.Errorf("eth_getLogs %d..%d on %s: %w", fromBlock, toBlock, anchorAddr.Hex(), err)
	}

	out := make([]ProofExecutedLog, 0, len(logs))
	for _, l := range logs {
		// topics[0] is the event id; topics[1] is the indexed anchorId, which IS the bundle id.
		if len(l.Topics) < 2 || l.Removed {
			continue
		}
		entry := ProofExecutedLog{
			ChainID:     chainID,
			TxHash:      l.TxHash.Hex(),
			BlockNumber: l.BlockNumber,
		}
		copy(entry.BundleID[:], l.Topics[1].Bytes())
		out = append(out, entry)
	}
	return out, nil
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
