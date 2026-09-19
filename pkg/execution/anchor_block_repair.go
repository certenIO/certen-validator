// Copyright 2025 Certen Protocol
//
// Repair of anchor coordinates stored before 2026-09-18, when layer 5 and the Certen anchor proof stated
// the verify transaction's block for the anchor-create transaction. Each canonical anchor's create
// transaction is read back from its own chain and accepted only when it succeeded, is final and its
// createBatchAnchor calldata names the row's bundle and root. Then, and only where the stored value
// differs from the chain:
//
//	anchor_batches.anchor_block_num   filled or corrected
//	layer-5 rows naming the anchor    withdrawn and replaced by a corrected row
//	Certen anchor proofs              anchor reference revised and re-signed by the validator that signed
//	                                  them; another validator's proofs are left for that validator's run
//
// Every change is recorded in evidence_corrections with the reading that justifies it. Without Apply the
// repair only reports what it would do.

package execution

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// AnchorTxReading is an anchor transaction as its chain reports it.
type AnchorTxReading struct {
	Found       bool
	Succeeded   bool
	BlockNumber uint64
	BlockHash   string
	Head        uint64
	Input       []byte
}

// AnchorTxReader reads a transaction, its receipt and the chain head.
type AnchorTxReader interface {
	ReadAnchorTx(ctx context.Context, chainID int64, txHash string) (*AnchorTxReading, error)
}

// AnchorRepairConfig configures RepairAnchorBlocks.
type AnchorRepairConfig struct {
	Repair *database.EvidenceRepair
	Proofs *database.ProofRepository
	Reader AnchorTxReader

	// ValidatorID is who runs the repair: it is recorded on every correction, and only Certen proofs this
	// validator signed are revised, with Signers keyed by signature scheme ("ed25519", "bls12-381").
	ValidatorID string
	Signers     map[string]func(proofHash []byte) []byte

	// MinDepth is how deep a create transaction must be before its block is taken as final (default 12).
	MinDepth int
	Apply    bool
	Logf     func(format string, args ...any)
	Now      func() time.Time
}

// AnchorRepairReport says what a run found and did (or, without Apply, would do).
type AnchorRepairReport struct {
	Anchors         int      `json:"anchors"`
	Confirmed       int      `json:"confirmed"`
	BlocksFilled    int      `json:"anchor_blocks_filled"`
	BlocksCorrected int      `json:"anchor_blocks_corrected"`
	Layer5Replaced  int      `json:"layer5_rows_replaced"`
	ProofsRevised   int      `json:"certen_proofs_revised"`
	Actions         []string `json:"actions"`
	LeftForOwner    []string `json:"left_for_signing_validator"`
	NotYetFinal     []string `json:"not_yet_final"`
	Refused         []string `json:"refused"`
}

// Clean reports whether nothing was refused or left over.
func (r *AnchorRepairReport) Clean() bool {
	return len(r.Refused) == 0 && len(r.LeftForOwner) == 0 && len(r.NotYetFinal) == 0
}

const defaultAnchorRepairDepth = 12

var createBatchAnchorMethod = func() abi.Method {
	parsed, err := abi.JSON(strings.NewReader(contracts.CertenAnchorV7BatchABI))
	if err != nil {
		panic(fmt.Sprintf("CertenAnchorV7 batch ABI: %v", err))
	}
	return parsed.Methods["createBatchAnchor"]
}()

// createBatchAnchorArgs decodes the bundle id and root a createBatchAnchor call carries.
func createBatchAnchorArgs(input []byte) (bundle, root [32]byte, err error) {
	if len(input) < 4 || !bytes.Equal(input[:4], createBatchAnchorMethod.ID) {
		return bundle, root, errors.New("the transaction is not a createBatchAnchor call")
	}
	args, err := createBatchAnchorMethod.Inputs.Unpack(input[4:])
	if err != nil || len(args) < 2 {
		return bundle, root, fmt.Errorf("createBatchAnchor calldata does not decode: %v", err)
	}
	var ok bool
	if bundle, ok = args[0].([32]byte); !ok {
		return bundle, root, errors.New("createBatchAnchor bundleId is not bytes32")
	}
	if root, ok = args[1].([32]byte); !ok {
		return bundle, root, errors.New("createBatchAnchor batchRoot is not bytes32")
	}
	return bundle, root, nil
}

func sameHex(a, b string) bool {
	return strings.EqualFold(strings.TrimPrefix(a, "0x"), strings.TrimPrefix(b, "0x"))
}

// RepairAnchorBlocks corrects stored anchor coordinates against each anchor transaction's chain.
func RepairAnchorBlocks(ctx context.Context, cfg AnchorRepairConfig) (*AnchorRepairReport, error) {
	if cfg.Repair == nil || cfg.Proofs == nil || cfg.Reader == nil || cfg.ValidatorID == "" {
		return nil, errors.New("anchor repair needs the repositories, a chain reader and the validator id")
	}
	if cfg.MinDepth <= 0 {
		cfg.MinDepth = defaultAnchorRepairDepth
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	anchors, err := cfg.Repair.ListCanonicalAnchors(ctx)
	if err != nil {
		return nil, err
	}
	report := &AnchorRepairReport{Anchors: len(anchors), Actions: []string{}, LeftForOwner: []string{}, NotYetFinal: []string{}, Refused: []string{}}
	for _, anchor := range anchors {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if err := repairAnchor(ctx, cfg, anchor, report); err != nil {
			return report, err
		}
	}
	return report, nil
}

// confirmAnchor reads the anchor's create transaction back and checks it is this anchor's.
func confirmAnchor(ctx context.Context, cfg AnchorRepairConfig, anchor database.CanonicalAnchor) (*database.AnchorChainFacts, string, error) {
	reading, err := cfg.Reader.ReadAnchorTx(ctx, anchor.ChainID, anchor.AnchorCreateTx)
	if err != nil {
		return nil, "", err
	}
	name := anchor.TargetChain
	if name == "" {
		name = chainName(anchor.ChainID)
	}
	switch {
	case reading == nil || !reading.Found:
		return nil, "the chain has no such transaction", nil
	case !reading.Succeeded:
		return nil, "the transaction reverted", nil
	case reading.BlockNumber == 0 || reading.BlockHash == "":
		return nil, "the receipt has no block", nil
	}
	bundle, root, err := createBatchAnchorArgs(reading.Input)
	if err != nil {
		return nil, err.Error(), nil
	}
	if !sameHex(hex.EncodeToString(bundle[:]), anchor.BundleID) {
		return nil, fmt.Sprintf("it created bundle 0x%x, not %s", bundle, anchor.BundleID), nil
	}
	if !bytes.Equal(root[:], anchor.Root) {
		return nil, fmt.Sprintf("it anchored root 0x%x, not 0x%x", root, anchor.Root), nil
	}
	depth := 0
	if reading.Head >= reading.BlockNumber {
		depth = int(reading.Head-reading.BlockNumber) + 1
	}
	return &database.AnchorChainFacts{
		ChainID: anchor.ChainID, TargetChain: name, TxHash: anchor.AnchorCreateTx, Succeeded: true,
		BlockNumber: int64(reading.BlockNumber), BlockHash: reading.BlockHash,
		Head: int64(reading.Head), Depth: depth,
		BundleID: "0x" + hex.EncodeToString(bundle[:]), Root: "0x" + hex.EncodeToString(root[:]),
		ReadAt: cfg.Now().UTC().Format(time.RFC3339Nano),
	}, "", nil
}

func repairAnchor(ctx context.Context, cfg AnchorRepairConfig, anchor database.CanonicalAnchor, report *AnchorRepairReport) error {
	label := fmt.Sprintf("anchor %s (batch %s)", anchor.AnchorCreateTx, anchor.BatchID)
	facts, refusal, err := confirmAnchor(ctx, cfg, anchor)
	if err != nil {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: could not be read: %v", label, err))
		return nil
	}
	if refusal != "" {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: %s; nothing changed", label, refusal))
		return nil
	}
	if facts.Depth < cfg.MinDepth {
		report.NotYetFinal = append(report.NotYetFinal, fmt.Sprintf("%s: %d confirmations, %d required", label, facts.Depth, cfg.MinDepth))
		return nil
	}
	report.Confirmed++

	// 1. The canonical row's block.
	if anchor.AnchorBlockNum != facts.BlockNumber {
		action := fmt.Sprintf("%s: anchor_block_num %d -> %d", label, anchor.AnchorBlockNum, facts.BlockNumber)
		if cfg.Apply {
			switch err := cfg.Repair.CorrectAnchorBlock(ctx, anchor, *facts, cfg.ValidatorID); {
			case errors.Is(err, database.ErrEvidenceChanged):
				action += " (changed underneath; left for the next run)"
			case err != nil:
				return err
			case anchor.AnchorBlockNum == 0:
				report.BlocksFilled++
			default:
				report.BlocksCorrected++
			}
		}
		report.Actions = append(report.Actions, action)
	}

	// 2. Layer-5 rows naming this anchor.
	claims, err := cfg.Repair.ListLayer5ForAnchorTx(ctx, anchor.AnchorCreateTx)
	if err != nil {
		return err
	}
	for _, claim := range claims {
		if err := repairLayer5(ctx, cfg, anchor, facts, claim, report); err != nil {
			return err
		}
	}

	// 3. Certen anchor proofs naming this anchor.
	proofs, err := cfg.Proofs.GetProofsByAnchorTxHash(ctx, anchor.AnchorCreateTx)
	if err != nil {
		return err
	}
	for _, proof := range proofs {
		if err := repairCertenProof(ctx, cfg, facts, proof, report); err != nil {
			return err
		}
	}
	return nil
}

func repairLayer5(ctx context.Context, cfg AnchorRepairConfig, anchor database.CanonicalAnchor, facts *database.AnchorChainFacts, claim database.Layer5Claim, report *AnchorRepairReport) error {
	label := fmt.Sprintf("layer-5 row %s (proof %s)", claim.LayerID, claim.ProofID)
	var stated Layer5
	if err := json.Unmarshal(claim.LayerJSON, &stated); err != nil {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: unreadable: %v", label, err))
		return nil
	}
	if !strings.EqualFold(stated.BatchRoot, hex.EncodeToString(anchor.Root)) {
		// A different root under this transaction is a false claim of another kind; 020 withdraws those.
		report.Refused = append(report.Refused, fmt.Sprintf("%s: names root %s, which this anchor did not publish; not corrected", label, stated.BatchRoot))
		return nil
	}
	blockWrong := int64(stated.BlockNumber) != facts.BlockNumber
	hashWrong := stated.BlockHash != "" && !sameHex(stated.BlockHash, facts.BlockHash)
	if !blockWrong && !hashWrong {
		return nil
	}

	// Change exactly the coordinates the chain contradicts, and nothing else in the layer.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(claim.LayerJSON, &fields); err != nil {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: unreadable: %v", label, err))
		return nil
	}
	fields["blockNumber"], _ = json.Marshal(facts.BlockNumber)
	fields["blockHash"], _ = json.Marshal(facts.BlockHash)
	fields["network"], _ = json.Marshal(facts.TargetChain)
	corrected, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	var check Layer5
	if err := json.Unmarshal(corrected, &check); err != nil {
		return err
	}
	if err := check.VerifyOffline(); err != nil {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: the corrected layer does not verify: %v", label, err))
		return nil
	}
	action := fmt.Sprintf("%s: block %d -> %d (hash %s), replaced", label, stated.BlockNumber, facts.BlockNumber, facts.BlockHash)
	if cfg.Apply {
		reason := fmt.Sprintf("anchor %s is in block %d (%s) on %s, not block %d as this row stated; "+
			"the stated block was the verify transaction's. Corrected by `validator repair anchor-blocks`.",
			anchor.AnchorCreateTx, facts.BlockNumber, facts.BlockHash, facts.TargetChain, stated.BlockNumber)
		replacement, err := cfg.Repair.ReplaceLayer5(ctx, claim, corrected, reason, *facts, cfg.ValidatorID)
		switch {
		case errors.Is(err, database.ErrEvidenceChanged):
			action += " (changed underneath; left for the next run)"
		case err != nil:
			return err
		default:
			action += " by " + replacement.String()
			report.Layer5Replaced++
		}
	}
	report.Actions = append(report.Actions, action)
	return nil
}

func repairCertenProof(ctx context.Context, cfg AnchorRepairConfig, facts *database.AnchorChainFacts, proof *database.CertenAnchorProof, report *AnchorRepairReport) error {
	label := fmt.Sprintf("Certen proof %s", proof.ProofID)
	blockWrong := proof.AnchorBlockNumber != facts.BlockNumber
	hashWrong := proof.AnchorBlockHash.Valid && proof.AnchorBlockHash.String != "" && !sameHex(proof.AnchorBlockHash.String, facts.BlockHash)
	if !blockWrong && !hashWrong {
		return nil
	}
	owner := proof.ValidatorID
	if owner != cfg.ValidatorID {
		report.LeftForOwner = append(report.LeftForOwner, fmt.Sprintf("%s: signed by %s, which must revise it (block %d -> %d)",
			label, owner, proof.AnchorBlockNumber, facts.BlockNumber))
		return nil
	}
	scheme := signatureScheme(proof.VerifyDetails)
	sign := cfg.Signers[scheme]
	if sign == nil {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: signed with scheme %q, for which this run has no key", label, scheme))
		return nil
	}
	action := fmt.Sprintf("%s: anchor block %d -> %d on %s, revised and re-signed (%s)",
		label, proof.AnchorBlockNumber, facts.BlockNumber, facts.TargetChain, scheme)
	if cfg.Apply {
		reason := fmt.Sprintf("anchor %s is in block %d (%s) on %s, not block %d as the proof stated; the "+
			"stated block was the verify transaction's. The anchor reference was revised, the proof hash "+
			"recomputed and the proof re-signed by %s.",
			facts.TxHash, facts.BlockNumber, facts.BlockHash, facts.TargetChain, proof.AnchorBlockNumber, cfg.ValidatorID)
		revised, err := cfg.Repair.ReviseCertenProofAnchor(ctx, proof.ProofID, proof.ProofHash, database.CertenAnchorRevision{
			Chain: database.TargetChain(facts.TargetChain), BlockNumber: facts.BlockNumber, BlockHash: facts.BlockHash,
			Confirmations: facts.Depth,
		}, scheme, sign, reason, *facts, cfg.ValidatorID)
		switch {
		case errors.Is(err, database.ErrEvidenceChanged):
			action += " (changed underneath; left for the next run)"
		case errors.Is(err, database.ErrProofDocumentNotCanonical):
			report.Refused = append(report.Refused, fmt.Sprintf("%s: %v; not revised", label, err))
			return nil
		case err != nil:
			return err
		default:
			action += fmt.Sprintf("; proof hash now %x", revised.ProofHash)
			report.ProofsRevised++
		}
	}
	report.Actions = append(report.Actions, action)
	return nil
}

// signatureScheme is the scheme the proof was signed with, as its verification details record it.
func signatureScheme(details json.RawMessage) string {
	var d struct {
		Scheme string `json:"signature_scheme"`
	}
	_ = json.Unmarshal(details, &d)
	return d.Scheme
}

// EthAnchorTxReader reads anchor transactions over each chain's configured RPC endpoints.
type EthAnchorTxReader struct {
	mu    sync.Mutex
	pools map[int64]*ethrpc.Pool
}

// NewEthAnchorTxReader creates a reader; pools are built per chain on first use.
func NewEthAnchorTxReader() *EthAnchorTxReader {
	return &EthAnchorTxReader{pools: map[int64]*ethrpc.Pool{}}
}

func (r *EthAnchorTxReader) pool(chainID int64) (*ethrpc.Pool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.pools[chainID]; ok {
		return p, nil
	}
	key := ethrpc.ChainKeyForID(chainID)
	if key == "" {
		return nil, fmt.Errorf("chain %d is not known to this build", chainID)
	}
	p, err := ethrpc.PoolForChain(key, nil)
	if err != nil {
		return nil, err
	}
	r.pools[chainID] = p
	return p, nil
}

// ReadAnchorTx implements AnchorTxReader. It reads over the pool so that an endpoint lacking the history
// (see ReadAnchorTxFrom) hands the read to the next provider instead of ending it.
func (r *EthAnchorTxReader) ReadAnchorTx(ctx context.Context, chainID int64, txHash string) (*AnchorTxReading, error) {
	p, err := r.pool(chainID)
	if err != nil {
		return nil, err
	}
	var reading *AnchorTxReading
	err = p.Do(ctx, func(c *ethclient.Client) error {
		got, err := ReadAnchorTxFrom(ctx, c, txHash)
		if err == nil {
			reading = got
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return reading, nil
}

// rpcTransaction is the part of eth_getTransactionByHash the reading needs, including the block it was
// mined in, which ethclient's TransactionByHash does not return.
type rpcTransaction struct {
	BlockNumber *hexutil.Big  `json:"blockNumber"`
	BlockHash   *common.Hash  `json:"blockHash"`
	Input       hexutil.Bytes `json:"input"`
}

// ReadAnchorTxFrom reads a transaction, its receipt and the head from one endpoint. The receipt is taken
// by hash, or else from its block's receipts, which do not depend on a transaction index. An endpoint that
// returns the transaction but neither receipt does not hold that block's receipts; that is
// ethrpc.ErrEndpointLacksHistory, never "no such transaction".
func ReadAnchorTxFrom(ctx context.Context, c *ethclient.Client, txHash string) (*AnchorTxReading, error) {
	hash := common.HexToHash(txHash)
	var tx *rpcTransaction
	if err := c.Client().CallContext(ctx, &tx, "eth_getTransactionByHash", hash); err != nil {
		return nil, err
	}
	if tx == nil {
		// Unknown here. The pool asks the next provider; absent from every provider is reported by the
		// caller as unreadable, not as proven absent.
		return nil, fmt.Errorf("transaction %s: %w", txHash, ethrpc.ErrEndpointLacksHistory)
	}
	if tx.BlockNumber == nil || tx.BlockHash == nil {
		return &AnchorTxReading{Found: true}, nil // pending: no block to state
	}
	block := tx.BlockNumber.ToInt().Uint64()

	receipt, err := c.TransactionReceipt(ctx, hash)
	if errors.Is(err, ethereum.NotFound) {
		receipt, err = nil, nil
		receipts, blockErr := c.BlockReceipts(ctx, rpc.BlockNumberOrHashWithHash(*tx.BlockHash, false))
		if blockErr != nil && !errors.Is(blockErr, ethereum.NotFound) {
			return nil, blockErr
		}
		for _, candidate := range receipts {
			if candidate != nil && candidate.TxHash == hash {
				receipt = candidate
				break
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if receipt == nil {
		return nil, fmt.Errorf("receipt of %s in block %d: %w", txHash, block, ethrpc.ErrEndpointLacksHistory)
	}
	if receipt.BlockHash != *tx.BlockHash || receipt.BlockNumber == nil || receipt.BlockNumber.Uint64() != block {
		return nil, fmt.Errorf("receipt of %s names block %v %s, the transaction block %d %s",
			txHash, receipt.BlockNumber, receipt.BlockHash.Hex(), block, tx.BlockHash.Hex())
	}
	head, err := c.BlockNumber(ctx)
	if err != nil {
		return nil, err
	}
	return &AnchorTxReading{
		Found: true, Succeeded: receipt.Status == types.ReceiptStatusSuccessful,
		BlockNumber: block, BlockHash: tx.BlockHash.Hex(), Head: head, Input: tx.Input,
	}, nil
}

// Close releases the reader's connections.
func (r *EthAnchorTxReader) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.pools {
		p.Close()
	}
}
