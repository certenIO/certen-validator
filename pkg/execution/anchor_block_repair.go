// Copyright 2025 Certen Protocol
//
// Repair of stored anchor evidence against the anchor's own chain.
//
// Each canonical anchor's verify transaction is read back and accepted only when it succeeded, is final and
// its executeComprehensiveProof calldata names the row's bundle and root; the contract it called is the
// anchor. The create transaction is the one the row names or, where it names none (RB3-F33: 235 of 289
// rows, because a validator whose createBatchAnchor found the anchor already there recorded nothing), the
// one LocateAnchorCreate finds from the anchor's own record and its BatchAnchorCreated log. It is accepted
// only when it succeeded, is final, called the same anchor, and its createBatchAnchor calldata names the
// row's bundle and root; a located one must also be signed by the creator the anchor records. Every
// transaction is taken as signed (see signedTransaction) and its signer recovered. Then, and only where
// the stored value is missing or differs from the chain:
//
//	anchor_batches.anchor_create_tx   completed (with anchor_block_num and anchor_tx_hash)
//	anchor_batches.anchor_block_num   filled or corrected
//	anchor_batches.verify_block       filled or corrected
//	anchor_batches.*_sender           the signers of both transactions, recorded or corrected (RB3-F127)
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
	"math/big"
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
//
// From, To and Input come from the signed transaction itself, accepted only when it hashes to the hash
// asked for: From is recovered from the signature (RB3-F127), never taken from the endpoint's word.
type AnchorTxReading struct {
	Found       bool
	Succeeded   bool
	BlockNumber uint64
	BlockHash   string
	Head        uint64
	Input       []byte
	// From is the signer, lower-case 0x-hex; To the called contract, lower-case ("" for a creation).
	From string
	To   string
	// BlockTime is the timestamp of the block that mined it, from the header its block hash names.
	BlockTime uint64
}

// AnchorTxReader reads a transaction, its receipt and the chain head, and locates an anchor's create
// transaction (see LocateAnchorCreate).
type AnchorTxReader interface {
	ReadAnchorTx(ctx context.Context, chainID int64, txHash string) (*AnchorTxReading, error)
	LocateAnchorCreate(ctx context.Context, chainID int64, anchor string, bundle, root [32]byte, notAfter uint64) (*AnchorCreateLocation, error)
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
	Anchors               int `json:"anchors"`
	Confirmed             int `json:"confirmed"`
	CreatesCompleted      int `json:"anchor_creates_completed"`
	BlocksFilled          int `json:"anchor_blocks_filled"`
	BlocksCorrected       int `json:"anchor_blocks_corrected"`
	VerifyBlocksFilled    int `json:"verify_blocks_filled"`
	VerifyBlocksCorrected int `json:"verify_blocks_corrected"`
	SendersRecorded       int `json:"senders_recorded"`
	SendersCorrected      int `json:"senders_corrected"`
	// CompletionTimesCorrected counts consensus_completed_at set to the verify block's time.
	CompletionTimesCorrected int      `json:"completion_times_corrected"`
	Layer5Replaced           int      `json:"layer5_rows_replaced"`
	ProofsRevised            int      `json:"certen_proofs_revised"`
	Actions                  []string `json:"actions"`
	LeftForOwner             []string `json:"left_for_signing_validator"`
	NotYetFinal              []string `json:"not_yet_final"`
	Refused                  []string `json:"refused"`
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
		Sender: reading.From, Contract: reading.To,
		ReadAt: cfg.Now().UTC().Format(time.RFC3339Nano),
	}, "", nil
}

// confirmVerify reads the anchor's verify transaction back and checks it proved this anchor: it succeeded
// and its executeComprehensiveProof calldata names the row's bundle and root. The contract it called is
// the anchor, where the create transaction must be too.
func confirmVerify(ctx context.Context, cfg AnchorRepairConfig, anchor database.CanonicalAnchor) (*database.AnchorChainFacts, string, error) {
	if !IsTransactionHash(anchor.VerifyTx) {
		return nil, "the row names no verify transaction", nil
	}
	reading, err := cfg.Reader.ReadAnchorTx(ctx, anchor.ChainID, anchor.VerifyTx)
	if err != nil {
		return nil, "", err
	}
	name := anchor.TargetChain
	if name == "" {
		name = chainName(anchor.ChainID)
	}
	switch {
	case reading == nil || !reading.Found:
		return nil, "the chain has no such verify transaction", nil
	case !reading.Succeeded:
		return nil, "the verify transaction reverted", nil
	case reading.BlockNumber == 0 || reading.BlockHash == "":
		return nil, "the verify receipt has no block", nil
	case reading.To == "":
		return nil, "the verify transaction called no contract", nil
	}
	call, err := DecodeExecuteComprehensiveProof(reading.Input)
	if err != nil {
		return nil, "the verify transaction is not an executeComprehensiveProof call: " + err.Error(), nil
	}
	if !sameHex(hex.EncodeToString(call.BundleID[:]), anchor.BundleID) {
		return nil, fmt.Sprintf("the verify transaction proved bundle 0x%x, not %s", call.BundleID, anchor.BundleID), nil
	}
	if !bytes.Equal(call.MerkleRoot[:], anchor.Root) {
		return nil, fmt.Sprintf("the verify transaction proved root 0x%x, not 0x%x", call.MerkleRoot, anchor.Root), nil
	}
	depth := 0
	if reading.Head >= reading.BlockNumber {
		depth = int(reading.Head-reading.BlockNumber) + 1
	}
	if reading.BlockTime == 0 {
		return nil, "the verify block has no time", nil
	}
	return &database.AnchorChainFacts{
		ChainID: anchor.ChainID, TargetChain: name, TxHash: anchor.VerifyTx, Succeeded: true,
		BlockNumber: int64(reading.BlockNumber), BlockHash: reading.BlockHash, BlockTime: int64(reading.BlockTime),
		Head: int64(reading.Head), Depth: depth,
		BundleID: "0x" + hex.EncodeToString(call.BundleID[:]), Root: "0x" + hex.EncodeToString(call.MerkleRoot[:]),
		Sender: reading.From, Contract: reading.To,
		ReadAt: cfg.Now().UTC().Format(time.RFC3339Nano),
	}, "", nil
}

func repairAnchor(ctx context.Context, cfg AnchorRepairConfig, anchor database.CanonicalAnchor, report *AnchorRepairReport) error {
	label := fmt.Sprintf("anchor %s (batch %s)", anchor.BundleID, anchor.BatchID)

	// The verify transaction first: it names the anchor contract the create transaction must have called.
	verify, refusal, err := confirmVerify(ctx, cfg, anchor)
	if err != nil {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: verify transaction %s could not be read: %v", label, anchor.VerifyTx, err))
		return nil
	}
	if refusal != "" {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: %s; nothing changed", label, refusal))
		return nil
	}
	if verify.Depth < cfg.MinDepth {
		report.NotYetFinal = append(report.NotYetFinal, fmt.Sprintf("%s: verify transaction has %d confirmations, %d required", label, verify.Depth, cfg.MinDepth))
		return nil
	}

	// The create transaction: the one the row names, or else the one the chain says created the anchor.
	stored := anchor
	var creator string
	// misnamed is a transaction the row states as publishing the root that did not (RB3-F134): its layer-5
	// rows and Certen proofs are corrected below with the rest.
	var misnamed string
	if anchor.AnchorCreateTx == "" {
		bundle, err := bytes32FromHex(anchor.BundleID)
		if err != nil || len(anchor.Root) != 32 {
			report.Refused = append(report.Refused, fmt.Sprintf("%s: the row's bundle or root is not 32 bytes; nothing changed", label))
			return nil
		}
		var root [32]byte
		copy(root[:], anchor.Root)
		loc, err := cfg.Reader.LocateAnchorCreate(ctx, anchor.ChainID, verify.Contract, bundle, root, uint64(verify.BlockNumber))
		if err != nil {
			report.Refused = append(report.Refused, fmt.Sprintf("%s: its create transaction could not be located: %v; nothing changed", label, err))
			return nil
		}
		if anchor.AnchorTxHash != "" && !sameHex(anchor.AnchorTxHash, loc.TxHash) {
			// The row names another transaction as publishing its root. The anchor can be created once, so
			// only the located one did - unless the named one is itself this anchor's successful
			// createBatchAnchor call, which would contradict the chain and is refused.
			named, err := cfg.Reader.ReadAnchorTx(ctx, anchor.ChainID, anchor.AnchorTxHash)
			if err != nil {
				report.Refused = append(report.Refused, fmt.Sprintf("%s: the transaction the row names, %s, could not be read: %v; nothing changed",
					label, anchor.AnchorTxHash, err))
				return nil
			}
			if named == nil || !named.Found || named.BlockNumber == 0 {
				report.Refused = append(report.Refused, fmt.Sprintf("%s: the row names %s, which the chain does not show mined; it cannot be established what it is, so nothing changed",
					label, anchor.AnchorTxHash))
				return nil
			}
			if b, r, err := createBatchAnchorArgs(named.Input); err == nil && named.Succeeded &&
				sameHex(hex.EncodeToString(b[:]), anchor.BundleID) && bytes.Equal(r[:], anchor.Root) {
				report.Refused = append(report.Refused, fmt.Sprintf("%s: the row names %s and the chain locates %s as this anchor's creation; nothing changed",
					label, anchor.AnchorTxHash, loc.TxHash))
				return nil
			}
			misnamed = anchor.AnchorTxHash
		}
		anchor.AnchorCreateTx = loc.TxHash
		creator = strings.ToLower(loc.Validator.Hex())
	}
	facts, refusal, err := confirmAnchor(ctx, cfg, anchor)
	if err != nil {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: create transaction %s could not be read: %v", label, anchor.AnchorCreateTx, err))
		return nil
	}
	if refusal != "" {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: create transaction %s: %s; nothing changed", label, anchor.AnchorCreateTx, refusal))
		return nil
	}
	if !sameHex(facts.Contract, verify.Contract) {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: created at %s but verified at %s; nothing changed", label, facts.Contract, verify.Contract))
		return nil
	}
	if creator != "" && !sameHex(facts.Sender, creator) {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: create transaction %s is signed by %s, but the anchor records %s as its creator; nothing changed",
			label, anchor.AnchorCreateTx, facts.Sender, creator))
		return nil
	}
	if facts.Depth < cfg.MinDepth {
		report.NotYetFinal = append(report.NotYetFinal, fmt.Sprintf("%s: create transaction %s has %d confirmations, %d required",
			label, anchor.AnchorCreateTx, facts.Depth, cfg.MinDepth))
		return nil
	}
	report.Confirmed++

	// The canonical row's create transaction and its block. createKnown says whether the row names it, so
	// that its sender can be recorded against it.
	createKnown := stored.AnchorCreateTx != ""
	switch {
	case !createKnown:
		action := fmt.Sprintf("%s: anchor_create_tx NULL -> %s (block %d, located by the anchor's BatchAnchorCreated log)",
			label, facts.TxHash, facts.BlockNumber)
		if misnamed != "" {
			action += fmt.Sprintf("; anchor_tx_hash %s, which did not publish the root, -> %s", misnamed, facts.TxHash)
		}
		if cfg.Apply {
			switch err := cfg.Repair.CompleteAnchorCreate(ctx, stored, *facts, cfg.ValidatorID); {
			case errors.Is(err, database.ErrEvidenceChanged):
				action += " (changed underneath; left for the next run)"
			case err != nil:
				return err
			default:
				report.CreatesCompleted++
				createKnown = true
			}
		}
		report.Actions = append(report.Actions, action)
	case anchor.AnchorBlockNum != facts.BlockNumber:
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

	// The verify transaction's block.
	if anchor.VerifyBlock != verify.BlockNumber {
		action := fmt.Sprintf("%s: verify_block %d -> %d", label, anchor.VerifyBlock, verify.BlockNumber)
		if cfg.Apply {
			switch err := cfg.Repair.CorrectVerifyBlock(ctx, anchor, *verify, cfg.ValidatorID); {
			case errors.Is(err, database.ErrEvidenceChanged):
				action += " (changed underneath; left for the next run)"
			case err != nil:
				return err
			case anchor.VerifyBlock == 0:
				report.VerifyBlocksFilled++
			default:
				report.VerifyBlocksCorrected++
			}
		}
		report.Actions = append(report.Actions, action)
	}

	// When the quorum was confirmed on-chain: the verify block's time (RB3-F131, RB3-F133).
	if onChain := time.Unix(verify.BlockTime, 0).UTC(); !anchor.CompletedAt.Equal(onChain) {
		action := fmt.Sprintf("%s: consensus_completed_at %s -> %s (verify block %d)", label,
			anchor.CompletedAt.UTC().Format(time.RFC3339Nano), onChain.Format(time.RFC3339), verify.BlockNumber)
		if cfg.Apply {
			switch err := cfg.Repair.CorrectCompletedAt(ctx, anchor, *verify, cfg.ValidatorID); {
			case errors.Is(err, database.ErrEvidenceChanged):
				action += " (changed underneath; left for the next run)"
			case err != nil:
				return err
			default:
				report.CompletionTimesCorrected++
			}
		}
		report.Actions = append(report.Actions, action)
	}

	// Who sent them (RB3-F127). The create sender is recorded against the row's create transaction, so only
	// once the row names it; in a dry run it is reported as it would be.
	if createKnown || !cfg.Apply {
		if err := recordSender(ctx, cfg, anchor, database.AnchorSenderCreate, stored.AnchorCreateSender, facts, label, report); err != nil {
			return err
		}
	}
	if err := recordSender(ctx, cfg, anchor, database.AnchorSenderVerify, stored.VerifySender, verify, label, report); err != nil {
		return err
	}

	// Layer-5 rows naming this anchor - and those naming the transaction the row misnamed as it.
	claims, err := cfg.Repair.ListLayer5ForAnchorTx(ctx, anchor.AnchorCreateTx)
	if err != nil {
		return err
	}
	if misnamed != "" {
		more, err := cfg.Repair.ListLayer5ForAnchorTx(ctx, misnamed)
		if err != nil {
			return err
		}
		claims = append(claims, more...)
	}
	for _, claim := range claims {
		if err := repairLayer5(ctx, cfg, anchor, facts, claim, report); err != nil {
			return err
		}
	}

	// Certen anchor proofs naming this anchor, or the transaction the row misnamed as it.
	proofs, err := cfg.Proofs.GetProofsByAnchorTxHash(ctx, anchor.AnchorCreateTx)
	if err != nil {
		return err
	}
	if misnamed != "" {
		more, err := cfg.Proofs.GetProofsByAnchorTxHash(ctx, misnamed)
		if err != nil {
			return err
		}
		proofs = append(proofs, more...)
	}
	for _, proof := range proofs {
		if err := repairCertenProof(ctx, cfg, anchor, facts, proof, report); err != nil {
			return err
		}
	}
	return nil
}

// recordSender records a transaction's signer on the row where it has none, and corrects one the
// signature contradicts.
func recordSender(ctx context.Context, cfg AnchorRepairConfig, anchor database.CanonicalAnchor, which, stored string,
	facts *database.AnchorChainFacts, label string, report *AnchorRepairReport) error {
	if facts.Sender == "" {
		return fmt.Errorf("%s: %s transaction %s was read without its signer", label, which, facts.TxHash)
	}
	if sameHex(stored, facts.Sender) {
		return nil
	}
	action := fmt.Sprintf("%s: %s sender -> %s", label, which, facts.Sender)
	if stored != "" {
		action = fmt.Sprintf("%s: %s sender %s -> %s (the signature contradicts the row)", label, which, stored, facts.Sender)
	}
	if cfg.Apply {
		switch err := cfg.Repair.RecordAnchorSender(ctx, anchor, which, stored, *facts, cfg.ValidatorID); {
		case errors.Is(err, database.ErrEvidenceChanged):
			action += " (changed underneath; left for the next run)"
		case err != nil:
			return err
		case stored == "":
			report.SendersRecorded++
		default:
			report.SendersCorrected++
		}
	}
	report.Actions = append(report.Actions, action)
	return nil
}

// bytes32FromHex parses a 0x-prefixed or bare 32-byte hex value.
func bytes32FromHex(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("%d bytes, not 32", len(b))
	}
	copy(out[:], b)
	return out, nil
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
	// RB3-F134: a layer that named the settlement's transaction as the anchor's states the wrong transaction
	// and, with it, the settlement's block.
	txWrong := !sameHex(stated.AnchorTx, facts.TxHash)
	blockWrong := int64(stated.BlockNumber) != facts.BlockNumber
	hashWrong := stated.BlockHash != "" && !sameHex(stated.BlockHash, facts.BlockHash)
	// RB3-F119: a row written while the anchor could not be read back states no hash. Missing is completed,
	// exactly as wrong is corrected - it used to stay missing for ever.
	hashMissing := stated.BlockHash == ""
	if !txWrong && !blockWrong && !hashWrong && !hashMissing {
		return nil
	}

	// Change exactly the coordinates the chain contradicts, and nothing else in the layer.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(claim.LayerJSON, &fields); err != nil {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: unreadable: %v", label, err))
		return nil
	}
	fields["anchorTx"], _ = json.Marshal(facts.TxHash)
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
	reason := fmt.Sprintf("anchor %s is in block %d (%s) on %s, not block %d as this row stated; "+
		"the stated block was the verify transaction's. Corrected by `validator repair anchor-blocks`.",
		anchor.AnchorCreateTx, facts.BlockNumber, facts.BlockHash, facts.TargetChain, stated.BlockNumber)
	switch {
	case txWrong:
		action = fmt.Sprintf("%s: anchorTx %s @ %d -> %s @ %d (hash %s), replaced", label, stated.AnchorTx, stated.BlockNumber,
			facts.TxHash, facts.BlockNumber, facts.BlockHash)
		reason = fmt.Sprintf("this row stated that root %s was published in %s at block %d; that transaction did not "+
			"publish it (it is the settlement's). Anchor %s published it: transaction %s in block %d (%s) on %s. "+
			"Corrected by `validator repair anchor-blocks` (RB3-F134).",
			stated.BatchRoot, stated.AnchorTx, stated.BlockNumber, anchor.BundleID, facts.TxHash, facts.BlockNumber, facts.BlockHash, facts.TargetChain)
	case !blockWrong && hashWrong:
		action = fmt.Sprintf("%s: block %d hash %s -> %s, replaced", label, stated.BlockNumber, stated.BlockHash, facts.BlockHash)
		reason = fmt.Sprintf("anchor %s is in block %d on %s with hash %s, not %s as this row stated. "+
			"Corrected by `validator repair anchor-blocks`.",
			anchor.AnchorCreateTx, facts.BlockNumber, facts.TargetChain, facts.BlockHash, stated.BlockHash)
	case !blockWrong:
		action = fmt.Sprintf("%s: block %d stated without its hash, completed (hash %s), replaced", label, stated.BlockNumber, facts.BlockHash)
		reason = fmt.Sprintf("this row stated anchor %s's block %d on %s without its hash (the anchor could not be "+
			"read back when the row was written); completed with the chain's %s by `validator repair anchor-blocks`.",
			anchor.AnchorCreateTx, facts.BlockNumber, facts.TargetChain, facts.BlockHash)
	}
	if cfg.Apply {
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

func repairCertenProof(ctx context.Context, cfg AnchorRepairConfig, anchor database.CanonicalAnchor, facts *database.AnchorChainFacts, proof *database.CertenAnchorProof, report *AnchorRepairReport) error {
	label := fmt.Sprintf("Certen proof %s", proof.ProofID)
	txWrong := !sameHex(proof.AnchorTxHash, facts.TxHash)
	if txWrong && !bytes.Equal(proof.MerkleRoot, anchor.Root) {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: names %s but proves root %x, not anchor %s's; not revised",
			label, proof.AnchorTxHash, proof.MerkleRoot, anchor.BundleID))
		return nil
	}
	blockWrong := proof.AnchorBlockNumber != facts.BlockNumber
	hashWrong := proof.AnchorBlockHash.Valid && proof.AnchorBlockHash.String != "" && !sameHex(proof.AnchorBlockHash.String, facts.BlockHash)
	// RB3-F119: a proof stating no hash is completed, as a wrong one is corrected.
	hashMissing := !proof.AnchorBlockHash.Valid || proof.AnchorBlockHash.String == ""
	if !txWrong && !blockWrong && !hashWrong && !hashMissing {
		return nil
	}
	change := fmt.Sprintf("block %d -> %d", proof.AnchorBlockNumber, facts.BlockNumber)
	if txWrong {
		change = fmt.Sprintf("anchor tx %s @ %d -> %s @ %d", proof.AnchorTxHash, proof.AnchorBlockNumber, facts.TxHash, facts.BlockNumber)
	}
	if !blockWrong {
		change = fmt.Sprintf("block %d hash -> %s", proof.AnchorBlockNumber, facts.BlockHash)
	}
	owner := proof.ValidatorID
	if owner != cfg.ValidatorID {
		report.LeftForOwner = append(report.LeftForOwner, fmt.Sprintf("%s: signed by %s, which must revise it (%s)",
			label, owner, change))
		return nil
	}
	scheme := signatureScheme(proof.VerifyDetails)
	sign := cfg.Signers[scheme]
	if sign == nil {
		report.Refused = append(report.Refused, fmt.Sprintf("%s: signed with scheme %q, for which this run has no key", label, scheme))
		return nil
	}
	action := fmt.Sprintf("%s: anchor %s on %s, revised and re-signed (%s)", label, change, facts.TargetChain, scheme)
	if cfg.Apply {
		reason := fmt.Sprintf("anchor %s is in block %d (%s) on %s, not block %d as the proof stated; the "+
			"stated block was the verify transaction's. The anchor reference was revised, the proof hash "+
			"recomputed and the proof re-signed by %s.",
			facts.TxHash, facts.BlockNumber, facts.BlockHash, facts.TargetChain, proof.AnchorBlockNumber, cfg.ValidatorID)
		switch {
		case txWrong:
			reason = fmt.Sprintf("the proof named %s at block %d as its anchor; that transaction did not publish root %x (it is "+
				"the settlement's). Transaction %s in block %d (%s) on %s did. The anchor reference was revised, the proof "+
				"hash recomputed and the proof re-signed by %s (RB3-F134).",
				proof.AnchorTxHash, proof.AnchorBlockNumber, anchor.Root, facts.TxHash, facts.BlockNumber, facts.BlockHash,
				facts.TargetChain, cfg.ValidatorID)
		case !blockWrong && hashWrong:
			reason = fmt.Sprintf("anchor %s is in block %d on %s with hash %s, not %s as the proof stated. The anchor "+
				"reference was revised, the proof hash recomputed and the proof re-signed by %s.",
				facts.TxHash, facts.BlockNumber, facts.TargetChain, facts.BlockHash, proof.AnchorBlockHash.String, cfg.ValidatorID)
		case !blockWrong:
			reason = fmt.Sprintf("the proof stated anchor %s's block %d on %s without its hash (the anchor could not "+
				"be read back when it was written); completed with the chain's %s, the proof hash recomputed and "+
				"the proof re-signed by %s.",
				facts.TxHash, facts.BlockNumber, facts.TargetChain, facts.BlockHash, cfg.ValidatorID)
		}
		revised, err := cfg.Repair.ReviseCertenProofAnchor(ctx, proof.ProofID, proof.ProofHash, database.CertenAnchorRevision{
			Chain: database.TargetChain(facts.TargetChain), BlockNumber: facts.BlockNumber, BlockHash: facts.BlockHash,
			Confirmations: facts.Depth, TxHash: facts.TxHash,
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
		got, err := ReadAnchorTxFrom(ctx, c, chainID, txHash)
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

// rpcTransaction is the part of eth_getTransactionByHash the reading needs besides the signed transaction:
// the block it was mined in, which ethclient's TransactionByHash does not return, and the sender the
// endpoint states, which is only compared with the one recovered from the signature.
type rpcTransaction struct {
	BlockNumber *hexutil.Big    `json:"blockNumber"`
	BlockHash   *common.Hash    `json:"blockHash"`
	From        *common.Address `json:"from"`
}

// signedTransaction decodes an eth_getTransactionByHash result into the transaction that was signed and
// returns it with its signer. It is accepted only when it hashes to want - so its calldata, destination
// and signature are the transaction's own, not an endpoint's paraphrase - and was signed for chainID;
// the signer is recovered from the signature and must be the sender the endpoint states (RB3-F127).
func signedTransaction(raw json.RawMessage, chainID int64, want common.Hash) (*types.Transaction, common.Address, error) {
	var tx types.Transaction
	if err := tx.UnmarshalJSON(raw); err != nil {
		return nil, common.Address{}, fmt.Errorf("transaction %s does not decode as a signed transaction: %w", want.Hex(), err)
	}
	if tx.Hash() != want {
		return nil, common.Address{}, fmt.Errorf("the endpoint's transaction for %s hashes to %s", want.Hex(), tx.Hash().Hex())
	}
	if !tx.Protected() || tx.ChainId() == nil || tx.ChainId().Cmp(big.NewInt(chainID)) != 0 {
		return nil, common.Address{}, fmt.Errorf("transaction %s is signed for chain %v, not %d", want.Hex(), tx.ChainId(), chainID)
	}
	from, err := types.Sender(types.LatestSignerForChainID(big.NewInt(chainID)), &tx)
	if err != nil {
		return nil, common.Address{}, fmt.Errorf("transaction %s: recovering its signer: %w", want.Hex(), err)
	}
	var stated rpcTransaction
	if err := json.Unmarshal(raw, &stated); err != nil {
		return nil, common.Address{}, fmt.Errorf("transaction %s: %w", want.Hex(), err)
	}
	if stated.From == nil || *stated.From != from {
		return nil, common.Address{}, fmt.Errorf("transaction %s is signed by %s but the endpoint states sender %v",
			want.Hex(), from.Hex(), stated.From)
	}
	return &tx, from, nil
}

// ReadAnchorTxFrom reads a transaction, its receipt and the head from one endpoint. The receipt is taken
// by hash, or else from its block's receipts, which do not depend on a transaction index. An endpoint that
// returns the transaction but neither receipt does not hold that block's receipts; that is
// ethrpc.ErrEndpointLacksHistory, never "no such transaction".
func ReadAnchorTxFrom(ctx context.Context, c *ethclient.Client, chainID int64, txHash string) (*AnchorTxReading, error) {
	hash := common.HexToHash(txHash)
	var raw json.RawMessage
	if err := c.Client().CallContext(ctx, &raw, "eth_getTransactionByHash", hash); err != nil {
		return nil, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		// Unknown here. The pool asks the next provider; absent from every provider is reported by the
		// caller as unreadable, not as proven absent.
		return nil, fmt.Errorf("transaction %s: %w", txHash, ethrpc.ErrEndpointLacksHistory)
	}
	signed, from, err := signedTransaction(raw, chainID, hash)
	if err != nil {
		return nil, err
	}
	var tx rpcTransaction
	if err := json.Unmarshal(raw, &tx); err != nil {
		return nil, fmt.Errorf("transaction %s: %w", txHash, err)
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
	header, err := c.HeaderByHash(ctx, *tx.BlockHash)
	if err != nil {
		return nil, fmt.Errorf("header of block %d (%s): %w", block, tx.BlockHash.Hex(), err)
	}
	if header == nil || header.Number == nil || header.Number.Uint64() != block || header.Hash() != *tx.BlockHash || header.Time == 0 {
		return nil, fmt.Errorf("the header for block hash %s is not block %d", tx.BlockHash.Hex(), block)
	}
	head, err := c.BlockNumber(ctx)
	if err != nil {
		return nil, err
	}
	to := ""
	if signed.To() != nil {
		to = strings.ToLower(signed.To().Hex())
	}
	return &AnchorTxReading{
		Found: true, Succeeded: receipt.Status == types.ReceiptStatusSuccessful,
		BlockNumber: block, BlockHash: tx.BlockHash.Hex(), Head: head, Input: signed.Data(),
		From: strings.ToLower(from.Hex()), To: to, BlockTime: header.Time,
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
