package execution

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// Batch proof submitter
// =============================================================================
//
// Submits executeComprehensiveProof for a BATCH anchor, carrying a quorum aggregate produced
// by consensus.AggregateBatchAttestations. The proof struct it builds must
// satisfy every gate in CertenAnchorV7._verifyAllComponents; each field below is set to the
// specific value that gate requires, and the reason is stated where it is non-obvious.

// EVMChainResolver hands the submitter the per-chain contract manager and anchor address.
// Kept narrow so the submitter does not have to know how chains are configured.
type EVMChainResolver interface {
	ManagerForChain(chainID int64) (*EthereumContractManager, common.Address, error)
}

// BatchProofSubmitterImpl submits batch attestations across chains.
type BatchProofSubmitterImpl struct {
	chains EVMChainResolver
	logf   func(string, ...interface{})
}

// NewBatchProofSubmitter builds a submitter.
func NewBatchProofSubmitter(chains EVMChainResolver, logf func(string, ...interface{})) *BatchProofSubmitterImpl {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	return &BatchProofSubmitterImpl{chains: chains, logf: logf}
}

// BatchOperationID reads the batch operationID the anchor actually stored.
//
// Read from chain rather than recomputed: it is what the contract will feed into the BLS
// message, so reading it removes any chance of the validator signing over a value the
// contract disagrees with.
func (s *BatchProofSubmitterImpl) BatchOperationID(
	ctx context.Context,
	chainID int64,
	bundleID [32]byte,
) ([32]byte, error) {
	ecm, anchorAddr, err := s.chains.ManagerForChain(chainID)
	if err != nil {
		return [32]byte{}, err
	}
	return s.batchOperationIDViaV7(ctx, anchorAddr, ecm, bundleID)
}

func (s *BatchProofSubmitterImpl) batchOperationIDViaV7(
	ctx context.Context,
	anchorAddr common.Address,
	ecm *EthereumContractManager,
	bundleID [32]byte,
) ([32]byte, error) {
	// Read operationID out of the public `anchors` mapping getter.
	//
	// This used to call getOperationID(bytes32), described in the old comment as "the explicit
	// V6.1 view". It IS a V6.1 view — and it was never carried into V7/V8/V8_1. On those
	// anchors the selector matches nothing, so the call hit the fallback and reverted with
	// empty return data. The flush loop had already MINED the batch anchor by that point, so
	// every cadence flush paid for an anchor and then failed on the very next read:
	//
	//	quorum attestation over batch root failed: reading batch operationID: execution reverted
	//
	// The struct getter is the portable route: `mapping(bytes32 => Anchor) public anchors`
	// flattens Anchor into a tuple, and operationID is field index 7. The ordering below is
	// transcribed from CertenAnchorV8_1.sol and is asserted against the DEPLOYED contract by
	// TestAnchorsTupleLayoutMatchesDeployedContract — if a future anchor reorders these
	// fields, that test fails rather than this silently decoding the wrong 32 bytes.
	const operationIDFieldIndex = 7

	parsed, err := abiFromJSON(anchorsABIJSON)
	if err != nil {
		return [32]byte{}, err
	}
	bound := bind.NewBoundContract(anchorAddr, parsed, ecm.client, ecm.client, ecm.client)
	var out []interface{}
	if err := bound.Call(&bind.CallOpts{Context: ctx}, &out, "anchors", bundleID); err != nil {
		return [32]byte{}, fmt.Errorf("reading batch operationID: %w", err)
	}
	if len(out) <= operationIDFieldIndex {
		return [32]byte{}, fmt.Errorf(
			"anchors() returned %d fields, need at least %d — the Anchor struct layout changed",
			len(out), operationIDFieldIndex+1)
	}
	v, ok := out[operationIDFieldIndex].([32]byte)
	if !ok {
		return [32]byte{}, fmt.Errorf("anchors().operationID returned unexpected type %T", out[operationIDFieldIndex])
	}
	if v == ([32]byte{}) {
		return [32]byte{}, fmt.Errorf("anchor 0x%x has a zero operationID — not a batch anchor?", bundleID[:8])
	}
	return v, nil
}

// anchorsABIJSON is the `mapping(bytes32 => Anchor) public anchors` getter, transcribed field
// for field from CertenAnchorV8_1.sol. Shared with the layout test so both read one source of
// truth; TestAnchorsTupleLayoutMatchesDeployedContract checks it against a DEPLOYED anchor.
const anchorsABIJSON = `[{"type":"function","name":"anchors","inputs":[{"name":"","type":"bytes32"}],"outputs":[` +
	`{"name":"bundleId","type":"bytes32"},` +
	`{"name":"merkleRoot","type":"bytes32"},` +
	`{"name":"adiURLHash","type":"bytes32"},` +
	`{"name":"operationCommitment","type":"bytes32"},` +
	`{"name":"crossChainCommitment","type":"bytes32"},` +
	`{"name":"governanceRoot","type":"bytes32"},` +
	`{"name":"executionCommitment","type":"bytes32"},` +
	`{"name":"operationID","type":"bytes32"},` +
	`{"name":"accumulateBlockHeight","type":"uint256"},` +
	`{"name":"timestamp","type":"uint256"},` +
	`{"name":"validator","type":"address"},` +
	`{"name":"valid","type":"bool"},` +
	`{"name":"proofExecuted","type":"bool"},` +
	`{"name":"governanceExecuted","type":"bool"},` +
	`{"name":"governanceLevel","type":"uint8"}` +
	`],"stateMutability":"view"}]`

// AnchorProofExecuted reports whether the quorum attestation has landed.
func (s *BatchProofSubmitterImpl) AnchorProofExecuted(
	ctx context.Context,
	chainID int64,
	bundleID [32]byte,
) (bool, error) {
	ecm, anchorAddr, err := s.chains.ManagerForChain(chainID)
	if err != nil {
		return false, err
	}
	const abiJSON = `[{"type":"function","name":"anchors","inputs":[{"name":"","type":"bytes32"}],"outputs":[
		{"name":"bundleId","type":"bytes32"},{"name":"merkleRoot","type":"bytes32"},
		{"name":"adiURLHash","type":"bytes32"},{"name":"operationCommitment","type":"bytes32"},
		{"name":"crossChainCommitment","type":"bytes32"},{"name":"governanceRoot","type":"bytes32"},
		{"name":"executionCommitment","type":"bytes32"},{"name":"operationID","type":"bytes32"},
		{"name":"accumulateBlockHeight","type":"uint256"},{"name":"timestamp","type":"uint256"},
		{"name":"validator","type":"address"},{"name":"valid","type":"bool"},
		{"name":"proofExecuted","type":"bool"},{"name":"governanceExecuted","type":"bool"},
		{"name":"governanceLevel","type":"uint8"}],"stateMutability":"view"}]`
	parsed, err := abiFromJSON(abiJSON)
	if err != nil {
		return false, err
	}
	bound := bind.NewBoundContract(anchorAddr, parsed, ecm.client, ecm.client, ecm.client)
	var out []interface{}
	if err := bound.Call(&bind.CallOpts{Context: ctx}, &out, "anchors", bundleID); err != nil {
		return false, fmt.Errorf("reading anchor: %w", err)
	}
	if len(out) < 13 {
		return false, fmt.Errorf("anchors returned %d fields, expected 15", len(out))
	}
	executed, ok := out[12].(bool)
	if !ok {
		return false, fmt.Errorf("proofExecuted field has unexpected type")
	}
	return executed, nil
}

// SubmitBatchQuorumProof submits the quorum attestation over a batch root.
//
// Every field is chosen to satisfy a specific gate in CertenAnchorV7._verifyAllComponents:
//
//   - MerkleRoot          must equal anchor.merkleRoot (executeComprehensiveProof requires it
//     explicitly before any component check runs).
//   - ProofHashes         unused for a batch: the batch branch of _verifyAllComponents
//     re-derives bundleId from stored state instead of walking a path,
//     so nothing here can influence the outcome.
//   - Commitments.OperationCommitment must equal the anchor's operationID — the V7 rule that
//     makes usedCommitments replay protection meaningful per batch.
//   - Commitments.ExecutionCommitment must equal batchRoot, which is what createBatchAnchor
//     stored in that slot.
//   - BlsProof.MessageHash must equal the six-field V6.1 pre-exec message the contract
//     reconstructs; the quorum computed and signed exactly that.
//
// # THE TWO FIELDS THAT MUST COME FROM THE AGGREGATE, NOT FROM CONFIG
//
// AggregateSignature carries the abi-encoded Groth16 blob, not the raw 48-byte BLS signature.
// The anchor's BLSZKVerifierV2 path expects the blob; submitting the raw signature is what
// produced the live `blsVerified: false, reason: "BLS signature verification failed"` on
// Sepolia, and it is also what kept the earlier single-signer bug failing safe.
//
// SignedVotingPower is agg.SignedVotingPower — the sum of the registered power of validators
// whose partials ACTUALLY verified. The previous code passed the full total here regardless of
// who signed. Combined with the ZK blob that would have been a quorum forgery: a proof
// asserting 700/700 from however many keys happened to answer. The pubkey commitment derived
// inside the blob is checked against the anchor's 29 authorized subsets, so an honest
// SignedVotingPower and an honest aggregate key must agree — passing the total here breaks that
// agreement in the one direction the chain cannot detect from the arithmetic alone.
func (s *BatchProofSubmitterImpl) SubmitBatchQuorumProof(
	ctx context.Context,
	chainID int64,
	bundleID [32]byte,
	batchRoot [32]byte,
	batchOperationID [32]byte,
	agg *consensus.QuorumAggregate,
	messageHash [32]byte,
) error {
	if agg == nil {
		return fmt.Errorf("nil quorum aggregate; refusing to submit an unattested batch root")
	}
	if agg.SignedVotingPower == nil || agg.SignedVotingPower.Sign() <= 0 {
		return fmt.Errorf("quorum aggregate reports no signed voting power")
	}
	if len(agg.Signers) < 2 {
		// AggregateBatchAttestations already enforces threshold by power, so this is
		// belt-and-braces against a degenerate registry (e.g. a one-validator set slipping
		// into production config) producing a single-signer aggregate that the anchor's
		// authorized-subset commitments would reject anyway.
		return fmt.Errorf(
			"refusing to submit a %d-signer aggregate: the anchor's authorized pubkey "+
				"commitments cover subsets of 5, 6 and 7 only", len(agg.Signers))
	}

	ecm, anchorAddr, err := s.chains.ManagerForChain(chainID)
	if err != nil {
		return err
	}

	sigBytes, err := hex.DecodeString(strings.TrimPrefix(agg.AggregateSignatureHex, "0x"))
	if err != nil {
		return fmt.Errorf("decoding aggregate signature: %w", err)
	}
	if len(sigBytes) == 0 {
		return fmt.Errorf("empty aggregate signature")
	}

	validators, powers, _, err := buildValidatorSetForBatch()
	if err != nil {
		return err
	}
	total := agg.TotalVotingPower
	signed := agg.SignedVotingPower

	// The ZK blob. Proven against the AGGREGATE public key — the pairing only holds for the key
	// the aggregate signature actually verifies under, which is what AggregateBatchAttestations
	// returned after checking that very relation.
	zkProofBytes, pubkeyCommitment := ecm.generateBLSZKProof(
		sigBytes, messageHash, signed, total, agg.AggregatePublicKeyHex,
	)
	if len(zkProofBytes) == 0 {
		return fmt.Errorf(
			"BLS ZK proof generation returned nothing for anchor 0x%x; the anchor exists but "+
				"cannot be attested", bundleID[:8])
	}
	s.logf("[BATCH-PROOF] chain=%d zk proof %d bytes, pubkeyCommitment=0x%x, signed=%s/%s over %d signers",
		chainID, len(zkProofBytes), pubkeyCommitment[:8], signed, total, len(agg.Signers))

	proof := contracts.CertenAnchorV4CertenProof{
		TransactionHash: bundleID, // no single Accumulate tx for a batch; the id identifies it
		MerkleRoot:      batchRoot,
		ProofHashes:     [][32]byte{},
		LeafHash:        [32]byte{},
		GovernanceProof: contracts.CertenAnchorV4GovernanceProofData{
			KeyBookURL:         "",
			KeyBookRoot:        [32]byte{},
			KeyPageProofs:      [][32]byte{},
			AuthorityAddress:   ecm.auth.From,
			AuthorityLevel:     2, // G2 — batches carry value-moving members
			Nonce:              new(big.Int).SetBytes(bundleID[24:]),
			RequiredSignatures: big.NewInt(1),
			ProvidedSignatures: big.NewInt(1),
			ThresholdMet:       true,
		},
		BlsProof: contracts.CertenAnchorV4BLSProofData{
			// The Groth16 blob, NOT sigBytes. The raw aggregate is the witness that produced it.
			AggregateSignature: zkProofBytes,
			ValidatorAddresses: validators,
			VotingPowers:       powers,
			TotalVotingPower:   total,
			SignedVotingPower:  signed,
			// Computed from the two values above, never asserted. Asserting it would let a
			// sub-threshold aggregate claim compliance the arithmetic does not support.
			ThresholdMet: new(big.Int).Mul(signed, big.NewInt(batchQuorumThresholdDen)).
				Cmp(new(big.Int).Mul(total, big.NewInt(batchQuorumThresholdNum))) >= 0,
			MessageHash: messageHash,
		},
		Commitments: contracts.CertenAnchorV4CommitmentData{
			OperationCommitment:  batchOperationID, // V7 requires this exact value
			CrossChainCommitment: [32]byte{},
			GovernanceRoot:       [32]byte{},
			ExecutionCommitment:  batchRoot,
			SourceChain:          "accumulate",
			SourceBlockHeight:    big.NewInt(0),
			SourceTxHash:         bundleID,
			TargetChain:          fmt.Sprintf("evm-%d", chainID),
			TargetAddress:        anchorAddr,
		},
		ExpirationTime: big.NewInt(time.Now().Add(time.Hour).Unix()),
		Metadata:       []byte(fmt.Sprintf("batch:%d", chainID)),
	}

	s.logf("[BATCH-PROOF] chain=%d submitting attestation for anchor 0x%x root=0x%x msg=0x%x",
		chainID, bundleID[:8], batchRoot[:8], messageHash[:8])

	ecm.auth.GasLimit = 900000
	tx, err := ecm.anchor.ExecuteComprehensiveProofSimple(ecm.auth, bundleID, proof)
	if err != nil {
		return fmt.Errorf("executeComprehensiveProof: %w", err)
	}

	receipt, err := bind.WaitMined(ctx, ecm.client, tx)
	if err != nil {
		return fmt.Errorf("waiting for attestation tx %s: %w", tx.Hash().Hex(), err)
	}
	if receipt.Status == 0 {
		return fmt.Errorf("executeComprehensiveProof reverted (tx %s)", tx.Hash().Hex())
	}

	s.logf("[BATCH-PROOF] chain=%d attestation mined tx=%s gas=%d",
		chainID, tx.Hash().Hex(), receipt.GasUsed)
	return nil
}

// buildValidatorSetForBatch returns the REGISTERED validator roster and its total power.
//
// Sourced from contracts.GetV6_1ValidatorSet — the SAME place the validator-set root comes
// from. Deriving these independently would let the roster submitted on-chain drift from the
// one the signed setRoot commits to.
//
// It deliberately does NOT return a signed power. It used to, and it returned the total: every
// batch declared a full 7-of-7 quorum no matter who signed. Signed power is a property of the
// partials that verified, so it now comes from QuorumAggregate.SignedVotingPower and nowhere
// else.
func buildValidatorSetForBatch() ([]common.Address, []*big.Int, *big.Int, error) {
	addrs, powers, err := contracts.GetV6_1ValidatorSet()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("validator set: %w", err)
	}
	total := big.NewInt(0)
	for _, p := range powers {
		total = new(big.Int).Add(total, p)
	}
	return addrs, powers, total, nil
}

// abiFromJSON parses a minimal inline ABI.
func abiFromJSON(j string) (abi.ABI, error) {
	return abi.JSON(strings.NewReader(j))
}
