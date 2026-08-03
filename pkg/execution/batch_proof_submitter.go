package execution

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

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

	// THE SIGNERS, not the roster.
	//
	// _verifyBLSProof does not take signedVotingPower on trust. It walks validatorAddresses,
	// looks each address up in the anchor's own registry, refuses unregistered entries,
	// duplicates and mis-declared powers, and then requires
	//
	//	blsProof.signedVotingPower == sum(registered power of validatorAddresses)
	//
	// Passing the full seven-validator roster here alongside a 600/700 signed power therefore
	// fails: the contract recomputes 700 and rejects. That is exactly what a 6-of-7 batch hit
	// live on 2026-08-02 — the aggregate and the ZK proof were both correct, and the submission
	// was rejected on the declared signer SET.
	//
	// The roster still reaches the contract, via totalVotingPower, which it compares against its
	// own stored total.
	validators := make([]common.Address, 0, len(agg.Signers))
	powers := make([]*big.Int, 0, len(agg.Signers))
	if len(agg.SignerPowers) != len(agg.Signers) {
		return fmt.Errorf("aggregate reports %d signers but %d powers; refusing to submit an "+
			"inconsistent signer set", len(agg.Signers), len(agg.SignerPowers))
	}
	for i, s := range agg.Signers {
		if !common.IsHexAddress(s) {
			return fmt.Errorf("signer %q is not an EVM address", s)
		}
		validators = append(validators, common.HexToAddress(s))
		powers = append(powers, new(big.Int).Set(agg.SignerPowers[i]))
	}
	total := agg.TotalVotingPower
	signed := agg.SignedVotingPower

	// Cheap local restatement of the contract's own rule, so a mismatch is caught here with a
	// clear message instead of as an opaque revert that costs the anchor gas.
	check := big.NewInt(0)
	for _, p := range powers {
		check.Add(check, p)
	}
	if check.Cmp(signed) != 0 {
		return fmt.Errorf("declared signed power %s does not equal the sum of the signers' "+
			"registered powers %s; the anchor would reject this", signed, check)
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

	// Governance material. The anchor rejects a zero keyBookRoot when minimumGovernanceLevel
	// >= 1, which is why every previous batch attestation reverted with a perfectly valid BLS
	// proof.
	keyBookRoot, keyPageProof, err := buildValidatorKeyPageProof(ecm.auth.From)
	if err != nil {
		return fmt.Errorf("building validator key page proof: %w", err)
	}

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
			KeyBookURL:         "certen:validator-set:v1",
			KeyBookRoot:        keyBookRoot,
			KeyPageProofs:      keyPageProof,
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
	ecm.nextNonce()
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

// NOTE: buildValidatorSetForBatch was REMOVED.
//
// It returned the full registered roster, which is the wrong thing to put in
// BLSProofData.validatorAddresses. The anchor treats that field as the set that SIGNED and
// recomputes signedVotingPower from it, so a roster paired with a partial signed power is
// rejected outright. The signer set now comes from QuorumAggregate.Signers/SignerPowers, which
// are derived from partials that actually verified.

// abiFromJSON parses a minimal inline ABI.
func abiFromJSON(j string) (abi.ABI, error) {
	return abi.JSON(strings.NewReader(j))
}

// buildValidatorKeyPageProof builds the governance material a batch attestation needs.
//
// CertenAnchorV8_1._verifyGovernanceProof requires it. With minimumGovernanceLevel >= 1 (it is
// 1 on the deployed anchor), a proof carrying a zero keyBookRoot is rejected outright:
//
//	} else if (minimumGovernanceLevel >= 1) {
//	    // G1+ requires governance proof material — reject if nothing provided
//	    return false;
//	}
//
// The batch submitter previously sent a zero root and empty proofs, so governanceVerified was
// false and executeComprehensiveProof reverted even though the BLS quorum, the ZK proof and
// every commitment were correct. Confirmed live 2026-08-02: calling the deployed Groth16
// verifier with the exact failing proof returned SUCCESS, which located the failure here.
//
// # WHAT THE ROOT COMMITS TO, AND WHY THIS ONE
//
// A batch has no single ADI, so there is no per-intent key book to prove against. The authority
// being asserted is the SUBMITTING VALIDATOR, and the meaningful statement is "this address is
// one of the registered validators". So the tree is built over the registered validator set —
// the same roster the anchor's own currentValidatorSetRoot commits to — and the proof is that
// validator's path to the root. A self-signed single-leaf tree would satisfy the check while
// proving nothing, which is why it is not used here.
//
// Hashing matches _verifyMerkleProof exactly: leaf = keccak256(abi.encodePacked(address)),
// internal nodes = keccak256 of the two children in ascending order.
func buildValidatorKeyPageProof(who common.Address) ([32]byte, [][32]byte, error) {
	var root [32]byte

	addrs, _, err := contracts.GetV6_1ValidatorSet()
	if err != nil {
		return root, nil, fmt.Errorf("validator set: %w", err)
	}
	if len(addrs) < 2 {
		// The contract refuses a non-zero root with an empty proof, so a single-leaf tree
		// cannot satisfy it — and would prove nothing anyway.
		return root, nil, fmt.Errorf("validator set has %d entries; need at least 2 to build a "+
			"key page tree the anchor will accept", len(addrs))
	}

	leaves := make([][32]byte, 0, len(addrs))
	idx := -1
	for _, a := range addrs {
		var leaf [32]byte
		copy(leaf[:], crypto.Keccak256(a.Bytes()))
		if a == who {
			idx = len(leaves)
		}
		leaves = append(leaves, leaf)
	}
	if idx < 0 {
		return root, nil, fmt.Errorf(
			"submitter %s is not in the registered validator set; it cannot prove key page "+
				"authority and the anchor would reject the attestation", who.Hex())
	}

	// Build bottom-up, carrying the position of our leaf so the sibling at each level is the
	// proof element. An odd node at any level is promoted unchanged.
	var proof [][32]byte
	level := leaves
	pos := idx
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				if pos == i {
					pos = len(next) - 1
				}
				continue
			}
			a, b := level[i], level[i+1]
			var node [32]byte
			if bytes.Compare(a[:], b[:]) < 0 {
				copy(node[:], crypto.Keccak256(a[:], b[:]))
			} else {
				copy(node[:], crypto.Keccak256(b[:], a[:]))
			}
			if pos == i {
				proof = append(proof, b)
				pos = len(next)
			} else if pos == i+1 {
				proof = append(proof, a)
				pos = len(next)
			}
			next = append(next, node)
		}
		level = next
	}
	root = level[0]

	// Self-check against the contract's algorithm before spending gas on it.
	computed := leaves[idx]
	for _, p := range proof {
		var node [32]byte
		if bytes.Compare(computed[:], p[:]) < 0 {
			copy(node[:], crypto.Keccak256(computed[:], p[:]))
		} else {
			copy(node[:], crypto.Keccak256(p[:], computed[:]))
		}
		computed = node
	}
	if computed != root {
		return root, nil, fmt.Errorf("internal error: key page proof does not reproduce its own root")
	}
	return root, proof, nil
}
