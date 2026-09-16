package execution

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// Reconstructing anchor quorum evidence from the chain.
//
// Anchors proven before this code existed left no canonical row, but they did leave the
// executeComprehensiveProof transaction that proved them, and the anchor state that transaction wrote.
// Both are readable, so the rows can be rebuilt without inventing anything.
//
// # WHAT VERIFIES THE AGGREGATE, AND WHAT THIS TOOL VERIFIES
//
// The raw 48-byte BLS aggregate is NOT in the calldata. BLSProofData.aggregateSignature carries the
// Groth16 blob proven against the aggregate public key (see SubmitBatchQuorumProof), and the anchor
// verifies that blob — against its own authorized-pubkey commitments, its own registry, and the message
// it reconstructs itself — as a precondition of setting proofExecuted. So the aggregate signature is
// verified on-chain, by the contract, and a backfill cannot re-run that pairing offline from calldata.
//
// What this tool does, therefore, is establish that the on-chain verification is the one being recorded:
//
//  1. the transaction succeeded (receipt status 1);
//  2. the anchor's own state says valid AND proofExecuted for that bundle;
//  3. the root and operation id recorded come from ANCHOR STATE, not from the calldata that claimed them;
//  4. the message hash the proof carried equals the message recomputed here from (chain id, bundle id,
//     root, operation id, validator-set root) — the binding that makes the on-chain signature check a
//     statement about THIS batch and no other;
//  5. every declared signer is registered on-chain with exactly the declared power, none repeated;
//  6. the declared signed power equals the sum of those registered powers, and the declared total equals
//     the registry's total — the same arithmetic _verifyBLSProof applies;
//  7. the signed power actually meets the 2/3 threshold.
//
// A candidate failing any of these is reported and skipped. A backfilled row is labelled
// evidence_source='chain_backfill' and carries no aggregate signature bytes, because the bytes the
// transaction carried are a ZK proof and writing them into a column named aggregated_signature would be
// the same class of mislabelling this whole change exists to remove.

// BackfillCandidate is one verify transaction to examine.
type BackfillCandidate struct {
	ChainID int64
	TxHash  string
}

// BackfillOutcome is what examining one candidate established.
type BackfillOutcome struct {
	Candidate BackfillCandidate
	// Record is non-nil only when every check passed.
	Record *database.AnchorQuorumRecord
	// Rejected names the check that failed, for the dry-run report. Empty when the candidate passed.
	Rejected string
	// Err is an access failure (RPC, decode plumbing) rather than a verdict about the candidate.
	Err error
}

// AnchorOnChainState is the anchor's own record of a bundle, read from `anchors(bytes32)`.
type AnchorOnChainState struct {
	MerkleRoot          [32]byte
	OperationCommitment [32]byte
	ExecutionCommitment [32]byte
	Timestamp           time.Time
	Valid               bool
	ProofExecuted       bool
}

// BackfillChain is the chain access the reconstruction needs. Satisfied by the live EVM stack; an
// interface so every verification rule above is testable without an RPC endpoint.
type BackfillChain interface {
	// VerifyTransaction returns the calldata, block number and success flag of a mined transaction.
	VerifyTransaction(ctx context.Context, chainID int64, txHash string) (input []byte, blockNumber uint64, success bool, err error)
	// AnchorState reads the anchor's own record of a bundle.
	AnchorState(ctx context.Context, chainID int64, bundleID [32]byte) (AnchorOnChainState, error)
	// ValidatorRegistry returns the anchor's registry, keyed by lowercased EVM address.
	ValidatorRegistry(ctx context.Context, chainID int64) (map[string]consensus.ValidatorRegistryEntry, error)
	// BlockTime returns the timestamp of a block, used as consensus_completed_at.
	BlockTime(ctx context.Context, chainID int64, blockNumber uint64) (time.Time, error)
}

// DecodedVerifyCall is what an executeComprehensiveProof calldata blob asserts about a quorum.
//
// Every field here is an ASSERTION by the transaction's sender. None of it is written to the database
// without a matching fact from anchor state or the on-chain registry.
type DecodedVerifyCall struct {
	BundleID          [32]byte
	MerkleRoot        [32]byte
	OperationID       [32]byte
	MessageHash       [32]byte
	Signers           []string
	SignerPowers      []*big.Int
	SignedVotingPower *big.Int
	TotalVotingPower  *big.Int
}

// ReconstructAnchorQuorum examines one verify transaction and returns a record only if the chain
// supports every part of it.
func ReconstructAnchorQuorum(
	ctx context.Context,
	chain BackfillChain,
	cand BackfillCandidate,
	decode func([]byte) (*DecodedVerifyCall, error),
) BackfillOutcome {
	out := BackfillOutcome{Candidate: cand}

	input, blockNumber, success, err := chain.VerifyTransaction(ctx, cand.ChainID, cand.TxHash)
	if err != nil {
		out.Err = fmt.Errorf("reading %s: %w", cand.TxHash, err)
		return out
	}
	if !success {
		out.Rejected = "the verify transaction reverted"
		return out
	}

	call, err := decode(input)
	if err != nil {
		out.Rejected = fmt.Sprintf("calldata is not an executeComprehensiveProof call: %v", err)
		return out
	}

	state, err := chain.AnchorState(ctx, cand.ChainID, call.BundleID)
	if err != nil {
		out.Err = fmt.Errorf("reading anchor state for 0x%x: %w", call.BundleID[:8], err)
		return out
	}

	registry, err := chain.ValidatorRegistry(ctx, cand.ChainID)
	if err != nil {
		out.Err = fmt.Errorf("reading validator registry: %w", err)
		return out
	}

	if err := VerifyBackfilledQuorum(cand.ChainID, call, state, registry); err != nil {
		out.Rejected = err.Error()
		return out
	}

	verifiedAt, err := chain.BlockTime(ctx, cand.ChainID, blockNumber)
	if err != nil || verifiedAt.IsZero() {
		// The quorum is established; only the block's clock is not. Fall back to the anchor's own
		// timestamp rather than to now(), which would assert a completion time that never happened.
		verifiedAt = state.Timestamp
	}

	signers := make([]database.AnchorQuorumSigner, 0, len(call.Signers))
	for i, addr := range call.Signers {
		signers = append(signers, database.AnchorQuorumSigner{
			Address:     strings.ToLower(addr),
			VotingPower: new(big.Int).Set(call.SignerPowers[i]),
		})
	}

	// Everything below comes from anchor STATE where state has it, and from the (now verified) call only
	// where the chain does not store it.
	out.Record = &database.AnchorQuorumRecord{
		ChainID:          cand.ChainID,
		BundleID:         hexPrefixed(call.BundleID[:]),
		Root:             append([]byte(nil), state.MerkleRoot[:]...),
		BatchOperationID: hexPrefixed(state.OperationCommitment[:]),
		MessageHash:      hexPrefixed(call.MessageHash[:]),
		VerifyTx:         cand.TxHash,
		VerifyBlock:      int64(blockNumber),
		VerifiedAt:       verifiedAt,
		// The anchor-create transaction is a DIFFERENT transaction and is not named in this calldata, so
		// it stays empty rather than being filled with this one. Conflating the two is precisely what
		// published the false layer-5 binding.
		AnchorCreateTx: "",
		// No aggregate bytes: see the header. The signature was verified by the anchor, not here.
		AggregateSignature: nil,
		AggregatePubKey:    nil,
		Signers:            signers,
		SignedVotingPower:  new(big.Int).Set(call.SignedVotingPower),
		TotalVotingPower:   new(big.Int).Set(call.TotalVotingPower),
		// Membership is not in the calldata: an anchor commits to a root, not to a member list. A
		// backfilled row therefore carries the quorum but no members, and reports as much.
		Members:        nil,
		Lane:           "",
		EvidenceSource: "chain_backfill",
		TargetChain:    chainName(cand.ChainID),
	}
	return out
}

// VerifyBackfilledQuorum applies checks 2–7 from the header: anchor state, the message binding, and the
// registry arithmetic. This is what makes a backfill a projection of the chain rather than a copy of a
// stranger's calldata.
func VerifyBackfilledQuorum(
	chainID int64,
	call *DecodedVerifyCall,
	state AnchorOnChainState,
	registry map[string]consensus.ValidatorRegistryEntry,
) error {
	if call == nil {
		return fmt.Errorf("no decoded call")
	}

	// 2. The anchor's own verdict. A mined transaction is not an attested anchor.
	if !state.Valid {
		return fmt.Errorf("anchor state reports valid=false")
	}
	if !state.ProofExecuted {
		return fmt.Errorf("anchor state reports proofExecuted=false")
	}
	if state.MerkleRoot == ([32]byte{}) {
		return fmt.Errorf("anchor state holds no merkle root")
	}

	// 3. The calldata must agree with anchor state; the row records state either way.
	if call.MerkleRoot != state.MerkleRoot {
		return fmt.Errorf("calldata root 0x%x is not the anchor's stored root 0x%x",
			call.MerkleRoot[:8], state.MerkleRoot[:8])
	}
	if call.OperationID != state.OperationCommitment {
		return fmt.Errorf("calldata operation id 0x%x is not the anchor's operation commitment 0x%x",
			call.OperationID[:8], state.OperationCommitment[:8])
	}

	// 5/6. The signer set, against the registry.
	if len(call.Signers) == 0 {
		return fmt.Errorf("no signers declared")
	}
	if len(call.SignerPowers) != len(call.Signers) {
		return fmt.Errorf("%d signers but %d powers", len(call.Signers), len(call.SignerPowers))
	}
	signedSum := big.NewInt(0)
	seen := make(map[string]bool, len(call.Signers))
	for i, addr := range call.Signers {
		if !common.IsHexAddress(addr) {
			return fmt.Errorf("signer %q is not an EVM address", addr)
		}
		key := strings.ToLower(addr)
		if seen[key] {
			return fmt.Errorf("signer %s appears twice", key)
		}
		seen[key] = true

		entry, ok := registry[key]
		if !ok {
			return fmt.Errorf("signer %s is not in the on-chain validator registry", key)
		}
		if call.SignerPowers[i] == nil {
			return fmt.Errorf("signer %s declares no power", key)
		}
		if entry.VotingPower == nil || entry.VotingPower.Cmp(call.SignerPowers[i]) != 0 {
			return fmt.Errorf("signer %s declares power %s but the registry says %v",
				key, call.SignerPowers[i], entry.VotingPower)
		}
		signedSum.Add(signedSum, entry.VotingPower)
	}
	if call.SignedVotingPower == nil || signedSum.Cmp(call.SignedVotingPower) != 0 {
		return fmt.Errorf("declared signed power %v does not equal the registry sum %s",
			call.SignedVotingPower, signedSum)
	}

	registryTotal := big.NewInt(0)
	for _, e := range registry {
		if e.VotingPower != nil {
			registryTotal.Add(registryTotal, e.VotingPower)
		}
	}
	if call.TotalVotingPower == nil || registryTotal.Cmp(call.TotalVotingPower) != 0 {
		return fmt.Errorf("declared total power %v does not equal the registry total %s",
			call.TotalVotingPower, registryTotal)
	}

	// 7. The threshold, recomputed rather than believed.
	lhs := new(big.Int).Mul(call.SignedVotingPower, big.NewInt(batchQuorumThresholdDen))
	rhs := new(big.Int).Mul(call.TotalVotingPower, big.NewInt(batchQuorumThresholdNum))
	if lhs.Cmp(rhs) < 0 {
		return fmt.Errorf("signed power %s does not meet the %d/%d threshold of %s",
			call.SignedVotingPower, batchQuorumThresholdNum, batchQuorumThresholdDen, call.TotalVotingPower)
	}

	// 4. The message binding, recomputed HERE from the anchor's own identity fields. A proof over an
	//    attacker-chosen message proves nothing; this is what ties the on-chain verification to THIS batch.
	setRoot, err := contracts.GetV6_1ValidatorSetRoot()
	if err != nil {
		return fmt.Errorf("validator-set root: %w", err)
	}
	want := contracts.ComputeEvmMessageHashV6_1_Pre(
		chainID, call.BundleID, state.MerkleRoot, state.OperationCommitment, setRoot,
	)
	if call.MessageHash != want {
		return fmt.Errorf(
			"the proof's message 0x%x is not the message this batch commits to (0x%x); the on-chain "+
				"signature check was about something else",
			call.MessageHash[:8], want[:8])
	}
	return nil
}
