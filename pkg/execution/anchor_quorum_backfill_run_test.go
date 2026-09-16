package execution

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

type fakeBackfillStore struct {
	existing map[string]*database.AnchorQuorumRow
	written  []*database.AnchorQuorumRecord
	conflict bool
	getErr   error
}

func (f *fakeBackfillStore) GetAnchorQuorum(_ context.Context, chainID int64, bundleID string) (*database.AnchorQuorumRow, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.existing[fmt.Sprintf("%d/%s", chainID, bundleID)], nil
}

func (f *fakeBackfillStore) RecordAnchorQuorum(_ context.Context, rec *database.AnchorQuorumRecord) (bool, error) {
	if f.conflict {
		return false, &database.AnchorQuorumConflict{
			ChainID: rec.ChainID, BundleID: rec.BundleID,
			StoredRoot: "0xstored", IncomingRoot: "0xincoming",
		}
	}
	f.written = append(f.written, rec)
	return true, nil
}

func backfillFixture(t *testing.T) (*fakeBackfillChain, []BackfillCandidate) {
	t.Helper()
	return &fakeBackfillChain{
			input: []byte("calldata"), block: 100, success: true,
			state: bfState(), registry: bfRegistry(t),
		}, []BackfillCandidate{
			{ChainID: backfillChainID, TxHash: "0xverify"},
		}
}

// A dry run must read the chain, verify everything, and write NOTHING.
func TestBackfillDryRunWritesNothing(t *testing.T) {
	chain, cands := backfillFixture(t)
	store := &fakeBackfillStore{}
	call := bfCall(t)

	rep, err := runWithDecoder(t, chain, store, cands, call, AnchorQuorumBackfillOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(store.written) != 0 {
		t.Fatalf("a dry run wrote %d row(s)", len(store.written))
	}
	if rep.WouldWrite != 1 || rep.Written != 0 {
		t.Fatalf("report: would-write=%d written=%d", rep.WouldWrite, rep.Written)
	}
}

func TestBackfillWritesWhenAskedTo(t *testing.T) {
	chain, cands := backfillFixture(t)
	store := &fakeBackfillStore{}

	rep, err := runWithDecoder(t, chain, store, cands, bfCall(t), AnchorQuorumBackfillOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Written != 1 || len(store.written) != 1 {
		t.Fatalf("written=%d rows=%d", rep.Written, len(store.written))
	}
	if store.written[0].EvidenceSource != "chain_backfill" {
		t.Fatalf("evidence_source = %q", store.written[0].EvidenceSource)
	}
}

// A bundle that already has a row — in particular a LIVE one, which carries the members and the
// aggregate a backfill cannot recover — must be left exactly as it is.
func TestBackfillNeverTouchesAnExistingCanonicalRow(t *testing.T) {
	chain, cands := backfillFixture(t)
	call := bfCall(t)
	key := fmt.Sprintf("%d/0x%x", backfillChainID, call.BundleID)
	store := &fakeBackfillStore{existing: map[string]*database.AnchorQuorumRow{
		key: {ChainID: backfillChainID, EvidenceSource: "live", MemberCount: 3},
	}}

	rep, err := runWithDecoder(t, chain, store, cands, call, AnchorQuorumBackfillOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(store.written) != 0 {
		t.Fatal("a backfill overwrote live evidence")
	}
	if rep.AlreadyCanonical != 1 {
		t.Fatalf("already-canonical=%d", rep.AlreadyCanonical)
	}
}

// A conflict is reported, never resolved.
func TestBackfillSurfacesAConflictWithoutRetrying(t *testing.T) {
	chain, cands := backfillFixture(t)
	store := &fakeBackfillStore{conflict: true}

	rep, err := runWithDecoder(t, chain, store, cands, bfCall(t), AnchorQuorumBackfillOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Conflicts != 1 || rep.Written != 0 {
		t.Fatalf("conflicts=%d written=%d", rep.Conflicts, rep.Written)
	}
}

// A refused candidate is counted and explained, and does not stop the run.
func TestBackfillRefusalIsReportedAndTheRunContinues(t *testing.T) {
	chain := &fakeBackfillChain{
		input: []byte("calldata"), block: 100, success: true,
		state: bfState(), registry: bfRegistry(t),
	}
	chain.state.ProofExecuted = false
	store := &fakeBackfillStore{}

	rep, err := runWithDecoder(t, chain, store,
		[]BackfillCandidate{{ChainID: backfillChainID, TxHash: "0xa"}, {ChainID: backfillChainID, TxHash: "0xb"}},
		bfCall(t), AnchorQuorumBackfillOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Candidates != 2 || rep.Rejected != 2 {
		t.Fatalf("candidates=%d rejected=%d", rep.Candidates, rep.Rejected)
	}
	if len(rep.Refusals) != 2 || !strings.Contains(rep.Refusals[0], "proofExecuted=false") {
		t.Fatalf("refusals: %v", rep.Refusals)
	}
	if len(store.written) != 0 {
		t.Fatal("a refused candidate was written")
	}
}

func TestBackfillHonoursLimit(t *testing.T) {
	chain, _ := backfillFixture(t)
	store := &fakeBackfillStore{}
	cands := []BackfillCandidate{
		{ChainID: backfillChainID, TxHash: "0xa"},
		{ChainID: backfillChainID, TxHash: "0xb"},
		{ChainID: backfillChainID, TxHash: "0xc"},
	}
	rep, err := runWithDecoder(t, chain, store, cands, bfCall(t), AnchorQuorumBackfillOptions{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Candidates != 1 {
		t.Fatalf("limit ignored: examined %d", rep.Candidates)
	}
}

// runWithDecoder runs the backfill with an injected decoder, so the runner's control flow is testable
// without packing calldata for every case. Decoding itself is covered by the round-trip test.
func runWithDecoder(
	t *testing.T,
	chain BackfillChain,
	store anchorQuorumStore,
	cands []BackfillCandidate,
	call *DecodedVerifyCall,
	opts AnchorQuorumBackfillOptions,
) (*AnchorQuorumBackfillReport, error) {
	t.Helper()
	opts.Pause = 0
	opts.Logf = t.Logf

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// RunAnchorQuorumBackfill uses the real decoder, so the fake chain must return real calldata: the
	// runner is exercised over the same decode path production takes.
	if f, ok := chain.(*fakeBackfillChain); ok {
		f.input = packCallForTest(t, call)
	}
	return RunAnchorQuorumBackfill(ctx, chain, store, cands, opts)
}

// packCallForTest encodes a DecodedVerifyCall as the submitter would send it.
func packCallForTest(t *testing.T, call *DecodedVerifyCall) []byte {
	t.Helper()
	parsed, err := contracts.CertenAnchorV4MetaData.GetAbi()
	if err != nil {
		t.Fatalf("anchor ABI: %v", err)
	}
	validators := make([]common.Address, 0, len(call.Signers))
	for _, s := range call.Signers {
		validators = append(validators, common.HexToAddress(s))
	}
	proof := contracts.CertenAnchorV4CertenProof{
		TransactionHash: call.BundleID,
		MerkleRoot:      call.MerkleRoot,
		ProofHashes:     [][32]byte{},
		GovernanceProof: contracts.CertenAnchorV4GovernanceProofData{
			KeyBookURL:         "certen:validator-set:v1",
			KeyPageProofs:      [][32]byte{},
			Nonce:              big.NewInt(1),
			RequiredSignatures: big.NewInt(1),
			ProvidedSignatures: big.NewInt(1),
		},
		BlsProof: contracts.CertenAnchorV4BLSProofData{
			AggregateSignature: []byte{0x01},
			ValidatorAddresses: validators,
			VotingPowers:       call.SignerPowers,
			TotalVotingPower:   call.TotalVotingPower,
			SignedVotingPower:  call.SignedVotingPower,
			MessageHash:        call.MessageHash,
		},
		Commitments: contracts.CertenAnchorV4CommitmentData{
			OperationCommitment: call.OperationID,
			ExecutionCommitment: call.MerkleRoot,
			SourceChain:         "accumulate",
			SourceBlockHeight:   big.NewInt(0),
			SourceTxHash:        call.BundleID,
			TargetChain:         "evm-84532",
		},
		ExpirationTime: big.NewInt(0),
	}
	packed, err := parsed.Pack("executeComprehensiveProof", call.BundleID, proof)
	if err != nil {
		t.Fatalf("packing: %v", err)
	}
	return packed
}
