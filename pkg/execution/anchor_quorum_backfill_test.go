package execution

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// The backfill's whole job is to refuse. These tests are written from the attacker's side: each one
// submits a transaction that looks like a proven anchor and checks that exactly one missing fact is
// enough to keep it out of the database.

const backfillChainID = int64(84532)

func bfWord(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func bfAddr(n byte) string {
	var a common.Address
	a[19] = n
	return strings.ToLower(a.Hex())
}

// testRegistry is a 7-validator registry of 100 power each, as the lab fleet is.
func bfRegistry(t *testing.T) map[string]consensus.ValidatorRegistryEntry {
	t.Helper()
	reg := make(map[string]consensus.ValidatorRegistryEntry, 7)
	for i := byte(1); i <= 7; i++ {
		reg[bfAddr(i)] = consensus.ValidatorRegistryEntry{
			EVMAddress:  bfAddr(i),
			VotingPower: big.NewInt(100),
		}
	}
	return reg
}

func bfState() AnchorOnChainState {
	return AnchorOnChainState{
		MerkleRoot:          bfWord(0xaa),
		OperationCommitment: bfWord(0xbb),
		ExecutionCommitment: bfWord(0xaa),
		Timestamp:           time.Unix(1_757_000_000, 0).UTC(),
		Valid:               true,
		ProofExecuted:       true,
	}
}

// goodCall is a 5-of-7 proof over the message the anchor's own fields produce.
func bfCall(t *testing.T) *DecodedVerifyCall {
	t.Helper()
	st := bfState()
	setRoot, err := contracts.GetV6_1ValidatorSetRoot()
	if err != nil {
		t.Skipf("no validator-set root configured in this environment: %v", err)
	}
	signers := make([]string, 0, 5)
	powers := make([]*big.Int, 0, 5)
	for i := byte(1); i <= 5; i++ {
		signers = append(signers, bfAddr(i))
		powers = append(powers, big.NewInt(100))
	}
	return &DecodedVerifyCall{
		BundleID:    bfWord(0xcc),
		MerkleRoot:  st.MerkleRoot,
		OperationID: st.OperationCommitment,
		MessageHash: contracts.ComputeEvmMessageHashV6_1_Pre(
			backfillChainID, bfWord(0xcc), st.MerkleRoot, st.OperationCommitment, setRoot),
		Signers:           signers,
		SignerPowers:      powers,
		SignedVotingPower: big.NewInt(500),
		TotalVotingPower:  big.NewInt(700),
	}
}

func TestBackfillAcceptsAnAnchorTheChainActuallyProved(t *testing.T) {
	if err := VerifyBackfilledQuorum(backfillChainID, bfCall(t), bfState(), bfRegistry(t)); err != nil {
		t.Fatalf("a genuine anchor was refused: %v", err)
	}
}

func TestBackfillRefusals(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*DecodedVerifyCall, *AnchorOnChainState, map[string]consensus.ValidatorRegistryEntry)
		wantErr string
	}{
		{
			// The transaction mined, but the anchor does not consider itself attested.
			name: "anchor says proofExecuted=false",
			mutate: func(_ *DecodedVerifyCall, s *AnchorOnChainState, _ map[string]consensus.ValidatorRegistryEntry) {
				s.ProofExecuted = false
			},
			wantErr: "proofExecuted=false",
		},
		{
			name: "anchor says valid=false",
			mutate: func(_ *DecodedVerifyCall, s *AnchorOnChainState, _ map[string]consensus.ValidatorRegistryEntry) {
				s.Valid = false
			},
			wantErr: "valid=false",
		},
		{
			// THE INCIDENT SHAPE: calldata naming a root the anchor never stored. A row built from this
			// would publish a binding for a root nobody anchored — exactly the d2d24ab3 class of claim.
			name: "calldata root is not the anchor's stored root",
			mutate: func(c *DecodedVerifyCall, _ *AnchorOnChainState, _ map[string]consensus.ValidatorRegistryEntry) {
				c.MerkleRoot = bfWord(0xd2)
			},
			wantErr: "is not the anchor's stored root",
		},
		{
			name: "calldata operation id is not the anchor's commitment",
			mutate: func(c *DecodedVerifyCall, _ *AnchorOnChainState, _ map[string]consensus.ValidatorRegistryEntry) {
				c.OperationID = bfWord(0x99)
			},
			wantErr: "operation commitment",
		},
		{
			// A valid signature over a DIFFERENT batch, replayed onto this one.
			name: "message hash belongs to another batch",
			mutate: func(c *DecodedVerifyCall, _ *AnchorOnChainState, _ map[string]consensus.ValidatorRegistryEntry) {
				c.MessageHash = bfWord(0x77)
			},
			wantErr: "is not the message this batch commits to",
		},
		{
			name: "a signer is not registered on-chain",
			mutate: func(c *DecodedVerifyCall, _ *AnchorOnChainState, _ map[string]consensus.ValidatorRegistryEntry) {
				c.Signers[0] = bfAddr(9)
			},
			wantErr: "not in the on-chain validator registry",
		},
		{
			// Duplicating a signer to reach the threshold with fewer real validators.
			name: "a signer is counted twice",
			mutate: func(c *DecodedVerifyCall, _ *AnchorOnChainState, _ map[string]consensus.ValidatorRegistryEntry) {
				c.Signers[4] = c.Signers[0]
			},
			wantErr: "appears twice",
		},
		{
			name: "a signer declares more power than the registry grants",
			mutate: func(c *DecodedVerifyCall, _ *AnchorOnChainState, _ map[string]consensus.ValidatorRegistryEntry) {
				c.SignerPowers[0] = big.NewInt(400)
				c.SignedVotingPower = big.NewInt(800)
			},
			wantErr: "the registry says 100",
		},
		{
			// Four signers claiming five signers' worth of power.
			name: "signed power exceeds the signers' registered sum",
			mutate: func(c *DecodedVerifyCall, _ *AnchorOnChainState, _ map[string]consensus.ValidatorRegistryEntry) {
				c.Signers = c.Signers[:4]
				c.SignerPowers = c.SignerPowers[:4]
			},
			wantErr: "does not equal the registry sum",
		},
		{
			// Understating the total to make a minority look like a supermajority.
			name: "total power is understated",
			mutate: func(c *DecodedVerifyCall, _ *AnchorOnChainState, _ map[string]consensus.ValidatorRegistryEntry) {
				c.TotalVotingPower = big.NewInt(500)
			},
			wantErr: "does not equal the registry total",
		},
		{
			name: "honest but sub-threshold",
			mutate: func(c *DecodedVerifyCall, _ *AnchorOnChainState, _ map[string]consensus.ValidatorRegistryEntry) {
				c.Signers = c.Signers[:4]
				c.SignerPowers = c.SignerPowers[:4]
				c.SignedVotingPower = big.NewInt(400)
			},
			wantErr: "does not meet the 2/3 threshold",
		},
		{
			name: "no signers at all",
			mutate: func(c *DecodedVerifyCall, _ *AnchorOnChainState, _ map[string]consensus.ValidatorRegistryEntry) {
				c.Signers = nil
				c.SignerPowers = nil
			},
			wantErr: "no signers declared",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			call := bfCall(t)
			state := bfState()
			reg := bfRegistry(t)
			tc.mutate(call, &state, reg)

			err := VerifyBackfilledQuorum(backfillChainID, call, state, reg)
			if err == nil {
				t.Fatal("a candidate the chain does not support was accepted")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("refused for the wrong reason:\n got: %v\nwant substring: %s", err, tc.wantErr)
			}
		})
	}
}

// A signature covering another chain's copy of the same batch must not be reusable here.
func TestBackfillRefusesACrossChainReplay(t *testing.T) {
	call := bfCall(t)
	// The message was computed for base-sepolia; examine it as if it were sepolia's.
	if err := VerifyBackfilledQuorum(11155111, call, bfState(), bfRegistry(t)); err == nil {
		t.Fatal("a message bound to another chain id was accepted")
	}
}

// ---- The end-to-end shape, against a fake chain ----------------------------------------------

type fakeBackfillChain struct {
	input    []byte
	block    uint64
	success  bool
	state    AnchorOnChainState
	registry map[string]consensus.ValidatorRegistryEntry
	blockErr error
}

func (f *fakeBackfillChain) VerifyTransaction(_ context.Context, _ int64, _ string) ([]byte, uint64, bool, error) {
	return f.input, f.block, f.success, nil
}
func (f *fakeBackfillChain) AnchorState(_ context.Context, _ int64, _ [32]byte) (AnchorOnChainState, error) {
	return f.state, nil
}
func (f *fakeBackfillChain) ValidatorRegistry(_ context.Context, _ int64) (map[string]consensus.ValidatorRegistryEntry, error) {
	return f.registry, nil
}
func (f *fakeBackfillChain) BlockTime(_ context.Context, _ int64, _ uint64) (time.Time, error) {
	if f.blockErr != nil {
		return time.Time{}, f.blockErr
	}
	return time.Unix(1_757_000_123, 0).UTC(), nil
}

func TestReconstructBuildsARowFromChainStateNotCalldata(t *testing.T) {
	call := bfCall(t)
	f := &fakeBackfillChain{
		input:    []byte("ignored; the decoder is injected"),
		block:    45_943_100,
		success:  true,
		state:    bfState(),
		registry: bfRegistry(t),
	}
	out := ReconstructAnchorQuorum(context.Background(), f,
		BackfillCandidate{ChainID: backfillChainID, TxHash: "0xverify"},
		func([]byte) (*DecodedVerifyCall, error) { return call, nil })

	if out.Err != nil || out.Rejected != "" {
		t.Fatalf("a genuine anchor was not reconstructed: err=%v rejected=%s", out.Err, out.Rejected)
	}
	rec := out.Record
	if rec == nil {
		t.Fatal("no record")
	}
	if rec.EvidenceSource != "chain_backfill" {
		t.Fatalf("evidence_source = %q", rec.EvidenceSource)
	}
	// The anchor-create transaction is NOT this transaction. Filling it here is the false-binding bug.
	if rec.AnchorCreateTx != "" {
		t.Fatalf("anchor_create_tx was invented as %q", rec.AnchorCreateTx)
	}
	if rec.VerifyTx != "0xverify" || rec.VerifyBlock != 45_943_100 {
		t.Fatalf("verify leg = %s @ %d", rec.VerifyTx, rec.VerifyBlock)
	}
	// The ZK blob must never be recorded as if it were the aggregate signature.
	if len(rec.AggregateSignature) != 0 || len(rec.AggregatePubKey) != 0 {
		t.Fatal("a backfilled row carries aggregate bytes the calldata does not contain")
	}
	if len(rec.Members) != 0 {
		t.Fatal("membership was invented for a backfilled row")
	}
	if want := "0x" + strings.Repeat("aa", 32); rec.BundleID == want {
		t.Fatal("bundle id came from the root")
	}
	if got := fmt.Sprintf("0x%x", bfState().MerkleRoot); got != "0x"+strings.Repeat("aa", 32) {
		t.Fatalf("fixture drift: %s", got)
	}
	if len(rec.Signers) != 5 || rec.SignedVotingPower.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("signers not carried: %d signers, %v signed", len(rec.Signers), rec.SignedVotingPower)
	}
}

func TestReconstructRefusesARevertedTransaction(t *testing.T) {
	f := &fakeBackfillChain{success: false, state: bfState(), registry: bfRegistry(t)}
	out := ReconstructAnchorQuorum(context.Background(), f,
		BackfillCandidate{ChainID: backfillChainID, TxHash: "0xreverted"},
		func([]byte) (*DecodedVerifyCall, error) { return bfCall(t), nil })
	if out.Record != nil {
		t.Fatal("a reverted transaction produced a row")
	}
	if !strings.Contains(out.Rejected, "reverted") {
		t.Fatalf("unexpected reason: %q", out.Rejected)
	}
}

// A block whose timestamp cannot be read must not fall back to now(): the row would assert a completion
// time that never happened.
func TestReconstructNeverInventsACompletionTime(t *testing.T) {
	f := &fakeBackfillChain{
		input: []byte("x"), block: 1, success: true,
		state: bfState(), registry: bfRegistry(t),
		blockErr: fmt.Errorf("pruned"),
	}
	out := ReconstructAnchorQuorum(context.Background(), f,
		BackfillCandidate{ChainID: backfillChainID, TxHash: "0xverify"},
		func([]byte) (*DecodedVerifyCall, error) { return bfCall(t), nil })
	if out.Record == nil {
		t.Fatalf("rejected: %s %v", out.Rejected, out.Err)
	}
	if !out.Record.VerifiedAt.Equal(bfState().Timestamp) {
		t.Fatalf("verified_at = %v, want the anchor's own timestamp %v",
			out.Record.VerifiedAt, bfState().Timestamp)
	}
}

// ---- The decoder -------------------------------------------------------------------------------

func TestDecodeRejectsCalldataThatIsNotAVerifyCall(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
	}{
		{"empty", nil},
		{"short", []byte{0x01, 0x02}},
		{"wrong selector", append([]byte{0xde, 0xad, 0xbe, 0xef}, make([]byte, 64)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeExecuteComprehensiveProof(tc.input); err == nil {
				t.Fatal("non-verify calldata decoded as a proof")
			}
		})
	}
}

// Round-trip: pack a proof exactly as the submitter does, decode it, and require every quorum field back.
func TestDecodeRoundTripsASubmittedProof(t *testing.T) {
	parsed, err := contracts.CertenAnchorV4MetaData.GetAbi()
	if err != nil {
		t.Fatalf("anchor ABI: %v", err)
	}
	bundleID, root, opID, msg := bfWord(0xcc), bfWord(0xaa), bfWord(0xbb), bfWord(0x42)

	validators := []common.Address{}
	powers := []*big.Int{}
	for i := byte(1); i <= 5; i++ {
		var a common.Address
		a[19] = i
		validators = append(validators, a)
		powers = append(powers, big.NewInt(100))
	}

	proof := contracts.CertenAnchorV4CertenProof{
		TransactionHash: bundleID,
		MerkleRoot:      root,
		ProofHashes:     [][32]byte{},
		LeafHash:        [32]byte{},
		GovernanceProof: contracts.CertenAnchorV4GovernanceProofData{
			KeyBookURL:         "certen:validator-set:v1",
			KeyBookRoot:        bfWord(0x11),
			KeyPageProofs:      [][32]byte{},
			AuthorityAddress:   validators[0],
			AuthorityLevel:     2,
			Nonce:              big.NewInt(1),
			RequiredSignatures: big.NewInt(1),
			ProvidedSignatures: big.NewInt(1),
			ThresholdMet:       true,
		},
		BlsProof: contracts.CertenAnchorV4BLSProofData{
			AggregateSignature: []byte{0x01, 0x02, 0x03}, // the ZK blob, in reality
			ValidatorAddresses: validators,
			VotingPowers:       powers,
			TotalVotingPower:   big.NewInt(700),
			SignedVotingPower:  big.NewInt(500),
			ThresholdMet:       true,
			MessageHash:        msg,
		},
		Commitments: contracts.CertenAnchorV4CommitmentData{
			OperationCommitment: opID,
			ExecutionCommitment: root,
			SourceChain:         "accumulate",
			SourceBlockHeight:   big.NewInt(0),
			SourceTxHash:        bundleID,
			TargetChain:         "evm-84532",
			TargetAddress:       validators[0],
		},
		ExpirationTime: big.NewInt(0),
		Metadata:       []byte("batch:84532"),
	}

	packed, err := parsed.Pack("executeComprehensiveProof", bundleID, proof)
	if err != nil {
		t.Fatalf("packing: %v", err)
	}

	call, err := DecodeExecuteComprehensiveProof(packed)
	if err != nil {
		t.Fatalf("decoding calldata the submitter itself packs: %v", err)
	}
	if call.BundleID != bundleID || call.MerkleRoot != root || call.OperationID != opID || call.MessageHash != msg {
		t.Fatalf("identity fields did not round-trip: %+v", call)
	}
	if len(call.Signers) != 5 {
		t.Fatalf("got %d signers", len(call.Signers))
	}
	if call.Signers[0] != strings.ToLower(validators[0].Hex()) {
		t.Fatalf("signer 0 = %s", call.Signers[0])
	}
	if call.SignedVotingPower.Cmp(big.NewInt(500)) != 0 || call.TotalVotingPower.Cmp(big.NewInt(700)) != 0 {
		t.Fatalf("powers did not round-trip: %v/%v", call.SignedVotingPower, call.TotalVotingPower)
	}

	// And the decoded call must survive verification against matching state.
	setRoot, err := contracts.GetV6_1ValidatorSetRoot()
	if err != nil {
		t.Skipf("no validator-set root configured: %v", err)
	}
	call.MessageHash = contracts.ComputeEvmMessageHashV6_1_Pre(backfillChainID, bundleID, root, opID, setRoot)
	state := AnchorOnChainState{
		MerkleRoot: root, OperationCommitment: opID, Valid: true, ProofExecuted: true,
	}
	if err := VerifyBackfilledQuorum(backfillChainID, call, state, bfRegistry(t)); err != nil {
		t.Fatalf("a round-tripped genuine proof was refused: %v", err)
	}
}
