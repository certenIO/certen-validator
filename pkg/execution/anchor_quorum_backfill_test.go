package execution

import (
	"context"
	"encoding/hex"
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
		MerkleRoot: bfWord(0xaa),
		// A batch anchor binds operationID; operationCommitment is zero, exactly as the live anchors show.
		OperationID:         bfWord(0xbb),
		OperationCommitment: [32]byte{},
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
		OperationID: st.OperationID,
		MessageHash: contracts.ComputeEvmMessageHashV6_1_Pre(
			backfillChainID, bfWord(0xcc), st.MerkleRoot, st.OperationID, setRoot),
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
			name: "calldata operation id is not the anchor's operation id",
			mutate: func(c *DecodedVerifyCall, _ *AnchorOnChainState, _ map[string]consensus.ValidatorRegistryEntry) {
				c.OperationID = bfWord(0x99)
			},
			wantErr: "operation id",
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
		MerkleRoot: root, OperationID: opID, Valid: true, ProofExecuted: true,
	}
	if err := VerifyBackfilledQuorum(backfillChainID, call, state, bfRegistry(t)); err != nil {
		t.Fatalf("a round-tripped genuine proof was refused: %v", err)
	}
}

// REGRESSION — the field a batch anchor actually binds.
//
// The first live dry run refused all 313 candidates with "is not the anchor's operation commitment
// 0x00000000…", because the check read operationCommitment (index 3), which createBatchAnchor leaves
// empty, instead of operationID (index 7), which it fills. Zero never equals a real operation id, so
// every genuine anchor was refused. It failed closed, which is the right direction — but it made the
// backfill incapable of accepting anything.
//
// This pins the rule with the live values from base-sepolia anchor 0xa9cc3e51…:
//
//	merkleRoot  0xd4d5fe5c…   operationCommitment 0x0   operationID 0x6ba3ae63…
func TestBackfillChecksOperationIDNotOperationCommitment(t *testing.T) {
	call := bfCall(t)
	state := bfState()

	// As live: operationCommitment empty, operationID carrying the batch operation id.
	if state.OperationCommitment != ([32]byte{}) {
		t.Fatal("fixture drift: a batch anchor's operationCommitment is empty")
	}
	if err := VerifyBackfilledQuorum(backfillChainID, call, state, bfRegistry(t)); err != nil {
		t.Fatalf("a genuine batch anchor was refused: %v", err)
	}

	// And the message hash must be rebuilt from operationID too: a state whose operationID differs is a
	// different batch, and must be refused even though operationCommitment still matches (both zero).
	other := state
	other.OperationID = bfWord(0x5e)
	if err := VerifyBackfilledQuorum(backfillChainID, call, other, bfRegistry(t)); err == nil {
		t.Fatal("an anchor bound to a different operation id was accepted")
	}
}

// GOLDEN VECTOR — a real anchors() response from the deployed base-sepolia anchor.
//
// These are the exact 15 words returned by CertenAnchorV8_1.anchors(0xa9cc3e51…) at
// 0xEA9eeeE42a7971792B11Fd2f682C9c1172490272, read live on 2026-09-16. They are kept verbatim because
// the production defect was a FIELD INDEX: the code read operationCommitment (index 3, empty on a batch
// anchor) where it had to read operationID (index 7). A hand-built fixture would not have caught that;
// this response does, because it is what the chain actually says.
const liveAnchorsResponse = "" +
	"a9cc3e51e3f77f3ade8e6ae80ea30bb3b606e67b0a5df17cba94a287bfe4ff22" + // [ 0] bundleId
	"d4d5fe5ca51b390b851000cd698dcd63e831e380732e78c31020f056669662b2" + // [ 1] merkleRoot
	"0000000000000000000000000000000000000000000000000000000000000000" + // [ 2] adiURLHash
	"0000000000000000000000000000000000000000000000000000000000000000" + // [ 3] operationCommitment — EMPTY
	"0000000000000000000000000000000000000000000000000000000000000000" + // [ 4] crossChainCommitment
	"0000000000000000000000000000000000000000000000000000000000000000" + // [ 5] governanceRoot
	"d4d5fe5ca51b390b851000cd698dcd63e831e380732e78c31020f056669662b2" + // [ 6] executionCommitment
	"6ba3ae631e0fa12fbe602bb9d5e0d24e4348281d9e8c7a3154a4cc3272ea0ad2" + // [ 7] operationID — THE BINDING
	"000000000000000000000000000000000000000000000000000000000081a673" + // [ 8] accumulateBlockHeight
	"000000000000000000000000000000000000000000000000000000006a9c84ba" + // [ 9] timestamp
	"000000000000000000000000d4a3dbbae0c04d4307c5e00a5e05b66acc289f5d" + // [10] validator
	"0000000000000000000000000000000000000000000000000000000000000001" + // [11] valid
	"0000000000000000000000000000000000000000000000000000000000000001" + // [12] proofExecuted
	"0000000000000000000000000000000000000000000000000000000000000000" + // [13] governanceExecuted
	"0000000000000000000000000000000000000000000000000000000000000002" //   [14] governanceLevel

func TestDecodeAnchorStateReadsTheLiveAnchorLayout(t *testing.T) {
	raw, err := hex.DecodeString(liveAnchorsResponse)
	if err != nil {
		t.Fatalf("bad golden vector: %v", err)
	}
	parsed, err := abiFromJSON(anchorsABIJSON)
	if err != nil {
		t.Fatalf("anchors ABI: %v", err)
	}
	out, err := parsed.Methods["anchors"].Outputs.Unpack(raw)
	if err != nil {
		t.Fatalf("unpacking the live response: %v", err)
	}

	state, err := decodeAnchorState(out)
	if err != nil {
		t.Fatalf("decodeAnchorState: %v", err)
	}

	wantRoot := "d4d5fe5ca51b390b851000cd698dcd63e831e380732e78c31020f056669662b2"
	wantOpID := "6ba3ae631e0fa12fbe602bb9d5e0d24e4348281d9e8c7a3154a4cc3272ea0ad2"

	if got := hex.EncodeToString(state.MerkleRoot[:]); got != wantRoot {
		t.Fatalf("merkleRoot = %s", got)
	}
	// THE REGRESSION: operationID must come from index 7, not index 3.
	if got := hex.EncodeToString(state.OperationID[:]); got != wantOpID {
		t.Fatalf("operationID = %s, want %s — reading the wrong tuple index refuses every batch anchor", got, wantOpID)
	}
	if state.OperationCommitment != ([32]byte{}) {
		t.Fatalf("operationCommitment = %x, want empty on a batch anchor", state.OperationCommitment)
	}
	if hex.EncodeToString(state.ExecutionCommitment[:]) != wantRoot {
		t.Fatal("executionCommitment must equal the published root on a batch anchor")
	}
	if !state.Valid || !state.ProofExecuted {
		t.Fatalf("valid=%v proofExecuted=%v, want both true", state.Valid, state.ProofExecuted)
	}
	if state.Timestamp.IsZero() {
		t.Fatal("timestamp was not decoded")
	}
}

// A truncated response must be refused rather than silently decoded from whatever words arrived.
func TestDecodeAnchorStateRefusesAChangedLayout(t *testing.T) {
	if _, err := decodeAnchorState(make([]interface{}, 14)); err == nil {
		t.Fatal("a 14-field response was accepted")
	}
}

// REGRESSION — the live gate found these two columns empty on a genuine anchor.
//
// The first live on-demand intent after deploy produced a correct canonical row (quorum_reached, 7
// attestations, 700/700) with anchor_create_tx and verify_block BLANK: prove() never received the
// transaction that created the anchor, and the submitter discarded the verify receipt's block number.
//
// anchor_create_tx blank is the one that matters. Layer 5 falls back to the settlement observation when
// the canonical row has no anchor transaction — which is exactly the false binding this work removed, so
// the field has to arrive with the evidence.
func TestAnchorQuorumRecordCarriesTheAnchorCreateTxAndVerifyBlock(t *testing.T) {
	const createTx = "0x51a1c0de00000000000000000000000000000000000000000000000000000baa"
	const verifyTx = "0x06308e33e18b541148029acae074ccb76fdf0573ee1da181275b7ab04b7e2228"

	ev := &AnchorQuorumEvidence{
		ChainID:        84532,
		BundleID:       bfWord(0xcc),
		Root:           bfWord(0xaa),
		VerifyTx:       verifyTx,
		VerifyBlock:    46_437_104,
		AnchorCreateTx: createTx,
		Lane:           AnchorLaneOnDemand,
	}
	rec := AnchorQuorumRecordFrom(ev)
	if rec == nil {
		t.Fatal("no record")
	}
	if rec.AnchorCreateTx != createTx {
		t.Fatalf("anchor_create_tx = %q, want the anchor-create transaction; blank makes layer 5 fall "+
			"back to the settlement observation, which is the false binding", rec.AnchorCreateTx)
	}
	if rec.VerifyTx != verifyTx {
		t.Fatalf("verify_tx = %q", rec.VerifyTx)
	}
	if rec.VerifyBlock != 46_437_104 {
		t.Fatalf("verify_block = %d", rec.VerifyBlock)
	}
	// And the two must never be confused: the verify transaction proved the root, it did not publish it.
	if rec.AnchorCreateTx == rec.VerifyTx {
		t.Fatal("the verify transaction is being recorded as the transaction that published the root")
	}
}

// An anchor created by ANOTHER leader leaves the field empty here. Empty is honest; inventing a
// transaction would be the original defect in a new place.
func TestAnchorQuorumRecordLeavesTheCreateTxEmptyWhenThisNodeDidNotAnchor(t *testing.T) {
	rec := AnchorQuorumRecordFrom(&AnchorQuorumEvidence{
		ChainID:  84532,
		BundleID: bfWord(0xcc),
		Root:     bfWord(0xaa),
		VerifyTx: "0x06308e33e18b541148029acae074ccb76fdf0573ee1da181275b7ab04b7e2228",
		Lane:     AnchorLaneOnDemand,
	})
	if rec.AnchorCreateTx != "" {
		t.Fatalf("anchor_create_tx was invented as %q", rec.AnchorCreateTx)
	}
}
