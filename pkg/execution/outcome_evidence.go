// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// A member's recorded batch outcome, verifiable offline (RB5-F15)
// =============================================================================
//
// CertenOutcomeRegistryV1 records ONE root per V8.2 batch anchor, under a quorum attestation (RB5 D4). That record is a
// claim about every member of the anchor. OutcomeEvidence is what a third party needs to check the claim for ONE member,
// with no network and nothing of CERTEN's database:
//
//	the anchor        its commitment, re-deriving its bundle id; the member's batch leaf under its batch root
//	the record        the outcome root, the recordBatchOutcome transaction and its receipt, proven into the header of
//	                  the block it names, whose hash is the stated block hash
//	the quorum        the anchor's validator set (addresses, powers, BLS keys, threshold) re-deriving the set root the
//	                  outcome message covers; the signers at their registered powers, at or above the threshold; the
//	                  Groth16 proof the registry verified, checked under the deployed verification key against the
//	                  recomputed outcome message and the commitment of the signers' aggregate key; and the BLS
//	                  aggregate itself when the recording validator held it
//	the member        its outcome leaf, recomputed from its fields and its branch to the outcome root; its batch leaf
//	                  recomputed from its committed calls; and the chain evidence its status rests on: the settlement
//	                  or consuming transaction and its receipt proven into its block's header, the committed state
//	                  proven at that block's state root, or the claim block and its parent for a member not settled
//
// What offline verification CANNOT establish, and says so: that the blocks are canonical and final on their chain (the
// headers hash to the stated hashes; whether the chain holds them is the online check, --online-rpc); that a LeafConsumed
// log's emitter is the member's CertenAccountV7_2 (its code is not part of the evidence); that the stated validator BLS
// keys are the ones the anchor registered (the set root commits addresses and powers, not keys - the online check reads
// the registry); that a member not settled stayed unconsumed through its claim block (a LeafConsumed log's absence is
// not provable from one block; it is the quorum's certified statement) and that its deadline is the one the user signed.

// OutcomeEvidenceVersion names this encoding.
const OutcomeEvidenceVersion = "certen:outcome-evidence:v1"

// Layer6LayerNumber and Layer6RowName are the chained_proof_layers row a member's proof carries its outcome evidence in.
// Like layer 5, it is not part of the govRoot: the outcome is recorded after the proof that settled the member.
const (
	Layer6LayerNumber = 6
	Layer6RowName     = "L6 - Batch Outcome"
)

// OutcomeQuorumScheme names the signature scheme the quorum fields are checked under.
const OutcomeQuorumScheme = "bls12-381 G1 signatures over HashMessageToG1V2(message), G2 keys; Groth16 BN254 V2 proof (BLSZKVerifierV2_1)"

// ErrOutcomeEvidence is wrapped by every failed offline check of an outcome's evidence: evidence that is present and
// does not check out.
var ErrOutcomeEvidence = errors.New("outcome evidence does not verify")

// ErrNoOutcomeEvidence: the proof carries no outcome evidence - its anchor's outcome is not recorded yet, or the proof
// predates the outcome evidence. A named weaker state, never a pass.
var ErrNoOutcomeEvidence = errors.New("no recorded batch outcome evidence for this proof: the outcome is not recorded yet, " +
	"or the proof predates outcome evidence")

// ErrOutcomeSetRotated: the outcome was certified by a CERTEN validator set other than the one that signed the anchor.
// The quorum verifies under the set it states; that this set succeeded the anchor's is not established offline.
var ErrOutcomeSetRotated = errors.New("the outcome was certified by a CERTEN validator set other than the anchor's")

// OutcomeEvidence is one member's outcome evidence (see the file comment).
type OutcomeEvidence struct {
	Version  string                `json:"version"`
	ChainID  int64                 `json:"chainId"`
	Registry string                `json:"registry"`
	Anchor   OutcomeAnchorEvidence `json:"anchor"`
	Record   OutcomeRecordEvidence `json:"record"`
	Quorum   OutcomeQuorumEvidence `json:"quorum"`
	Member   OutcomeMemberEvidence `json:"member"`
}

// OutcomeAnchorEvidence is what the V8.2 anchor committed (anchors(bundleId) and its derivation), and the CERTEN
// validator set root the outcome message covers.
type OutcomeAnchorEvidence struct {
	Address               string `json:"address"`
	BundleID              string `json:"bundleId"`
	BatchRoot             string `json:"batchRoot"`
	LeafCount             uint64 `json:"leafCount"`
	BatchOperationID      string `json:"batchOperationId"`
	AccumulateBlockHeight uint64 `json:"accumulateBlockHeight"`
	AccumulateSetRoot     string `json:"accumulateSetRoot"`
	Incarnation           string `json:"incarnation"`
	CertenSetRoot         string `json:"certenSetRoot"`
}

// OutcomeRecordEvidence is the registry's record and the transaction that wrote it.
type OutcomeRecordEvidence struct {
	OutcomeRoot string                 `json:"outcomeRoot"`
	MessageHash string                 `json:"messageHash"`
	Recorder    string                 `json:"recorder"`
	Tx          string                 `json:"tx"`
	BlockNumber uint64                 `json:"blockNumber"`
	BlockHash   string                 `json:"blockHash"`
	Inclusion   ChainInclusionEvidence `json:"inclusion"`
}

// ChainInclusionEvidence proves one transaction and its receipt into a block header: the header's RLP (its keccak is the
// block hash), and the transaction and receipt consensus encodings with their Patricia-trie proofs at rlp(index) under
// the header's transactionsRoot and receiptsRoot.
type ChainInclusionEvidence struct {
	Header           hexutil.Bytes   `json:"header"`
	Index            uint64          `json:"index"`
	Transaction      hexutil.Bytes   `json:"transaction"`
	TransactionProof []hexutil.Bytes `json:"transactionProof"`
	Receipt          hexutil.Bytes   `json:"receipt"`
	ReceiptProof     []hexutil.Bytes `json:"receiptProof"`
}

// OutcomeQuorumEvidence is the quorum that certified the outcome message.
type OutcomeQuorumEvidence struct {
	Scheme               string                   `json:"scheme"`
	ThresholdNumerator   uint64                   `json:"thresholdNumerator"`
	ThresholdDenominator uint64                   `json:"thresholdDenominator"`
	Validators           []OutcomeQuorumValidator `json:"validators"`
	Signers              []string                 `json:"signers"`
	SignerPowers         []string                 `json:"signerPowers"`
	SignedVotingPower    string                   `json:"signedVotingPower"`
	TotalVotingPower     string                   `json:"totalVotingPower"`
	// ZKProof is BLSProofData.aggregateSignature as recordBatchOutcome submitted it: the Groth16 proof the registry
	// verified.
	ZKProof hexutil.Bytes `json:"zkProof"`
	// AggregateSignature and AggregatePublicKey are the BLS aggregate itself, held only by the validator that recorded.
	AggregateSignature string `json:"aggregateSignature,omitempty"`
	AggregatePublicKey string `json:"aggregatePublicKey,omitempty"`
}

// OutcomeQuorumValidator is one validator of the anchor's registry.
type OutcomeQuorumValidator struct {
	Address      string `json:"address"`
	VotingPower  string `json:"votingPower"`
	BLSPublicKey string `json:"blsPublicKey"`
}

// OutcomeLeafEvidence is an outcome leaf's fields (OutcomeLeaf) bar the chain and anchor, which the evidence states once.
type OutcomeLeafEvidence struct {
	LeafIndex    uint64 `json:"leafIndex"`
	BatchLeaf    string `json:"batchLeaf"`
	OperationID  string `json:"operationId"`
	Status       uint8  `json:"status"`
	Tx           string `json:"tx"`
	BlockNumber  uint64 `json:"blockNumber"`
	BlockHash    string `json:"blockHash"`
	ReceiptsRoot string `json:"receiptsRoot"`
	EffectsHash  string `json:"effectsHash"`
}

// OutcomeMemberEvidence is the member's leaf and the evidence its status rests on.
type OutcomeMemberEvidence struct {
	Leaf          OutcomeLeafEvidence `json:"leaf"`
	OutcomeBranch []string            `json:"outcomeBranch"`
	BatchBranch   []string            `json:"batchBranch"`
	// The member: its account, and the inputs of its batch leaf - its ADI, its committed calls with the effects each
	// committed (as its user-signed intent states them), and the certified authority book and page.
	Account       string           `json:"account"`
	ADIURL        string           `json:"adiUrl"`
	AuthorityBook string           `json:"authorityBook"`
	AuthorityPage uint64           `json:"authorityPage"`
	Legs          []OutcomeTreeLeg `json:"legs"`
	// LeafVersion is the account leaf version the member's batch leaf is of (RB5-F57): absent for v3, as the tree keeps it.
	// NotBefore is the notBefore a v4 leaf binds (unix seconds; its notAfter is Deadline), and absent for v3, which binds
	// no window.
	LeafVersion AccountLeafVersion `json:"leafVersion,omitempty"`
	NotBefore   int64              `json:"notBefore,omitempty"`
	// Deadline (unix seconds) and FinalityMargin (seconds): a member not settled is decided at the first block past
	// deadline + margin.
	Deadline       int64 `json:"deadline"`
	FinalityMargin int64 `json:"finalityMargin"`
	// Transaction: the settlement (1, 2), the consuming transaction (4), or the last reverted attempt (3, when named).
	Transaction *ChainInclusionEvidence `json:"transaction,omitempty"`
	// StateProofs: every committed state slot, proven at the settlement block's state root (1, 2).
	StateProofs []*StateProof `json:"stateProofs,omitempty"`
	// ClaimHeader and ClaimParentHeader: the block a member not settled is decided at, and its parent (3).
	ClaimHeader       hexutil.Bytes `json:"claimHeader,omitempty"`
	ClaimParentHeader hexutil.Bytes `json:"claimParentHeader,omitempty"`
}

// OutcomeEvidenceCheck is what an offline verification established.
type OutcomeEvidenceCheck struct {
	ChainID       int64
	BundleID      [32]byte
	OutcomeRoot   [32]byte
	Message       [32]byte
	Leaf          OutcomeLeaf
	LeafHash      [32]byte
	Signers       int
	SignedPower   *big.Int
	TotalPower    *big.Int
	BLSAggregate  bool // the BLS aggregate itself was verified, not only the proof of it
	ConsumedUnder [32]byte
	// Established and NotEstablished are what the check proved, and what it could not, in words.
	Established    []string
	NotEstablished []string
}

func (c *OutcomeEvidenceCheck) proved(format string, a ...interface{}) {
	c.Established = append(c.Established, fmt.Sprintf(format, a...))
}

func (c *OutcomeEvidenceCheck) unproven(format string, a ...interface{}) {
	c.NotEstablished = append(c.NotEstablished, fmt.Sprintf(format, a...))
}

func evidenceFail(format string, a ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrOutcomeEvidence, fmt.Sprintf(format, a...))
}

func evHash(s, what string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "0x"), "0X"))
	if err != nil || len(b) != 32 {
		return out, evidenceFail("%s %q is not 32 bytes of hex", what, s)
	}
	copy(out[:], b)
	return out, nil
}

func evAddress(s, what string) (common.Address, error) {
	if !common.IsHexAddress(s) {
		return common.Address{}, evidenceFail("%s %q is not an address", what, s)
	}
	return common.HexToAddress(s), nil
}

func evPower(s, what string) (*big.Int, error) {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() < 0 {
		return nil, evidenceFail("%s %q is not a power", what, s)
	}
	return v, nil
}

func evBranch(in []string, what string) ([][32]byte, error) {
	out := make([][32]byte, 0, len(in))
	for i, s := range in {
		h, err := evHash(s, fmt.Sprintf("%s[%d]", what, i))
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

// VerifyOffline checks the evidence with no network access and returns what it established. Every failure wraps
// ErrOutcomeEvidence.
func (e *OutcomeEvidence) VerifyOffline() (*OutcomeEvidenceCheck, error) {
	chk, anchor, err := e.verifyRecordAndQuorum()
	if err != nil {
		return nil, err
	}
	if err := e.Member.verify(e.ChainID, anchor, chk.OutcomeRoot, chk); err != nil {
		return nil, err
	}
	e.boundaries(chk)
	return chk, nil
}

// VerifyRecordOffline checks the anchor, the record and the quorum - everything but a member. It is what a record
// read from the chain alone can be checked for: the members' leaves are not on chain, only their root.
func (e *OutcomeEvidence) VerifyRecordOffline() (*OutcomeEvidenceCheck, error) {
	chk, _, err := e.verifyRecordAndQuorum()
	if err != nil {
		return nil, err
	}
	e.boundaries(chk)
	return chk, nil
}

func (e *OutcomeEvidence) verifyRecordAndQuorum() (*OutcomeEvidenceCheck, *anchorFacts, error) {
	if e == nil {
		return nil, nil, ErrNoOutcomeEvidence
	}
	if e.Version != OutcomeEvidenceVersion {
		return nil, nil, evidenceFail("version %q, this verifier reads %q", e.Version, OutcomeEvidenceVersion)
	}
	if e.ChainID <= 0 {
		return nil, nil, evidenceFail("chain id %d", e.ChainID)
	}
	registry, err := evAddress(e.Registry, "registry")
	if err != nil {
		return nil, nil, err
	}
	chk := &OutcomeEvidenceCheck{ChainID: e.ChainID}
	anchor, err := e.Anchor.verify(e.ChainID, chk)
	if err != nil {
		return nil, nil, err
	}
	_, msg, err := e.verifyRecord(registry, anchor, chk)
	if err != nil {
		return nil, nil, err
	}
	if err := e.Quorum.verify(anchor.certenSetRoot, msg, e.Record, chk); err != nil {
		return nil, nil, err
	}
	return chk, anchor, nil
}

func (e *OutcomeEvidence) boundaries(chk *OutcomeEvidenceCheck) {
	chk.unproven("that the blocks named here are canonical and final on chain %d: each header hashes to its stated hash; "+
		"whether the chain holds it is the online check", e.ChainID)
	chk.unproven("that the stated BLS keys are the ones the anchor registered (the set root commits addresses and powers; " +
		"the online check reads the registry and its authorized key commitments)")
}

// anchorFacts are the anchor evidence decoded.
type anchorFacts struct {
	address                          common.Address
	bundleID, batchRoot, batchOpID   [32]byte
	accSetRoot, inc, certenSetRoot   [32]byte
	leafCount, accumulateBlockHeight uint64
}

func (a OutcomeAnchorEvidence) verify(chainID int64, chk *OutcomeEvidenceCheck) (*anchorFacts, error) {
	f := &anchorFacts{leafCount: a.LeafCount, accumulateBlockHeight: a.AccumulateBlockHeight}
	var err error
	if f.address, err = evAddress(a.Address, "anchor.address"); err != nil {
		return nil, err
	}
	for _, x := range []struct {
		dst  *[32]byte
		src  string
		name string
	}{{&f.bundleID, a.BundleID, "anchor.bundleId"}, {&f.batchRoot, a.BatchRoot, "anchor.batchRoot"},
		{&f.batchOpID, a.BatchOperationID, "anchor.batchOperationId"}, {&f.accSetRoot, a.AccumulateSetRoot, "anchor.accumulateSetRoot"},
		{&f.inc, a.Incarnation, "anchor.incarnation"}, {&f.certenSetRoot, a.CertenSetRoot, "anchor.certenSetRoot"}} {
		if *x.dst, err = evHash(x.src, x.name); err != nil {
			return nil, err
		}
	}
	if f.leafCount == 0 {
		return nil, evidenceFail("an anchor of zero leaves")
	}
	if f.accSetRoot == ([32]byte{}) || f.inc == ([32]byte{}) {
		return nil, evidenceFail("the anchor commits no Accumulate validator set or incarnation: not a V8.2 anchor")
	}
	want := contracts.DeriveV8_2BatchBundleID(chainID, f.batchRoot, f.leafCount, f.batchOpID, f.accumulateBlockHeight, f.accSetRoot, f.inc)
	if want != f.bundleID {
		return nil, evidenceFail("the anchor's commitment derives bundle id 0x%x, the evidence names 0x%x", want, f.bundleID)
	}
	chk.BundleID = f.bundleID
	chk.proved("anchor 0x%x re-derives from its commitment: batch root 0x%x, %d leaf/leaves, batch operation id 0x%x, "+
		"Accumulate height %d, set root 0x%x, incarnation 0x%x", f.bundleID[:8], f.batchRoot[:8], f.leafCount, f.batchOpID[:8],
		f.accumulateBlockHeight, f.accSetRoot[:8], f.inc[:8])
	return f, nil
}

func (e *OutcomeEvidence) verifyRecord(registry common.Address, a *anchorFacts, chk *OutcomeEvidenceCheck) ([32]byte, [32]byte, error) {
	var zero [32]byte
	r := e.Record
	root, err := evHash(r.OutcomeRoot, "record.outcomeRoot")
	if err != nil {
		return zero, zero, err
	}
	if root == zero {
		return zero, zero, evidenceFail("a zero outcome root")
	}
	stated, err := evHash(r.MessageHash, "record.messageHash")
	if err != nil {
		return zero, zero, err
	}
	msg := contracts.ComputeEvmMessageHashV8_2_Outcome(e.ChainID, a.bundleID, root, a.certenSetRoot, a.accSetRoot, a.inc)
	if msg != stated {
		return zero, zero, evidenceFail("the outcome message recomputes to 0x%x, the record states 0x%x", msg, stated)
	}
	recorder, err := evAddress(r.Recorder, "record.recorder")
	if err != nil {
		return zero, zero, err
	}
	txHash, err := evHash(r.Tx, "record.tx")
	if err != nil {
		return zero, zero, err
	}
	blockHash, err := evHash(r.BlockHash, "record.blockHash")
	if err != nil {
		return zero, zero, err
	}
	hdr, tx, rcpt, err := r.Inclusion.verify(txHash, blockHash, r.BlockNumber, "record")
	if err != nil {
		return zero, zero, err
	}
	if rcpt.Status != types.ReceiptStatusSuccessful {
		return zero, zero, evidenceFail("the record transaction %s reverted", r.Tx)
	}
	if tx.To() == nil || *tx.To() != registry {
		return zero, zero, evidenceFail("the record transaction %s is not a call to the registry %s", r.Tx, registry.Hex())
	}
	sender, err := types.LatestSignerForChainID(big.NewInt(e.ChainID)).Sender(tx)
	if err != nil || sender != recorder {
		return zero, zero, evidenceFail("the record transaction %s was signed by %s (%v), the record names %s", r.Tx, sender.Hex(), err,
			recorder.Hex())
	}
	bundle, gotRoot, proof, err := decodeRecordBatchOutcome(tx.Data())
	if err != nil {
		return zero, zero, evidenceFail("the record transaction %s: %v", r.Tx, err)
	}
	if bundle != a.bundleID || gotRoot != root {
		return zero, zero, evidenceFail("the record transaction %s submitted anchor 0x%x root 0x%x, the evidence names 0x%x root 0x%x",
			r.Tx, bundle[:8], gotRoot[:8], a.bundleID[:8], root[:8])
	}
	if err := e.Quorum.matchesSubmitted(proof, msg); err != nil {
		return zero, zero, err
	}
	found := false
	for _, lg := range rcpt.Logs {
		if lg.Address == registry && len(lg.Topics) == 4 && lg.Topics[0] == batchOutcomeRecordedTopic &&
			lg.Topics[1] == common.Hash(a.bundleID) && lg.Topics[2] == common.Hash(root) &&
			common.BytesToAddress(lg.Topics[3][12:]) == recorder && bytes.Equal(lg.Data, msg[:]) {
			found = true
		}
	}
	if !found {
		return zero, zero, evidenceFail("the record transaction's receipt holds no BatchOutcomeRecorded(0x%x, 0x%x, %s) from the registry",
			a.bundleID[:8], root[:8], recorder.Hex())
	}
	chk.OutcomeRoot, chk.Message = root, msg
	chk.proved("record: recordBatchOutcome %s by %s to registry %s, its receipt (status 1, BatchOutcomeRecorded) proven into "+
		"block %d whose header hashes to 0x%x; it submitted outcome root 0x%x and the quorum proof checked below",
		r.Tx, recorder.Hex(), registry.Hex(), hdr.Number.Uint64(), blockHash[:8], root[:8])
	chk.proved("outcome message 0x%x recomputed (certen:bls:v2:outcome over chain %d, the anchor, the root, CERTEN set 0x%x and "+
		"the anchor's Accumulate commitment)", msg[:8], e.ChainID, a.certenSetRoot[:8])
	return root, msg, nil
}

// verify proves the transaction and its receipt into the header, the header to its hash, and returns them decoded.
func (c *ChainInclusionEvidence) verify(txHash, blockHash [32]byte, blockNumber uint64, what string) (*types.Header, *types.Transaction, *types.Receipt, error) {
	hdr, err := decodeEvidenceHeader(c.Header, what)
	if err != nil {
		return nil, nil, nil, err
	}
	if hdr.Hash() != common.Hash(blockHash) {
		return nil, nil, nil, evidenceFail("%s: the header hashes to %s, the evidence names block 0x%x", what, hdr.Hash().Hex(), blockHash)
	}
	if blockNumber != 0 && hdr.Number.Uint64() != blockNumber {
		return nil, nil, nil, evidenceFail("%s: the header is block %d, the evidence names %d", what, hdr.Number.Uint64(), blockNumber)
	}
	if crypto.Keccak256Hash(c.Transaction) != common.Hash(txHash) {
		return nil, nil, nil, evidenceFail("%s: the transaction bytes hash to %s, the evidence names 0x%x", what,
			crypto.Keccak256Hash(c.Transaction).Hex(), txHash)
	}
	if !inclusionVerifies(c.Transaction, c.TransactionProof, c.Index, hdr.TxHash) {
		return nil, nil, nil, evidenceFail("%s: the transaction is not proven at index %d under the header's transactionsRoot %s", what,
			c.Index, hdr.TxHash.Hex())
	}
	if !inclusionVerifies(c.Receipt, c.ReceiptProof, c.Index, hdr.ReceiptHash) {
		return nil, nil, nil, evidenceFail("%s: the receipt is not proven at index %d under the header's receiptsRoot %s", what,
			c.Index, hdr.ReceiptHash.Hex())
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(c.Transaction); err != nil {
		return nil, nil, nil, evidenceFail("%s: the transaction does not decode: %v", what, err)
	}
	rcpt := new(types.Receipt)
	if err := rcpt.UnmarshalBinary(c.Receipt); err != nil {
		return nil, nil, nil, evidenceFail("%s: the receipt does not decode: %v", what, err)
	}
	return hdr, tx, rcpt, nil
}

func inclusionVerifies(value []byte, nodes []hexutil.Bytes, index uint64, root common.Hash) bool {
	if len(value) == 0 || len(nodes) == 0 {
		return false
	}
	p := &MerkleInclusionProof{LeafHash: [32]byte(crypto.Keccak256Hash(value)), LeafIndex: index, ExpectedRoot: [32]byte(root),
		LeafValue: value}
	for _, n := range nodes {
		p.ProofNodes = append(p.ProofNodes, []byte(n))
	}
	return p.Verify()
}

// decodeEvidenceHeader decodes a header's RLP, requiring the canonical encoding: the bytes hashed are the bytes read.
func decodeEvidenceHeader(raw []byte, what string) (*types.Header, error) {
	if len(raw) == 0 {
		return nil, evidenceFail("%s: no block header", what)
	}
	hdr := new(types.Header)
	if err := rlp.DecodeBytes(raw, hdr); err != nil {
		return nil, evidenceFail("%s: the block header does not decode: %v", what, err)
	}
	again, err := rlp.EncodeToBytes(hdr)
	if err != nil || !bytes.Equal(again, raw) {
		return nil, evidenceFail("%s: the block header is not in its canonical encoding", what)
	}
	if hdr.Number == nil {
		return nil, evidenceFail("%s: the block header has no number", what)
	}
	return hdr, nil
}

// quorumFacts is the quorum evidence decoded.
type quorumFacts struct {
	keys    map[common.Address]*bls.PublicKey
	powers  map[common.Address]*big.Int
	signers []common.Address
	sPowers []*big.Int
	signed  *big.Int
	total   *big.Int
}

func (q OutcomeQuorumEvidence) decode() (*quorumFacts, error) {
	if q.Scheme != OutcomeQuorumScheme {
		return nil, evidenceFail("quorum scheme %q, this verifier checks %q", q.Scheme, OutcomeQuorumScheme)
	}
	if q.ThresholdDenominator == 0 || q.ThresholdNumerator == 0 || q.ThresholdNumerator > q.ThresholdDenominator {
		return nil, evidenceFail("threshold %d/%d", q.ThresholdNumerator, q.ThresholdDenominator)
	}
	if len(q.Validators) == 0 {
		return nil, evidenceFail("the quorum names no validator set")
	}
	f := &quorumFacts{keys: map[common.Address]*bls.PublicKey{}, powers: map[common.Address]*big.Int{}, total: new(big.Int)}
	var prev common.Address
	for i, v := range q.Validators {
		addr, err := evAddress(v.Address, fmt.Sprintf("quorum.validators[%d].address", i))
		if err != nil {
			return nil, err
		}
		if i > 0 && bytes.Compare(prev[:], addr[:]) >= 0 {
			return nil, evidenceFail("the validator set is not in ascending address order without repeats (%s after %s)", addr.Hex(), prev.Hex())
		}
		prev = addr
		p, err := evPower(v.VotingPower, fmt.Sprintf("quorum.validators[%d].votingPower", i))
		if err != nil {
			return nil, err
		}
		if p.Sign() <= 0 {
			return nil, evidenceFail("validator %s has no power", addr.Hex())
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(v.BLSPublicKey, "0x"))
		if err != nil {
			return nil, evidenceFail("validator %s's BLS key is not hex", addr.Hex())
		}
		if err := bls.ValidateBLSPublicKeySubgroup(raw); err != nil {
			return nil, evidenceFail("validator %s's BLS key: %v", addr.Hex(), err)
		}
		pk, err := bls.PublicKeyFromBytes(raw)
		if err != nil {
			return nil, evidenceFail("validator %s's BLS key: %v", addr.Hex(), err)
		}
		f.keys[addr], f.powers[addr] = pk, p
		f.total.Add(f.total, p)
	}
	if len(q.Signers) == 0 || len(q.Signers) != len(q.SignerPowers) {
		return nil, evidenceFail("%d signers, %d powers", len(q.Signers), len(q.SignerPowers))
	}
	seen := map[common.Address]bool{}
	sum := new(big.Int)
	for i, s := range q.Signers {
		addr, err := evAddress(s, fmt.Sprintf("quorum.signers[%d]", i))
		if err != nil {
			return nil, err
		}
		if seen[addr] {
			return nil, evidenceFail("signer %s is counted twice", addr.Hex())
		}
		seen[addr] = true
		reg, ok := f.powers[addr]
		if !ok {
			return nil, evidenceFail("signer %s is not in the validator set", addr.Hex())
		}
		p, err := evPower(q.SignerPowers[i], fmt.Sprintf("quorum.signerPowers[%d]", i))
		if err != nil {
			return nil, err
		}
		if p.Cmp(reg) != 0 {
			return nil, evidenceFail("signer %s is credited %s, its registered power is %s", addr.Hex(), p, reg)
		}
		f.signers, f.sPowers = append(f.signers, addr), append(f.sPowers, p)
		sum.Add(sum, p)
	}
	var err error
	if f.signed, err = evPower(q.SignedVotingPower, "quorum.signedVotingPower"); err != nil {
		return nil, err
	}
	total, err := evPower(q.TotalVotingPower, "quorum.totalVotingPower")
	if err != nil {
		return nil, err
	}
	if f.signed.Cmp(sum) != 0 {
		return nil, evidenceFail("the signers' registered powers sum to %s, the quorum states %s signed", sum, f.signed)
	}
	if total.Cmp(f.total) != 0 {
		return nil, evidenceFail("the validator set's powers sum to %s, the quorum states a total of %s", f.total, total)
	}
	return f, nil
}

// matchesSubmitted requires the quorum evidence to be exactly the proof recordBatchOutcome submitted.
func (q OutcomeQuorumEvidence) matchesSubmitted(p *contracts.CertenAnchorV4BLSProofData, msg [32]byte) error {
	if p == nil {
		return evidenceFail("the record transaction carries no quorum proof")
	}
	if !bytes.Equal(p.AggregateSignature, q.ZKProof) {
		return evidenceFail("the quorum proof is not the one the record transaction submitted")
	}
	if p.MessageHash != msg {
		return evidenceFail("the record transaction's proof is over message 0x%x, not the outcome message 0x%x", p.MessageHash, msg)
	}
	if len(p.ValidatorAddresses) != len(q.Signers) || len(p.VotingPowers) != len(q.SignerPowers) {
		return evidenceFail("the record transaction submitted %d signers, the evidence names %d", len(p.ValidatorAddresses), len(q.Signers))
	}
	for i, a := range p.ValidatorAddresses {
		if !strings.EqualFold(a.Hex(), q.Signers[i]) || p.VotingPowers[i] == nil || p.VotingPowers[i].String() != q.SignerPowers[i] {
			return evidenceFail("signer %d: the record transaction submitted %s at %v, the evidence names %s at %s", i, a.Hex(),
				p.VotingPowers[i], q.Signers[i], q.SignerPowers[i])
		}
	}
	if p.SignedVotingPower == nil || p.TotalVotingPower == nil || p.SignedVotingPower.String() != q.SignedVotingPower ||
		p.TotalVotingPower.String() != q.TotalVotingPower {
		return evidenceFail("the record transaction submitted %v of %v power, the evidence states %s of %s", p.SignedVotingPower,
			p.TotalVotingPower, q.SignedVotingPower, q.TotalVotingPower)
	}
	return nil
}

func (q OutcomeQuorumEvidence) verify(certenSetRoot, msg [32]byte, rec OutcomeRecordEvidence, chk *OutcomeEvidenceCheck) error {
	f, err := q.decode()
	if err != nil {
		return err
	}
	addrs := make([]common.Address, 0, len(q.Validators))
	powers := make([]*big.Int, 0, len(q.Validators))
	for _, v := range q.Validators {
		a := common.HexToAddress(v.Address)
		addrs, powers = append(addrs, a), append(powers, f.powers[a])
	}
	setRoot, err := contracts.ComputeValidatorSetRootV6_1(addrs, powers, new(big.Int).SetUint64(q.ThresholdNumerator),
		new(big.Int).SetUint64(q.ThresholdDenominator))
	if err != nil {
		return evidenceFail("the validator set root: %v", err)
	}
	if setRoot != certenSetRoot {
		return evidenceFail("the validator set (%d validators, threshold %d/%d) derives set root 0x%x, the outcome message covers 0x%x",
			len(addrs), q.ThresholdNumerator, q.ThresholdDenominator, setRoot, certenSetRoot)
	}
	// The anchor's rule (_verifyBLSQuorum): signed >= total * numerator / denominator, in integer arithmetic.
	required := new(big.Int).Div(new(big.Int).Mul(f.total, new(big.Int).SetUint64(q.ThresholdNumerator)),
		new(big.Int).SetUint64(q.ThresholdDenominator))
	if f.signed.Cmp(required) < 0 {
		return evidenceFail("%s of %s voting power signed; the anchor requires %s", f.signed, f.total, required)
	}
	recorder := common.HexToAddress(rec.Recorder)
	if _, ok := f.powers[recorder]; !ok {
		return evidenceFail("the recorder %s is not a validator of the set (the registry accepts only a registered validator)", recorder.Hex())
	}

	// The aggregate key of exactly the signers.
	pubs := make([]*bls.PublicKey, 0, len(f.signers))
	for _, s := range f.signers {
		pubs = append(pubs, f.keys[s])
	}
	aggPub, err := bls.AggregatePublicKeys(pubs)
	if err != nil {
		return evidenceFail("aggregating the signers' keys: %v", err)
	}
	var g2 bls12381.G2Affine
	if _, err := g2.SetBytes(aggPub.Bytes()); err != nil {
		return evidenceFail("the signers' aggregate key: %v", err)
	}
	commitment, err := bls_zkp.ComputePubkeyCommitmentV2(g2)
	if err != nil {
		return evidenceFail("the signers' key commitment: %v", err)
	}

	// The Groth16 proof the registry verified, under the deployed verification key.
	pi, err := bls_zkp.DecodeV2PublicInputs(q.ZKProof)
	if err != nil {
		return evidenceFail("the quorum proof: %v", err)
	}
	if pi.MessageHash != msg {
		return evidenceFail("the quorum proof is over message 0x%x, not the outcome message 0x%x", pi.MessageHash, msg)
	}
	if pi.PubkeyCommitment != commitment {
		return evidenceFail("the quorum proof commits key 0x%x, the signers' aggregate key commits 0x%x", pi.PubkeyCommitment, commitment)
	}
	if new(big.Int).SetUint64(pi.SignedVotingPower).Cmp(f.signed) != 0 || new(big.Int).SetUint64(pi.TotalVotingPower).Cmp(f.total) != 0 {
		return evidenceFail("the quorum proof states %d of %d power, the evidence %s of %s", pi.SignedVotingPower, pi.TotalVotingPower,
			f.signed, f.total)
	}
	verifier, err := bls_zkp.DeployedV2Verifier()
	if err != nil {
		return fmt.Errorf("the deployed verification key: %w", err)
	}
	ok, err := verifier.Verify(q.ZKProof)
	if err != nil || !ok {
		return evidenceFail("the quorum proof does not verify under the deployed verification key (%v)", err)
	}
	chk.Signers, chk.SignedPower, chk.TotalPower = len(f.signers), f.signed, f.total
	chk.proved("quorum: %d signer(s) at their registered powers, %s of %s voting power (threshold %d/%d requires %s), of the "+
		"validator set whose addresses, powers and threshold derive the CERTEN set root 0x%x the message covers",
		len(f.signers), f.signed, f.total, q.ThresholdNumerator, q.ThresholdDenominator, required, certenSetRoot[:8])
	chk.proved("quorum: the Groth16 proof the registry verified verifies offline under the deployed verification key "+
		"(sha256 %s…), over the outcome message, committing exactly the signers' aggregate key", bls_zkp.DeployedV2VerificationKeySHA256[:16])

	if q.AggregateSignature == "" && q.AggregatePublicKey == "" {
		chk.unproven("the BLS aggregate signature itself: the evidence carries the proof of it, not the aggregate (it was " +
			"rebuilt from the record transaction by a validator that did not send it)")
		return nil
	}
	if err := verifyOutcomeAggregate(aggPub, q.AggregateSignature, q.AggregatePublicKey, msg); err != nil {
		return err
	}
	chk.BLSAggregate = true
	chk.proved("quorum: the BLS aggregate signature verifies under the signers' aggregate key over the outcome message")
	return nil
}

// verify checks the member: its leaf and branch to the outcome root, its batch leaf under the anchor, and its status
// against the chain evidence.
func (m OutcomeMemberEvidence) verify(chainID int64, a *anchorFacts, root [32]byte, chk *OutcomeEvidenceCheck) error {
	leaf, err := m.Leaf.decode(chainID, a.bundleID)
	if err != nil {
		return err
	}
	if leaf.LeafIndex >= a.leafCount {
		return evidenceFail("leaf %d of an anchor of %d leaves", leaf.LeafIndex, a.leafCount)
	}
	lh, err := leaf.Hash()
	if err != nil {
		return evidenceFail("the outcome leaf: %v", err)
	}
	branch, err := evBranch(m.OutcomeBranch, "member.outcomeBranch")
	if err != nil {
		return err
	}
	if !VerifyBranch(branch, root, lh) {
		return evidenceFail("outcome leaf 0x%x (index %d) does not reach the recorded outcome root 0x%x over its %d-step branch",
			lh[:8], leaf.LeafIndex, root[:8], len(branch))
	}
	chk.Leaf, chk.LeafHash = leaf, lh
	chk.proved("member: outcome leaf %d (status %d) recomputed to 0x%x from its fields, under the recorded outcome root",
		leaf.LeafIndex, leaf.Status, lh[:8])

	account, err := m.batchLeaf(chainID, a, leaf, chk)
	if err != nil {
		return err
	}
	switch leaf.Status {
	case OutcomeExecuted, OutcomeEffectsNotProven:
		return m.verifyExecuted(chainID, a, leaf, account, chk)
	case OutcomeConsumedElsewhere:
		return m.verifyConsumedElsewhere(a, leaf, account, chk)
	case OutcomeNotSettled:
		return m.verifyNotSettled(leaf, account, chk)
	}
	return evidenceFail("status %d", leaf.Status)
}

func (l OutcomeLeafEvidence) decode(chainID int64, bundle [32]byte) (OutcomeLeaf, error) {
	out := OutcomeLeaf{ChainID: chainID, BundleID: bundle, LeafIndex: l.LeafIndex, Status: OutcomeStatus(l.Status), BlockNumber: l.BlockNumber}
	var err error
	for _, x := range []struct {
		dst  *[32]byte
		src  string
		name string
	}{{&out.BatchLeaf, l.BatchLeaf, "leaf.batchLeaf"}, {&out.OperationID, l.OperationID, "leaf.operationId"}, {&out.Tx, l.Tx, "leaf.tx"},
		{&out.BlockHash, l.BlockHash, "leaf.blockHash"}, {&out.ReceiptsRoot, l.ReceiptsRoot, "leaf.receiptsRoot"},
		{&out.EffectsHash, l.EffectsHash, "leaf.effectsHash"}} {
		if *x.dst, err = evHash(x.src, x.name); err != nil {
			return OutcomeLeaf{}, err
		}
	}
	if err := out.Validate(); err != nil {
		return OutcomeLeaf{}, evidenceFail("%v", err)
	}
	return out, nil
}

// memberLegCalls are a member's committed calls.
func memberLegCalls(legs []OutcomeTreeLeg) ([]BatchCall, error) {
	calls := make([]BatchCall, 0, len(legs))
	for i, l := range legs {
		if l.Value == nil {
			return nil, fmt.Errorf("leg %d has no value", i)
		}
		calls = append(calls, BatchCall{Target: l.Target, Value: l.Value.ToInt(), Data: l.Data})
	}
	if len(calls) == 0 {
		return nil, fmt.Errorf("no committed call")
	}
	return calls, nil
}

// memberExecutionCommitment is the execution commitment a member's leaf binds: the single-call commitment for one leg,
// the batch commitment for more.
func memberExecutionCommitment(chainID int64, calls []BatchCall) [32]byte {
	if len(calls) == 1 {
		return computeExecutionCommitment(chainID, calls[0].Target, calls[0].Value, calls[0].Data)
	}
	return computeBatchExecutionCommitment(chainID, calls)
}

// batchLeaf recomputes the member's batch leaf (ComputeBatchLeafV3, the leaf CertenAccountV7_2 consumes) from its ADI,
// committed calls, operation and certified authority, and walks it to the anchor's batch root.
func (m OutcomeMemberEvidence) batchLeaf(chainID int64, a *anchorFacts, leaf OutcomeLeaf, chk *OutcomeEvidenceCheck) (common.Address, error) {
	account, err := evAddress(m.Account, "member.account")
	if err != nil {
		return account, err
	}
	book, err := evHash(m.AuthorityBook, "member.authorityBook")
	if err != nil {
		return account, err
	}
	if m.ADIURL == "" || m.AuthorityPage == 0 || book == ([32]byte{}) {
		return account, evidenceFail("the member names no ADI or certified authority")
	}
	calls, err := memberLegCalls(m.Legs)
	if err != nil {
		return account, evidenceFail("the member's committed calls: %v", err)
	}
	in := BatchLeafInput{ADIURL: m.ADIURL, ExecutionCommitment: memberExecutionCommitment(chainID, calls),
		OperationID: leaf.OperationID, AuthorityBook: book, AuthorityPage: m.AuthorityPage}
	// The leaf is recomputed as the version the member states (absent is v3), never another (RB5-F57).
	version := AccountLeafV3
	if m.LeafVersion != "" {
		if version, err = ParseAccountLeafVersion(string(m.LeafVersion)); err != nil {
			return account, evidenceFail("the member's leaf version: %v", err)
		}
	}
	var got [32]byte
	switch version {
	case AccountLeafV3:
		if m.NotBefore != 0 {
			return account, evidenceFail("the member states a notBefore, and a v3 leaf binds no window")
		}
		got = ComputeBatchLeafV3(chainID, in)
	case AccountLeafV4:
		if m.NotBefore <= 0 {
			return account, evidenceFail("a v4 leaf binds [notBefore, deadline], and the member states no notBefore")
		}
		in.NotBefore, in.NotAfter = uint64(m.NotBefore), uint64(m.Deadline)
		got = ComputeBatchLeafV4(chainID, in)
	default:
		return account, evidenceFail("the member's leaf version %s has no recomputation", version)
	}
	if got != leaf.BatchLeaf {
		return account, evidenceFail("the member's ADI, %d committed call(s), operation and authority recompute batch leaf 0x%x as %s, "+
			"the outcome leaf names 0x%x", len(calls), got[:8], version, leaf.BatchLeaf[:8])
	}
	branch, err := evBranch(m.BatchBranch, "member.batchBranch")
	if err != nil {
		return account, err
	}
	if !VerifyBranch(branch, a.batchRoot, got) {
		return account, evidenceFail("batch leaf 0x%x does not reach the anchor's batch root 0x%x over its %d-step branch", got[:8],
			a.batchRoot[:8], len(branch))
	}
	chk.proved("member: %s batch leaf 0x%x recomputed from %s, its %d committed call(s), operation 0x%x and authority page %d, "+
		"under the anchor's batch root", version, got[:8], m.ADIURL, len(calls), leaf.OperationID[:8], m.AuthorityPage)
	return account, nil
}

// leafConsumedIn is the LeafConsumed(anchorId, leaf, operationID) log account emitted for leaf in the receipt.
func leafConsumedIn(rcpt *types.Receipt, account common.Address, leaf [32]byte) *types.Log {
	for _, lg := range rcpt.Logs {
		if lg.Address == account && len(lg.Topics) == 3 && lg.Topics[0] == leafConsumedTopic && lg.Topics[2] == common.Hash(leaf) &&
			len(lg.Data) == 32 {
			return lg
		}
	}
	return nil
}

func (m OutcomeMemberEvidence) settlement(leaf OutcomeLeaf, what string) (*types.Header, *types.Transaction, *types.Receipt, error) {
	if m.Transaction == nil {
		return nil, nil, nil, evidenceFail("a status-%d member carries no transaction evidence", leaf.Status)
	}
	hdr, tx, rcpt, err := m.Transaction.verify(leaf.Tx, leaf.BlockHash, leaf.BlockNumber, what)
	if err != nil {
		return nil, nil, nil, err
	}
	if hdr.ReceiptHash != common.Hash(leaf.ReceiptsRoot) {
		return nil, nil, nil, evidenceFail("%s: block %d's receiptsRoot is %s, the leaf names 0x%x", what, leaf.BlockNumber,
			hdr.ReceiptHash.Hex(), leaf.ReceiptsRoot)
	}
	return hdr, tx, rcpt, nil
}

func (m OutcomeMemberEvidence) verifyExecuted(chainID int64, a *anchorFacts, leaf OutcomeLeaf, account common.Address, chk *OutcomeEvidenceCheck) error {
	hdr, _, rcpt, err := m.settlement(leaf, "settlement")
	if err != nil {
		return err
	}
	if rcpt.Status != types.ReceiptStatusSuccessful {
		return evidenceFail("status %d (executed) but the settlement %s's receipt is status %d", leaf.Status, common.Hash(leaf.Tx).Hex(), rcpt.Status)
	}
	lg := leafConsumedIn(rcpt, account, leaf.BatchLeaf)
	if lg == nil {
		return evidenceFail("the settlement's receipt holds no LeafConsumed of leaf 0x%x from the member's account %s", leaf.BatchLeaf[:8],
			account.Hex())
	}
	if lg.Topics[1] != common.Hash(a.bundleID) {
		return evidenceFail("status %d (executed under this anchor) but the leaf was consumed under 0x%x", leaf.Status, lg.Topics[1][:8])
	}
	if !bytes.Equal(lg.Data, leaf.OperationID[:]) {
		return evidenceFail("the LeafConsumed log names operation 0x%x, the leaf 0x%x", lg.Data[:8], leaf.OperationID[:8])
	}

	// The committed effects: every event among the proven receipt's logs, every slot proven at the block's state root.
	logs := make([]LogEntry, 0, len(rcpt.Logs))
	for _, l := range rcpt.Logs {
		logs = append(logs, LogEntry{Address: l.Address, Topics: l.Topics, Data: l.Data})
	}
	var missing, unset []CommittedEffect
	events, state := make([][]ExpectedEvent, len(m.Legs)), make([][]ExpectedStateSlot, len(m.Legs))
	for li, l := range m.Legs {
		for ei, e := range l.Events {
			ev := ExpectedEvent{Contract: e.Contract, Topic0: e.Topic0, DataHash: e.DataHash}
			events[li] = append(events[li], ev)
			if !eventPresent(logs, ev) {
				missing = append(missing, CommittedEffect{Leg: uint64(li), Index: uint64(ei)})
			}
		}
		state[li] = append(state[li], l.State...)
		holds, err := slotsHoldAt(m.StateProofs, hdr.Root, l.State)
		if err != nil {
			return evidenceFail("leg %d's committed state is proven neither present nor absent at block %d's state root %s: %v", li,
				leaf.BlockNumber, hdr.Root.Hex(), err)
		}
		for si, ok := range holds {
			if !ok {
				unset = append(unset, CommittedEffect{Leg: uint64(li), Index: uint64(si)})
			}
		}
	}
	committed := CommittedEffectsHash(events, state)
	nEvents, nSlots := 0, 0
	for li := range events {
		nEvents, nSlots = nEvents+len(events[li]), nSlots+len(state[li])
	}
	switch leaf.Status {
	case OutcomeExecuted:
		if len(missing) > 0 || len(unset) > 0 {
			return evidenceFail("status 1 (every committed effect proven) but the evidence proves %d event(s) absent and %d slot(s) "+
				"not holding their value", len(missing), len(unset))
		}
		if committed != leaf.EffectsHash {
			return evidenceFail("the committed effects hash to 0x%x, the leaf states 0x%x", committed, leaf.EffectsHash)
		}
	case OutcomeEffectsNotProven:
		if len(missing) == 0 && len(unset) == 0 {
			return evidenceFail("status 2 (a committed effect absent) but every committed effect is proven present")
		}
		want, err := ShortfallEffectsHash(committed, missing, unset)
		if err != nil {
			return evidenceFail("%v", err)
		}
		if want != leaf.EffectsHash {
			return evidenceFail("the proven shortfall hashes to 0x%x, the leaf states 0x%x", want, leaf.EffectsHash)
		}
	}
	chk.ConsumedUnder = a.bundleID
	chk.proved("member: settlement %s and its receipt (status 1) proven at index %d into block %d (header hashes to 0x%x, "+
		"receiptsRoot 0x%x); the account %s emitted LeafConsumed(this anchor, its leaf, its operation)", common.Hash(leaf.Tx).Hex(),
		m.Transaction.Index, leaf.BlockNumber, leaf.BlockHash[:8], leaf.ReceiptsRoot[:8], account.Hex())
	chk.proved("member: %d committed event(s) checked among the proven receipt's logs and %d committed slot(s) proven at the block's "+
		"state root; %d absent, %d not holding - consistent with status %d and effects hash 0x%x", nEvents, nSlots, len(missing),
		len(unset), leaf.Status, leaf.EffectsHash[:8])
	chk.unproven("that the LeafConsumed log's emitter %s runs CertenAccountV7_2 code (an account consumes a leaf only by "+
		"executing exactly the calls it recomputes into it)", account.Hex())
	return nil
}

func (m OutcomeMemberEvidence) verifyConsumedElsewhere(a *anchorFacts, leaf OutcomeLeaf, account common.Address, chk *OutcomeEvidenceCheck) error {
	_, _, rcpt, err := m.settlement(leaf, "consuming transaction")
	if err != nil {
		return err
	}
	if rcpt.Status != types.ReceiptStatusSuccessful {
		return evidenceFail("status 4 (consumed elsewhere) but the consuming transaction's receipt is status %d", rcpt.Status)
	}
	lg := leafConsumedIn(rcpt, account, leaf.BatchLeaf)
	if lg == nil {
		return evidenceFail("the consuming transaction's receipt holds no LeafConsumed of leaf 0x%x from the member's account %s",
			leaf.BatchLeaf[:8], account.Hex())
	}
	if lg.Topics[1] == common.Hash(a.bundleID) {
		return evidenceFail("status 4 (consumed under another anchor) but the leaf was consumed under this anchor")
	}
	chk.ConsumedUnder = lg.Topics[1]
	chk.proved("member: the leaf was consumed under another anchor, 0x%x, by %s, its receipt proven into block %d (header hashes "+
		"to 0x%x)", lg.Topics[1][:8], common.Hash(leaf.Tx).Hex(), leaf.BlockNumber, leaf.BlockHash[:8])
	chk.unproven("that the LeafConsumed log's emitter %s runs CertenAccountV7_2 code", account.Hex())
	return nil
}

func (m OutcomeMemberEvidence) verifyNotSettled(leaf OutcomeLeaf, account common.Address, chk *OutcomeEvidenceCheck) error {
	if m.Deadline <= 0 {
		return evidenceFail("a member not settled with no deadline")
	}
	if m.FinalityMargin != int64(nonSettlementFinality.Seconds()) {
		return evidenceFail("finality margin %ds, the rule is %ds", m.FinalityMargin, int64(nonSettlementFinality.Seconds()))
	}
	horizon := uint64(m.Deadline + m.FinalityMargin)
	claim, err := decodeEvidenceHeader(m.ClaimHeader, "claim block")
	if err != nil {
		return err
	}
	if claim.Hash() != common.Hash(leaf.BlockHash) || claim.Number.Uint64() != leaf.BlockNumber ||
		claim.ReceiptHash != common.Hash(leaf.ReceiptsRoot) {
		return evidenceFail("the claim header is block %d %s (receiptsRoot %s), the leaf names block %d 0x%x (receiptsRoot 0x%x)",
			claim.Number.Uint64(), claim.Hash().Hex(), claim.ReceiptHash.Hex(), leaf.BlockNumber, leaf.BlockHash, leaf.ReceiptsRoot)
	}
	if claim.Time <= horizon {
		return evidenceFail("status 3 (not settled) at block %d, whose time %d is not past the deadline %d and margin %ds", leaf.BlockNumber,
			claim.Time, m.Deadline, m.FinalityMargin)
	}
	parent, err := decodeEvidenceHeader(m.ClaimParentHeader, "claim parent block")
	if err != nil {
		return err
	}
	if parent.Hash() != claim.ParentHash {
		return evidenceFail("the claim block's parent is %s, the evidence carries %s", claim.ParentHash.Hex(), parent.Hash().Hex())
	}
	if parent.Time > horizon {
		return evidenceFail("the claim block %d is not the FIRST past the horizon: its parent's time %d is already past %d",
			leaf.BlockNumber, parent.Time, horizon)
	}
	chk.proved("member: not settled - block %d (header hashes to 0x%x) is the first past deadline %d + %ds: its time %d, its "+
		"parent's %d", leaf.BlockNumber, leaf.BlockHash[:8], m.Deadline, m.FinalityMargin, claim.Time, parent.Time)
	if leaf.Tx != ([32]byte{}) {
		if m.Transaction == nil {
			return evidenceFail("status 3 names attempt %s and carries no evidence of it", common.Hash(leaf.Tx).Hex())
		}
		hdr, err := decodeEvidenceHeader(m.Transaction.Header, "attempt")
		if err != nil {
			return err
		}
		ahdr, tx, rcpt, err := m.Transaction.verify(leaf.Tx, hdr.Hash(), 0, "attempt")
		if err != nil {
			return err
		}
		if rcpt.Status != types.ReceiptStatusFailed {
			return evidenceFail("the named attempt %s did not revert", common.Hash(leaf.Tx).Hex())
		}
		if tx.To() == nil || *tx.To() != account {
			return evidenceFail("the named attempt %s is not a call to the member's account %s", common.Hash(leaf.Tx).Hex(), account.Hex())
		}
		if ahdr.Number.Uint64() > leaf.BlockNumber {
			return evidenceFail("the named attempt is in block %d, after the claim block %d", ahdr.Number.Uint64(), leaf.BlockNumber)
		}
		chk.proved("member: its last named attempt %s reverted, its receipt proven into block %d (header hashes to %s)",
			common.Hash(leaf.Tx).Hex(), ahdr.Number.Uint64(), ahdr.Hash().Hex()[:18])
	} else if m.Transaction != nil {
		return evidenceFail("status 3 names no attempt, and the evidence carries a transaction")
	}
	chk.unproven("that the leaf stayed unconsumed through block %d (an absent LeafConsumed is not provable from one block: it is "+
		"the quorum's certified statement), and that the deadline %d is the one the user signed", leaf.BlockNumber, m.Deadline)
	return nil
}

// SortQuorumValidators orders a validator set as the anchor's set root does: ascending by address.
func SortQuorumValidators(v []OutcomeQuorumValidator) {
	sort.Slice(v, func(i, j int) bool {
		a, b := common.HexToAddress(v[i].Address), common.HexToAddress(v[j].Address)
		return bytes.Compare(a[:], b[:]) < 0
	})
}

// verifyOutcomeAggregate checks a BLS aggregate the recording validator held: its key is the aggregate of exactly the
// signers' keys (signersKey), and the signature verifies under it over the outcome message, hashed to G1 as the quorum
// signs (HashMessageToG1V2).
func verifyOutcomeAggregate(signersKey *bls.PublicKey, sigHex, keyHex string, msg [32]byte) error {
	sig, err := bls.SignatureFromHex(strings.TrimPrefix(sigHex, "0x"))
	if err != nil {
		return evidenceFail("the BLS aggregate signature: %v", err)
	}
	stated, err := bls.PublicKeyFromHex(strings.TrimPrefix(keyHex, "0x"))
	if err != nil {
		return evidenceFail("the BLS aggregate key: %v", err)
	}
	if !stated.Equal(signersKey) {
		return evidenceFail("the stated aggregate key is not the aggregate of the signers' keys")
	}
	if !signersKey.VerifyG1(sig, bls_zkp.HashMessageToG1V2(msg)) {
		return evidenceFail("the BLS aggregate signature does not verify under the signers' aggregate key over the outcome message")
	}
	return nil
}
