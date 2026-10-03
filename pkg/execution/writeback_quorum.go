package execution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/ethereum/go-ethereum/common"
)

// The Accumulate write-back's quorum, verifiable from the entry alone (RB5-F14).
//
// The write-back's SEC-14 fields claimed a third party could verify the >=2/3 BLS aggregate. In production they were
// never filled: the live write-back of 2026-10-03 carried a zero validator_set_root and snapshot id, an empty bitfield
// and a 0/0 threshold, beside an aggregate signature over a message hash whose preimage was not written and signers
// whose keys were not named. Now Phase 9 states the registry snapshot Phase 8 counted against (every validator's id,
// address, BLS key and power, and the block it was taken at), the participants, the threshold rule, the exact message
// preimage, the signature scheme and its domain - and VerifyWriteBackQuorum checks all of it from those entries.

// WriteBackSignatureScheme names how the aggregate is signed: BLS12-381 with G1 signatures and G2 keys, the message
// hashed to G1 with RFC 9380 hash_to_curve (BLS12381G1_XMD:SHA-256_SSWU_RO_, DST bls.SignatureDST, RB5-F54), over
// sha256(domain || messageHash). A write-back without this entry predates RB5-F54, and its aggregate is of the scheme
// whose hash points had a public discrete log: it is not evidence of a quorum.
const WriteBackSignatureScheme = "bls12381-g1-sig/rfc9380-xmd-sha256-sswu-ro/" + bls.SignatureDST + "/sha256(domain||messageHash)"

// ErrWriteBackQuorum is wrapped by every refusal of a write-back's quorum evidence.
var ErrWriteBackQuorum = errors.New("write-back quorum")

// WriteBackValidator is one validator of the snapshot the quorum was counted against, as the write-back states it.
type WriteBackValidator struct {
	Index     uint32 `json:"index"`
	ID        string `json:"id"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"` // hex BLS12-381 G2
	Power     string `json:"power"`      // decimal
}

// quorumEvidence fills a write-back aggregate's verifiable fields from Phase 8's snapshot and fold. It refuses a
// message preimage that does not hash to the signed message and a counted signer that is not in the snapshot: a
// write-back never states a quorum its own entries cannot establish.
func quorumEvidence(agg *AggregatedAttestation, set *ValidatorSetSnapshot, folded *attestation.AggregatedAttestation,
	threshold *attestation.ThresholdConfig, domain string) error {
	if set == nil || len(set.Validators) == 0 {
		return fmt.Errorf("%w: no validator set snapshot", ErrWriteBackQuorum)
	}
	if folded == nil || len(folded.Attestations) == 0 || folded.Attestations[0].Message == nil {
		return fmt.Errorf("%w: no counted attestation carrying its message", ErrWriteBackQuorum)
	}
	preimage, err := json.Marshal(folded.Attestations[0].Message)
	if err != nil {
		return fmt.Errorf("%w: encode the attested message: %v", ErrWriteBackQuorum, err)
	}
	if sha256.Sum256(preimage) != folded.MessageHash {
		return fmt.Errorf("%w: the attested message does not hash to the message the quorum signed", ErrWriteBackQuorum)
	}
	index := make(map[string]uint32, len(set.Validators))
	validators := make([]WriteBackValidator, len(set.Validators))
	for i, v := range set.Validators {
		index[hex.EncodeToString(v.PublicKey)] = v.Index
		validators[i] = WriteBackValidator{Index: v.Index, ID: v.ValidatorID, Address: v.Address.Hex(),
			PublicKey: hex.EncodeToString(v.PublicKey), Power: v.Weight.String()}
	}
	bitfield := make([]byte, (len(set.Validators)+7)/8)
	signed := big.NewInt(0)
	for _, att := range folded.Attestations {
		i, ok := index[hex.EncodeToString(att.PublicKey)]
		if !ok {
			return fmt.Errorf("%w: counted signer %s is not in the snapshot", ErrWriteBackQuorum, att.ValidatorID)
		}
		if bitfield[i/8]&(1<<(i%8)) != 0 {
			return fmt.Errorf("%w: signer %s counted twice", ErrWriteBackQuorum, att.ValidatorID)
		}
		bitfield[i/8] |= 1 << (i % 8)
		signed.Add(signed, set.Validators[i].Weight)
	}
	// The fold's achieved weight is what Phase 8 counted; it must be exactly the snapshot weight of the signers it
	// counted. A disagreement is stated by neither value (RB3-F81: no signed power is ever substituted) - it is refused.
	if !signed.IsInt64() || signed.Int64() != folded.AchievedWeight {
		return fmt.Errorf("%w: Phase 8 achieved weight %d, the signers it counted hold %s", ErrWriteBackQuorum, folded.AchievedWeight, signed)
	}
	agg.MessagePreimage = preimage
	agg.Validators = validators
	agg.SnapshotBlock = set.BlockNumber
	agg.SnapshotID = set.SnapshotID
	agg.ValidatorRoot = set.ValidatorRoot
	agg.ValidatorBitfield = bitfield
	agg.TotalVotingPower = new(big.Int).Set(set.TotalWeight)
	agg.SignedVotingPower = signed
	agg.ThresholdNumerator, agg.ThresholdDenominator = threshold.Numerator, threshold.Denominator
	agg.MinValidators = threshold.MinValidators
	agg.SignatureScheme = WriteBackSignatureScheme
	agg.AttestationDomain = domain
	return nil
}

// validatorSetJSON is the write-back's validator_set entry: the snapshot's validators as JSON, or "" when none.
func validatorSetJSON(vs []WriteBackValidator) string {
	if len(vs) == 0 {
		return ""
	}
	b, err := json.Marshal(vs)
	if err != nil {
		return ""
	}
	return string(b)
}

// WriteBackQuorumFromEntry reads the quorum a write-back entry states.
func WriteBackQuorumFromEntry(e *CertenDataEntry) (*WriteBackQuorum, error) {
	if e == nil {
		return nil, fmt.Errorf("%w: no entry", ErrWriteBackQuorum)
	}
	q := &WriteBackQuorum{
		AggregateSignature: e.AggregateSignature, MessageHash: e.AttestationMessageHash, MessagePreimage: e.AttestationMessage,
		ValidatorSetRoot: e.ValidatorSetRoot, SnapshotID: e.AttestationSnapshotID, SnapshotBlock: e.SnapshotBlock,
		Bitfield: e.ValidatorBitfield, TotalPower: e.TotalPower, ThresholdNumerator: e.ThresholdNumerator,
		ThresholdDenominator: e.ThresholdDenominator, MinValidators: e.MinValidators, SignatureScheme: e.SignatureScheme,
		Domain: e.AttestationDomain,
	}
	if e.ValidatorSet != "" {
		if err := json.Unmarshal([]byte(e.ValidatorSet), &q.Validators); err != nil {
			return nil, fmt.Errorf("%w: validator_set: %v", ErrWriteBackQuorum, err)
		}
	}
	return q, nil
}

// WriteBackQuorumFromEntries reads the quorum from a write-back's raw data entries, each "key=value" as
// ToDoubleHashFormat writes them - what a third party fetches from Accumulate. A write-back that carries no
// signature_scheme predates RB5-F14 and is reported by ErrWriteBackPredatesEvidence.
func WriteBackQuorumFromEntries(entries [][]byte) (*WriteBackQuorum, error) {
	kv := make(map[string]string, len(entries))
	for _, e := range entries {
		if k, v, ok := strings.Cut(string(e), "="); ok {
			if _, dup := kv[k]; dup {
				return nil, fmt.Errorf("%w: entry %q appears twice", ErrWriteBackQuorum, k)
			}
			kv[k] = v
		}
	}
	if kv["signature_scheme"] == "" {
		return nil, ErrWriteBackPredatesEvidence
	}
	num := func(k string) (uint64, error) {
		v, err := strconv.ParseUint(kv[k], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: %s %q", ErrWriteBackQuorum, k, kv[k])
		}
		return v, nil
	}
	block, err := num("snapshot_block")
	if err != nil {
		return nil, err
	}
	tn, err := num("threshold_numerator")
	if err != nil {
		return nil, err
	}
	td, err := num("threshold_denominator")
	if err != nil {
		return nil, err
	}
	minV, err := num("min_validators")
	if err != nil {
		return nil, err
	}
	e := &CertenDataEntry{
		AggregateSignature: kv["aggregate_signature"], AttestationMessageHash: kv["attestation_message_hash"],
		AttestationMessage: kv["attestation_message"], ValidatorSetRoot: kv["validator_set_root"],
		AttestationSnapshotID: kv["attestation_snapshot_id"], SnapshotBlock: block, ValidatorBitfield: kv["validator_bitfield"],
		TotalPower: kv["total_power"], ThresholdNumerator: tn, ThresholdDenominator: td, MinValidators: int(minV),
		SignatureScheme: kv["signature_scheme"], AttestationDomain: kv["attestation_domain"], ValidatorSet: kv["validator_set"],
	}
	return WriteBackQuorumFromEntry(e)
}

// ErrWriteBackPredatesEvidence: the write-back was written before RB5-F14 and states its quorum without the means to
// check it - a named weaker state, not proof of tampering.
var ErrWriteBackPredatesEvidence = errors.New("the write-back predates its quorum evidence (RB5-F14): it states a quorum it carries no means to check")

// WriteBackQuorum is what a write-back states about its quorum, as its entries carry it.
type WriteBackQuorum struct {
	AggregateSignature   string
	MessageHash          string
	MessagePreimage      string // hex
	ValidatorSetRoot     string
	SnapshotID           string
	SnapshotBlock        uint64
	Validators           []WriteBackValidator
	Bitfield             string
	TotalPower           string
	ThresholdNumerator   uint64
	ThresholdDenominator uint64
	MinValidators        int
	SignatureScheme      string
	Domain               string
}

// WriteBackQuorumReport is what VerifyWriteBackQuorum established.
type WriteBackQuorumReport struct {
	Signers        []string
	SignedPower    *big.Int
	TotalPower     *big.Int
	RequiredPower  *big.Int
	AttestedResult string // the attested message, as written
}

// VerifyWriteBackQuorum checks a write-back's quorum from its own entries: the message preimage hashes to the signed
// message; the validator list reproduces the stated validator root and snapshot id; the bitfield's validators carry
// at least the threshold Phase 8 applies (total*num/den + 1, and at least MinValidators signers); and the aggregate
// signature verifies under exactly their keys, in the stated scheme and domain.
func VerifyWriteBackQuorum(q *WriteBackQuorum) (*WriteBackQuorumReport, error) {
	fail := func(format string, a ...any) (*WriteBackQuorumReport, error) {
		return nil, fmt.Errorf("%w: "+format, append([]any{ErrWriteBackQuorum}, a...)...)
	}
	if q == nil {
		return fail("absent")
	}
	if q.SignatureScheme != WriteBackSignatureScheme {
		return fail("signature scheme %q is not %q; a write-back without it predates RB5-F54 and is not evidence of a quorum",
			q.SignatureScheme, WriteBackSignatureScheme)
	}
	if q.Domain == "" {
		return fail("no signing domain")
	}
	preimage, err := hex.DecodeString(strings.TrimPrefix(q.MessagePreimage, "0x"))
	if err != nil || len(preimage) == 0 {
		return fail("no message preimage")
	}
	msgHash := sha256.Sum256(preimage)
	if !strings.EqualFold(hex.EncodeToString(msgHash[:]), strings.TrimPrefix(q.MessageHash, "0x")) {
		return fail("the message preimage does not hash to the stated message hash")
	}
	if len(q.Validators) == 0 {
		return fail("no validator set")
	}
	set := &ValidatorSetSnapshot{BlockNumber: q.SnapshotBlock, TotalWeight: big.NewInt(0), Validators: make([]ValidatorEntry, len(q.Validators))}
	for i, v := range q.Validators {
		if v.Index != uint32(i) {
			return fail("validator %d is listed at index %d", i, v.Index)
		}
		pub, err := hex.DecodeString(strings.TrimPrefix(v.PublicKey, "0x"))
		if err != nil {
			return fail("validator %d key: %v", i, err)
		}
		power, ok := new(big.Int).SetString(v.Power, 10)
		if !ok || power.Sign() <= 0 {
			return fail("validator %d power %q", i, v.Power)
		}
		if !common.IsHexAddress(v.Address) {
			return fail("validator %d address %q", i, v.Address)
		}
		set.Validators[i] = ValidatorEntry{ValidatorID: v.ID, Address: common.HexToAddress(v.Address), PublicKey: pub, Weight: power, Index: uint32(i)}
		set.TotalWeight.Add(set.TotalWeight, power)
	}
	set.ValidatorRoot = set.ComputeValidatorRoot()
	if !strings.EqualFold(hex.EncodeToString(set.ValidatorRoot[:]), strings.TrimPrefix(q.ValidatorSetRoot, "0x")) {
		return fail("the listed validators do not reproduce the stated validator set root")
	}
	sid := set.ComputeSnapshotID()
	if !strings.EqualFold(hex.EncodeToString(sid[:]), strings.TrimPrefix(q.SnapshotID, "0x")) {
		return fail("the listed validators and block do not reproduce the stated snapshot id")
	}
	if q.TotalPower != set.TotalWeight.String() {
		return fail("stated total power %s, the listed validators sum to %s", q.TotalPower, set.TotalWeight)
	}
	bitfield, err := hex.DecodeString(strings.TrimPrefix(q.Bitfield, "0x"))
	if err != nil || len(bitfield) != (len(q.Validators)+7)/8 {
		return fail("bitfield %q does not cover %d validators", q.Bitfield, len(q.Validators))
	}
	var keys []*bls.PublicKey
	rep := &WriteBackQuorumReport{SignedPower: big.NewInt(0), TotalPower: set.TotalWeight, AttestedResult: string(preimage)}
	for i, v := range set.Validators {
		if bitfield[i/8]&(1<<(i%8)) == 0 {
			continue
		}
		pk, err := bls.PublicKeyFromBytes(v.PublicKey)
		if err != nil {
			return fail("signer %s key: %v", v.ValidatorID, err)
		}
		keys = append(keys, pk)
		rep.Signers = append(rep.Signers, v.ValidatorID)
		rep.SignedPower.Add(rep.SignedPower, v.Weight)
	}
	if extra := len(q.Validators) % 8; extra != 0 && bitfield[len(bitfield)-1]>>extra != 0 {
		return fail("bitfield marks validators beyond the set")
	}
	if q.ThresholdDenominator == 0 || q.ThresholdNumerator == 0 {
		return fail("threshold %d/%d", q.ThresholdNumerator, q.ThresholdDenominator)
	}
	if !set.TotalWeight.IsInt64() {
		return fail("total power does not fit 64 bits")
	}
	cfg := attestation.ThresholdConfig{Numerator: q.ThresholdNumerator, Denominator: q.ThresholdDenominator, MinValidators: q.MinValidators}
	rep.RequiredPower = big.NewInt(cfg.CalculateThresholdWeight(set.TotalWeight.Int64()))
	if rep.SignedPower.Cmp(rep.RequiredPower) < 0 {
		return fail("signed power %s is below the required %s of %s", rep.SignedPower, rep.RequiredPower, set.TotalWeight)
	}
	if len(keys) < q.MinValidators {
		return fail("%d signers, at least %d are required", len(keys), q.MinValidators)
	}
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(q.AggregateSignature, "0x"))
	if err != nil {
		return fail("aggregate signature: %v", err)
	}
	sig, err := bls.SignatureFromBytes(sigBytes)
	if err != nil {
		return fail("aggregate signature: %v", err)
	}
	if !bls.VerifyAggregateSignatureWithDomain(sig, keys, msgHash[:], q.Domain) {
		return fail("the aggregate signature does not verify under the %d signers' keys", len(keys))
	}
	return rep, nil
}
