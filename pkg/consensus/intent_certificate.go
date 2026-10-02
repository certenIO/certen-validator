package consensus

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/accumulateset"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/intentcert"
	"github.com/certen/independant-validator/pkg/ledger"
	govproof "github.com/certen/independant-validator/pkg/proof"
)

// The per-intent signature CERTEN's quorum certifies (RB5 D3).
//
// A ValidatorBlock carries its validator's BLS signature over the per-intent message (pkg/intentcert): the
// operation, govRoot v2 over the proof's L1-L4 and canonical G0-G2, the Accumulate validator set its L4 was
// verified against under the chain's incarnation, the governance commitment and CERTEN's set root, on this
// CERTEN chain. FinalizeBlock recomputes every one of those from the block's OWN contents and the committed
// registry - nothing the block claims is taken on its word - and verifies the signature against the key the
// registry holds for the validator the block names. That is what authenticates a ValidatorBlock (RB5-F25):
// before it, a block's validator_id was self-declared and bound to no key.

// IntentCertificateEvidence is what a ValidatorBlock adds for its intent signature. The claimed values are
// recomputed by the verifier and must match; they are carried so a mismatch names which input disagrees.
type IntentCertificateEvidence struct {
	// RegistryVersion is the BLS registry the block was built against; it must be the one in force at its height.
	RegistryVersion uint64 `json:"registry_version"`
	KeyPageURL      string `json:"key_page_url"`
	KeyBookURL      string `json:"key_book_url"`
	// AuthorizationRecord is G1's vote record. The governance decision record is recomputed from it and the
	// block's own G0, so the commitment is bound to the transaction this block proves.
	AuthorizationRecord json.RawMessage `json:"authorization_record"`
	// VoteEvidence is the record's evidence (govvote.Evidence): the governed transaction, the chain-bound signatures
	// and votes, the page histories from genesis. The record is evaluated again from it (RB4-F66).
	VoteEvidence json.RawMessage `json:"vote_evidence"`
	// ChainedProof is the full L1-L4 proof the block's lite_client_proof is the projection of. It is verified, and
	// the projection required to be exactly the block's (RB5-F11).
	ChainedProof      *chained_proof.ChainedProof `json:"chained_proof"`
	GovRootV2         string                      `json:"gov_root_v2"`         // hex32, claimed
	AccumulateSetRoot string                      `json:"accumulate_set_root"` // hex32, claimed
	Message           string                      `json:"message"`             // hex32, claimed
	Signature         string                      `json:"signature"`           // hex G1 (compressed), over Message
}

// Refusals of an intent certificate, each by name.
var (
	ErrIntentCertificateMissing    = errors.New("intent certificate missing")
	ErrIntentSignerNotRegistered   = errors.New("the block's validator is not in the BLS registry in force")
	ErrIntentRegistryVersion       = errors.New("the block was built against a BLS registry not in force at its height")
	ErrIntentGovRootMismatch       = errors.New("govRoot v2 recomputed from the block differs from the one it claims")
	ErrIntentAccumulateSetMismatch = errors.New("the Accumulate set root recomputed from the block's L4 differs from the one it claims")
	ErrIntentMessageMismatch       = errors.New("the intent message recomputed from the block differs from the one it claims")
	ErrIntentSignatureInvalid      = errors.New("the intent signature does not verify against the validator's registered BLS key")
	ErrIntentGovernanceUnderivable = errors.New("the governance commitment cannot be derived from the block")
	ErrIntentInputsMissing         = errors.New("the block lacks an input of its intent message")
)

// intentInputs recomputes every input of the block's intent message from the block and the registry.
func intentInputs(vb *ValidatorBlock, chainID string, reg *ledger.BLSRegistryRecord) (intentcert.MessageInputs, [32]byte, [32]byte, error) {
	ev := vb.IntentCertificate
	var in intentcert.MessageInputs
	var govRoot, accRoot [32]byte
	op, err := hex32(vb.CrossChainProof.OperationID)
	if err != nil {
		return in, govRoot, accRoot, fmt.Errorf("%w: operation id: %v", ErrIntentInputsMissing, err)
	}
	gp := &vb.GovernanceProof
	if vb.LiteClientProof == nil || gp.G0Proof == nil || gp.G1Proof == nil || gp.G2Proof == nil {
		return in, govRoot, accRoot, fmt.Errorf("%w: the L1-L4 proof and G0-G2 are all required", ErrIntentInputsMissing)
	}
	govRoot, _, err = intentcert.GovRootV2(intentcert.GovRootV2Inputs{Lite: vb.LiteClientProof, G0: gp.G0Proof, G1: gp.G1Proof,
		G2: gp.G2Proof, KeyPageURL: ev.KeyPageURL, KeyBookURL: ev.KeyBookURL, OperationID: op})
	if err != nil {
		return in, govRoot, accRoot, fmt.Errorf("%w: %v", ErrIntentGovRootMismatch, err)
	}
	inc, err := hex32(reg.AccumulateIncarnation)
	if err != nil {
		return in, govRoot, accRoot, fmt.Errorf("registry incarnation: %w", err)
	}
	accRoot, err = accumulateset.CommittedAccumulateSetRoot(vb.LiteClientProof.Layer4DN, inc)
	if err != nil {
		return in, govRoot, accRoot, fmt.Errorf("%w: %v", ErrIntentAccumulateSetMismatch, err)
	}
	rec, err := authorizationOf(ev)
	if err != nil {
		return in, govRoot, accRoot, err
	}
	gdr, err := govproof.GovernanceDecisionRecord(gp.G0Proof, rec)
	if err != nil {
		return in, govRoot, accRoot, fmt.Errorf("%w: %v", ErrIntentGovernanceUnderivable, err)
	}
	setRoot, err := hex32(reg.CertenSetRoot)
	if err != nil {
		return in, govRoot, accRoot, fmt.Errorf("registry set root: %w", err)
	}
	in = intentcert.MessageInputs{CertenChainID: chainID, OperationID: op, GovRootV2: govRoot, AccumulateSetRoot: accRoot,
		Incarnation: inc, GovernanceCommitment: govproof.GovernanceCommitment(gdr), CertenSetRoot: setRoot}
	return in, govRoot, accRoot, nil
}

// registryMember is the member the block names, or nil.
func registryMember(reg *ledger.BLSRegistryRecord, validatorID string) *ledger.BLSRegistryMember {
	for i := range reg.Members {
		if reg.Members[i].ValidatorID == validatorID {
			return &reg.Members[i]
		}
	}
	return nil
}

// VerifyIntentCertificate judges a ValidatorBlock's intent signature against the registry in force at its height
// (reg) on CERTEN chain chainID. It returns the recomputed message.
func VerifyIntentCertificate(vb *ValidatorBlock, chainID string, reg *ledger.BLSRegistryRecord) ([32]byte, error) {
	ev := vb.IntentCertificate
	if ev == nil {
		return [32]byte{}, ErrIntentCertificateMissing
	}
	if reg == nil || ev.RegistryVersion != reg.Version {
		return [32]byte{}, fmt.Errorf("%w (built against v%d)", ErrIntentRegistryVersion, ev.RegistryVersion)
	}
	member := registryMember(reg, vb.ValidatorID)
	if member == nil {
		return [32]byte{}, fmt.Errorf("%w: %q", ErrIntentSignerNotRegistered, vb.ValidatorID)
	}
	in, govRoot, accRoot, err := intentInputs(vb, chainID, reg)
	if err != nil {
		return [32]byte{}, err
	}
	rec, err := authorizationOf(ev)
	if err != nil {
		return [32]byte{}, err
	}
	if err := verifyIntentProof(vb, rec); err != nil {
		return [32]byte{}, err
	}
	if !hexEquals(ev.GovRootV2, govRoot) {
		return [32]byte{}, fmt.Errorf("%w: claims %s, is %x", ErrIntentGovRootMismatch, ev.GovRootV2, govRoot)
	}
	if !hexEquals(ev.AccumulateSetRoot, accRoot) {
		return [32]byte{}, fmt.Errorf("%w: claims %s, is %x", ErrIntentAccumulateSetMismatch, ev.AccumulateSetRoot, accRoot)
	}
	msg, err := intentcert.Message(in)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrIntentInputsMissing, err)
	}
	if !hexEquals(ev.Message, msg) {
		return [32]byte{}, fmt.Errorf("%w: claims %s, is %x", ErrIntentMessageMismatch, ev.Message, msg)
	}
	keyRaw, err := hex.DecodeString(member.BLSPubKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("registry key of %s: %w", member.ValidatorID, err)
	}
	pub, err := bls.PublicKeyFromBytes(keyRaw)
	if err != nil {
		return [32]byte{}, fmt.Errorf("registry key of %s: %w", member.ValidatorID, err)
	}
	sigRaw, err := hex.DecodeString(strings.TrimPrefix(ev.Signature, "0x"))
	if err != nil || bls.ValidateBLSSignatureSubgroup(sigRaw) != nil {
		return [32]byte{}, fmt.Errorf("%w: not a valid G1 signature", ErrIntentSignatureInvalid)
	}
	sig, err := bls.SignatureFromBytes(sigRaw)
	if err != nil || !pub.VerifyG1(sig, bls_zkp.HashMessageToG1V2(msg)) {
		return [32]byte{}, ErrIntentSignatureInvalid
	}
	return msg, nil
}

// BuildIntentCertificate is the proposer's half: it fills the block's evidence for the registry reg and signs the
// message with sk, then checks its own result with the verifier - a block this node would refuse is never built.
func BuildIntentCertificate(vb *ValidatorBlock, chainID string, reg *ledger.BLSRegistryRecord, sk *bls.PrivateKey,
	keyPageURL, keyBookURL string, authorization *govproof.AuthorizationRecord, voteEvidence json.RawMessage,
	cp *chained_proof.ChainedProof) error {
	if reg == nil {
		return fmt.Errorf("no BLS registry is recorded on this chain")
	}
	if authorization == nil || len(voteEvidence) == 0 {
		return fmt.Errorf("%w: the vote record and its evidence are both required", ErrIntentGovernanceUnderivable)
	}
	if cp == nil {
		return fmt.Errorf("%w: no chained proof", ErrIntentProofInvalid)
	}
	rec, err := json.Marshal(authorization)
	if err != nil {
		return err
	}
	vb.IntentCertificate = &IntentCertificateEvidence{RegistryVersion: reg.Version, KeyPageURL: keyPageURL,
		KeyBookURL: keyBookURL, AuthorizationRecord: rec, VoteEvidence: voteEvidence, ChainedProof: cp}
	in, govRoot, accRoot, err := intentInputs(vb, chainID, reg)
	if err != nil {
		vb.IntentCertificate = nil
		return err
	}
	msg, err := intentcert.Message(in)
	if err != nil {
		vb.IntentCertificate = nil
		return err
	}
	ev := vb.IntentCertificate
	ev.GovRootV2 = "0x" + hex.EncodeToString(govRoot[:])
	ev.AccumulateSetRoot = "0x" + hex.EncodeToString(accRoot[:])
	ev.Message = "0x" + hex.EncodeToString(msg[:])
	ev.Signature = hex.EncodeToString(bls_zkp.SignV6_1PreExec(sk, msg).Bytes())
	if _, err := VerifyIntentCertificate(vb, chainID, reg); err != nil {
		vb.IntentCertificate = nil
		return fmt.Errorf("the intent certificate this node built does not verify: %w", err)
	}
	return nil
}

// ErrIntentProofInvalid: the block's proof does not verify offline.
var ErrIntentProofInvalid = errors.New("the block's proof does not verify offline")

// verifyIntentProof re-verifies, offline and deterministically, what the block proves - what cmd/proofverify
// checks of a stored proof (RB5-F11; before it, consensus verified no proof content):
//
//   - the L1-L4 chained proof (receipts, both L4 legs' signatures, membership and quorum, and each leg's binding
//     to the layer beneath), and that the block's lite_client_proof is exactly its projection;
//   - G0 bound to that proof (its entry, witness and execution block are L1's and the BVN quorum's);
//   - G1 and G2 carry the same G0 and G1 (canonical v2 forms);
//   - the vote record evaluated again from its evidence, about the transaction G0 proved executed, reaching
//     exactly the record carried; any authority set the intent declares equal to it;
//   - G1 states the threshold satisfied, as the record does; G2's payload binding names G0's transaction.
func verifyIntentProof(vb *ValidatorBlock, rec *govproof.AuthorizationRecord) error {
	ev := vb.IntentCertificate
	fail := func(format string, a ...interface{}) error {
		return fmt.Errorf("%w: %s", ErrIntentProofInvalid, fmt.Sprintf(format, a...))
	}
	if ev.ChainedProof == nil {
		return fail("no chained proof")
	}
	if err := chained_proof.NewProofVerifier(false).Verify(context.Background(), ev.ChainedProof); err != nil {
		return fail("L1-L4: %v", err)
	}
	projected, err := json.Marshal(govproof.ChainedProofToCompleteProof(ev.ChainedProof))
	if err != nil {
		return fail("projection: %v", err)
	}
	carried, err := json.Marshal(vb.LiteClientProof)
	if err != nil {
		return fail("lite_client_proof: %v", err)
	}
	if !bytes.Equal(projected, carried) {
		return fail("the block's lite_client_proof is not the projection of its verified chained proof")
	}
	gp := &vb.GovernanceProof
	if err := govproof.BindG0ToChainedProof(gp.G0Proof, vb.LiteClientProof); err != nil {
		return fail("%v", err)
	}
	g0c, err := govproof.CanonicalG0JSONV2(gp.G0Proof)
	if err != nil {
		return fail("G0: %v", err)
	}
	for _, e := range []struct {
		name string
		g0   *govproof.G0Result
	}{{"G1", &gp.G1Proof.G0Result}, {"G2", &gp.G2Proof.G0Result}} {
		c, err := govproof.CanonicalG0JSONV2(e.g0)
		if err != nil || !bytes.Equal(c, g0c) {
			return fail("%s carries another G0 than the block's", e.name)
		}
	}
	g1c, err := govproof.CanonicalG1JSONV2(gp.G1Proof)
	if err != nil {
		return fail("G1: %v", err)
	}
	if c, err := govproof.CanonicalG1JSONV2(&gp.G2Proof.G1Result); err != nil || !bytes.Equal(c, g1c) {
		return fail("G2 carries another G1 than the block's")
	}
	vote, err := govproof.DecodeVoteEvidence(ev.VoteEvidence)
	if err != nil {
		return fail("%v", err)
	}
	if err := govproof.VerifyVoteEvidence(context.Background(), gp.G0Proof, vote, rec); err != nil {
		return fail("the vote record: %v", err)
	}
	declared, err := govproof.DeclaredGovernanceOfEvidence(vote)
	if err != nil {
		return fail("the intent's declared governance: %v", err)
	}
	if declared != nil {
		if err := govproof.CheckDeclaredGovernance(declared, rec); err != nil {
			return fail("%v", err)
		}
	}
	if !gp.G1Proof.ThresholdSatisfied || !rec.Satisfied {
		return fail("G1 and the vote record must both state the threshold satisfied")
	}
	tx := strings.ToLower(strings.TrimPrefix(gp.G0Proof.TxHash, "0x"))
	if pb := gp.G2Proof.OutcomeLeaf.PayloadBinding; !pb.Verified ||
		strings.ToLower(strings.TrimPrefix(pb.ComputedTxHash, "0x")) != tx {
		return fail("G2's payload binding does not name the transaction G0 proved executed")
	}
	return nil
}

// authorizationOf decodes the evidence's vote record, strictly.
func authorizationOf(ev *IntentCertificateEvidence) (*govproof.AuthorizationRecord, error) {
	var rec govproof.AuthorizationRecord
	dec := json.NewDecoder(bytes.NewReader(ev.AuthorizationRecord))
	dec.DisallowUnknownFields()
	if len(ev.AuthorizationRecord) == 0 || dec.Decode(&rec) != nil {
		return nil, fmt.Errorf("%w: the authorization record is missing or malformed", ErrIntentGovernanceUnderivable)
	}
	return &rec, nil
}

func hex32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x"))
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("%q is not 32 bytes of hex", s)
	}
	copy(out[:], b)
	return out, nil
}

func hexEquals(s string, v [32]byte) bool {
	got, err := hex32(s)
	return err == nil && got == v
}
