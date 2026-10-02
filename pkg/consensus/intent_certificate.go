package consensus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
	GovRootV2           string          `json:"gov_root_v2"`         // hex32, claimed
	AccumulateSetRoot   string          `json:"accumulate_set_root"` // hex32, claimed
	Message             string          `json:"message"`             // hex32, claimed
	Signature           string          `json:"signature"`           // hex G1 (compressed), over Message
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
	var rec govproof.AuthorizationRecord
	dec := json.NewDecoder(bytes.NewReader(ev.AuthorizationRecord))
	dec.DisallowUnknownFields()
	if len(ev.AuthorizationRecord) == 0 || dec.Decode(&rec) != nil {
		return in, govRoot, accRoot, fmt.Errorf("%w: the authorization record is missing or malformed", ErrIntentGovernanceUnderivable)
	}
	gdr, err := govproof.GovernanceDecisionRecord(gp.G0Proof, &rec)
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
	keyPageURL, keyBookURL string, authorization *govproof.AuthorizationRecord) error {
	if reg == nil {
		return fmt.Errorf("no BLS registry is recorded on this chain")
	}
	if authorization == nil {
		return fmt.Errorf("%w: no authorization record", ErrIntentGovernanceUnderivable)
	}
	rec, err := json.Marshal(authorization)
	if err != nil {
		return err
	}
	vb.IntentCertificate = &IntentCertificateEvidence{RegistryVersion: reg.Version, KeyPageURL: keyPageURL,
		KeyBookURL: keyBookURL, AuthorizationRecord: rec}
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
