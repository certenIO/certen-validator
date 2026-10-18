package consensus

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/accumulateset"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/intentcert"
	"github.com/certen/independant-validator/pkg/ledger"
	govproof "github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
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
	GovRootV2         string                      `json:"gov_root_v2"`         // hex32, claimed; empty under v3
	AccumulateSetRoot string                      `json:"accumulate_set_root"` // hex32, claimed
	// ProofV2 and GovRootV3 are carried exactly when the chain requires the v3 certificate (ProofV3Required): the
	// proof v2 evidence, judged against the chain's own spine, and the govRoot v3 it gives. Absent, the block encodes
	// byte for byte as before v3.
	ProofV2   *proofv2.Evidence `json:"proof_v2,omitempty"`
	GovRootV3 string            `json:"gov_root_v3,omitempty"` // hex32, claimed
	Message   string            `json:"message"`               // hex32, claimed
	Signature string            `json:"signature"`             // hex G1 (compressed), over Message
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
	ErrIntentProofV2Missing        = errors.New("the chain requires the v3 intent certificate, and the block carries no proof v2")
	ErrIntentProofV3NotInForce     = errors.New("the block carries a v3 intent certificate, which the chain does not require yet")
	// ErrIntentProofV21NotInForce: a v3 certificate whose proof v2 is evidence 2.1, before the chain's cross-partition
	// activation (rules v15, g1_activation.go) - the v14 refusal of the same block carries the same result code.
	ErrIntentProofV21NotInForce = errors.New("the block carries evidence 2.1, which the chain does not require yet")
	// ErrIntentProofV21Missing: a v3 certificate whose proof v2 is not evidence 2.1, from the height after the chain's
	// cross-partition activation.
	ErrIntentProofV21Missing = errors.New("the chain requires evidence 2.1, and the block's proof v2 is not")
	ErrIntentProofV2Invalid  = errors.New("the block's proof v2 does not verify against the chain's Accumulate spine")
)

// ProofV3Required is whether a block judged with spine (the chain's Accumulate spine as committed for its height) and
// registry reg must carry the v3 intent certificate: exactly when the chain holds a spine under the registry's
// incarnation with at least one verified major block. That is consensus state, so every validator switches at the
// same block, and the switch is the governed act that put the spine there (rules v13), never a node's configuration.
// A registry update to another incarnation (an Accumulate restart) leaves the old spine behind, and v3 is required
// again only once a spine for the new incarnation is verified.
func ProofV3Required(spine *ledger.AccumulateSpineLog, reg *ledger.BLSRegistryRecord) bool {
	if spine == nil || spine.Genesis == nil || reg == nil || len(spine.Checkpoints) == 0 {
		return false
	}
	return strings.EqualFold(strings.TrimPrefix(spine.Genesis.Incarnation, "0x"), strings.TrimPrefix(reg.AccumulateIncarnation, "0x"))
}

// intentFacts is every input of a block's intent message, recomputed from the block, and which message it is.
type intentFacts struct {
	v3      bool
	in      intentcert.MessageInputs
	in3     intentcert.MessageInputsV3
	govRoot [32]byte // v2 or v3, as v3 says
	accRoot [32]byte
}

func (f *intentFacts) message() ([32]byte, error) {
	if f.v3 {
		return intentcert.MessageV3(f.in3)
	}
	return intentcert.Message(f.in)
}

// proofV2Verifier judges a proof v2 document against the chain's spine, pinned to the registry's incarnation. Production never
// names one (ValidatorApp.proofVerifier is nil outside tests): intentInputs then judges a 2.0 document with proofv2.VerifyFromSpine
// and a 2.1 document - reached only when the rules v15 activation is in force at the block - with proofv2.VerifyEvidence21FromSpine,
// the real verifier of evidence 2.1. The type remains only so a test of the activation gate can drive the 2.1 branch of consensus
// with a report it builds; TestRulesV15AcceptsAVerifiedEvidence21 runs the real one over the real stored 2.1 document. It is never
// configuration.
type proofV2Verifier func(ev *proofv2.Evidence, l *ledger.AccumulateSpineLog, pinned [32]byte) (*proofv2.Report, error)

// defaultProofV2Verifier is the production verifier for a document of this version. The 2.0 entry points refuse 2.1 and the 2.1
// entry point refuses 2.0, so neither can be reached with the other's document.
func defaultProofV2Verifier(is21 bool) proofV2Verifier {
	if is21 {
		return proofv2.VerifyEvidence21FromSpine
	}
	return proofv2.VerifyFromSpine
}

// intentInputs recomputes every input of the block's intent message from the block and the registry. g1 is the
// cross-partition activation in force for the block's height (G1ActivationAt), nil before it: from the height after the
// activation a v3 certificate must carry evidence 2.1 and is judged by govRoot v4; before it, a certificate carrying 2.1 is
// refused by name and every other block is decided exactly as rules v14 decided it.
func intentInputs(vb *ValidatorBlock, chainID string, reg *ledger.BLSRegistryRecord, spine *ledger.AccumulateSpineLog,
	g1 *ledger.G1ActivationRecord, verify proofV2Verifier) (*intentFacts, error) {
	in, govRoot, accRoot, err := intentInputsV2(vb, chainID, reg)
	if err != nil {
		return nil, err
	}
	if !ProofV3Required(spine, reg) {
		return &intentFacts{in: in, govRoot: govRoot, accRoot: accRoot}, nil
	}
	ev, gp := vb.IntentCertificate, &vb.GovernanceProof
	govRoot3, rep, err := judgeProofV2(ev, gp.G0Proof, gp.G1Proof, gp.G2Proof, in.Incarnation, in.OperationID, accRoot, spine, g1, verify)
	if err != nil {
		return nil, err
	}
	return &intentFacts{v3: true, in: in, govRoot: govRoot3, accRoot: rep.AccumulateSetRoot,
		in3: intentcert.MessageInputsV3{CertenChainID: in.CertenChainID, OperationID: in.OperationID, GovRootV3: govRoot3,
			AccumulateSetRoot: rep.AccumulateSetRoot, Incarnation: in.Incarnation, GovernanceCommitment: in.GovernanceCommitment,
			CertenSetRoot: in.CertenSetRoot}}, nil
}

// judgeProofV2 is the part of intentInputs that judges a v3 certificate's proof v2, in the order consensus judges it, and returns the
// govRoot (v3 over evidence 2.0, v4 over evidence 2.1) the message commits:
//
//  1. the evidence's version against the activation in force: 2.1 before it, or 2.0 after it, is refused by name;
//  2. the document, by the real verifier of its version (verify nil in production: defaultProofV2Verifier) against the chain's spine
//     and the registry's incarnation;
//  3. one validator set: the set root the spine derived must be the one the L4 leg was verified against (accRoot);
//  4. the binding and the root together (intentcert.ProofV2Root): BindProofV2 and govRoot v3 for 2.0, BindProofV21 over the intent's own
//     vote evidence and govRoot v4 for 2.1.
//
// TestRulesV15AcceptsAVerifiedEvidence21 calls it over the real stored 2.1 document.
func judgeProofV2(ev *IntentCertificateEvidence, g0 *govproof.G0Result, g1doc *govproof.G1Result, g2 *govproof.G2Result,
	incarnation [32]byte, operationID [32]byte, accRoot [32]byte, spine *ledger.AccumulateSpineLog, g1 *ledger.G1ActivationRecord,
	verify proofV2Verifier) ([32]byte, *proofv2.Report, error) {
	var zero [32]byte
	if ev.ProofV2 == nil {
		return zero, nil, ErrIntentProofV2Missing
	}
	is21 := ev.ProofV2.Version == proofv2.Version21
	switch {
	case is21 && !G1CrossPartitionRequired(g1):
		return zero, nil, ErrIntentProofV21NotInForce
	case !is21 && G1CrossPartitionRequired(g1):
		return zero, nil, fmt.Errorf("%w (proof version %q)", ErrIntentProofV21Missing, ev.ProofV2.Version)
	}
	if verify == nil {
		verify = defaultProofV2Verifier(is21)
	}
	rep, err := verify(ev.ProofV2, spine, incarnation)
	if err != nil {
		return zero, nil, fmt.Errorf("%w: %v", ErrIntentProofV2Invalid, err)
	}
	// One anchor commits one Accumulate set root: the set the spine derived must be the set the L4 leg was verified
	// against, or the two proofs describe different validator sets and the intent is refused rather than certified
	// under either.
	if rep.AccumulateSetRoot != accRoot {
		return zero, nil, fmt.Errorf("%w: the spine derives set root %x, the L4 leg %x", ErrIntentAccumulateSetMismatch, rep.AccumulateSetRoot, accRoot)
	}
	// Binding and root together, by the evidence's version.
	govRoot, _, err := intentcert.ProofV2Root(rep, ev.ProofV2, g0, g1doc, g2, ev.KeyPageURL, ev.KeyBookURL, ev.VoteEvidence, operationID)
	if err != nil {
		if errors.Is(err, intentcert.ErrBind) {
			return zero, nil, fmt.Errorf("%w: %v", ErrIntentProofV2Invalid, err)
		}
		return zero, nil, fmt.Errorf("%w: %v", ErrIntentGovRootMismatch, err)
	}
	return govRoot, rep, nil
}

// intentInputsV2 recomputes the v2 message's inputs: govRoot v2 over the L1-L4 proof and G0-G2, and the set root of
// the L4 leg. Under v3 they are still recomputed - the v1 proof is still verified, and its set root must agree.
func intentInputsV2(vb *ValidatorBlock, chainID string, reg *ledger.BLSRegistryRecord) (intentcert.MessageInputs, [32]byte, [32]byte, error) {
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
//
// spine is the chain's Accumulate spine as committed for the block's height; it decides whether the certificate must
// be v3 (ProofV3Required), and a v3 certificate's proof v2 is judged against it. g1 is the cross-partition activation in
// force for that height (nil before rules v15's activation): it decides whether the proof v2 must be evidence 2.1.
func VerifyIntentCertificate(vb *ValidatorBlock, chainID string, reg *ledger.BLSRegistryRecord, spine *ledger.AccumulateSpineLog,
	g1 *ledger.G1ActivationRecord) ([32]byte, error) {
	return verifyIntentCertificate(vb, chainID, reg, spine, g1, nil)
}

// verifyIntentCertificate is VerifyIntentCertificate with the proof verifier named (see proofV2Verifier).
func verifyIntentCertificate(vb *ValidatorBlock, chainID string, reg *ledger.BLSRegistryRecord, spine *ledger.AccumulateSpineLog,
	g1 *ledger.G1ActivationRecord, verify proofV2Verifier) ([32]byte, error) {
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
	v3 := ProofV3Required(spine, reg)
	if !v3 && (ev.ProofV2 != nil || ev.GovRootV3 != "") {
		return [32]byte{}, ErrIntentProofV3NotInForce
	}
	f, err := intentInputs(vb, chainID, reg, spine, g1, verify)
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
	switch {
	case v3 && ev.GovRootV2 != "":
		return [32]byte{}, fmt.Errorf("%w: a v3 certificate claims govRoot v2 %s", ErrIntentGovRootMismatch, ev.GovRootV2)
	case v3 && !hexEquals(ev.GovRootV3, f.govRoot):
		return [32]byte{}, fmt.Errorf("%w: claims govRoot v3 %s, is %x", ErrIntentGovRootMismatch, ev.GovRootV3, f.govRoot)
	case !v3 && !hexEquals(ev.GovRootV2, f.govRoot):
		return [32]byte{}, fmt.Errorf("%w: claims %s, is %x", ErrIntentGovRootMismatch, ev.GovRootV2, f.govRoot)
	}
	if !hexEquals(ev.AccumulateSetRoot, f.accRoot) {
		return [32]byte{}, fmt.Errorf("%w: claims %s, is %x", ErrIntentAccumulateSetMismatch, ev.AccumulateSetRoot, f.accRoot)
	}
	msg, err := f.message()
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
	cp *chained_proof.ChainedProof, spine *ledger.AccumulateSpineLog, g1 *ledger.G1ActivationRecord, pv2 *proofv2.Evidence) error {
	return buildIntentCertificate(vb, chainID, reg, sk, keyPageURL, keyBookURL, authorization, voteEvidence, cp, spine, g1, pv2, nil)
}

// buildIntentCertificate is BuildIntentCertificate with the proof verifier named (see proofV2Verifier).
func buildIntentCertificate(vb *ValidatorBlock, chainID string, reg *ledger.BLSRegistryRecord, sk *bls.PrivateKey,
	keyPageURL, keyBookURL string, authorization *govproof.AuthorizationRecord, voteEvidence json.RawMessage,
	cp *chained_proof.ChainedProof, spine *ledger.AccumulateSpineLog, g1 *ledger.G1ActivationRecord, pv2 *proofv2.Evidence,
	verify proofV2Verifier) error {
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
	if ProofV3Required(spine, reg) {
		vb.IntentCertificate.ProofV2 = pv2
	}
	f, err := intentInputs(vb, chainID, reg, spine, g1, verify)
	if err != nil {
		vb.IntentCertificate = nil
		return err
	}
	msg, err := f.message()
	if err != nil {
		vb.IntentCertificate = nil
		return err
	}
	ev := vb.IntentCertificate
	if f.v3 {
		ev.GovRootV3 = "0x" + hex.EncodeToString(f.govRoot[:])
	} else {
		ev.GovRootV2 = "0x" + hex.EncodeToString(f.govRoot[:])
	}
	ev.AccumulateSetRoot = "0x" + hex.EncodeToString(f.accRoot[:])
	ev.Message = "0x" + hex.EncodeToString(msg[:])
	ev.Signature = hex.EncodeToString(bls_zkp.SignV6_1PreExec(sk, msg).Bytes())
	if _, err := verifyIntentCertificate(vb, chainID, reg, spine, g1, verify); err != nil {
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
	// The key page and book govRoot v2 commits are the ones the proof is about: the page G1 validated the
	// signatures against, and that page's own book.
	page, book := govvote.CanonicalAccSpelling(ev.KeyPageURL), govvote.CanonicalAccSpelling(ev.KeyBookURL)
	if page == "" || page != govvote.CanonicalAccSpelling(gp.G1Proof.AuthoritySnapshot.Page) {
		return fail("the key page %q is not the page G1 validated against (%q)", ev.KeyPageURL, gp.G1Proof.AuthoritySnapshot.Page)
	}
	if n := strings.TrimPrefix(page, book+"/"); book == "" || n == page || n == "" || strings.Trim(n, "0123456789") != "" {
		return fail("the key page %q is not a page of the key book %q", ev.KeyPageURL, ev.KeyBookURL)
	}
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
