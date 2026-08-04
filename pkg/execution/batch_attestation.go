package execution

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// Batch attestation — the attester side
// =============================================================================
//
// A proposer forms a batch and asks its peers to co-sign it. This is what a peer does with
// that request, and the single most important property in the whole batch design lives here:
//
//	THE ATTESTER REBUILDS THE BATCH FROM ITS OWN MEMPOOL AND SIGNS ONLY IF ITS OWN
//	DERIVED bundleId EQUALS THE PROPOSER'S.
//
// Without that check, a malicious proposer could include a leaf that drains an ADI's account
// and have six honest validators bless it. The quorum would be genuine and the theft would be
// valid on chain — CertenAccountV7 only checks that a leaf is in an attested root, so a root
// the quorum never independently verified is exactly as good as an honest one.
//
// The leaf's adiURLHash binding prevents FORGED leaves for an ADI that never signed. It does
// NOT prevent a quorum from signing a root it did not check. That is this file's job.
//
// Determinism is what makes the check possible: membership is selected by
// PeekForPeriod(chainID, cutoffHeight) over committed state, so an honest peer holding the
// same intents derives byte-identical leaves, root, and bundleId.

// BatchAttestationRequest is sent by the proposer to each peer.
//
// It deliberately carries NO member data. The attester must reconstruct membership itself from
// (chainID, cutoffHeight); accepting a member list from the proposer would defeat the entire
// point of the check. BundleID is present only so the attester can compare — never to build from.
type BatchAttestationRequest struct {
	ChainID int64 `json:"chain_id"`
	// CutoffHeight is the START of the period. Membership is the half-open window
	// [CutoffHeight, CutoffHeight+PeriodBlocks).
	CutoffHeight uint64 `json:"cutoff_height"`
	// PeriodBlocks is the window width. Carried explicitly so a proposer running a different
	// BATCH_PERIOD_BLOCKS cannot quietly ask for a different member set under the same cutoff —
	// the attester would then derive a different bundleId and refuse, which is the safe
	// outcome, but the value being on the wire makes the misconfiguration diagnosable.
	PeriodBlocks uint64 `json:"period_blocks"`
	BundleID     string `json:"bundle_id"` // hex, for comparison ONLY
	ProposerID   string `json:"proposer_id"`
}

// BatchAttestationResponse is the peer's partial signature, or a refusal.
type BatchAttestationResponse struct {
	ValidatorID  string `json:"validator_id"`
	EVMAddress   string `json:"evm_address"`
	SignatureHex string `json:"signature_hex"`
	PublicKeyHex string `json:"public_key_hex"`
	BundleID     string `json:"bundle_id"` // what the ATTESTER derived
	MessageHash  string `json:"message_hash"`
	Error        string `json:"error,omitempty"`
	// Code classifies a refusal so the proposer can tell "not yet" from "we disagree".
	//
	// Error stays human prose and must never be parsed: a proposer matching on substrings
	// would silently reclassify every refusal the moment someone reworded a message. The
	// on-demand submitter retries on CodeMemberNotHeld without spending an attempt, because a
	// peer that has not finished processing the round yet is not a disagreement — it is the
	// normal state for the first few seconds after an intent is discovered.
	Code AttestationRefusalCode `json:"code,omitempty"`
}

// AttestationRefusalCode is the machine-readable reason a peer declined.
type AttestationRefusalCode string

const (
	// CodeMemberNotHeld — this validator does not (yet) hold the member. RETRYABLE, and the
	// expected answer for a few seconds after discovery: measured live on 2026-08-04, all seven
	// validators enqueued the same intent within a 5-second window.
	CodeMemberNotHeld AttestationRefusalCode = "member_not_held"

	// CodeBundleMismatch — this validator holds the member(s) but derived a different bundleId.
	// A REAL disagreement. For a one-member batch it means the two nodes disagree about the
	// intent's own data, which is a bug worth surfacing, not a race to retry away.
	CodeBundleMismatch AttestationRefusalCode = "bundle_mismatch"

	// CodeConfigMismatch — the request cannot be served because the two nodes are configured
	// differently. Retrying cannot help; an operator has to fix it.
	CodeConfigMismatch AttestationRefusalCode = "config_mismatch"

	// CodeNotReady — this validator's batch stack or attester identity is not up yet.
	// Retryable, but it is a local startup condition rather than a view difference.
	CodeNotReady AttestationRefusalCode = "not_ready"

	// CodeRefused — anything else. Not retryable by default.
	CodeRefused AttestationRefusalCode = "refused"
)

// BatchAttesterIdentity is who this validator is when attesting.
type BatchAttesterIdentity struct {
	ValidatorID string
	EVMAddress  string // must match its registry entry on the anchor
}

// HandleBatchAttestationRequest is the peer-side handler.
//
// Returns a response with Error set (and no signature) whenever this validator cannot honestly
// attest. Refusing is always safe: the proposer simply fails to reach quorum and the members
// fall back to the per-intent path.
func (s *BatchStack) HandleBatchAttestationRequest(
	req *BatchAttestationRequest,
	me BatchAttesterIdentity,
) *BatchAttestationResponse {
	resp := &BatchAttestationResponse{
		ValidatorID: me.ValidatorID,
		EVMAddress:  me.EVMAddress,
	}
	// refuse keeps the generic code. The three cases a proposer must be able to ACT on
	// differently — not-held, bundle mismatch, misconfiguration — use refuseWith below.
	refuse := func(format string, a ...interface{}) *BatchAttestationResponse {
		resp.Error = fmt.Sprintf(format, a...)
		resp.Code = CodeRefused
		return resp
	}
	refuseWith := func(code AttestationRefusalCode, format string, a ...interface{}) *BatchAttestationResponse {
		resp.Error = fmt.Sprintf(format, a...)
		resp.Code = code
		return resp
	}

	if req == nil {
		return refuse("nil request")
	}
	if s == nil || s.Mempool == nil {
		return refuse("batch stack not ready")
	}
	if me.EVMAddress == "" {
		return refuse("attester has no EVM identity; its signature could not be attributed")
	}
	if req.CutoffHeight == 0 {
		return refuse("cutoff height 0 is not a valid period")
	}
	wantBundle, err := parseHex32(req.BundleID)
	if err != nil {
		return refuse("malformed bundleId in request: %v", err)
	}

	// This chain must be one we can actually anchor on, or our signature would endorse a batch
	// we could not verify the destination of.
	if _, err := s.OrchestratorFor(req.ChainID); err != nil {
		return refuse("chain %d is not configured for batching here: %v", req.ChainID, err)
	}

	// The period width is the ONE request field that influences which of OUR members are
	// selected, so it is checked against our own configuration rather than adopted.
	//
	// Adopting it would let a proposer name an arbitrary window — say the whole chain history —
	// and have peers co-sign a batch spanning every intent they hold. That is not a theft (every
	// leaf still belongs to an ADI that authorised it, and the bundleId must still match), but
	// it dissolves the period discipline the whole design rests on, and a batch nobody intended
	// would settle. Refusing a mismatch keeps the field purely diagnostic: it tells us WHICH
	// misconfiguration we are looking at, and never changes what we build.
	myPeriodBlocks := s.PeriodBlocks
	if myPeriodBlocks == 0 {
		myPeriodBlocks = DefaultBatchPeriodBlocks
	}
	// Older proposers omit the field; treat that as "the default", not as zero.
	theirPeriodBlocks := req.PeriodBlocks
	if theirPeriodBlocks == 0 {
		theirPeriodBlocks = DefaultBatchPeriodBlocks
	}
	if theirPeriodBlocks != myPeriodBlocks {
		return refuseWith(CodeConfigMismatch, "period width mismatch: proposer uses %d blocks, "+
			"this validator is configured for %d — BATCH_PERIOD_BLOCKS must be identical across "+
			"the set, or every batch derives a different bundleId",
			theirPeriodBlocks, myPeriodBlocks)
	}
	periodBlocks := myPeriodBlocks

	// ---- Rebuild from OUR OWN view. Never from the request. --------------------
	members := s.Mempool.PeekForPeriod(req.ChainID, req.CutoffHeight, periodBlocks)
	if len(members) == 0 {
		return refuseWith(CodeMemberNotHeld,
			"no members for chain %d in period [%d,%d) in this validator's mempool",
			req.ChainID, req.CutoffHeight, req.CutoffHeight+periodBlocks)
	}

	inputs := make([]BatchLeafInput, 0, len(members))
	for _, m := range members {
		in, err := m.LeafInput()
		if err != nil {
			return refuse("member %s: %v", m.IntentID, err)
		}
		inputs = append(inputs, in)
	}

	tree, err := BuildBatchTree(req.ChainID, inputs, req.CutoffHeight)
	if err != nil {
		return refuse("rebuilding batch: %v", err)
	}
	resp.BundleID = "0x" + hex.EncodeToString(tree.BundleID[:])

	// ---- THE SECURITY BOUNDARY -------------------------------------------------
	// Any disagreement — an extra leaf, a missing one, a different height, a substituted
	// executionCommitment — changes the root and therefore the bundleId. Refuse.
	if tree.BundleID != wantBundle {
		return refuseWith(CodeBundleMismatch,
			"bundleId mismatch: proposer %s, this validator derived %s over %d member(s) — "+
				"refusing to attest a batch it did not independently reproduce",
			shortHex(req.BundleID), shortHex(resp.BundleID), len(members))
	}

	// ---- Sign the same 6-field pre-exec message the contract reconstructs -------
	setRoot, err := contracts.GetV6_1ValidatorSetRoot()
	if err != nil {
		return refuse("validator-set root: %v", err)
	}
	msgHash := contracts.ComputeEvmMessageHashV6_1_Pre(
		req.ChainID, tree.BundleID, tree.Root, tree.BatchOperationID, setRoot,
	)
	resp.MessageHash = "0x" + hex.EncodeToString(msgHash[:])

	km := bls.GetValidatorBLSKey()
	if km == nil {
		return refuse("validator BLS key manager not initialized")
	}
	sk := km.PrivateKey()
	if sk == nil {
		return refuse("validator BLS private key not loaded")
	}

	// SignV6_1PreExec, never SignWithDomain: the latter hashes to a different G1 point and
	// makes the V2 circuit unsatisfiable, which is what took Sepolia test #7 down.
	sig := bls_zkp.SignV6_1PreExec(sk, msgHash)
	if sig == nil {
		return refuse("signing returned nil")
	}
	resp.SignatureHex = sig.Hex()
	resp.PublicKeyHex = sk.PublicKey().Hex()
	return resp
}

func parseHex32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

func shortHex(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}
