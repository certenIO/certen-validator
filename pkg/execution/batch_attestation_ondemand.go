package execution

import (
	"encoding/hex"
	"fmt"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// On-demand attestation — the attester side
// =============================================================================
//
// Same security boundary as the period handler, and for the same reason:
//
//	THE ATTESTER REBUILDS THE BATCH FROM ITS OWN MEMPOOL AND SIGNS ONLY IF ITS OWN
//	DERIVED bundleId EQUALS THE PROPOSER'S.
//
// Without it, a malicious proposer could name a leaf that drains an ADI's account and have six
// honest validators bless it: CertenAccountV7 only checks that a leaf is in an attested root,
// so a root the quorum never independently verified is exactly as good as an honest one.
//
// The boundary is TIGHTER here than on the period path. There, the request carries a period
// width, and the handler has to refuse a mismatch to stop a proposer widening the window. Here
// the request carries only a lookup key: the chain and the operationID. There is no window to
// widen, no member set to influence, and every value the bundleId derives from comes from THIS
// validator's own copy of the member — including the commit height.

// OnDemandAttestationEndpoint is the peer path the on-demand proposer posts to.
//
// A SEPARATE route from BatchAttestationEndpoint on purpose. The period handler is untouched by
// this work, and a validator that has not been upgraded yet answers 404 here rather than
// misinterpreting an on-demand request as a period one.
const OnDemandAttestationEndpoint = "/api/batch/attestation/ondemand"

// OnDemandAttestationRequest asks a peer to co-sign a one-member batch.
//
// It deliberately carries NO member data — only the key to look one up. OperationID is the
// Accumulate 4-blob intent hash, which every validator derives identically from committed
// state, so it names a member without asserting anything about it.
type OnDemandAttestationRequest struct {
	ChainID int64 `json:"chain_id"`
	// OperationID identifies the member. Hex, 32 bytes. The LOOKUP KEY, never member data.
	OperationID string `json:"operation_id"`
	// BundleID is what the proposer derived, for comparison ONLY — never to build from.
	BundleID   string `json:"bundle_id"`
	ProposerID string `json:"proposer_id"`
}

// HandleOnDemandAttestationRequest is the peer-side handler.
//
// Refusing is always safe: the proposer retries or, once its deadline expires, routes the
// member to fallback. Returning CodeMemberNotHeld in particular is the normal answer in the
// first seconds after an intent is discovered and must not be treated as a disagreement.
func (s *BatchStack) HandleOnDemandAttestationRequest(
	req *OnDemandAttestationRequest,
	me BatchAttesterIdentity,
) *BatchAttestationResponse {
	resp := &BatchAttestationResponse{
		ValidatorID: me.ValidatorID,
		EVMAddress:  me.EVMAddress,
	}
	refuseWith := func(code AttestationRefusalCode, format string, a ...interface{}) *BatchAttestationResponse {
		resp.Error = fmt.Sprintf(format, a...)
		resp.Code = code
		return resp
	}

	if req == nil {
		return refuseWith(CodeRefused, "nil request")
	}
	if s == nil || s.Mempool == nil {
		return refuseWith(CodeNotReady, "batch stack not ready")
	}
	if me.EVMAddress == "" {
		return refuseWith(CodeNotReady,
			"attester has no EVM identity; its signature could not be attributed")
	}

	opID, err := parseHex32(req.OperationID)
	if err != nil {
		return refuseWith(CodeRefused, "malformed operationID in request: %v", err)
	}
	if opID == ([32]byte{}) {
		return refuseWith(CodeRefused, "operationID is zero; the anchor rejects it")
	}
	wantBundle, err := parseHex32(req.BundleID)
	if err != nil {
		return refuseWith(CodeRefused, "malformed bundleId in request: %v", err)
	}

	// This chain must be one we can actually anchor on, or our signature would endorse a batch
	// we could not verify the destination of.
	if _, err := s.OrchestratorFor(req.ChainID); err != nil {
		return refuseWith(CodeConfigMismatch,
			"chain %d is not configured for batching here: %v", req.ChainID, err)
	}

	// ---- Rebuild from OUR OWN view. Never from the request. --------------------
	member := s.Mempool.GetOnDemand(req.ChainID, opID)
	if member == nil {
		// NOT an error condition. This validator has not finished processing the round yet.
		return refuseWith(CodeMemberNotHeld,
			"operationID %s is not held on chain %d by this validator",
			shortHex(req.OperationID), req.ChainID)
	}

	in, err := member.LeafInput()
	if err != nil {
		return refuseWith(CodeRefused, "member %s: %v", member.IntentID, err)
	}

	// The height comes from OUR member, never from the request. That is what leaves a proposer
	// with no input to the derivation at all: it names which member, and nothing more.
	tree, err := BuildBatchTree(req.ChainID, []BatchLeafInput{in}, member.CommitHeight)
	if err != nil {
		return refuseWith(CodeRefused, "rebuilding batch: %v", err)
	}
	resp.BundleID = "0x" + hex.EncodeToString(tree.BundleID[:])

	// ---- THE SECURITY BOUNDARY -------------------------------------------------
	// For a one-member batch a mismatch cannot be a "peer saw a different member set" race —
	// there is no set. It means the two nodes disagree about the intent's own data (its legs,
	// its ADI, its account, its commit height), which is a bug, not a timing artifact.
	if tree.BundleID != wantBundle {
		return refuseWith(CodeBundleMismatch,
			"bundleId mismatch on a ONE-MEMBER batch: proposer %s, this validator derived %s "+
				"for operationID %s at height %d — the two nodes disagree about the intent "+
				"itself, not about membership",
			shortHex(req.BundleID), shortHex(resp.BundleID), shortHex(req.OperationID),
			member.CommitHeight)
	}

	// ---- Sign the same 6-field pre-exec message the contract reconstructs -------
	// Identical to the period path: one anchor is one anchor, whatever formed it.
	setRoot, err := contracts.GetV6_1ValidatorSetRoot()
	if err != nil {
		return refuseWith(CodeNotReady, "validator-set root: %v", err)
	}
	msgHash := contracts.ComputeEvmMessageHashV6_1_Pre(
		req.ChainID, tree.BundleID, tree.Root, tree.BatchOperationID, setRoot,
	)
	resp.MessageHash = "0x" + hex.EncodeToString(msgHash[:])

	km := bls.GetValidatorBLSKey()
	if km == nil {
		return refuseWith(CodeNotReady, "validator BLS key manager not initialized")
	}
	sk := km.PrivateKey()
	if sk == nil {
		return refuseWith(CodeNotReady, "validator BLS private key not loaded")
	}

	// SignV6_1PreExec, never SignWithDomain: the latter hashes to a different G1 point and
	// makes the V2 circuit unsatisfiable, which is what took Sepolia test #7 down.
	sig := bls_zkp.SignV6_1PreExec(sk, msgHash)
	if sig == nil {
		return refuseWith(CodeRefused, "signing returned nil")
	}
	resp.SignatureHex = sig.Hex()
	resp.PublicKeyHex = sk.PublicKey().Hex()
	return resp
}
