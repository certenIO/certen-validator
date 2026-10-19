package consensus

import (
	"encoding/json"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// RB9-K defect 1. A certificate's proof v2 is decoded as the rules v14 binary decoded it (proofv2.UnmarshalCertifiedEvidence): a document
// that claims 2.1 completely, every other document into v14's member set, so a key evidence 2.1 added (votes, anchors, transaction,
// check.routing, a page's partition, roles or history) is ignored whatever its JSON type, exactly as v14 ignored it. Evidence20View, applied
// after a full decode, cleared those members from a document that decoded; it could not make a document with a wrongly typed one decode, so
// a block v14 accepted (result code 0) got code 1 here (CheckTx, FinalizeBlock) or REJECT (ProcessProposal). Both holders of a certificate's
// proof v2 decode through this: the block's certificate and the stored inputs of a certified message (which the offline check reads).

// UnmarshalJSON decodes the certificate with its proof v2 decoded by proofv2.UnmarshalCertifiedEvidence; every other member decodes as before.
func (e *IntentCertificateEvidence) UnmarshalJSON(b []byte) error {
	type plain IntentCertificateEvidence
	aux := struct {
		*plain
		ProofV2 json.RawMessage `json:"proof_v2,omitempty"`
	}{plain: (*plain)(e)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	return decodeCertifiedProofV2(aux.ProofV2, &e.ProofV2)
}

// UnmarshalJSON decodes the stored inputs with their proof v2 decoded by proofv2.UnmarshalCertifiedEvidence.
func (in *IntentMessageInputs) UnmarshalJSON(b []byte) error {
	type plain IntentMessageInputs
	aux := struct {
		*plain
		ProofV2 json.RawMessage `json:"proof_v2,omitempty"`
	}{plain: (*plain)(in)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	return decodeCertifiedProofV2(aux.ProofV2, &in.ProofV2)
}

// decodeCertifiedProofV2 sets *dst from the raw member: absent leaves it, null clears it, anything else is decoded.
func decodeCertifiedProofV2(raw json.RawMessage, dst **proofv2.Evidence) error {
	if raw == nil {
		return nil
	}
	ev, err := proofv2.UnmarshalCertifiedEvidence(raw)
	if err != nil {
		return err
	}
	*dst = ev
	return nil
}
