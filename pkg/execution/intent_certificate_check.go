// Copyright 2026 Certen Protocol
//
// CHECKING A STORED PROOF'S PER-INTENT QUORUM CERTIFICATE OFFLINE (RB5 D3).
//
// CERTEN's quorum signs, per intent, a message binding the operation, govRoot v2 over the proof's L1-L4 and
// canonical G0-G2, the Accumulate validator set its L4 was verified against under the incarnation, the governance
// commitment, and CERTEN's set root, on its CERTEN chain. The chain records the aggregate once the signers hold the
// BLS registry's threshold, and intent_quorum_certificates keeps it with the registry and the message's inputs.
//
// From those and the stored proof alone:
//   - the certificate verifies against its registry: registered, distinct signers holding the threshold, the
//     aggregate key exactly theirs, the aggregate signature over the message;
//   - the registry is the one the anchor's quorum is: its CERTEN set root is the root the anchor committed, and
//     on a V8.2 anchor its incarnation is the anchor's (and, pinned, the verifier's);
//   - every input of the message is recomputed from the stored proof - the operation from layer 5, govRoot v2 from
//     the stored L1-L4 and G0-G2, the Accumulate set root from the stored Directory leg, the governance commitment
//     from the stored vote record and G0, the key page from G1 - and the message from them.
package execution

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/accumulateset"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/intentcert"
	"github.com/certen/independant-validator/pkg/ledger"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// ErrNoIntentCertificate: no quorum certificate is recorded for the proof's operation - it settled before a BLS
// registry was in force. Nothing about the proof is known to be wrong.
var ErrNoIntentCertificate = errors.New("no intent quorum certificate is recorded for the proof's operation")

// IntentCertificateCheck is what CheckIntentCertificate established.
type IntentCertificateCheck struct {
	OperationID     string
	Message         string
	CertenChainID   string
	RegistryVersion uint64
	Signers         int
	SignedPower     string
	TotalPower      string
	CertifiedHeight int64
	// IncarnationPinned: the registry's incarnation was checked against the verifier's own pin.
	IncarnationPinned bool
	// AnchoredInBatch: the proof's batch is v3 and its anchored operation id commits this certified message.
	AnchoredInBatch bool
}

// CheckIntentCertificate checks row, the certificate recorded for the proof's operation, against the stored proof.
func CheckIntentCertificate(row *database.IntentQuorumCertificateRow, cp *chained_proof.ChainedProof,
	levels []certenproof.StoredGovernanceLevel, l5 *Layer5, pinned *[32]byte) (*IntentCertificateCheck, error) {
	if row == nil {
		return nil, ErrNoIntentCertificate
	}
	var cert ledger.IntentQuorumCertificate
	var reg ledger.BLSRegistryRecord
	var in consensus.IntentMessageInputs
	for _, d := range []struct {
		name string
		raw  json.RawMessage
		v    interface{}
	}{{"certificate", row.Certificate, &cert}, {"registry", row.Registry, &reg}, {"message inputs", row.MessageInputs, &in}} {
		if err := json.Unmarshal(d.raw, d.v); err != nil {
			return nil, fmt.Errorf("the stored %s does not decode: %w", d.name, err)
		}
	}
	op := strings.ToLower(row.OperationID)
	switch {
	case !strings.EqualFold(cert.OperationID, op) || !strings.EqualFold(in.OperationID, op):
		return nil, fmt.Errorf("the certificate row names operation %s, its certificate %s and its inputs %s", op, cert.OperationID, in.OperationID)
	case !strings.EqualFold(cert.Message, row.Message):
		return nil, fmt.Errorf("the certificate row's message is not its certificate's")
	case uint64(row.RegistryVersion) != cert.RegistryVersion || reg.Version != cert.RegistryVersion:
		return nil, fmt.Errorf("the certificate row, its certificate and its registry name different registry versions")
	case in.CertenChainID != row.CertenChainID:
		return nil, fmt.Errorf("the message's inputs name CERTEN chain %q, the row %q", in.CertenChainID, row.CertenChainID)
	}
	if err := consensus.VerifyIntentQuorumCertificate(&cert, &reg); err != nil {
		return nil, fmt.Errorf("the certificate: %w", err)
	}

	// The registry is the anchor's quorum.
	if l5 == nil || l5.Governance == nil || l5.Commitment == nil {
		return nil, fmt.Errorf("the proof's layer 5 does not record the operation and the anchor's commitment the certificate is checked against")
	}
	if !strings.EqualFold(l5.Governance.OperationID, op) {
		return nil, fmt.Errorf("the certificate is of operation %s, the proof's layer 5 of %s", op, l5.Governance.OperationID)
	}
	if !strings.EqualFold(l5.Commitment.CertenSetRoot, reg.CertenSetRoot) {
		return nil, fmt.Errorf("the registry's CERTEN set root %s is not the root the anchor committed (%s)", reg.CertenSetRoot, l5.Commitment.CertenSetRoot)
	}
	inc, err := hex32Of(reg.AccumulateIncarnation)
	if err != nil {
		return nil, fmt.Errorf("the registry's incarnation: %w", err)
	}
	if l5.Commitment.Version == "v8_2" && !strings.EqualFold(l5.Commitment.Incarnation, reg.AccumulateIncarnation) {
		return nil, fmt.Errorf("the registry's incarnation %s is not the one the anchor committed (%s)", reg.AccumulateIncarnation, l5.Commitment.Incarnation)
	}
	if pinned != nil && *pinned != inc {
		return nil, fmt.Errorf("the registry's incarnation %x is not the one pinned (%x)", inc, *pinned)
	}

	// Every input of the message, from the stored proof.
	var g0 certenproof.G0Result
	var g1 certenproof.G1Result
	var g2 certenproof.G2Result
	var rec certenproof.AuthorizationRecord
	have := map[string]bool{}
	for _, l := range levels {
		switch l.Level {
		case "G0":
			err = json.Unmarshal(l.Result, &g0)
		case "G1":
			err = json.Unmarshal(l.Result, &g1)
			if err == nil {
				err = json.Unmarshal(l.Flags[GovLevelAuthorizationKey], &rec)
			}
		case "G2":
			err = json.Unmarshal(l.Result, &g2)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("the stored %s: %w", l.Level, err)
		}
		have[l.Level] = true
	}
	if !have["G0"] || !have["G1"] || !have["G2"] {
		return nil, fmt.Errorf("the proof does not store G0, G1 and G2, which the certified govRoot covers")
	}
	page := govvote.CanonicalAccSpelling(in.KeyPageURL)
	if page == "" || page != govvote.CanonicalAccSpelling(g1.AuthoritySnapshot.Page) {
		return nil, fmt.Errorf("the certified key page %q is not the page G1 validated against (%q)", in.KeyPageURL, g1.AuthoritySnapshot.Page)
	}
	opBytes, err := hex32Of(op)
	if err != nil {
		return nil, err
	}
	govRoot, _, err := intentcert.GovRootV2(intentcert.GovRootV2Inputs{Lite: certenproof.ChainedProofToCompleteProof(cp),
		G0: &g0, G1: &g1, G2: &g2, KeyPageURL: in.KeyPageURL, KeyBookURL: in.KeyBookURL, OperationID: opBytes})
	if err != nil {
		return nil, fmt.Errorf("govRoot v2 from the stored proof: %w", err)
	}
	accRoot, err := accumulateset.CommittedAccumulateSetRoot(cp.Layer4DN, inc)
	if err != nil {
		return nil, fmt.Errorf("the Accumulate set root from the stored Directory leg: %w", err)
	}
	gdr, err := certenproof.GovernanceDecisionRecord(&g0, &rec)
	if err != nil {
		return nil, fmt.Errorf("the governance decision from the stored vote record: %w", err)
	}
	setRoot, err := hex32Of(reg.CertenSetRoot)
	if err != nil {
		return nil, err
	}
	recomputed := intentcert.MessageInputs{CertenChainID: row.CertenChainID, OperationID: opBytes, GovRootV2: govRoot,
		AccumulateSetRoot: accRoot, Incarnation: inc, GovernanceCommitment: certenproof.GovernanceCommitment(gdr), CertenSetRoot: setRoot}
	for _, c := range []struct {
		name    string
		claimed string
		is      [32]byte
	}{{"govRoot v2", in.GovRootV2, recomputed.GovRootV2}, {"Accumulate set root", in.AccumulateSetRoot, recomputed.AccumulateSetRoot},
		{"governance commitment", in.GovernanceCommitment, recomputed.GovernanceCommitment}, {"incarnation", in.Incarnation, inc},
		{"CERTEN set root", in.CertenSetRoot, setRoot}} {
		if got, err := hex32Of(c.claimed); err != nil || got != c.is {
			return nil, fmt.Errorf("the certified %s %s is not the stored proof's %x", c.name, c.claimed, c.is)
		}
	}
	msg, err := intentcert.Message(recomputed)
	if err != nil {
		return nil, err
	}
	if got, err := hex32Of(cert.Message); err != nil || got != msg {
		return nil, fmt.Errorf("the certified message %s is not the one the stored proof computes (%x)", cert.Message, msg)
	}
	// On a v3 batch the anchor's operation id commits the member's certified message: it must be this one.
	anchored := false
	if l5.Governance.Version == BatchOperationIDV3 {
		if !strings.EqualFold(l5.Governance.CertifiedIntentMessage, cert.Message) {
			return nil, fmt.Errorf("the batch anchored certified message %s for this member, the certificate is over %s",
				l5.Governance.CertifiedIntentMessage, cert.Message)
		}
		anchored = true
	}
	return &IntentCertificateCheck{OperationID: op, Message: "0x" + hex.EncodeToString(msg[:]), CertenChainID: row.CertenChainID,
		RegistryVersion: reg.Version, Signers: len(cert.Signers), SignedPower: cert.SignedPower, TotalPower: cert.TotalPower,
		CertifiedHeight: row.CertifiedHeight, IncarnationPinned: pinned != nil, AnchoredInBatch: anchored}, nil
}

func hex32Of(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x"))
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("%q is not 32 bytes of hex", s)
	}
	copy(out[:], b)
	return out, nil
}
