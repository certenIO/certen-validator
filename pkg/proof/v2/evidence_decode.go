// Copyright 2026 Certen Protocol
//
// The decode of a certificate's proof v2 as the rules v14 binary performed it (RB9-K, defect 1).
//
// v14 decoded a certificate's proof v2 with encoding/json into structs that did not have the members evidence 2.1 added, so a document
// that claims version 2.0 and carries a key named like one of them (votes, anchors, transaction, check.routing, a page's partition,
// roles or history) had that key IGNORED WHATEVER ITS JSON TYPE: v14 decoded {"votes": 5} without error. A decode into the current
// Evidence rejects the same bytes ("cannot unmarshal number into ... votes of type []proofv2.Vote"), which gives a block a result code
// (1, or REJECT in ProcessProposal) v14 did not give. UnmarshalCertifiedEvidence is the decode consensus and the offline check of a
// stored certificate use for a certificate's proof v2: it reads the version first, decodes a document that claims 2.1 completely, and
// decodes every other document into v14's member set only, leaving every evidence 2.1 member zero. It is not the decode of a stand-alone
// proof file (proofverify, the conformance vectors): those decode with Evidence's own tags and the 2.0 verifier refuses a 2.0 document
// that carries 2.1 members ("evidence 2.0 carries 2.1 members").

package proofv2

import (
	"bytes"
	"encoding/json"

	"github.com/certen/independant-validator/pkg/proof"
)

// EvidenceV14 is Evidence as the rules v14 head (d20f693, pkg/proof/v2/evidence.go) declared it: the members a v14 decode kept. The
// json tags are v14's. TestCertifiedEvidenceDecodeShapeIsV14 (pkg/consensus) compares it, field by field and tag by tag, to an
// independent copy of v14's structs, and TestEveryEvidenceFieldIsClassifiedForThe20View to the lists Evidence20View keeps.
type EvidenceV14 struct {
	Version string          `json:"version"`
	Account string          `json:"account"`
	TxHash  string          `json:"txHash"`
	Receipt string          `json:"receipt"`
	Majors  uint64          `json:"majors"`
	Certify []string        `json:"certify"`
	Anchor  PartitionAnchor `json:"anchor"`
	Pages   []PageStateV14  `json:"pages,omitempty"`
	Check   SetCheckV14     `json:"check"`
}

// SetCheckV14 is SetCheck as v14 declared it.
type SetCheckV14 struct {
	Majors uint64                  `json:"majors"`
	Hops   []string                `json:"hops"`
	Set    proof.ValidatorSetProof `json:"set"`
}

// PageStateV14 is PageState as v14 declared it.
type PageStateV14 struct {
	URL         string            `json:"url"`
	State       string            `json:"state"`
	Receipt     string            `json:"receipt"`
	Chains      []proof.ChainRoot `json:"chains,omitempty"`
	PendingHash string            `json:"pendingHash,omitempty"`
	ChainError  string            `json:"chainError,omitempty"`
}

// UnmarshalCertifiedEvidence decodes a certificate's proof v2 exactly as the rules v14 binary did for a document that claims 2.0 and as
// this binary does for one that claims 2.1: it reads "version" first (a wrongly typed version fails here, as it failed in v14's decode of
// the whole struct); a document that claims "2.1" is decoded into Evidence completely; every other document is decoded into v14's member
// set (EvidenceV14), so a key v14's structs did not have is ignored whatever its type, and the evidence 2.1 members of the result are
// zero. JSON null returns (nil, nil), as encoding/json leaves a pointer to the struct nil.
func UnmarshalCertifiedEvidence(raw []byte) (*Evidence, error) {
	var probe struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, err
	}
	if probe.Version == Version21 {
		ev := new(Evidence)
		if err := json.Unmarshal(raw, ev); err != nil {
			return nil, err
		}
		return ev, nil
	}
	var w EvidenceV14
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, err
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	return w.Evidence(), nil
}

// Evidence is the document with v14's members set and every evidence 2.1 member zero.
func (w *EvidenceV14) Evidence() *Evidence {
	ev := &Evidence{Version: w.Version, Account: w.Account, TxHash: w.TxHash, Receipt: w.Receipt, Majors: w.Majors,
		Certify: w.Certify, Anchor: w.Anchor,
		Check: SetCheck{Majors: w.Check.Majors, Hops: w.Check.Hops, Set: w.Check.Set}}
	if w.Pages != nil {
		ev.Pages = make([]PageState, len(w.Pages))
		for i, p := range w.Pages {
			ev.Pages[i] = PageState{URL: p.URL, State: p.State, Receipt: p.Receipt, Chains: p.Chains, PendingHash: p.PendingHash, ChainError: p.ChainError}
		}
	}
	return ev
}
