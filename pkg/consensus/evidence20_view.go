package consensus

import (
	"reflect"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// Evidence20View is a certificate's proof v2 as the rules v14 binary decoded it: every member that evidence 2.1 defines and v14's
// structs did not have is cleared. v14 decoded a certificate with encoding/json into structs without those fields, so a document that
// claimed version 2.0 and carried any of them (votes, anchors, the transaction, a routing proof, a page's partition, roles or history, a
// vote's production with its sequenced message) was judged on what remained. This binary decodes the members, and the 2.0 verifier
// refuses a 2.0 document that carries them ("evidence 2.0 carries 2.1 members"), which would give the block a result code (10) v14 did
// not (0). Before the cross-partition activation a block is decided as v14 decided it, so a document that claims 2.0 is verified, bound
// and committed (govRoot v3) on this view. It is applied exactly where the document claims 2.0 and no activation is in force; a document
// that claims 2.1 is never viewed, and from the activation a document that claims 2.0 is refused by name before it is looked at.
//
// The members kept are the audited list below, which is the field set of v14's Evidence, SetCheck and PageState (pkg/proof/v2/evidence.go
// and page.go at d20f693); every other field is cleared, so a member added to those structs later is cleared by default, and
// TestEveryEvidenceFieldIsClassifiedForThe20View fails until it is placed in one list. The view copies the slices a caller could write
// through (Certify, Hops, Pages); the page chain roots and the validator set proof are shared and only read. It is used by the offline check of a stored certificate (execution.CheckIntentCertificate) as well, so the two cannot judge a 2.0
// document differently.
//
// RB9-K: this view is for a document that is already in memory. A certificate that arrives as JSON is decoded by
// proofv2.UnmarshalCertifiedEvidence (evidence_decode.go), which decodes a document that does not claim 2.1 into v14's member set only, so a
// key evidence 2.1 added is ignored whatever its JSON type exactly as v14's decode ignored it (a full decode followed by this view failed on
// a wrongly typed one: code 1 / REJECT where v14 gave 0 / ACCEPT).
func Evidence20View(ev *proofv2.Evidence) *proofv2.Evidence {
	if ev == nil {
		return nil
	}
	out := new(proofv2.Evidence)
	copyKept(reflect.ValueOf(out).Elem(), reflect.ValueOf(ev).Elem(), evidenceKept)
	if ev.Certify != nil {
		out.Certify = append([]string(nil), ev.Certify...)
	}
	out.Check = proofv2.SetCheck{} // copied whole with the field above; only the kept members come back
	copyKept(reflect.ValueOf(&out.Check).Elem(), reflect.ValueOf(&ev.Check).Elem(), setCheckKept)
	if ev.Check.Hops != nil {
		out.Check.Hops = append([]string(nil), ev.Check.Hops...)
	}
	if ev.Pages != nil {
		out.Pages = make([]proofv2.PageState, len(ev.Pages))
		for i := range ev.Pages {
			copyKept(reflect.ValueOf(&out.Pages[i]).Elem(), reflect.ValueOf(&ev.Pages[i]).Elem(), pageStateKept)
		}
	}
	return out
}

// The fields v14's decode kept (rules v14 head d20f693).
var (
	evidenceKept  = []string{"Version", "Account", "TxHash", "Receipt", "Majors", "Certify", "Anchor", "Pages", "Check"}
	setCheckKept  = []string{"Majors", "Hops", "Set"}
	pageStateKept = []string{"URL", "State", "Receipt", "Chains", "PendingHash", "ChainError"}
)

// copyKept sets, in dst (zero), the named fields of src. The slice, map and pointer members it copies are shared with src; the callers
// above copy the ones a caller could write through (Certify, Hops).
func copyKept(dst, src reflect.Value, kept []string) {
	for _, n := range kept {
		dst.FieldByName(n).Set(src.FieldByName(n))
	}
}
