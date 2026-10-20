// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"reflect"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
)

// wantMovedByGenesis judges a frozen document of the xpartition suites whose verdict moved by RB9-F6 (F-VE-2 option b): the manifest entry says
// it is refused certify_link_missing{genesis} with the note that says why, and the verifier's refusal is that certify state. It moved from
// verified: a document that was refused for another reason keeps that refusal, because the offline walk judges the genesis link last for a
// document in the continuous form.
func wantMovedByGenesis(t *testing.T, err error, state string, fields []string, note string) {
	t.Helper()
	if state != proofv2.StateCertifyLinkMissing || !reflect.DeepEqual(fields, []string{"genesis"}) || note != xworld.GenesisMovedNote {
		t.Fatalf("the manifest entry is %s%v with note %q, want %s[genesis] with note %q", state, fields, note, proofv2.StateCertifyLinkMissing, xworld.GenesisMovedNote)
	}
	wantCertifyState(t, err, state, fields...)
}
