// Copyright 2026 Certen Protocol
//
// The names of the anchored certify form (evidence 2.1 `links`, RB9-F5 section 3). Go and TypeScript share these strings and their
// fields: testdata/certify1/names.json is the source, TestCertifyNamesMatchNamesJSON fails when a constant or a detail here drifts from
// it, and the TypeScript constants (packages/verify/src/s3/certify-names.ts) are generated from the same file.

package proofv2

import (
	"bytes"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// The verifier's refusals and the builder's states.
const (
	StateCertifyLinkMissing       = "certify_link_missing"
	StateCertifyLinkStart         = "certify_link_start"
	StateCertifyLinkEnd           = "certify_link_end"
	StateCertifyLinkInvalid       = "certify_link_invalid"
	StateCertifyLinkUnavailable   = "certify_link_unavailable"
	StateCertifyUpdateReplayed    = "certify_update_replayed"
	StateCertifyItemWithoutEffect = "certify_item_without_effect"
	StateCertifyUpdateUnproven    = "certify_update_unproven"
	StateCertifyWindowUnaccounted = "certify_window_unaccounted"
	StateCertifyRangeUnavailable  = "certify_range_unavailable"
	StateCertificateBudget        = "certificate_budget"
	StateCheckpointStale          = "checkpoint_stale"
)

// certifyDetails is the fixed text after the name and its fields.
var certifyDetails = map[string]string{
	StateCertifyLinkMissing:       "an anchored item has no link",
	StateCertifyLinkStart:         "the link does not start at the previous verified root chain anchor",
	StateCertifyLinkEnd:           "the link does not end at the item's root chain anchor",
	StateCertifyLinkInvalid:       "the link is not a valid receipt of an anchored item",
	StateCertifyLinkUnavailable:   "no receipt links the previous root chain anchor into the item's root chain height",
	StateCertifyUpdateReplayed:    "the update was already applied earlier in the walk",
	StateCertifyItemWithoutEffect: "an anchored item that is not the last of its sequence applies no update",
	StateCertifyUpdateUnproven:    "the update's root chain position does not lie between the previous and this anchor's root chain index",
	StateCertifyWindowUnaccounted: "the account's main chain holds writes the walk did not account for",
	StateCertifyRangeUnavailable:  "the Directory does not serve the minor-root range; retry",
	StateCertificateBudget:        "the certificate does not fit the transaction size limit (tx_too_large)",
	StateCheckpointStale:          "the evidence builds on a major block older than the newest verified one by more than the allowed lag",
}

// CertifyState is a named refusal or state of the certify form: Code, the fields it was judged at (decimal integers, lower-case hex
// hashes), and the fixed detail of its code.
type CertifyState struct {
	Code   string
	Fields []string
}

func (s *CertifyState) Error() string {
	return s.Code + "{" + strings.Join(s.Fields, ",") + "}: " + certifyDetails[s.Code]
}

func certifyState(code string, fields ...string) *CertifyState {
	return &CertifyState{Code: code, Fields: fields}
}

// CertifyStateDetail is the fixed detail text of a code (empty for a name this package does not define).
func CertifyStateDetail(code string) string { return certifyDetails[code] }

// genesisLinkIndex is the index a certify_link_* state carries for the genesis link (Evidence.GenesisLink), which has no ordinal in the
// links member.
const genesisLinkIndex = "genesis"

// checkGenesisLink judges the chain identity of an anchored document (V-E A1b): the genesis link must start at the pinned incarnation's
// genesis root chain anchor, end at the certified root chain anchor and validate. Its refusals are the certify_link_* states at index
// "genesis".
func checkGenesisLink(link *merkle.Receipt, genesisRoot, certifiedRoot [32]byte) error {
	switch {
	case link == nil:
		return certifyState(StateCertifyLinkMissing, genesisLinkIndex)
	case !stepsPresent(link):
		return certifyState(StateCertifyLinkInvalid, genesisLinkIndex)
	case !bytes.Equal(link.Start, genesisRoot[:]):
		return certifyState(StateCertifyLinkStart, genesisLinkIndex)
	case !bytes.Equal(link.Anchor, certifiedRoot[:]):
		return certifyState(StateCertifyLinkEnd, genesisLinkIndex)
	case !link.Validate(nil):
		return certifyState(StateCertifyLinkInvalid, genesisLinkIndex)
	}
	return nil
}
