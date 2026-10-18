// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// The Go constants of the certify names and their fixed details are exactly names.json, which the TypeScript constants are generated from.
func TestCertifyNamesMatchNamesJSON(t *testing.T) {
	n, _ := loadCertifyNames(t)
	if n.Format != "certen-certify1-names/1" || len(n.Names) != 12 {
		t.Fatalf("names.json is %q with %d names", n.Format, len(n.Names))
	}
	codes := map[string]string{
		"certify_link_missing":        proofv2.StateCertifyLinkMissing,
		"certify_link_start":          proofv2.StateCertifyLinkStart,
		"certify_link_end":            proofv2.StateCertifyLinkEnd,
		"certify_link_invalid":        proofv2.StateCertifyLinkInvalid,
		"certify_link_unavailable":    proofv2.StateCertifyLinkUnavailable,
		"certify_update_replayed":     proofv2.StateCertifyUpdateReplayed,
		"certify_item_without_effect": proofv2.StateCertifyItemWithoutEffect,
		"certify_update_unproven":     proofv2.StateCertifyUpdateUnproven,
		"certify_window_unaccounted":  proofv2.StateCertifyWindowUnaccounted,
		"certify_range_unavailable":   proofv2.StateCertifyRangeUnavailable,
		"certificate_budget":          proofv2.StateCertificateBudget,
		"checkpoint_stale":            proofv2.StateCheckpointStale,
	}
	for _, e := range n.Names {
		if codes[e.Name] != e.Name {
			t.Errorf("%s: the Go constant is %q", e.Name, codes[e.Name])
		}
		if got := proofv2.CertifyStateDetail(e.Name); got != e.Detail || e.Detail == "" {
			t.Errorf("%s: the Go detail is %q, names.json says %q", e.Name, got, e.Detail)
		}
		delete(codes, e.Name)
	}
	if len(codes) != 0 {
		t.Errorf("Go constants names.json does not list: %v", codes)
	}
}
