package main

// The suite of the RB9 verifier round VA fixes: the executor-override body-type gate, the partition derived from the committed anchor
// body, the binding of a sequenced vote's production to the vote, the held-vote name and the verifier-level semantics of the authority sets
// (readiness, the all-authorities-disabled mode and its disclosure, a voter outside an enabled list, a mismatching transaction). The same
// documents-and-verdicts contract as the earlier evidence 2.1 suites, over the timeline world, plus the disclosures a verified report
// carries. New files under their own directory and manifest; the earlier suites are never touched by this mode.
//
//	go run ./cmd/proofv2conformance -xpartition4 pkg/proof/v2/testdata/xpartition4

import "github.com/certen/independant-validator/pkg/proof/v2/xworld"

// XManifestFormat4 names the verifier-round suite.
const XManifestFormat4 = "certen-xpartition4-conformance/1"

func writeXPartition4(out string) error {
	return writeXSuite(out, XManifestFormat4, xworld.Cases4())
}
