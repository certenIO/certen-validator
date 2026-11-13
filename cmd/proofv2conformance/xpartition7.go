package main

// The suite of DAX-1G (G-83): a transaction initiated by a page that is NOT a voting authority - the tcl `*-erp` initiator, decision 0042 - whose
// signature the document carries (Evidence.InitiatingSignature) and the verifier proves. The xworld holds ErpPage1 of ErpBook (BVN3), an identity
// that is no authority of the principal, signing first beside the authority that votes; blocks are the ones the pinned executor-activation table
// proves (LayoutBVNProven), so intentcert.BindProofV21 judges the same documents. Every document is genesis-linked (F-VE-2 (b)). New files under
// their own directory and manifest; the earlier suites are never touched by this mode.
//
//	go run ./cmd/proofv2conformance -xpartition7 pkg/proof/v2/testdata/xpartition7

import "github.com/certen/independant-validator/pkg/proof/v2/xworld"

// XManifestFormat7 names the non-voting initiator suite.
const XManifestFormat7 = "certen-xpartition7-conformance/1"

func writeXPartition7(out string) error {
	return writeXSuite(out, XManifestFormat7, xworld.Cases7())
}
