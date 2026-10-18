package main

// The suite of RB9-K (verifier round VR, defect 2): UpdateAccountAuth with operations. The principal is proven at the anchor block, so its
// authority set is the set after the transaction while the executor required the set before it; the operation kinds the body lets the
// verifier invert are modelled and the rest are refused by name (pkg/proof/v2/xoverride.go). New files under their own directory and
// manifest; the earlier suites are never touched by this mode.
//
//	go run ./cmd/proofv2conformance -xpartition5 pkg/proof/v2/testdata/xpartition5

import "github.com/certen/independant-validator/pkg/proof/v2/xworld"

// XManifestFormat5 names the UpdateAccountAuth suite.
const XManifestFormat5 = "certen-xpartition5-conformance/1"

func writeXPartition5(out string) error {
	return writeXSuite(out, XManifestFormat5, xworld.Cases5())
}
