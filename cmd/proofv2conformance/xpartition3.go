package main

// The three-way partition suite (RB9 Phase C1b-2, design D2a-D2c): the same documents-and-verdicts contract as the first two evidence
// 2.1 suites, for a governing book on the Directory (D2b), a principal on the Directory (D2c) and the block validator pair (D2a),
// with the anchor kind checked per partition kind. New files under their own directory and manifest; the earlier suites are never
// touched by this mode.
//
//	go run ./cmd/proofv2conformance -xpartition3 pkg/proof/v2/testdata/xpartition3

import "github.com/certen/independant-validator/pkg/proof/v2/xworld"

// XManifestFormat3 names the three-way partition suite.
const XManifestFormat3 = "certen-xpartition3-conformance/1"

func writeXPartition3(out string) error {
	return writeXSuite(out, XManifestFormat3, xworld.GenesisRequired(xworld.Cases3()))
}
