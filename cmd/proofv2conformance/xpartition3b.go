package main

// The suite of the roles the carried transaction proves, the executor version and the evidence budget (RB9 Phase C1b-2): the same
// documents-and-verdicts contract as the earlier evidence 2.1 suites, over the timeline world. New files under their own directory
// and manifest; the earlier suites are never touched by this mode.
//
//	go run ./cmd/proofv2conformance -xpartition3b pkg/proof/v2/testdata/xpartition3b

import "github.com/certen/independant-validator/pkg/proof/v2/xworld"

// XManifestFormat3b names the roles / executor-version / budget suite.
const XManifestFormat3b = "certen-xpartition3b-conformance/1"

func writeXPartition3b(out string) error {
	return writeXSuite(out, XManifestFormat3b, xworld.GenesisRequired(xworld.Cases3b()))
}
