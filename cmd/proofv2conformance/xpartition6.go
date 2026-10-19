package main

// The suite of RB9-K-F1: UpdateAccountAuth with TWO voters. The xworld holds a second authority (DeleBook through DelePage1 on BVN3) beside
// the first (BankBook through BankPage1 on BVN2), so an Add operation whose added authority votes is a document: the executor admits the
// added book's signature, needs it and every book of the set before the transaction, and the verifier reads the same requirement from the
// principal proven after it (pkg/proof/v2/xoverride.go). New files under their own directory and manifest; the earlier suites are never
// touched by this mode.
//
//	go run ./cmd/proofv2conformance -xpartition6 pkg/proof/v2/testdata/xpartition6

import "github.com/certen/independant-validator/pkg/proof/v2/xworld"

// XManifestFormat6 names the two-voter UpdateAccountAuth suite.
const XManifestFormat6 = "certen-xpartition6-conformance/1"

func writeXPartition6(out string) error {
	return writeXSuite(out, XManifestFormat6, xworld.Cases6())
}
