// Copyright 2026 Certen Protocol
//
// The executor version the evidence proves (docs/proof/G1_CROSS_PARTITION.md D6 g1_executor_version_unsupported; RB9 Phase C1b-2).
//
// The re-evaluation implements the rules of an executor at Baikonur or later: the authority set of an account that lists none is its
// parent's (internal/core/execute/v2/block/utils.go:138-174, "Old logic" before), and the Path / delegator semantics of
// sig_authority.go:175-178. Before Baikonur the parent's set was COPIED into the account at creation, so a document judged by these rules
// could accept what the executor of that version refused. The version in force at a partition's block is not in the network or globals
// accounts the spine proves; it is SystemLedger.ExecutorVersion, an account of the partition itself (<partition>/ledger, protocol.Ledger).
// A document that proves a partition's ledger page at the partition's block (role system-ledger) therefore proves the version, and a
// version before Baikonur is refused by name with the partition and block it was judged at. The capture reads the ledger of every
// partition it reads pages from (proofv2shadow collect.go).
//
// A document that carries no ledger page proves nothing about the version by itself: live Kermit serves no historical receipt for
// <partition>/ledger (RB9-C1b-2-B2), so real documents carry none. The version is then derived by the binding (BindProofV21) from the
// pinned activation table (xexecutor_table.go, a view over govsig; superseding the earlier text that said BindProofV2 must require the
// system-ledger page of every partition, RB9-I-F3). A ledger page the document does carry is checked here (a version before Baikonur is refused) and the binding requires it to agree
// with the table.
package proofv2

import (
	"maps"
	"slices"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// ledgerOf says whether acct is the system ledger of the partition anchor xa names, and returns it.
func ledgerOf(acct protocol.Account, xa *xAnchor) (*protocol.SystemLedger, bool) {
	l, ok := acct.(*protocol.SystemLedger)
	if !ok || xa == nil {
		return nil, false
	}
	return l, strings.EqualFold(l.Url.String(), protocol.PartitionUrl(xa.id).JoinPath(protocol.Ledger).String())
}

// checkExecutorVersion refuses a document that proves a partition's executor version to be before Baikonur (g1_executor_version_unsupported
// {partition, block}). A system ledger proven through another partition's anchor than its own is a role mismatch.
func checkExecutorVersion(byURL map[string]*provenAcct) error {
	// In ascending order of the pages' lower-case URLs: when more than one ledger is refusable the refusal names the first of them in that
	// order, a function of the document and not of the order a map is walked in (RB9-L).
	for _, k := range slices.Sorted(maps.Keys(byURL)) {
		pa := byURL[k]
		l, isLedger := pa.acct.(*protocol.SystemLedger)
		if !isLedger {
			continue
		}
		if own, ok := ledgerOf(l, pa.anchor); !ok || own == nil {
			return refusal21(StateRoleMismatch, pa.anchor.id, pa.anchor.block, "url %s: a system ledger proven through another partition's anchor", l.Url)
		}
		if !l.ExecutorVersion.V2BaikonurEnabled() {
			return refusal21(StateExecutorVersionUnsupported, pa.anchor.id, pa.anchor.block,
				"%s proves executor version %d, before Baikonur (%d): the authority set inheritance and the delegation path differ (sig_authority.go:175-178, utils.go:152-154)",
				l.Url, l.ExecutorVersion, protocol.ExecutorVersionV2Baikonur)
		}
	}
	return nil
}

// StateExecutorVersionUnproven: the capture could not read a partition's system ledger at its block, so the executor version in force there is
// not proven (a note of the capture, never an assumed version).
const StateExecutorVersionUnproven = "g1_executor_version_unproven"
