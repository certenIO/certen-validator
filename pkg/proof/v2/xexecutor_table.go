// Copyright 2026 Certen Protocol
//
// The pinned executor-version activation table (docs/proof/G1_CROSS_PARTITION.md D6, g1_executor_version_unsupported; RB9 Phase I,
// finding RB9-C1b-2-B2).
//
// Live Kermit does not serve a historical receipt for <partition>/ledger ("cannot generate a receipt when there are uncommitted
// changes"), so a real 2.1 document carries no system-ledger page and the executor version in force at a page's (partition, block) cannot
// be proven from the document. The binding (intentcert.BindProofV21) derives it from this table instead, and the ledger page, when a
// document does carry one, must agree with it.
//
// THIS TABLE IS A PINNED TRUST INPUT. It is the same table the signature-type gate of RB8 pins, copied value for value:
//
//	source: accumulate-lite-client-2/liteclient/proof/govsig/gate.go, kermitActivations, branch pv2/rb8-b-every-key-signature-type
//	        (commit 71fd45a; research/R8-signature-types.md Measurements M5, read from Kermit's own system ledgers on 2026-10-17)
//
// Each of the Directory and BVN1-3 has exactly two entries on its partition main chain: systemGenesis, and one activateProtocolVersion
// v2-kourou. v2-kourou (9) is above v2-baikonur (6), so a transaction recorded in a block after a partition's activation block was
// executed by an executor at or above Baikonur. The version BEFORE the activation is the genesis version, which the public API cannot show
// (BPT history retention is about 710 blocks); it is not assumed, and a block at or below the activation block is not established.
//
// govsig is not part of the RB9 stack's base, so the table is pinned here. When the RB8 branch merges, one follow-up makes govsig the
// single source (this file then delegates to govsig.KermitActivations); TestExecutorTableIsPinned pins the values meanwhile. A later
// activation on any partition needs a row here and a library bump, exactly as protocol.ExecutorVersionLatest needs one.
package proofv2

import (
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// ExecutorActivation is one partition's executor-version activation: the version, and the partition's local block in which the
// activation message was received. The new version is proven to govern only blocks AFTER that block (whether it governs the same block's
// remaining messages is not established).
type ExecutorActivation struct {
	Version protocol.ExecutorVersion
	Block   uint64
}

// kermitExecutorActivations: keys are the normalised partition names (NormalizeExecutorPartition): "directory", "bvn1", "bvn2", "bvn3".
var kermitExecutorActivations = map[string]ExecutorActivation{
	"directory": {Version: protocol.ExecutorVersionV2Kourou, Block: 9_538_105},
	"bvn1":      {Version: protocol.ExecutorVersionV2Kourou, Block: 12_491_272},
	"bvn2":      {Version: protocol.ExecutorVersionV2Kourou, Block: 12_492_057},
	"bvn3":      {Version: protocol.ExecutorVersionV2Kourou, Block: 12_491_127},
}

// KermitExecutorActivations returns a copy of the pinned activation table.
func KermitExecutorActivations() map[string]ExecutorActivation {
	out := make(map[string]ExecutorActivation, len(kermitExecutorActivations))
	for k, v := range kermitExecutorActivations {
		out[k] = v
	}
	return out
}

// NormalizeExecutorPartition maps every spelling of a partition the evidence uses to the table's key: "acc://bvn-BVN1.acme", "bvn-BVN1",
// "BVN1" and "bvn1" are "bvn1"; "dn", "directory", "dn.acme" and "acc://dn.acme" are "directory". Anything else is returned lower-cased and
// is not in the table.
func NormalizeExecutorPartition(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	p = strings.TrimPrefix(p, "acc://")
	p = strings.TrimSuffix(p, "/")
	p = strings.TrimSuffix(p, ".acme")
	p = strings.TrimPrefix(p, "bvn-")
	if p == "dn" || p == "directory" {
		return "directory"
	}
	return p
}

// ExecutorFloorAt is the lowest executor version the pinned table proves to govern the given block of the partition. ok is false when the
// partition is not in the table or the block is at or below its activation block: the version is then not established (never assumed).
func ExecutorFloorAt(partition string, block uint64) (protocol.ExecutorVersion, bool) {
	a, ok := kermitExecutorActivations[NormalizeExecutorPartition(partition)]
	if !ok || block <= a.Block {
		return 0, false
	}
	return a.Version, true
}
