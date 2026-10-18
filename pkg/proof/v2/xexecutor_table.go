// Copyright 2026 Certen Protocol
//
// The executor-version activation table (docs/proof/G1_CROSS_PARTITION.md D6, g1_executor_version_unsupported; RB9 Phase I, finding
// RB9-C1b-2-B2; RB9 verifier round VA, note (a)).
//
// Live Kermit does not serve a historical receipt for <partition>/ledger ("cannot generate a receipt when there are uncommitted
// changes"), so a real 2.1 document carries no system-ledger page and the executor version in force at a page's (partition, block) cannot
// be proven from the document. The binding (intentcert.BindProofV21) derives it from the table instead, and the ledger page, when a
// document does carry one, must agree with it.
//
// THE TABLE HAS ONE SOURCE: accumulate-lite-client-2/liteclient/proof/govsig/gate.go (kermitActivations, RB8-B), which also gates the
// signature types that exist only from an executor version on. This file is a view over it - the same values through the same function
// (govsig.ExecutorFloor), in the types and spellings of the evidence (uint64 blocks, "acc://bvn-BVN1.acme") - and holds no copy.
//
// THE TABLE IS A PINNED TRUST INPUT of the proof, the fourth beside PROOF_V2 section 1's three: it describes Kermit at the pinned
// Accumulate commit and is published with the proof (docs/proof/EXECUTOR_VERSION_PINS.md). cmd/execversionpins re-derives it from the
// network (each partition's activateProtocolVersion message on its main chain, with the receipt to the partition's anchor) and fails if it
// differs from the compiled one. A later activation on any partition needs a row in govsig, a library bump and a deploy to all validators.
package proofv2

import (
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// ExecutorActivation is one partition's executor-version activation: the version, and the partition's local block in which the
// activation message was received. The new version is proven to govern only blocks AFTER that block (whether it governs the same block's
// remaining messages is not established).
type ExecutorActivation struct {
	Version protocol.ExecutorVersion
	Block   uint64
}

// KermitExecutorActivations returns the pinned activation table (a copy, read from govsig): keys are the normalised partition names
// (NormalizeExecutorPartition): "directory", "bvn1", "bvn2", "bvn3".
func KermitExecutorActivations() map[string]ExecutorActivation {
	src := govsig.KermitActivations()
	out := make(map[string]ExecutorActivation, len(src))
	for k, v := range src {
		out[k] = ExecutorActivation{Version: v.Version, Block: uint64(v.Block)}
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
	return govsig.NormalizePartition(p)
}

// ExecutorFloorAt is the lowest executor version the pinned table proves to govern the given block of the partition. ok is false when the
// partition is not in the table or the block is at or below its activation block: the version is then not established (never assumed).
func ExecutorFloorAt(partition string, block uint64) (protocol.ExecutorVersion, bool) {
	return govsig.ExecutorFloor(NormalizeExecutorPartition(partition), int64(block))
}
