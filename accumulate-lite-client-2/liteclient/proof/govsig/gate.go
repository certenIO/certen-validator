// Copyright 2026 Certen Protocol

package govsig

import (
	"fmt"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// THE EXECUTOR-VERSION GATE.
//
// Some of the nine types are not always registered with Accumulate's executor, and one verifies by a different rule
// before a version:
//
//	rsaSha256, ecdsaSha256, typedData   registered only at executor version >= v2-vandenberg  (sig_user.go:20-43)
//	eth, raw 64/65-byte r||s rule       only at executor version >= v2-baikonur               (sig_user.go:108-112)
//
// A signature's block is a block of ONE partition, and each partition (the Directory and every BVN) activated a
// version at its own block. So the gate is a pure function of (partition, block) against the activation table below.
//
// WHAT IS KNOWN (research/R8-signature-types.md Measurements M5, read from Kermit's own system ledgers on 2026-10-17):
// each of the Directory and BVN1-3 has exactly two entries on its partition main chain: systemGenesis, and one
// activateProtocolVersion v2-kourou. v2-kourou (9) is >= v2-vandenberg (7) and >= v2-baikonur (6), so a signature
// recorded after a partition's activation was verified by an executor that had both. The version BEFORE the activation
// is the genesis version, which the public API cannot show (BPT history retention is ~710 blocks, R8 M6, Open
// question O1); it is not assumed.
//
// So: after the activation block -> proven. At or before it -> the NAMED STATE ExecutorVersionUnproven{type,
// partition, block}. Never acceptance and never a silent refusal. The activation block itself is treated as not yet
// proven: the table records the block in which the activation message was RECEIVED, and whether the new version
// governs that same block's remaining messages is not established.

// Activation is one partition's executor-version activation.
type Activation struct {
	Version protocol.ExecutorVersion
	// Block is the partition's local block in which the activation message was received (R8 M5).
	Block int64
	// Time is that block's localBlockTime, UTC, as read from the chain entry's receipt. Informational.
	Time string
}

// kermitActivations is the pinned table (R8 M5). Keys are lower-case partition names as the validator's network router
// spells them (pkg/proof/network_routing.go): "directory", "bvn1", "bvn2", "bvn3".
//
// It describes Kermit (network DevNet) at the pinned accumulate commit e1d1db9ebb7c. A later activation on any
// partition needs a row here and a library bump, exactly as protocol.ExecutorVersionLatest needs one.
var kermitActivations = map[string]Activation{
	"directory": {Version: protocol.ExecutorVersionV2Kourou, Block: 9_538_105, Time: "2026-09-21T15:30:10Z"},
	"bvn1":      {Version: protocol.ExecutorVersionV2Kourou, Block: 12_491_272},
	"bvn2":      {Version: protocol.ExecutorVersionV2Kourou, Block: 12_492_057},
	"bvn3":      {Version: protocol.ExecutorVersionV2Kourou, Block: 12_491_127},
}

// KermitActivations returns a copy of the pinned activation table.
func KermitActivations() map[string]Activation {
	out := make(map[string]Activation, len(kermitActivations))
	for k, v := range kermitActivations {
		out[k] = v
	}
	return out
}

// NormalizePartition lower-cases a partition name and maps the Directory's spellings to "directory".
func NormalizePartition(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case "dn", "directory", "dn.acme":
		return "directory"
	}
	return p
}

// ExecutorFloor is the lowest executor version PROVEN to govern a block of a partition. ok is false when the block
// does not follow a known activation (or the partition is not in the table): the version is then unproven, not zero.
func ExecutorFloor(partition string, block int64) (protocol.ExecutorVersion, bool) {
	a, ok := kermitActivations[NormalizePartition(partition)]
	if !ok || block <= a.Block {
		return 0, false
	}
	return a.Version, true
}

// RequiredVersion is the executor version a signature of type t needs. Zero means the type is always registered and
// has one rule. rule is the eth rule the signature verified under (EthRuleNone for every other type).
func RequiredVersion(t protocol.SignatureType, rule string) protocol.ExecutorVersion {
	switch t {
	case protocol.SignatureTypeRsaSha256, protocol.SignatureTypeEcdsaSha256, protocol.SignatureTypeTypedData:
		return protocol.ExecutorVersionV2Vandenberg
	case protocol.SignatureTypeETH:
		if rule == EthRuleV2RSV {
			return protocol.ExecutorVersionV2Baikonur
		}
	}
	return 0
}

// ExecutorVersionUnproven is the named state for a signature whose type needs an executor version the evidence does
// not prove at the block it was recorded in.
type ExecutorVersionUnproven struct {
	Type      string
	Partition string
	Block     int64
	Needs     string
	// EarliestKnown is the first block of this partition from which the version IS proven (0 if the partition is not in
	// the pinned table).
	EarliestKnown int64
}

func (e ExecutorVersionUnproven) Error() string {
	where := fmt.Sprintf("partition %q block %d", e.Partition, e.Block)
	if e.Partition == "" || e.Block <= 0 {
		where = "an unknown partition/block (the evidence names none)"
	}
	return fmt.Sprintf("g1_executor_version_unproven{type=%s, partition=%q, block=%d}: a %s signature needs executor "+
		"version %s, and the version in force at %s is not proven (the pinned activation table proves it only after "+
		"block %d of that partition). This is NOT a governance rejection and the signature is NOT counted",
		e.Type, e.Partition, e.Block, e.Type, e.Needs, where, e.EarliestKnown)
}
func (e ExecutorVersionUnproven) Reason() string { return "g1_executor_version_unproven" }

// ExecutorGateNotMet: the evidence is inconsistent with Accumulate's rules. The partition's executor is proven to have
// been at a version under which this signature form could not have been accepted.
type ExecutorGateNotMet struct {
	Type      string
	Partition string
	Block     int64
	Proven    string
	Why       string
}

func (e ExecutorGateNotMet) Error() string {
	return fmt.Sprintf("executor_gate_not_met{type=%s, partition=%q, block=%d, version=%s}: %s", e.Type, e.Partition,
		e.Block, e.Proven, e.Why)
}
func (e ExecutorGateNotMet) Reason() string { return "executor_gate_not_met" }

// CheckExecutorGate applies the gate for a signature of type t, verified under the eth rule `rule`, recorded at where.
func CheckExecutorGate(t protocol.SignatureType, rule string, where Where) error {
	part := NormalizePartition(where.Partition)
	need := RequiredVersion(t, rule)
	floor, proven := ExecutorFloor(part, where.Block)

	// An eth signature in the pre-Baikonur DER form could only have been accepted while the executor was below
	// v2-baikonur. A proven floor at or above it means the chain cannot have recorded it.
	if t == protocol.SignatureTypeETH && rule == EthRuleV1DER {
		if proven && floor.V2BaikonurEnabled() {
			return ExecutorGateNotMet{Type: "eth(der)", Partition: part, Block: where.Block, Proven: floor.String(),
				Why: "the executor was already at v2-baikonur or later, which verifies eth by the raw r||s rule only; " +
					"a DER-form eth signature cannot have been accepted there"}
		}
		return nil
	}

	if need == 0 {
		return nil
	}
	if !proven {
		return ExecutorVersionUnproven{Type: t.String(), Partition: part, Block: where.Block, Needs: need.String(),
			EarliestKnown: kermitActivations[part].Block}
	}
	if floor < need {
		return ExecutorGateNotMet{Type: t.String(), Partition: part, Block: where.Block, Proven: floor.String(),
			Why: fmt.Sprintf("needs %s", need)}
	}
	return nil
}
