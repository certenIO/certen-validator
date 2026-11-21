// Copyright 2026 Certen Protocol
//
// The history floor of the Accumulate node proof v2 reads (AGT-F104, owner item OQ12).
//
// Design D2 reads every governing page as of ONE block of its partition: the latest block whose anchor the Directory executed
// at or before the Directory block that executed the transaction's own anchor (xcapture.go). On a partition nobody else uses,
// that block can be far older than the transaction. A node that prunes its BPT history (the public Kermit node keeps about 800
// blocks, some 13 minutes) refuses it as g1_historical_unavailable before the transaction is even executed, so whether an
// intent can be proven would depend on other parties' traffic. The rule is not relaxed (no later block is admitted, nothing
// falls back to another node): the node must keep every block from a floor on. The validator judges its node against the
// floor at start and every 10 minutes and reports the verdict (log, certen_proof_v2_history_floor_met, /health/detailed);
// it does not stop the validator, since each intent the node cannot serve is already refused by name.
//
// PROOF_V2_HISTORY_FLOOR names, for every partition of the network, the lowest block the node must keep serving, for example
// "Directory=13445000,BVN1=17574000,BVN2=17570000,BVN3=17561000" (the heights the full-history node started from). The check
// passes only when the floor names exactly the network's partitions and the node's advertised retained range of each starts
// at or below its floor. A pruning node fails it as soon as its earliest retained block passes the floor.

package proofv2

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// HistoryFloorEnv is the environment variable that carries the floor.
const HistoryFloorEnv = "PROOF_V2_HISTORY_FLOOR"

// The named refusals of the history floor. Each is definitive: retrying the same node and floor cannot change it.
const (
	// FloorUnset: proof v2 is on and no floor is configured.
	FloorUnset = "proof_v2_history_floor_unset"
	// FloorMalformed: the floor text is not a list of partition=height.
	FloorMalformed = "proof_v2_history_floor_malformed"
	// FloorPartitionMissing: a partition of the network has no floor.
	FloorPartitionMissing = "proof_v2_history_floor_partition_missing"
	// FloorPartitionUnknown: the floor names a partition the network does not have.
	FloorPartitionUnknown = "proof_v2_history_floor_partition_unknown"
	// FloorAboveHead: a floor is above the partition's newest retained block (a mistyped height).
	FloorAboveHead = "proof_v2_history_floor_above_head"
	// FloorUnmet: the node no longer serves the floor block: it prunes, or it started above the floor.
	FloorUnmet = "proof_v2_history_floor_unmet"
)

// FloorError is a definitive refusal of the history floor.
type FloorError struct {
	Code      string
	Partition string
	Detail    string
}

func (e *FloorError) Error() string {
	s := e.Code
	if e.Partition != "" {
		s += "{" + e.Partition + "}"
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// HistoryFloor maps a partition ID, spelled as the network's routing table spells it ("Directory", "BVN1"), to the lowest
// block the node must keep serving.
type HistoryFloor map[string]uint64

var floorName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,31}$`)

// ParseHistoryFloor reads "Partition=height,Partition=height". Every entry must be well formed, every partition named
// once, and every height a positive decimal; anything else is refused whole.
func ParseHistoryFloor(raw string) (HistoryFloor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, &FloorError{Code: FloorUnset, Detail: HistoryFloorEnv + " is not set: proof v2 needs a node that keeps every block from a floor on (AGT-F104)"}
	}
	f := HistoryFloor{}
	for _, entry := range strings.Split(raw, ",") {
		name, height, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if !ok || !floorName.MatchString(name) {
			return nil, &FloorError{Code: FloorMalformed, Detail: fmt.Sprintf("entry %q is not Partition=height", entry)}
		}
		if height == "" || strings.TrimLeft(height, "0123456789") != "" || (len(height) > 1 && height[0] == '0') {
			return nil, &FloorError{Code: FloorMalformed, Detail: fmt.Sprintf("entry %q: the height is not a decimal block number", entry)}
		}
		h, err := strconv.ParseUint(height, 10, 64)
		if err != nil || h == 0 {
			return nil, &FloorError{Code: FloorMalformed, Detail: fmt.Sprintf("entry %q: the height is not a positive block number", entry)}
		}
		if _, dup := f[name]; dup {
			return nil, &FloorError{Code: FloorMalformed, Detail: fmt.Sprintf("partition %s is named twice", name)}
		}
		f[name] = h
	}
	return f, nil
}

// String is the floor in its configured form, partitions sorted.
func (f HistoryFloor) String() string {
	names := make([]string, 0, len(f))
	for n := range f {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = fmt.Sprintf("%s=%d", n, f[n])
	}
	return strings.Join(parts, ",")
}

// Check judges the node behind ret against the floor for the network's partitions. A *FloorError is definitive; any other
// error is a failed read of the node (the caller may retry it) and never a pass.
func (f HistoryFloor) Check(ctx context.Context, ret Retention, partitions []string) error {
	if len(partitions) == 0 {
		return fmt.Errorf("the network names no partitions")
	}
	known := map[string]bool{}
	for _, p := range partitions {
		known[p] = true
		if _, ok := f[p]; !ok {
			return &FloorError{Code: FloorPartitionMissing, Partition: p, Detail: "the network has this partition and " + HistoryFloorEnv + " gives it no floor"}
		}
	}
	for p := range f {
		if !known[p] {
			return &FloorError{Code: FloorPartitionUnknown, Partition: p, Detail: "the network has no such partition"}
		}
	}
	sorted := append([]string(nil), partitions...)
	sort.Strings(sorted)
	for _, p := range sorted {
		earliest, latest, err := ret.Retained(ctx, p)
		if err != nil {
			return fmt.Errorf("history floor of %s: %w", p, err)
		}
		floor := f[p]
		if floor > latest {
			return &FloorError{Code: FloorAboveHead, Partition: p, Detail: fmt.Sprintf("floor %d is above the newest retained block %d", floor, latest)}
		}
		if earliest > floor {
			return &FloorError{Code: FloorUnmet, Partition: p, Detail: fmt.Sprintf("the node retains [%d, %d] and the floor is %d: it prunes its history or started above the floor", earliest, latest, floor)}
		}
	}
	return nil
}
