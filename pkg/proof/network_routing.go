// Copyright 2026 Certen Protocol

package proof

import (
	"context"
	"fmt"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// NetworkRouter names the partition an account lives on with the network's own routing table and
// Accumulate's own router (RB3-F107). Partitions used to come from a routing table written into this
// code for Kermit (routeByPrefixTable), which also ignored the table's overrides - acc://dn.acme and
// acc://ACME route to the Directory on the network, and by hash in the snapshot.
type NetworkRouter struct {
	table *protocol.RoutingTable
}

// NewNetworkRouter routes with table.
func NewNetworkRouter(table *protocol.RoutingTable) (*NetworkRouter, error) {
	if table == nil || len(table.Routes) == 0 {
		return nil, fmt.Errorf("the routing table has no routes")
	}
	return &NetworkRouter{table: table}, nil
}

// LoadNetworkRouter reads the routing table the network publishes in network-status.
func LoadNetworkRouter(ctx context.Context, endpoint string) (*NetworkRouter, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("no Accumulate v3 endpoint to read the routing table from")
	}
	// Read as raw JSON and only the routing table decoded: this module's typed client cannot decode the
	// network-status of a network running a newer executor (Kermit's "v2-kourou", RB3-F109).
	var resp struct {
		Result struct {
			Routing *protocol.RoutingTable `json:"routing"`
		} `json:"result"`
	}
	if err := queryRawJSON(ctx, endpoint, "network-status", map[string]any{}, &resp); err != nil {
		return nil, fmt.Errorf("read the network's routing table: %w", err)
	}
	return NewNetworkRouter(resp.Result.Routing)
}

// Partition is the lower-case partition name ("bvn1", "directory") the network routes account to.
func (r *NetworkRouter) Partition(account string) (string, error) {
	id, err := r.PartitionID(account)
	if err != nil {
		return "", err
	}
	return strings.ToLower(id), nil
}

// PartitionID is the partition the network routes account to, spelled exactly as the routing table spells it ("BVN2",
// "Directory"): the spelling a partition's own URLs (acc://bvn-BVN2.acme) carry, which a hash over a URL is sensitive to.
func (r *NetworkRouter) PartitionID(account string) (string, error) {
	return RoutePartition(r.table, account)
}

// RoutePartition is the ONE route function of the validator: the partition a routing table sends account to, spelled as the
// table spells it. The NetworkRouter (partition names for discovery and capture) and the proof v2 verifier (Partition ==
// route(URL) for every proven page, docs/proof/G1_CROSS_PARTITION.md D5) both call it, so the capture and the verifier cannot
// route differently.
//
// It is Accumulate's own rule (internal/api/routing RouteTree, R9 section 1d, validated 11 of 11 against the serving
// partition): an override keyed by the account's identity hash wins; otherwise the route whose top Length bits of the routing
// number equal its Value. A routing table is prefix-free, so exactly one route matches - anything else is refused, never
// resolved by order.
func RoutePartition(table *protocol.RoutingTable, account string) (string, error) {
	if table == nil || len(table.Routes) == 0 {
		return "", fmt.Errorf("the routing table has no routes")
	}
	u, err := url.Parse(account)
	if err != nil {
		return "", fmt.Errorf("account %q: %w", account, err)
	}
	if protocol.IsUnknown(u) {
		return "", fmt.Errorf("account %q is unknown and cannot be routed", account)
	}
	id := u.IdentityAccountID32()
	for _, o := range table.Overrides {
		if o.Account != nil && o.Account.IdentityAccountID32() == id {
			return o.Partition, nil
		}
	}
	n := u.Routing()
	var match []string
	for _, rt := range table.Routes {
		if rt.Length == 0 || rt.Length > 64 {
			return "", fmt.Errorf("routing table: route to %s has length %d", rt.Partition, rt.Length)
		}
		if n>>(64-rt.Length) == rt.Value {
			match = append(match, rt.Partition)
		}
	}
	if len(match) != 1 {
		return "", fmt.Errorf("route %s: %d routes match routing number %016x (%v); the table is not a partition of the space", account, len(match), n, match)
	}
	return match[0], nil
}
