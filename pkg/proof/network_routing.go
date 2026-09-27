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
	u, err := url.Parse(account)
	if err != nil {
		return "", fmt.Errorf("account %q: %w", account, err)
	}
	if protocol.IsUnknown(u) {
		return "", fmt.Errorf("account %q is unknown and cannot be routed", account)
	}
	// Accumulate's router (internal/api/routing RouteTree): an override for the account's identity wins;
	// otherwise the route whose top Length bits of the routing number equal its Value. A routing table is
	// prefix-free, so exactly one route matches - anything else is refused, never resolved by order.
	id := u.IdentityAccountID32()
	for _, o := range r.table.Overrides {
		if o.Account != nil && o.Account.IdentityAccountID32() == id {
			return strings.ToLower(o.Partition), nil
		}
	}
	n := u.Routing()
	var match []string
	for _, rt := range r.table.Routes {
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
	return strings.ToLower(match[0]), nil
}
