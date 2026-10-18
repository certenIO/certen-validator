// Copyright 2026 Certen Protocol

package govsig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Network is what a verifier needs of the network beyond the signature: its name (typedData's chain id is derived from
// it) and its routing table (which partition a signer page lives on, hence which partition's block a signature's
// receipt names).
type Network struct {
	Name  string
	table *protocol.RoutingTable
}

// NewNetwork builds a Network from a name and a routing table.
func NewNetwork(name string, table *protocol.RoutingTable) (*Network, error) {
	if table == nil || len(table.Routes) == 0 {
		return nil, fmt.Errorf("the routing table has no routes")
	}
	return &Network{Name: name, table: table}, nil
}

// ParseNetworkStatus reads a v3 JSON-RPC network-status response. Only the fields used here are decoded, so a field a
// newer protocol package would add (Kermit's executorVersion "v2-kourou" broke the typed client once) cannot break it.
func ParseNetworkStatus(body []byte) (*Network, error) {
	var resp struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
		Result struct {
			Network struct {
				NetworkName string `json:"networkName"`
			} `json:"network"`
			Routing *protocol.RoutingTable `json:"routing"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("network-status: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("network-status: %s", resp.Error.Message)
	}
	if resp.Result.Network.NetworkName == "" {
		return nil, fmt.Errorf("network-status names no network")
	}
	return NewNetwork(resp.Result.Network.NetworkName, resp.Result.Routing)
}

// FetchNetwork reads network-status from an Accumulate v3 endpoint.
func FetchNetwork(ctx context.Context, endpoint string) (*Network, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("no Accumulate v3 endpoint to read network-status from")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "network-status", "params": map[string]any{}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network-status: %w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20)) // a network-status document is tens of KB; never read an unbounded body
	if err != nil {
		return nil, fmt.Errorf("network-status: %w", err)
	}
	return ParseNetworkStatus(raw)
}

// Partition is the lower-case partition name ("bvn1", "directory") the network routes account to: Accumulate's own
// router rule (internal/api/routing RouteTree) - an override for the account's identity wins; otherwise the one route
// whose top Length bits of the routing number equal its Value. Anything else is refused, never resolved by order.
func (n *Network) Partition(account string) (string, error) {
	u, err := url.Parse(account)
	if err != nil {
		return "", fmt.Errorf("account %q: %w", account, err)
	}
	if protocol.IsUnknown(u) {
		return "", fmt.Errorf("account %q is unknown and cannot be routed", account)
	}
	id := u.IdentityAccountID32()
	for _, o := range n.table.Overrides {
		if o.Account != nil && o.Account.IdentityAccountID32() == id {
			return strings.ToLower(o.Partition), nil
		}
	}
	rn := u.Routing()
	var match []string
	for _, rt := range n.table.Routes {
		if rt.Length == 0 || rt.Length > 64 {
			return "", fmt.Errorf("routing table: route to %s has length %d", rt.Partition, rt.Length)
		}
		if rn>>(64-rt.Length) == rt.Value {
			match = append(match, rt.Partition)
		}
	}
	if len(match) != 1 {
		return "", fmt.Errorf("route %s: %d routes match routing number %016x (%v); the table is not a partition of the space",
			account, len(match), rn, match)
	}
	return strings.ToLower(match[0]), nil
}
