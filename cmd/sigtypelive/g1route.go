package main

// g1route: where an identity lives (RB9-E, phase "fixtures on the idle partitions").
//
// An Accumulate identity is routed to a partition by its root identity's name alone (docs/proof/G1_CROSS_PARTITION.md fact 6): an
// override keyed by the identity's hash wins, otherwise the route whose top Length bits of the routing number equal its Value. The
// table is the network's own - the Directory's acc://dn.acme/routing data account, which network-status also publishes - and this
// command reads BOTH and refuses to go on unless they are the same table, so a placement is never assumed from the code or from one
// source.
//
//	sigtypelive g1route                           print the table (both sources) and the partition of the standing names
//	sigtypelive g1route -from 500 -to 560         the partitions of pv2-cust-<n>, pv2-bank-<n>, pv2-deleg-<n> for each n
//	sigtypelive g1route -names acc://a.acme,b      the partition of each name (a bare name is <name>.acme)

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// liveRoutingTable reads the routing table from the Directory's routing account and from network-status, and returns it only if they
// are the same table byte for byte.
func (k *kermit) liveRoutingTable(ctx context.Context) (*protocol.RoutingTable, error) {
	acct, err := k.account(ctx, mustURL(proof.RoutingAccountURL))
	if err != nil {
		return nil, err
	}
	if acct == nil {
		return nil, fmt.Errorf("%s does not exist", proof.RoutingAccountURL)
	}
	da, ok := acct.(*protocol.DataAccount)
	if !ok || da.Entry == nil || len(da.Entry.GetData()) != 1 {
		return nil, fmt.Errorf("%s is %T, not a one-entry data account", proof.RoutingAccountURL, acct)
	}
	fromAccount := new(protocol.RoutingTable)
	if err := fromAccount.UnmarshalBinary(da.Entry.GetData()[0]); err != nil {
		return nil, fmt.Errorf("%s: the entry is not a routing table: %w", proof.RoutingAccountURL, err)
	}
	// network-status serves the table the network routes with (the typed client cannot decode a newer executor's status, so only
	// the routing table is decoded, as pkg/proof.LoadNetworkRouter does).
	raw, err := k.rawQuery2(ctx, "network-status", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("network-status: %w", err)
	}
	var st struct {
		Routing *protocol.RoutingTable `json:"routing"`
	}
	if err := json.Unmarshal(raw, &st); err != nil || st.Routing == nil {
		return nil, fmt.Errorf("network-status carries no routing table (%v)", err)
	}
	a, err := fromAccount.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b, err := st.Routing.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(a, b) {
		return nil, fmt.Errorf("the routing account and network-status publish different routing tables")
	}
	return fromAccount, nil
}

func routeOf(t *protocol.RoutingTable, name string) string {
	if !strings.HasPrefix(name, "acc://") {
		name = "acc://" + name + ".acme"
	}
	p, err := proof.RoutePartition(t, name)
	if err != nil {
		return "ERR(" + err.Error() + ")"
	}
	return p
}

func (a *app) g1route(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("g1route", flag.ExitOnError)
	from := fs.Int("from", 0, "first n of pv2-cust-<n>, pv2-bank-<n>, pv2-deleg-<n>")
	to := fs.Int("to", 0, "one past the last n")
	names := fs.String("names", "", "comma-separated names to route")
	_ = fs.Parse(args)
	t, err := a.k.liveRoutingTable(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("routing table (%s, and network-status agrees): %d routes, %d overrides\n", proof.RoutingAccountURL, len(t.Routes), len(t.Overrides))
	rs := append([]protocol.Route(nil), t.Routes...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].Value<<(64-rs[i].Length) < rs[j].Value<<(64-rs[j].Length) })
	for _, r := range rs {
		fmt.Printf("  route /%d value %d -> %s\n", r.Length, r.Value, r.Partition)
	}
	for _, o := range t.Overrides {
		fmt.Printf("  override %s -> %s\n", o.Account, o.Partition)
	}
	parts := map[string]bool{}
	for _, r := range t.Routes {
		parts[r.Partition] = true
	}
	var pl []string
	for p := range parts {
		pl = append(pl, p)
	}
	sort.Strings(pl)
	fmt.Printf("partitions a name can route to by the prefix rule: %v (the Directory is %s only through an override)\n", pl, protocol.Directory)
	for _, n := range []string{"acc://dn.acme", "acc://ACME", "certen-protocol.acme"} {
		fmt.Printf("  %-26s -> %s\n", n, routeOf(t, n))
	}
	if *names != "" {
		for _, n := range strings.Split(*names, ",") {
			n = strings.TrimSpace(n)
			fmt.Printf("  %-26s -> %s\n", n, routeOf(t, n))
		}
	}
	for n := *from; n < *to; n++ {
		fmt.Printf("n=%d  cust=%s bank=%s deleg=%s\n", n,
			routeOf(t, fmt.Sprintf("pv2-cust-%d", n)), routeOf(t, fmt.Sprintf("pv2-bank-%d", n)), routeOf(t, fmt.Sprintf("pv2-deleg-%d", n)))
	}
	return nil
}
