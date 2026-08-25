package main

// Which partition an account routes to.
//
// Routing is a property of the network, not something to be read off an
// account's name, and PHASE7_DELEGATION_PLAN Âsection 2 turns on it: a delegated signer
// may live on a different BVN than the principal, which is why one BVN leg is
// not enough. Case F is only the cross-partition case if its two ADIs actually
// land on different partitions, so this asks rather than assumes.
//
// Three things are combined deliberately:
//
//   1. the routing NUMBER comes from accumulate-core's own url.Routing(), so
//      the hash-and-truncate step is not reimplemented here;
//   2. the routing TABLE is fetched live from the network, so a table change
//      shows up as a different answer instead of a stale constant;
//   3. the answer is cross-checked against the validator's own
//      CalculateBVNFromAccountURL, which carries a HARDCODED Kermit table.
//
// (3) is the point. That hardcoded table is what production routes with, and a
// corpus that agreed with it by construction would prove nothing. Fetching the
// table and comparing turns "we assume Kermit has three BVNs" into a check that
// fails loudly the day it stops being true.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"

	proofpkg "github.com/certen/independant-validator/pkg/proof"
)

type router struct {
	overrides map[[32]byte]string
	routes    []protocol.Route
}

func newRouter(ctx context.Context, endpoint string) (*router, error) {
	// NOT c.NetworkStatus. Kermit runs executor version "v2-jiuquan"; the
	// pinned accumulate v1.4.2 dependency predates that label, so decoding a
	// network-status response into its typed form fails with
	//
	//     invalid Executor Version "v2-jiuquan"
	//
	// which is the same wall PHASE7_CORPUS_MANIFEST.md section 3.2 hit and attributed
	// to a stale CLI: it is the LIBRARY, and this program would have hit it too.
	// The drift matters only where ExecutorVersion is decoded - jiuquan gates
	// Ethereum-data signatures and Ethereum write-data entries and nothing about
	// ed25519 or delegated verification - so the routing table is read on its
	// own rather than pinning the whole client to a newer protocol package.
	var resp struct {
		Result struct {
			Routing *protocol.RoutingTable `json:"routing"`
		} `json:"result"`
	}
	if err := rawRPC(ctx, endpoint, "network-status",
		map[string]any{"partition": "Directory"}, &resp); err != nil {
		return nil, fmt.Errorf("network status: %w", err)
	}
	if resp.Result.Routing == nil {
		return nil, fmt.Errorf("network status carries no routing table")
	}
	r := &router{overrides: map[[32]byte]string{}, routes: resp.Result.Routing.Routes}
	for _, o := range resp.Result.Routing.Overrides {
		r.overrides[o.Account.IdentityAccountID32()] = o.Partition
	}
	return r, nil
}

// rawRPC issues a JSON-RPC call and decodes only the fields the caller asks for,
// so a field this build of the protocol package cannot parse does not sink the
// whole response.
func rawRPC(ctx context.Context, endpoint, method string, params any, into any) error {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	var probe struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &probe); err == nil && probe.Error != nil {
		return fmt.Errorf("%s: %s", method, probe.Error.Message)
	}
	return json.Unmarshal(raw, into)
}

// route returns the partition an account URL belongs to.
//
// The routing table partitions the space of routing numbers by bit prefix, so
// exactly one route matches. Anything else means the table was misread or the
// network published a table this code does not understand, and both must be
// errors rather than a best guess: a wrong partition produces a proof leg
// against the wrong BVN, which fails at verification with no hint of why.
func (r *router) route(account string) (string, error) {
	u, err := url.Parse(account)
	if err != nil {
		return "", err
	}
	if p, ok := r.overrides[u.IdentityAccountID32()]; ok {
		return p, nil
	}

	rn := u.Routing()
	var matched []protocol.Route
	for _, rt := range r.routes {
		if rt.Length > 64 {
			return "", fmt.Errorf("route with length %d is not a bit prefix", rt.Length)
		}
		if rt.Length == 0 {
			matched = append(matched, rt)
			continue
		}
		if rn>>(64-rt.Length) == rt.Value {
			matched = append(matched, rt)
		}
	}
	if len(matched) != 1 {
		return "", fmt.Errorf("account %s (routing %016x) matched %d routes, expected exactly 1",
			account, rn, len(matched))
	}
	return matched[0].Partition, nil
}

// reportPartitions prints the partition of every account the corpus names and
// checks the two claims the corpus rests on: that the validator's own routing
// agrees with the network's live table, and that case F really does span two
// BVNs. Case F is the whole reason ChainedProof grows a leg per partition; if
// its two ADIs collide on one BVN it is not the cross-partition case, and
// saying so is more useful than proceeding.
func reportPartitions(ctx context.Context, endpoint string, raw map[string]json.RawMessage) error {
	cases, err := parseCases(raw)
	if err != nil {
		return err
	}
	r, err := newRouter(ctx, endpoint)
	if err != nil {
		return err
	}

	accounts := map[string]string{}
	note := func(acct, why string) {
		if acct == "" {
			return
		}
		if _, seen := accounts[acct]; !seen {
			accounts[acct] = why
		}
	}
	// Case A is not in the manifest: it is the pre-existing production ADI, and
	// it is in the corpus precisely because it must not regress.
	note(caseAPrincipal, "A principal (baseline)")
	for _, name := range sortedCaseNames(cases) {
		cs := cases[name]
		note(cs.ADI, name+" ADI")
		note(cs.Principal, name+" principal")
		note(cs.Delegate, name+" delegate")
	}

	names := make([]string, 0, len(accounts))
	for a := range accounts {
		names = append(names, a)
	}
	sort.Strings(names)

	fmt.Println("== account -> partition, from the network's live routing table ==")
	part := map[string]string{}
	var disagreed int
	for _, a := range names {
		p, err := r.route(a)
		if err != nil {
			return err
		}
		part[a] = p
		// The validator ships its own copy of Kermit's routing table. Compare.
		ours := proofpkg.CalculateBVNFromAccountURL(a)
		mark := "ok"
		if !strings.EqualFold(ours, p) {
			mark = "DISAGREES"
			disagreed++
		}
		fmt.Printf("  %-34s %-9s validator=%-6s %-9s (%s)\n", a, p, ours, mark, accounts[a])
	}
	if disagreed > 0 {
		return fmt.Errorf("%d account(s) route differently under the network table and the "+
			"validator's hardcoded one - the hardcoded table is stale", disagreed)
	}

	f, ok := cases["F"]
	if !ok {
		return fmt.Errorf("case F is absent from the manifest; the cross-partition case is the " +
			"one that justifies a leg per partition")
	}
	pp, dp := part[f.Principal], part[f.Delegate]
	fmt.Printf("\ncase F: principal %s on %s, delegate %s on %s\n", f.Principal, pp, f.Delegate, dp)
	if pp == dp {
		return fmt.Errorf("case F does NOT span partitions - both ADIs route to %s. "+
			"Rename one and re-provision; a single-partition F proves nothing that B does not", pp)
	}
	fmt.Println("case F spans two partitions, as the cross-partition case requires")
	return nil
}
