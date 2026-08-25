package main

// Key page states, captured so Gate 3 can run offline.
//
// Authority resolution walks a delegation path and needs every page ON that
// path: its version, its accept threshold, and its entries - keys AND
// delegates. Those come from Kermit here, once, and are stored beside the
// signatures, so the resolution tests are checked against what the chain
// actually says rather than against a fixture someone wrote to match the
// implementation.

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// pageEntry mirrors one KeySpec. A page entry holds a key hash, a delegate, or
// both, and recording only the first is what made every delegation invisible.
type pageEntry struct {
	KeyHash  string `json:"keyHash,omitempty"`
	Delegate string `json:"delegate,omitempty"`
}

type pageState struct {
	URL       string      `json:"url"`
	Version   uint64      `json:"version"`
	Threshold uint64      `json:"threshold"`
	Partition string      `json:"partition"`
	Entries   []pageEntry `json:"entries"`
}

// capturePages reads every page named by the corpus - signer pages and every
// delegator on every chain - and records its state.
func capturePages(ctx context.Context, c *client, r *router, traces []trace) (map[string]pageState, error) {
	wanted := map[string]bool{}
	for _, t := range traces {
		wanted[t.Signer] = true
		for _, d := range t.Delegators {
			wanted[d] = true
		}
	}

	urls := make([]string, 0, len(wanted))
	for u := range wanted {
		urls = append(urls, u)
	}
	sort.Strings(urls)

	out := make(map[string]pageState, len(urls))
	for _, u := range urls {
		acct, err := account(ctx, c, mustURL(u))
		if err != nil {
			return nil, err
		}
		if acct == nil {
			return nil, fmt.Errorf("page %s does not exist, but the corpus names it", u)
		}
		kp, ok := acct.(*protocol.KeyPage)
		if !ok {
			return nil, fmt.Errorf("%s is a %v, not a key page", u, acct.Type())
		}
		part, err := r.route(u)
		if err != nil {
			return nil, err
		}

		ps := pageState{
			URL:       u,
			Version:   kp.Version,
			Threshold: kp.AcceptThreshold,
			Partition: part,
		}
		for _, k := range kp.Keys {
			var e pageEntry
			if len(k.PublicKeyHash) > 0 {
				e.KeyHash = hex.EncodeToString(k.PublicKeyHash)
			}
			if k.Delegate != nil {
				e.Delegate = k.Delegate.String()
			}
			ps.Entries = append(ps.Entries, e)
		}
		out[u] = ps
		fmt.Printf("  page %-42s v%-3d %d-of-%d  %s\n",
			shortURL(u), ps.Version, ps.Threshold, len(ps.Entries), part)
	}
	return out, nil
}
