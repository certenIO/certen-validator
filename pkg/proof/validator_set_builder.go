// Copyright 2026 Certen Protocol
//
// Building a ValidatorSetProof from a live Accumulate network.
//
// This is the producer half. The consumer half — Verify — is in
// validator_set_proof.go and performs no network access; everything fetched here
// is evidence a third party re-checks offline, not an answer they have to trust.
//
// # WHAT IT CAN AND CANNOT PRODUCE TODAY
//
// It produces a proof that DERIVES the validator set and the accept threshold
// from chain bytes. It cannot produce one that BINDS them to a quorum-signed
// anchor, and no amount of care here would change that: an account query returns
// a receipt against the node's CURRENT BPT root, while roots reach
// anchor(<partition>)-bpt only at anchor-emission points — one per ~46 blocks on
// Kermit, one per ~2,524 on MainNet. Measured 2026-08-28, a freshly fetched root
// matched none of the 300 most recent anchored roots.
//
// Polling for a lucky match would not help either, because the binding has to be
// to the anchor of the block the transaction settled in, and that block is
// chosen by when it settled. Reaching it requires a membership proof against a
// HISTORICAL BPT root, which is what AIP-058 asks Accumulate for.
//
// So a proof built here verifies to VerdictValidatorSetUnbound. That is a real
// improvement over VerdictValidatorSetAsserted — the set comes from chain bytes
// with a merkle path rather than from a build-time RPC — and it is deliberately
// short of VerdictVerified. Do not paper over the difference.
package proof

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// AccumulateQuerier is the narrow slice of the v3 API the builder needs. It is
// an interface so tests can drive the builder without a network.
type AccumulateQuerier interface {
	Query(ctx context.Context, params any) (json.RawMessage, error)
}

// HTTPQuerier is the default AccumulateQuerier, speaking v3 JSON-RPC.
type HTTPQuerier struct {
	Endpoint string
	Client   *http.Client
}

// NewHTTPQuerier returns a querier for a v3 endpoint, e.g.
// https://kermit.accumulatenetwork.io/v3
func NewHTTPQuerier(endpoint string) *HTTPQuerier {
	return &HTTPQuerier{Endpoint: endpoint, Client: &http.Client{Timeout: 60 * time.Second}}
}

func (q *HTTPQuerier) Query(ctx context.Context, params any) (json.RawMessage, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "query", "params": params,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, q.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := q.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var env struct {
		Result json.RawMessage  `json:"result"`
		Error  *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if env.Error != nil {
		return nil, fmt.Errorf("accumulate rpc error: %s", string(*env.Error))
	}
	return env.Result, nil
}

// BuildValidatorSetProof assembles the evidence for the Directory's validator
// set from a live network.
//
// It fetches, for acc://dn.acme/network and acc://dn.acme/globals: the account
// state with its BPT membership receipt, and the chain list with each chain's
// merkle state. It also fetches the incarnation identity —
// anchor(directory)-root[0], the genesis root anchor — which is the only value
// measured to differ between chains and which nothing in an L4 leg carries.
//
// The two accounts MUST land on the same BPT root or Verify refuses them: the
// set and the threshold have to have coexisted. Because both queries hit a
// moving chain, this retries until they agree.
func BuildValidatorSetProof(ctx context.Context, q AccumulateQuerier) (*ValidatorSetProof, error) {
	inc, err := fetchIncarnation(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("incarnation: %w", err)
	}

	const attempts = 5
	var lastErr error
	for i := 0; i < attempts; i++ {
		network, err := fetchAccountStateProof(ctx, q, "acc://dn.acme/network")
		if err != nil {
			return nil, fmt.Errorf("network account: %w", err)
		}
		globals, err := fetchAccountStateProof(ctx, q, "acc://dn.acme/globals")
		if err != nil {
			return nil, fmt.Errorf("globals account: %w", err)
		}
		if !strings.EqualFold(network.StateReceipt.Anchor, globals.StateReceipt.Anchor) {
			// The chain moved between the two queries. Retry rather than emit a
			// proof Verify would refuse.
			lastErr = fmt.Errorf("the two accounts landed on different BPT roots "+
				"(network=%s globals=%s)", short(network.StateReceipt.Anchor), short(globals.StateReceipt.Anchor))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(i+1) * time.Second):
			}
			continue
		}
		p := &ValidatorSetProof{Incarnation: inc, Network: *network, Globals: *globals}

		// Fail closed here rather than emitting evidence that does not check.
		// The producer proving its own output is what stops a malformed artifact
		// reaching storage and being discovered by a third party instead.
		if _, _, err := p.DerivedSet(); err != nil {
			return nil, fmt.Errorf("built a proof whose accounts do not decode: %w", err)
		}
		if err := p.Network.verifyChainBinding(); err != nil {
			return nil, fmt.Errorf("built a proof whose network chain binding fails: %w", err)
		}
		if err := p.Globals.verifyChainBinding(); err != nil {
			return nil, fmt.Errorf("built a proof whose globals chain binding fails: %w", err)
		}
		return p, nil
	}
	return nil, fmt.Errorf("could not read both accounts at one block after %d attempts: %w",
		attempts, lastErr)
}

// fetchIncarnation reads anchor(directory)-root[0] — the genesis root anchor.
//
// It is fetched BY INDEX deliberately. The by-hash form fails for genesis-era
// entries on every node, including one built from scratch: ElementIndex is a
// locally derived index record and genesis entries never receive one.
func fetchIncarnation(ctx context.Context, q AccumulateQuerier) (string, error) {
	raw, err := q.Query(ctx, map[string]any{
		"scope": "acc://dn.acme/anchors",
		"query": map[string]any{
			"queryType": "chain", "name": "anchor(directory)-root", "index": 0,
		},
	})
	if err != nil {
		return "", err
	}
	var rec struct {
		Entry string `json:"entry"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return "", err
	}
	if _, err := chained_proof.MustHex32Lower(rec.Entry, "incarnation"); err != nil {
		return "", err
	}
	return strings.ToLower(rec.Entry), nil
}

func fetchAccountStateProof(ctx context.Context, q AccumulateQuerier, url string) (*AccountStateProof, error) {
	raw, err := q.Query(ctx, map[string]any{
		"scope": url,
		"query": map[string]any{"queryType": "default", "includeReceipt": true},
	})
	if err != nil {
		return nil, err
	}
	var rec struct {
		Account json.RawMessage       `json:"account"`
		Receipt chained_proof.Receipt `json:"receipt"`
		Pending struct {
			Total int `json:"total"`
		} `json:"pending"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	if len(rec.Receipt.Entries) < 2 {
		return nil, fmt.Errorf("receipt has %d steps; expected at least the two state-hasher steps",
			len(rec.Receipt.Entries))
	}

	// Re-encode the account to its canonical binary form. This is the preimage
	// the BPT leaf hashes, so it is what a verifier re-derives from.
	acct, err := protocol.UnmarshalAccountJSON(rec.Account)
	if err != nil {
		return nil, fmt.Errorf("decode account: %w", err)
	}
	bin, err := acct.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("re-encode account: %w", err)
	}

	chains, err := fetchChainRoots(ctx, q, url)
	if err != nil {
		return nil, err
	}

	// The state hasher's second and fourth elements are not returned by the API,
	// but both are derivable, and verifyChainBinding checks the derivation
	// against the receipt — so a wrong guess is caught rather than trusted.
	//
	//   secondaryState: 32 zero bytes for a data account with no directory
	//   pending:        32 zero bytes when nothing is pending
	//
	// If either assumption ever stops holding, the binding check fails loudly
	// instead of producing an unverifiable proof.
	zeros := hex.EncodeToString(make([]byte, 32))
	if rec.Pending.Total != 0 {
		return nil, fmt.Errorf("%s has %d pending transactions; the pending component is no longer "+
			"32 zero bytes and must be obtained rather than assumed", url, rec.Pending.Total)
	}

	return &AccountStateProof{
		AccountURL:    url,
		AccountState:  hex.EncodeToString(bin),
		StateReceipt:  rec.Receipt,
		Chains:        chains,
		SecondaryHash: zeros,
		PendingHash:   zeros,
	}, nil
}

func fetchChainRoots(ctx context.Context, q AccumulateQuerier, url string) ([]ChainRoot, error) {
	raw, err := q.Query(ctx, map[string]any{
		"scope": url, "query": map[string]any{"queryType": "chain"},
	})
	if err != nil {
		return nil, err
	}
	var rec struct {
		Records []struct {
			Name  string    `json:"name"`
			Count uint64    `json:"count"`
			State []*string `json:"state"`
		} `json:"records"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	if len(rec.Records) == 0 {
		return nil, fmt.Errorf("%s reports no chains", url)
	}

	out := make([]ChainRoot, 0, len(rec.Records))
	for _, c := range rec.Records {
		cr := ChainRoot{Name: c.Name, Count: c.Count, Pending: c.State}
		// Restate the anchor from the merkle state. derive() recomputes both and
		// refuses any disagreement, so this is a convenience for readers rather
		// than an input anyone trusts.
		_, anchor, err := cr.derive()
		if err != nil {
			return nil, fmt.Errorf("%s chain %q: %w", url, c.Name, err)
		}
		cr.Anchor = hex.EncodeToString(anchor)
		out = append(out, cr)
	}
	return out, nil
}
