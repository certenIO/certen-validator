// Copyright 2026 Certen Protocol
//
// Which partitions actually signed, discovered from the transaction itself.
//
// WHY THIS EXISTS.
//
// The chained proof builder can carry a leg per signer partition, and the
// governance layer can resolve delegated authority across partitions. Until this
// file, production never connected the two: it called BuildProof with a single
// BVN, so a transaction whose signers spanned two partitions produced a
// ONE-LEG proof.
//
// That is not a missing feature, it is silent under-proving. The one-leg proof
// VERIFIES - it is internally consistent - while the second partition's quorum
// is simply absent from it. A reader cannot tell the difference between "this
// authority lives on one partition" and "we only proved one of the two it lives
// on". It is the same failure shape as a truncated reassembly, and it fails the
// same way: by passing.
//
// So the signer partitions are discovered from the transaction, before the proof
// is built, and a proof that needs several legs gets several legs.
//
// WHY FROM THE TRANSACTION AND NOT FROM G1.
//
// G1's threshold accounting knows which signatures were COUNTED, which is the
// smaller and arguably more precise set. It is not available at this call site,
// and reaching for it would thread governance state through the proof
// generator's callers.
//
// Reading the transaction is better anyway, for a reason beyond convenience: the
// leg set becomes a function of the transaction and of chain history alone, so
// two validators building the same proof agree without having to agree about a
// threshold computation first. Including a signature that did not contribute to
// the threshold costs one leg and proves one more true thing; omitting one that
// did is the failure this file exists to prevent.
package proof

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

// signerDiscovery is the subset of a transaction query this needs.
//
// Declared narrowly and decoded from raw JSON rather than through the typed
// client: the pinned protocol package cannot decode Kermit's executor version on
// some paths, and a narrow decode cannot be broken by a field it never reads.
type signerDiscovery struct {
	Result struct {
		Signatures struct {
			Records []struct {
				Account struct {
					Type string `json:"type"`
					URL  string `json:"url"`
				} `json:"account"`
				Signatures struct {
					Records []struct {
						ID      string `json:"id"`
						Message struct {
							Type      string `json:"type"`
							TxID      string `json:"txID"`
							Signature struct {
								Type string `json:"type"`
							} `json:"signature"`
						} `json:"message"`
					} `json:"records"`
				} `json:"signatures"`
			} `json:"records"`
		} `json:"signatures"`
	} `json:"result"`
}

// DiscoverSignerLegs returns one leg per signer account that carries a user
// signature over this transaction.
//
// Returned sorted by partition then account, so the set is canonical: two
// validators reading the same transaction produce the same legs in the same
// order, and the proof's bytes do not depend on response ordering.
func DiscoverSignerLegs(ctx context.Context, endpoint, txID string) ([]chained_proof.SignerLeg, error) {
	var resp signerDiscovery
	if err := queryRawJSON(ctx, endpoint, "query", map[string]any{"scope": txID}, &resp); err != nil {
		return nil, fmt.Errorf("discover signer partitions: %w", err)
	}

	txHash := hashOfTxID(txID)
	seen := map[string]bool{}
	var out []chained_proof.SignerLeg

	for _, set := range resp.Result.Signatures.Records {
		// Only key PAGES hold user signatures. A key book's set carries
		// signature requests, which are not votes.
		if !strings.EqualFold(set.Account.Type, "keyPage") || set.Account.URL == "" {
			continue
		}
		for _, rec := range set.Signatures.Records {
			// A user key signature, not an authority record, a signature request
			// or a credit payment. Only a key signature is a vote, and only a
			// vote needs its inclusion proven.
			st := strings.ToLower(rec.Message.Signature.Type)
			if st != "ed25519" && st != "delegated" {
				continue
			}
			// And it must cover THIS transaction. A key page's signature chain
			// carries its whole history; a signature for some other transaction
			// is not evidence about this one.
			if txHash != "" && hashOfTxID(rec.Message.TxID) != txHash {
				continue
			}
			msgHash := hashOfTxID(rec.ID)
			if msgHash == "" {
				continue
			}
			key := strings.ToLower(set.Account.URL)
			if seen[key] {
				continue
			}
			seen[key] = true

			partition := CalculateBVNFromAccountURL(set.Account.URL)
			if partition == "" {
				return nil, fmt.Errorf("discover signer partitions: %s does not route to a "+
					"partition; a leg whose partition is unknown cannot be checked against the "+
					"quorum that signed it", set.Account.URL)
			}
			out = append(out, chained_proof.SignerLeg{
				Account:     set.Account.URL,
				Partition:   partition,
				MessageHash: msgHash,
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if !strings.EqualFold(out[i].Partition, out[j].Partition) {
			return strings.ToLower(out[i].Partition) < strings.ToLower(out[j].Partition)
		}
		return strings.ToLower(out[i].Account) < strings.ToLower(out[j].Account)
	})
	return out, nil
}

// DistinctPartitions returns the partitions a leg set spans, sorted.
func DistinctPartitions(legs []chained_proof.SignerLeg) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range legs {
		p := strings.ToLower(l.Partition)
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// hashOfTxID pulls the 32-byte hash out of acc://<hash>@<scope>, or returns the
// input when it is already a bare hash.
func hashOfTxID(id string) string {
	s := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(id), "acc://"))
	if at := strings.Index(s, "@"); at > 0 {
		s = s[:at]
	}
	if len(s) != 64 {
		return ""
	}
	return s
}

// queryRawJSON issues a JSON-RPC call and decodes only what the caller asks for.
func queryRawJSON(ctx context.Context, endpoint, method string, params, into any) error {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		return err
	}
	raw, err := postJSON(ctx, endpoint, body)
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

// postJSON sends one JSON-RPC request and returns the raw response body.
func postJSON(ctx context.Context, endpoint string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return io.ReadAll(res.Body)
}

// signerTxScope builds the transaction scope a signature-set query takes:
// acc://<txhash>@<account>.
//
// The scope names the account the transaction was executed against, which is how
// Accumulate keys the transaction's signature sets. Passing a bare hash returns
// the message rather than the sets, and the signer partitions would then look
// like exactly one - the failure this discovery exists to prevent, arrived at by
// a different route.
func signerTxScope(accountURL, txHash string) string {
	h := hashOfTxID(txHash)
	if h == "" {
		h = strings.ToLower(strings.TrimSpace(txHash))
	}
	acct := strings.TrimPrefix(strings.TrimSpace(accountURL), "acc://")
	return "acc://" + h + "@" + acct
}
