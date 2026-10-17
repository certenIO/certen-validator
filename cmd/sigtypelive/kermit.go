package main

// Talking to Kermit: the operations the live run needs.
//
// A submission's status is not the transaction's status (PHASE7_CORPUS_MANIFEST.md section 6): every write here is
// confirmed by reading the effect back, and a query error that is not "not found" is an error, never absence.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

const kermitV3 = "https://kermit.accumulatenetwork.io/v3"

type kermit struct {
	endpoint string
	c        *jsonrpc.Client
}

func newKermit(endpoint string) *kermit {
	return &kermit{endpoint: endpoint, c: jsonrpc.NewClient(endpoint)}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		fatal("parse url %q: %v", s, err)
	}
	return u
}

func isNotFound(err error) bool {
	s := err.Error()
	return strings.Contains(s, "not found") || strings.Contains(s, "does not exist")
}

// account returns the account at u, or nil if it does not exist.
func (k *kermit) account(ctx context.Context, u *url.URL) (protocol.Account, error) {
	rec, err := k.c.Query(ctx, u, &api.DefaultQuery{})
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("query %s: %w", u, err)
	}
	ar, ok := rec.(*api.AccountRecord)
	if !ok {
		return nil, fmt.Errorf("query %s: not an account record (%T)", u, rec)
	}
	return ar.Account, nil
}

// page returns a key page; nil if absent.
func (k *kermit) page(ctx context.Context, u string) (*protocol.KeyPage, error) {
	a, err := k.account(ctx, mustURL(u))
	if err != nil || a == nil {
		return nil, err
	}
	kp, ok := a.(*protocol.KeyPage)
	if !ok {
		return nil, fmt.Errorf("%s is a %v, not a key page", u, a.Type())
	}
	return kp, nil
}

func (k *kermit) oracle(ctx context.Context) (uint64, error) {
	ns, err := k.c.NetworkStatus(ctx, api.NetworkStatusOptions{Partition: protocol.Directory})
	if err != nil {
		return 0, err
	}
	if ns.Oracle == nil || ns.Oracle.Price == 0 {
		return 0, fmt.Errorf("network-status carries no oracle price")
	}
	return ns.Oracle.Price, nil
}

// submit sends an envelope and returns an error unless every submission was accepted.
func (k *kermit) submit(ctx context.Context, env *messaging.Envelope) error {
	subs, err := k.c.Submit(ctx, env, api.SubmitOptions{})
	if err != nil {
		return err
	}
	if len(subs) == 0 {
		return fmt.Errorf("no submission result")
	}
	if os.Getenv("SIGTYPELIVE_DEBUG") != "" {
		b, _ := json.Marshal(subs)
		fmt.Printf("  submit result: %s\n", b)
	}
	for _, s := range subs {
		if s.Status != nil && s.Status.Error != nil {
			return fmt.Errorf("%s", s.Status.Error.Message)
		}
		if !s.Success {
			return fmt.Errorf("submission not accepted: %s", s.Message)
		}
	}
	return nil
}

// await polls a transaction until it is delivered (or terminal) and returns the executor's code and error text.
func (k *kermit) await(ctx context.Context, id *url.TxID, within time.Duration) (string, string) {
	deadline := time.Now().Add(within)
	var code, msg string
	for time.Now().Before(deadline) {
		rec, err := k.c.Query(ctx, id.AsUrl(), &api.DefaultQuery{})
		if err == nil {
			if mr, ok := rec.(*api.MessageRecord[messaging.Message]); ok && mr.Status != 0 {
				code = mr.Status.String()
				if mr.Error != nil {
					msg = mr.Error.Message
				}
				if mr.Status.Delivered() {
					return code, msg
				}
			}
		}
		select {
		case <-ctx.Done():
			return "cancelled", ctx.Err().Error()
		case <-time.After(3 * time.Second):
		}
	}
	if code == "" {
		code = "unresolved"
	}
	return code, msg
}

// rawQuery issues a v3 JSON-RPC query and returns the raw result, for the signature records the typed client folds away.
func (k *kermit) rawQuery(ctx context.Context, params map[string]any) (json.RawMessage, error) {
	return k.rawQuery2(ctx, "query", params)
}

// rawQuery2 issues any v3 JSON-RPC method and returns the raw result.
func (k *kermit) rawQuery2(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("query response is not JSON-RPC: %w", err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("query: %s", out.Error.Message)
	}
	return out.Result, nil
}

// delivered is a signature as the network served it for a transaction.
type delivered struct {
	Account  string          // the signature set's account (the signer page, or the principal's authority set)
	Type     string          // outermost signature type as served
	JSON     json.RawMessage // the signature JSON as served
	Binary   []byte          // Accumulate's binary encoding, from the pinned unmarshaller + marshaller
	Decoded  protocol.Signature
	TxnJSON  json.RawMessage
	Txn      *protocol.Transaction
	Status   string
	AllTypes []string
}

// deliveredSignatures reads the transaction record for txHash on principal and returns every user signature the
// network recorded on it, with the transaction as the network holds it.
func (k *kermit) deliveredSignatures(ctx context.Context, principal string, txHash []byte) ([]delivered, error) {
	scope := fmt.Sprintf("acc://%s@%s", hex.EncodeToString(txHash), strings.TrimPrefix(principal, "acc://"))
	raw, err := k.rawQuery(ctx, map[string]any{"scope": scope})
	if err != nil {
		return nil, err
	}
	var rec struct {
		Status  string `json:"status"`
		Message struct {
			Transaction json.RawMessage `json:"transaction"`
		} `json:"message"`
		Signatures struct {
			Records []struct {
				Account struct {
					Type string `json:"type"`
					Url  string `json:"url"`
				} `json:"account"`
				Signatures struct {
					Records []struct {
						Message struct {
							Type      string          `json:"type"`
							Signature json.RawMessage `json:"signature"`
						} `json:"message"`
					} `json:"records"`
				} `json:"signatures"`
			} `json:"records"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("decode transaction record: %w", err)
	}
	txn := new(protocol.Transaction)
	if err := txn.UnmarshalJSON(rec.Message.Transaction); err != nil {
		return nil, fmt.Errorf("decode transaction: %w", err)
	}
	if !bytes.Equal(txn.GetHash(), txHash) {
		return nil, fmt.Errorf("the served transaction hashes to %x, not %x", txn.GetHash(), txHash)
	}
	var out []delivered
	for _, set := range rec.Signatures.Records {
		for _, r := range set.Signatures.Records {
			if r.Message.Type != "signature" {
				continue
			}
			sig, err := protocol.UnmarshalSignatureJSON(r.Message.Signature)
			if err != nil {
				return nil, fmt.Errorf("decode signature on %s: %w", set.Account.Url, err)
			}
			if _, ok := sig.(protocol.UserSignature); !ok {
				continue
			}
			bin, err := sig.MarshalBinary()
			if err != nil {
				return nil, err
			}
			out = append(out, delivered{
				Account: set.Account.Url, Type: sig.Type().String(), JSON: r.Message.Signature,
				Binary: bin, Decoded: sig, TxnJSON: rec.Message.Transaction, Txn: txn, Status: rec.Status,
			})
		}
	}
	return out, nil
}

// pendingOn returns the transactions waiting on account (txid strings as the v3 API lists them).
func (k *kermit) pendingOn(ctx context.Context, account string) ([]string, error) {
	raw, err := k.rawQuery(ctx, map[string]any{"scope": account})
	if err != nil {
		return nil, err
	}
	var rec struct {
		Pending struct {
			Records []struct {
				Value string `json:"value"`
			} `json:"records"`
		} `json:"pending"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rec.Pending.Records {
		out = append(out, r.Value)
	}
	return out, nil
}

// transaction reads a transaction by its txid string as the network holds it.
func (k *kermit) transaction(ctx context.Context, txid string) (*protocol.Transaction, error) {
	raw, err := k.rawQuery(ctx, map[string]any{"scope": txid})
	if err != nil {
		return nil, err
	}
	var rec struct {
		Message struct {
			Transaction json.RawMessage `json:"transaction"`
		} `json:"message"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	txn := new(protocol.Transaction)
	if err := txn.UnmarshalJSON(rec.Message.Transaction); err != nil {
		return nil, err
	}
	return txn, nil
}
