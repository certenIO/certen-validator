package main

// submit: write one CERTEN intent per case, approved by that case's key, and capture what Kermit delivered.
//
// What is captured is the network's own record: the transaction as the v3 API serves it (JSON), the signature as served
// (JSON) and its Accumulate binary encoding (re-encoded by the pinned marshaller from the served JSON, then checked to
// decode back to the same JSON). Nothing here is a verdict.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

type liveConfig struct {
	Chain, Account, RPC, Out, Cases, Base, SSH, Verify string
	Wait                                               time.Duration
}

// capture is what one case leaves in captures/<tag>/capture.json.
type capture struct {
	Case        string   `json:"case"`
	Type        string   `json:"type"`
	Delegated   bool     `json:"delegated"`
	ADI         string   `json:"adi"`
	Principal   string   `json:"principal"`
	SignerPage  string   `json:"signerPage"`
	Delegators  []string `json:"delegators,omitempty"`
	PublicKey   string   `json:"publicKey"`
	KeyHash     string   `json:"keyHash"`
	IntentID    string   `json:"intentId"`
	OperationID string   `json:"operationId"`
	TxHash      string   `json:"txHash"`
	TxID        string   `json:"txId"`
	Status      string   `json:"status"`
	Error       string   `json:"error,omitempty"`
	SubmittedAt string   `json:"submittedAt"`
	Network     string   `json:"network"`
	Delivered   []string `json:"deliveredSignatureTypes"`
	Signature   string   `json:"signature,omitempty"`
}

func (l liveConfig) selected() ([]liveCase, error) {
	all := liveCases()
	if strings.TrimSpace(l.Cases) == "" {
		return all, nil
	}
	var out []liveCase
	for _, name := range strings.Split(l.Cases, ",") {
		name = strings.TrimSpace(name)
		found := false
		for _, c := range all {
			if strings.EqualFold(c.Name, name) || c.Tag == strings.ToLower(name) {
				out = append(out, c)
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("no case %q (cases: %s)", name, caseNames(all))
		}
	}
	return out, nil
}

func caseNames(cs []liveCase) string {
	var n []string
	for _, c := range cs {
		n = append(n, c.Name)
	}
	return strings.Join(n, ", ")
}

// loadKey returns the key that signs for c (the inner key for the delegated case).
func (a *app) loadKey(c liveCase) (sigfixture.Key, error) {
	name := c.keyName()
	if c.Delegated {
		name = "dinner"
	}
	k, ok, err := a.ks.load(name)
	if err != nil {
		return k, err
	}
	if !ok {
		return k, fmt.Errorf("no key %q in %s: run `sigtypelive setup` first", name, a.ks.dir)
	}
	return k, nil
}

// submitOne writes the intent for c and returns what Kermit delivered. A refusal by the network is recorded in the
// capture (status/error), not hidden; only an inability to talk to the network is an error.
func (a *app) submitOne(ctx context.Context, c liveCase, l liveConfig) (*capture, error) {
	key, err := a.loadKey(c)
	if err != nil {
		return nil, err
	}
	pub, hash, err := pubAndHash(key)
	if err != nil {
		return nil, err
	}
	blobs, err := buildIntent(a.adi, c, l.Account)
	if err != nil {
		return nil, err
	}
	txn := new(protocol.Transaction)
	txn.Header.Principal = mustURL(c.data(a.adi))
	txn.Header.Memo = "CERTEN_INTENT"
	txn.Body = &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{
		blobs.Blobs[0], blobs.Blobs[1], blobs.Blobs[2], blobs.Blobs[3],
	}}}
	spec, err := a.pageSigner(ctx, key, c.signerPage(a.adi), true, c.delegators(a.adi)...)
	if err != nil {
		return nil, err
	}
	env, err := a.envelope(txn, spec)
	if err != nil {
		return nil, err
	}
	cp := &capture{
		Case: c.Name, Type: c.Type.String(), Delegated: c.Delegated, ADI: a.adi, Principal: c.data(a.adi),
		SignerPage: c.signerPage(a.adi), Delegators: c.delegators(a.adi),
		PublicKey: hex.EncodeToString(pub), KeyHash: hex.EncodeToString(hash),
		IntentID: blobs.IntentID, OperationID: blobs.OperationID,
		TxHash: hex.EncodeToString(txn.GetHash()), TxID: txn.ID().String(),
		SubmittedAt: time.Now().UTC().Format(time.RFC3339), Network: "Kermit (DevNet)",
	}
	fmt.Printf("%-24s submit %s ...\n", c.Name, cp.TxHash[:12])
	if err := a.k.submit(ctx, env); err != nil {
		cp.Status, cp.Error = "submission_refused", err.Error()
		return cp, a.save(l, c, cp, nil)
	}
	code, msg := a.k.await(ctx, txn.ID(), l.Wait)
	cp.Status, cp.Error = code, msg
	var got []delivered
	if code == "delivered" {
		if got, err = a.k.deliveredSignatures(ctx, c.data(a.adi), txn.GetHash()); err != nil {
			return cp, fmt.Errorf("%s: delivered but unreadable: %w", c.Name, err)
		}
	}
	return cp, a.save(l, c, cp, got)
}

// save writes captures/<tag>/ and checks the served JSON and its binary form describe the same signature.
func (a *app) save(l liveConfig, c liveCase, cp *capture, got []delivered) error {
	dir := filepath.Join(l.Out, c.Tag)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var outer *delivered
	want := c.Type.String()
	if c.Delegated {
		want = protocol.SignatureTypeDelegated.String()
	}
	for i := range got {
		cp.Delivered = append(cp.Delivered, got[i].Type)
		if outer == nil && got[i].Type == want {
			outer = &got[i]
		}
	}
	if outer == nil && cp.Status == "delivered" {
		return fmt.Errorf("%s: Kermit delivered the transaction but no %s signature (it recorded: %v)", c.Name, want, cp.Delivered)
	}
	if outer != nil {
		// the JSON the network served must decode to exactly the binary encoding recorded
		back, err := protocol.UnmarshalSignatureJSON(outer.JSON)
		if err != nil {
			return err
		}
		bb, err := back.MarshalBinary()
		if err != nil || !bytes.Equal(bb, outer.Binary) {
			return fmt.Errorf("%s: served JSON and binary encoding disagree", c.Name)
		}
		cp.Signature = hex.EncodeToString(outer.Binary)
		files := map[string][]byte{
			"signature.bin":    outer.Binary,
			"signature.json":   outer.JSON,
			"transaction.json": outer.TxnJSON,
		}
		if tb, err := outer.Txn.MarshalBinary(); err == nil {
			files["transaction.bin"] = tb
		}
		for n, b := range files {
			if err := os.WriteFile(filepath.Join(dir, n), b, 0o644); err != nil {
				return err
			}
		}
	}
	b, _ := json.MarshalIndent(cp, "", "  ")
	return os.WriteFile(filepath.Join(dir, "capture.json"), append(b, '\n'), 0o644)
}

// submit runs every selected case once.
func (a *app) submit(ctx context.Context, l liveConfig) ([]*capture, error) {
	cases, err := l.selected()
	if err != nil {
		return nil, err
	}
	if l.Account == "" {
		return nil, fmt.Errorf("-account is required: the CertenAccount of %s on %s (the leg's `from`)", a.adi, l.Chain)
	}
	var out []*capture
	for _, c := range cases {
		cp, err := a.submitOne(ctx, c, l)
		if cp != nil {
			out = append(out, cp)
			fmt.Printf("%-24s %-10s tx %s key %s\n", c.Name, cp.Status, cp.TxHash, cp.KeyHash[:16])
		}
		if err != nil {
			return out, err
		}
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return out, os.WriteFile(filepath.Join(l.Out, "summary.json"), append(b, '\n'), 0o644)
}
