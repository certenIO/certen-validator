// Copyright 2026 Certen Protocol
//
// p8xpart — submit a CERTEN intent signed through a DELEGATED, CROSS-PARTITION
// signature, so the production settlement path builds a multi-leg proof for the
// first time.
//
// # WHY THIS EXISTS
//
// Phase 8 item 1: every piece of the multi-partition path is individually
// tested and the COMPOSITION has never run. Zero multi-leg proofs have ever
// been stored; no proof has more than two layer-4 rows; `additionalLegs` has
// never been persisted. `ConsensusProof.BVNs` is omitempty, so every govRoot in
// production has had it ABSENT — and a cross-partition intent produces the
// first preimage where it is present, which is what TX2 verifies against.
//
// So: a real intent, on the production ADI, whose only signature routes to a
// different partition than the principal.
//
//	principal  acc://certen-kermit-12.acme/data     -> BVN1
//	signer     acc://certen-p7f-omega.acme/book/1   -> BVN2
//	delegator  acc://certen-kermit-12.acme/book/1
//
// The delegate entry that makes this legal was added to the production page in
// runbook §1.3 step 1, verified against the page, and §1.3 step 2 confirmed
// ordinary single-key traffic still settles afterwards.
//
// # WHY THE PAYLOAD COMES FROM A FILE
//
// The four-blob CERTEN_INTENT body is built by scripts/e2e_matrix.mjs
// (`--emit-entries`), the same code every ordinary intent uses. Rebuilding it
// here in Go would be a SECOND implementation that has to agree about
// operationId, canonical field ordering and the execution commitment — and the
// two would drift the first time a field moved. The split is deliberate: JS
// owns the payload shape, this owns the signature.
//
// # WHY accumulate-core BUILDS THE SIGNATURE
//
// A delegated signature's digest commits to every delegator in the chain, and
// the canonical encoding is field-tagged, omit-if-zero, varint length.
// Hand-rolling it is how the field-strictness bugs happened. signing.Builder is
// the same code the corpus is verdicted against and the same code Accumulate
// itself uses.
//
// Usage:
//
//	node scripts/e2e_matrix.mjs --legs 1 --chains base --class on_demand \
//	     --emit-entries /tmp/xpart.json
//	go run ./cmd/p8xpart -entries /tmp/xpart.json
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/client/signing"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

const kermit = "https://kermit.accumulatenetwork.io/v3"

// The delegated path. The delegator is the PAGE that granted the authority —
// not the book — because the Delegator field of a DelegatedSignature names the
// signer whose authority is being exercised.
const (
	principalPage = "acc://certen-kermit-12.acme/book/1"
	signerPage    = "acc://certen-p7f-omega.acme/book/1"
	signerSeedKey = "f2"
)

type emitted struct {
	DataAccount string   `json:"dataAccount"`
	Memo        string   `json:"memo"`
	Entries     []string `json:"entries"`
}

func main() {
	var (
		endpoint  = flag.String("endpoint", kermit, "Accumulate v3 endpoint")
		entryFile = flag.String("entries", "", "file written by e2e_matrix.mjs --emit-entries")
		keysPath  = flag.String("keys", "scripts/phase7_corpus/keys.json", "corpus key seeds")
		wait      = flag.Duration("wait", 3*time.Minute, "how long to wait for delivery")
	)
	flag.Parse()
	if *entryFile == "" {
		fatal("-entries is required; run e2e_matrix.mjs --emit-entries first")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var em emitted
	readJSON(*entryFile, &em)
	if len(em.Entries) == 0 {
		fatal("%s carries no entries", *entryFile)
	}
	if em.Memo != "CERTEN_INTENT" {
		fatal("memo is %q, not CERTEN_INTENT — intent discovery matches on the memo, so this "+
			"would never be picked up", em.Memo)
	}

	var seeds map[string]string
	readJSON(*keysPath, &seeds)
	seed, ok := seeds[signerSeedKey]
	if !ok {
		fatal("key %q is not in %s", signerSeedKey, *keysPath)
	}
	raw, err := hex.DecodeString(seed)
	if err != nil || len(raw) < 32 {
		fatal("key %q is not a 32-byte seed", signerSeedKey)
	}
	priv := ed25519.NewKeyFromSeed(raw[:32])

	c := jsonrpc.NewClient(*endpoint)

	// The signer page's CURRENT version. A signature carries the version it was
	// made against and Accumulate refuses one made against an older page
	// (KPSW-EXEC), so this is read fresh rather than assumed. The delegator page
	// was just bumped to 2 by the delegate add; the SIGNER page is a different
	// account with its own version, and conflating the two is a signature that
	// is well-formed and never verifies.
	version, err := pageVersion(ctx, c, signerPage)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Printf("signer  %s  version %d\n", signerPage, version)
	fmt.Printf("delegator %s\n", principalPage)

	// Refuse to submit unless the delegate entry is actually on the delegator
	// page. Without it the signature is well-formed, the submission returns
	// code: ok, and nothing ever executes — the exact failure shape
	// PHASE7_CORPUS_MANIFEST.md §6 documents three ways into.
	if err := requireDelegateEntry(ctx, c, principalPage, bookOf(signerPage)); err != nil {
		fatal("%v", err)
	}

	txn := new(protocol.Transaction)
	txn.Header.Principal = mustURL(em.DataAccount)
	txn.Header.Memo = em.Memo
	data := make([][]byte, 0, len(em.Entries))
	for i, h := range em.Entries {
		b, err := hex.DecodeString(strings.TrimPrefix(h, "0x"))
		if err != nil {
			fatal("entry %d is not hex: %v", i, err)
		}
		data = append(data, b)
	}
	txn.Body = &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: data}}

	// Build the signature BEFORE reading the transaction hash. GetHash()
	// memoizes and Initiate() sets Header.Initiator, so reading the hash first
	// caches one computed with a ZERO initiator; the signature then covers a
	// stale hash and the network refuses the envelope with "transaction is not
	// signed".
	sig, err := new(signing.Builder).
		SetUrl(mustURL(signerPage)).
		SetPrivateKey(priv).
		SetVersion(version).
		SetTimestamp(uint64(time.Now().UnixMicro())).
		AddDelegator(mustURL(principalPage)).
		Initiate(txn)
	if err != nil {
		fatal("build delegated signature: %v", err)
	}

	var txHash [32]byte
	copy(txHash[:], txn.GetHash())

	// Say what was actually built, from the signature itself rather than from
	// what was intended.
	ds, ok := sig.(*protocol.DelegatedSignature)
	if !ok {
		fatal("the builder produced a %v, not a delegated signature — this intent would be "+
			"single-partition and would prove nothing item 1 needs", sig.Type())
	}
	fmt.Printf("txHash  %s\n", hex.EncodeToString(txHash[:]))
	fmt.Printf("sig     %v, delegator %s, inner signer %s\n",
		ds.Type(), ds.Delegator, innerSigner(ds))

	env := new(messaging.Envelope)
	env.Transaction = []*protocol.Transaction{txn}
	env.Signatures = []protocol.Signature{sig}

	subs, err := c.Submit(ctx, env, api.SubmitOptions{})
	if err != nil {
		fatal("submit: %v", err)
	}
	for _, s := range subs {
		if s.Status != nil && s.Status.Error != nil {
			fatal("submission refused: %s", s.Status.Error.Message)
		}
		if !s.Success {
			fatal("submission not accepted: %s", s.Message)
		}
	}
	fmt.Printf("SUBMITTED %s\n", hex.EncodeToString(txHash[:]))

	// A SUBMIT RESULT IS NOT AN EXECUTION RESULT. code: ok describes envelope
	// acceptance. Wait for the executor's verdict on the transaction itself.
	txid := mustURL(em.DataAccount).WithTxID(txHash)
	code, errMsg := awaitDelivered(ctx, c, txid, *wait)
	fmt.Printf("execution %s", code)
	if errMsg != "" {
		fmt.Printf(" (%s)", errMsg)
	}
	fmt.Println()
	if code != "delivered" {
		fatal("the transaction did not execute (%s) — nothing downstream can be attributed to "+
			"the multi-leg path until it does", code)
	}
	fmt.Printf("\nDELIVERED. Follow it through intent_lifecycle and chain_execution_results:\n  %s\n",
		hex.EncodeToString(txHash[:]))
}

// requireDelegateEntry fails closed unless page carries a delegate entry to book.
func requireDelegateEntry(ctx context.Context, c *jsonrpc.Client, page, book string) error {
	rec, err := c.Query(ctx, mustURL(page), &api.DefaultQuery{})
	if err != nil {
		return fmt.Errorf("query %s: %w", page, err)
	}
	ar, ok := rec.(*api.AccountRecord)
	if !ok {
		return fmt.Errorf("%s is not an account record", page)
	}
	kp, ok := ar.Account.(*protocol.KeyPage)
	if !ok {
		return fmt.Errorf("%s is a %v, not a key page", page, ar.Account.Type())
	}
	for _, k := range kp.Keys {
		if k.Delegate != nil && strings.EqualFold(k.Delegate.String(), book) {
			fmt.Printf("delegate entry %s is on %s (page version %d, acceptThreshold %d)\n",
				book, page, kp.Version, kp.AcceptThreshold)
			return nil
		}
	}
	return fmt.Errorf("%s carries NO delegate entry for %s — a signature via that path would be "+
		"accepted by the envelope layer and never execute; run scripts/phase8_delegate.py add",
		page, book)
}

func pageVersion(ctx context.Context, c *jsonrpc.Client, page string) (uint64, error) {
	rec, err := c.Query(ctx, mustURL(page), &api.DefaultQuery{})
	if err != nil {
		return 0, fmt.Errorf("query %s: %w", page, err)
	}
	ar, ok := rec.(*api.AccountRecord)
	if !ok {
		return 0, fmt.Errorf("%s is not an account record", page)
	}
	kp, ok := ar.Account.(*protocol.KeyPage)
	if !ok {
		return 0, fmt.Errorf("%s is a %v, not a key page", page, ar.Account.Type())
	}
	return kp.Version, nil
}

func awaitDelivered(ctx context.Context, c *jsonrpc.Client, txid *url.TxID, within time.Duration) (string, string) {
	deadline := time.Now().Add(within)
	var lastCode, lastErr string
	for time.Now().Before(deadline) {
		rec, err := c.Query(ctx, txid.AsUrl(), &api.DefaultQuery{})
		if err == nil {
			if mr, ok := rec.(*api.MessageRecord[messaging.Message]); ok && mr.Status != 0 {
				lastCode = mr.Status.String()
				if mr.Error != nil {
					lastErr = mr.Error.Message
				}
				if mr.Status.Delivered() {
					return lastCode, lastErr
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
	if lastCode == "" {
		lastCode = "unresolved"
	}
	return lastCode, lastErr
}

func innerSigner(sig protocol.Signature) string {
	for {
		d, ok := sig.(*protocol.DelegatedSignature)
		if !ok {
			break
		}
		sig = d.Signature
	}
	if ks, ok := sig.(protocol.KeySignature); ok {
		return ks.GetSigner().String()
	}
	return "?"
}

func bookOf(page string) string {
	if i := strings.LastIndex(page, "/"); i > 0 {
		return page[:i]
	}
	return page
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		fatal("parse url %q: %v", s, err)
	}
	return u
}

func readJSON(path string, into any) {
	b, err := os.ReadFile(path)
	if err != nil {
		fatal("read %s: %v", path, err)
	}
	if err := json.Unmarshal(b, into); err != nil {
		fatal("parse %s: %v", path, err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "p8xpart: "+format+"\n", args...)
	os.Exit(1)
}
