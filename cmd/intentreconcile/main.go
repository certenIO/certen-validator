// Copyright 2026 Certen Protocol

// intentreconcile finds the CERTEN intents discovery never saw (RB3-F125).
//
// Until RB3-F125 discovery passed the watermark over any Directory Network block it could not search -
// about 2% of them - and every intent anchored in those blocks was lost: neither settled, failed nor
// retried. The fix stops new losses; it cannot find the old ones. This tool does, without scanning
// millions of DN blocks: every intent is a data entry in some ADI's data account, so it reads each data
// account's main chain from Accumulate, keeps the transactions discovery would call intents (writeData
// with header memo CERTEN_INTENT, or the legacy certen-intent), and reports each one whose transaction hash
// is not among the intents discovery recorded.
//
// Read-only: it queries Accumulate and reads two files; it writes only its report. Re-driving what it finds
// is a separate, deliberate step.
//
//	intentreconcile -accumulate https://kermit.accumulatenetwork.io/v3 \
//	    -known known_tx_hashes.txt      # intent_lifecycle.accum_tx_hash, one per line
//	    -accounts data_accounts.txt     # data account URLs, one per line (e.g. every gateway ADI + "/data")
//	    [-derive-principals]            # also read the account of every known intent from its transaction
//	    -out report.json
//
// A page the endpoint cannot deliver is halved down to one record; a range that cannot be read, or
// answers with other than exactly the records asked for in order, fails the run naming the account:
// "could not read" is never reported as "no intents".
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	acmerrors "gitlab.com/accumulatenetwork/accumulate/pkg/errors"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// querier is the part of the v3 client this tool uses.
type querier interface {
	Query(ctx context.Context, scope *url.URL, query api.Query) (api.Record, error)
}

// Intent is one CERTEN intent written to a data account.
type Intent struct {
	Account    string `json:"account"`
	ChainIndex uint64 `json:"chain_index"`
	TxHash     string `json:"tx_hash"`
	TxID       string `json:"tx_id"`
	// Status is the transaction's status on the network; Received the block it was first received in.
	Status   string `json:"status"`
	Received uint64 `json:"received_block"`
}

// AccountReport is one data account's reconciliation.
type AccountReport struct {
	Account    string   `json:"account"`
	Absent     bool     `json:"account_absent,omitempty"` // the account does not exist on the network
	Entries    uint64   `json:"main_chain_entries"`
	Intents    int      `json:"intents"`
	Discovered int      `json:"discovered"`
	Missing    []Intent `json:"missing"`

	discovered []string
}

// Report is the run's result.
type Report struct {
	Endpoint      string          `json:"endpoint"`
	ReadAt        string          `json:"read_at"`
	KnownIntents  int             `json:"known_intents"`
	Accounts      []AccountReport `json:"accounts"`
	TotalIntents  int             `json:"total_intents"`
	TotalMissing  int             `json:"total_missing"`
	KnownNotFound []string        `json:"known_intents_not_found_in_any_account"`
	// KnownGone are known intents whose transaction the network no longer holds (an earlier state of the
	// network): they cannot be traced to an account, and are reported rather than counted as either.
	KnownGone []string `json:"known_intents_whose_transaction_the_network_no_longer_holds"`
}

func main() {
	endpoint := flag.String("accumulate", "https://kermit.accumulatenetwork.io/v3", "Accumulate v3 endpoint")
	knownFile := flag.String("known", "", "file of intent transaction hashes discovery recorded, one per line (required)")
	accountsFile := flag.String("accounts", "", "file of data account URLs, one per line")
	derive := flag.Bool("derive-principals", false, "also reconcile the data account of every known intent")
	out := flag.String("out", "", "write the JSON report here (required)")
	pageSize := flag.Uint64("page", 50, "chain entries requested per page (halved on failure)")
	flag.Parse()
	if *knownFile == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "intentreconcile: -known and -out are required")
		os.Exit(2)
	}
	known, err := readSet(*knownFile, normHash)
	if err != nil {
		fail(err)
	}
	accounts := map[string]bool{}
	if *accountsFile != "" {
		list, err := readSet(*accountsFile, normAccount)
		if err != nil {
			fail(err)
		}
		for a := range list {
			accounts[a] = true
		}
	}
	client := jsonrpc.NewClient(*endpoint)
	ctx := context.Background()
	var gone []string
	if *derive {
		for _, h := range sortedKeys(known) {
			principal, err := principalOf(ctx, client, h)
			if errors.Is(err, acmerrors.NotFound) {
				gone = append(gone, h)
				continue
			}
			if err != nil {
				fail(fmt.Errorf("the account of known intent %s: %w", h, err))
			}
			accounts[principal] = true
		}
	}
	if len(accounts) == 0 {
		fail(errors.New("no data account to reconcile (-accounts or -derive-principals)"))
	}
	rep, err := reconcile(ctx, client, sortedKeys(accounts), known, *pageSize)
	if err != nil {
		fail(err)
	}
	rep.Endpoint = *endpoint
	// A known intent the network no longer holds is reported as such, not as one no account read contains.
	rep.KnownGone = gone
	goneSet := map[string]bool{}
	for _, h := range gone {
		goneSet[h] = true
	}
	kept := rep.KnownNotFound[:0]
	for _, h := range rep.KnownNotFound {
		if !goneSet[h] {
			kept = append(kept, h)
		}
	}
	rep.KnownNotFound = kept
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o600); err != nil {
		fail(err)
	}
	fmt.Printf("%d accounts, %d intents on chain, %d known to discovery (%d no longer on the network), %d MISSING, %d known intents found in no account read\n",
		len(rep.Accounts), rep.TotalIntents, rep.KnownIntents, len(rep.KnownGone), rep.TotalMissing, len(rep.KnownNotFound))
}

func reconcile(ctx context.Context, q querier, accounts []string, known map[string]bool, pageSize uint64) (*Report, error) {
	rep := &Report{ReadAt: time.Now().UTC().Format(time.RFC3339), KnownIntents: len(known), Accounts: []AccountReport{}, KnownNotFound: []string{}}
	found := map[string]bool{}
	for _, a := range accounts {
		ar, err := reconcileAccount(ctx, q, a, known, pageSize)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", a, err)
		}
		for _, h := range ar.discovered {
			found[h] = true
		}
		rep.Accounts = append(rep.Accounts, *ar)
		rep.TotalIntents += ar.Intents
		rep.TotalMissing += len(ar.Missing)
	}
	// Every known intent must be in an account read; one that is not says the account list is short.
	for h := range known {
		if !found[h] {
			rep.KnownNotFound = append(rep.KnownNotFound, h)
		}
	}
	sort.Strings(rep.KnownNotFound)
	return rep, nil
}

func reconcileAccount(ctx context.Context, q querier, account string, known map[string]bool, pageSize uint64) (*AccountReport, error) {
	u, err := url.Parse(account)
	if err != nil {
		return nil, err
	}
	ar := &AccountReport{Account: account, Missing: []Intent{}}
	total, err := chainLength(ctx, q, u)
	if errors.Is(err, errAbsent) {
		ar.Absent = true
		return ar, nil
	}
	if err != nil {
		return nil, err
	}
	ar.Entries = total
	for start := uint64(0); start < total; {
		want := min(pageSize, total-start)
		entries, err := readChainRange(ctx, q, u, start, want)
		if err != nil {
			return nil, err
		}
		for i, e := range entries {
			in, ok, err := intentOf(account, start+uint64(i), e)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			ar.Intents++
			if known[in.TxHash] {
				ar.Discovered++
				ar.discovered = append(ar.discovered, in.TxHash)
			} else {
				ar.Missing = append(ar.Missing, in)
			}
		}
		start += uint64(len(entries))
	}
	return ar, nil
}

var errAbsent = errors.New("account does not exist")

// chainLength is the number of entries on the account's main chain.
func chainLength(ctx context.Context, q querier, u *url.URL) (uint64, error) {
	r, err := q.Query(ctx, u, &api.ChainQuery{Name: "main"})
	if err != nil {
		if errors.Is(err, acmerrors.NotFound) {
			return 0, errAbsent
		}
		return 0, fmt.Errorf("main chain: %w", err)
	}
	cr, ok := r.(*api.ChainRecord)
	if !ok {
		return 0, fmt.Errorf("main chain: got a %T, not a chain record", r)
	}
	return cr.Count, nil
}

// readChainRange reads exactly count entries from start, expanded to their messages. A page the endpoint
// cannot deliver is halved down to a single entry; a single entry that cannot be read fails.
func readChainRange(ctx context.Context, q querier, u *url.URL, start, count uint64) ([]*api.ChainEntryRecord[api.Record], error) {
	var out []*api.ChainEntryRecord[api.Record]
	for len(out) < int(count) {
		at := start + uint64(len(out))
		n := count - uint64(len(out))
		var page []*api.ChainEntryRecord[api.Record]
		var err error
		for {
			page, err = readPage(ctx, q, u, at, n)
			if err == nil || n == 1 {
				break
			}
			n /= 2
		}
		if err != nil {
			return nil, fmt.Errorf("main chain entry %d: %w", at, err)
		}
		out = append(out, page...)
	}
	return out, nil
}

func readPage(ctx context.Context, q querier, u *url.URL, start, count uint64) ([]*api.ChainEntryRecord[api.Record], error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	expand := true
	r, err := q.Query(cctx, u, &api.ChainQuery{Name: "main", Range: &api.RangeOptions{Start: start, Count: &count, Expand: &expand}})
	if err != nil {
		return nil, err
	}
	rr, ok := r.(*api.RecordRange[api.Record])
	if !ok {
		return nil, fmt.Errorf("got a %T, not a record range", r)
	}
	if uint64(len(rr.Records)) != count {
		return nil, fmt.Errorf("asked for %d entries from %d, got %d", count, start, len(rr.Records))
	}
	out := make([]*api.ChainEntryRecord[api.Record], 0, len(rr.Records))
	for i, rec := range rr.Records {
		e, ok := rec.(*api.ChainEntryRecord[api.Record])
		if !ok {
			return nil, fmt.Errorf("entry %d is a %T", start+uint64(i), rec)
		}
		if e.Index != start+uint64(i) {
			return nil, fmt.Errorf("asked for entry %d, got entry %d", start+uint64(i), e.Index)
		}
		out = append(out, e)
	}
	return out, nil
}

// intentOf decides, as discovery does, whether a main chain entry is a CERTEN intent: a writeData
// transaction whose header memo is CERTEN_INTENT (or the legacy certen-intent).
func intentOf(account string, index uint64, e *api.ChainEntryRecord[api.Record]) (Intent, bool, error) {
	mr, ok := e.Value.(*api.MessageRecord[messaging.Message])
	if !ok {
		return Intent{}, false, fmt.Errorf("entry %d was not expanded to its message (%T)", index, e.Value)
	}
	tm, ok := mr.Message.(*messaging.TransactionMessage)
	if !ok || tm.Transaction == nil {
		return Intent{}, false, nil
	}
	txn := tm.Transaction
	if _, ok := txn.Body.(*protocol.WriteData); !ok {
		return Intent{}, false, nil
	}
	memo := txn.Header.Memo
	if memo != "CERTEN_INTENT" && !strings.EqualFold(memo, "certen-intent") {
		return Intent{}, false, nil
	}
	h := txn.GetHash()
	return Intent{Account: account, ChainIndex: index, TxHash: hex.EncodeToString(h), TxID: txn.ID().String(),
		Status: mr.Status.String(), Received: mr.Received}, true, nil
}

// principalOf is the account a known intent was written to.
func principalOf(ctx context.Context, q querier, txHash string) (string, error) {
	b, err := hex.DecodeString(txHash)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("not a 32-byte transaction hash")
	}
	var h [32]byte
	copy(h[:], b)
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	r, err := q.Query(cctx, protocol.UnknownUrl().WithTxID(h).AsUrl(), nil)
	if err != nil {
		return "", err
	}
	mr, ok := r.(*api.MessageRecord[messaging.Message])
	if !ok {
		return "", fmt.Errorf("got a %T, not a message record", r)
	}
	tm, ok := mr.Message.(*messaging.TransactionMessage)
	if !ok || tm.Transaction == nil {
		return "", fmt.Errorf("the message is a %T, not a transaction", mr.Message)
	}
	return normAccount(tm.Transaction.Header.Principal.String()), nil
}

func readSet(path string, norm func(string) string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v := norm(sc.Text()); v != "" {
			out[v] = true
		}
	}
	return out, sc.Err()
}

func normHash(s string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
}

func normAccount(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(s), "/")
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "intentreconcile:", err)
	os.Exit(1)
}
