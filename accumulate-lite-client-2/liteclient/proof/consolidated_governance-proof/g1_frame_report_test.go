//go:build g1record

// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
)

// DAX-1G-R2 (G-85): the frame facts of the two erp-initiated intents, read from live Kermit (read-only, public v3):
//
//	go test -tags g1record -run TestReportG1FrameFacts -count=1 -v -timeout 20m .
//
// For each intent it prints the principal's EXEC_MBI (a block of the principal's partition: the receipt of the transaction on the
// principal's main chain), the partition the routing table sends the principal and each page to, the block each page was created at
// (its genesis, a block of the PAGE's partition), and the block each message of the page's signature set for this transaction was
// recorded at (a block of the PAGE's partition). The numbers of two different partitions are different counters; this is the table
// that shows whether the two intents' numbers can be compared at all.
func TestReportG1FrameFacts(t *testing.T) {
	ep := os.Getenv("ACC_V3_ENDPOINT")
	if ep == "" {
		ep = "https://kermit.accumulatenetwork.io/v3"
	}
	cases := []struct{ name, account, txHash, keyPage, authorityPage string }{
		{"g7 (DAX-1G probe, proved by ProveG1 on 2026-11-12)", "acc://dax1-probe-g7.acme/data",
			"488396f128eab23618e3a0a08a30373d33b4c467a0c0d6d06d84aeffed002936",
			"acc://dax1-probe-g7-erp.acme/book/1", "acc://dax1-probe-g7.acme/book/1"},
		{"r6a (DAX-1 round 6, refused by the validators on 2026-11-13)", "acc://dax1-r6a.acme/data",
			"e965cf4ccb51a6f55eb5327ec9fb2c56a591de8c992778694cf6bb0cd9ca8ca3",
			"acc://dax1-r6a-erp.acme/book/1", "acc://dax1-r6a.acme/book/1"},
	}
	netw, err := govsig.FetchNetwork(context.Background(), ep)
	if err != nil {
		t.Fatalf("network-status: %v", err)
	}
	t.Logf("network %s", netw.Name)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rc := NewRPCClient(RPCConfig{Endpoint: ep, Timeout: 60 * time.Second, Backend: "http", UseHTTP: true})
			am, err := NewArtifactManager(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			g1 := NewG1Layer(rc, am, "")
			g0, err := g1.g0Layer.ProveG0(ctx, G0Request{Account: c.account, TxHash: c.txHash, Chain: "main"})
			if err != nil {
				t.Fatalf("G0: %v", err)
			}
			part := func(acct string) string {
				p, err := netw.Partition(acct)
				if err != nil {
					return "ERR:" + err.Error()
				}
				return p
			}
			t.Logf("principal %s: partition %s, EXEC_MBI %d (a block of %s)", c.account, part(c.account), g0.ExecMBI, part(c.account))
			for _, page := range []string{c.keyPage, c.authorityPage} {
				tl, err := g1.authorityBuilder.BuildPageTimeline(ctx, page)
				if err != nil {
					t.Fatalf("timeline %s: %v", page, err)
				}
				t.Logf("page %s: partition %s, genesis block %d, EXEC_MBI-genesis = %d (negative: the page did not exist at EXEC_MBI, in the frame EXEC_MBI is measured in)",
					page, part(page), tl.Genesis.LocalBlock, g0.ExecMBI-tl.Genesis.LocalBlock)
				ids := sigSetMessageIDs(ctx, t, g1, g0.ExpandedMessageID, page)
				sort.Strings(ids)
				for _, id := range ids {
					hash, err := (URLUtils{}).ParseAccURLHash(id)
					if err != nil {
						t.Fatal(err)
					}
					r, err := g1.boundSignatureChainReceipt(ctx, page, hash, "frame_report_"+SafeTruncate(hash, 12))
					if err != nil {
						t.Logf("  message %s on %s: no bound receipt (%v)", SafeTruncate(hash, 12), page, err)
						continue
					}
					t.Logf("  message %s recorded on %s at block %d (a block of %s); EXEC_MBI-block = %d", SafeTruncate(hash, 12), page, r.LocalBlock, part(page), g0.ExecMBI-r.LocalBlock)
				}
			}
		})
	}
}

// sigSetMessageIDs are the ids of the messages the transaction's signature set holds under the page.
func sigSetMessageIDs(ctx context.Context, t *testing.T, g1 *G1Layer, txID, page string) []string {
	t.Helper()
	resp, err := g1.artifactManager.SaveRPCArtifact(ctx, "frame_report_sets", g1.client, txID, map[string]interface{}{"queryType": "default"})
	if err != nil {
		t.Fatalf("signature sets of %s: %v", txID, err)
	}
	pu := ProofUtilities{}
	result, err := pu.ExpectResult(resp)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	sets, _ := pu.CaseInsensitiveGet(result, "signatures").(map[string]interface{})
	setRecords, _ := pu.CaseInsensitiveGet(sets, "records").([]interface{})
	for _, sr := range setRecords {
		set, _ := sr.(map[string]interface{})
		acct, _ := pu.CaseInsensitiveGet(set, "account").(map[string]interface{})
		url, _ := pu.CaseInsensitiveGet(acct, "url").(string)
		if normalizeAccURL(url) != normalizeAccURL(page) {
			continue
		}
		sigs, _ := pu.CaseInsensitiveGet(set, "signatures").(map[string]interface{})
		records, _ := pu.CaseInsensitiveGet(sigs, "records").([]interface{})
		for _, r := range records {
			rec, _ := r.(map[string]interface{})
			id, _ := pu.CaseInsensitiveGet(rec, "id").(string)
			msg, _ := pu.CaseInsensitiveGet(rec, "message").(map[string]interface{})
			if mt, _ := pu.CaseInsensitiveGet(msg, "type").(string); !strings.EqualFold(mt, "signature") {
				continue
			}
			out = append(out, id)
		}
	}
	return out
}
