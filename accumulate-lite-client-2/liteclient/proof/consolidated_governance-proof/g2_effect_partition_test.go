package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// C5-D4 (RB9 phase E): the G2 effect check read the governed transaction's recorded result from Accumulate's
// COLLATED message-ID answer, which takes the result of the first partition (BVN1, BVN2, BVN3, Directory) that
// holds the message. A transaction approved by an authority on a partition that sorts BEFORE the principal's has a
// never-executed copy on that partition (the signature-request executor stores the transaction there and records no
// result): the collated answer then says {"type":"unknown"} although the principal's partition recorded the
// writeData result. The recorded result is read from the principal's own partition instead.
//
// The records in testdata/g2_effect_c5d4_* are Kermit's v3 responses, byte-exact, captured 2026-10-18T12:24Z:
//
//	cust504: principal pv2-cust-504.acme/data on BVN3, bank-504 book on BVN2 (executed by the bank's vote)  - the defect
//	cust590: principal pv2-cust-590.acme/data on BVN3, bank-590 book on BVN2                                 - the defect
//	cust508: principal pv2-cust-508.acme/data on BVN2, bank-508 book on BVN3                                 - the control
const (
	txCust504 = "76472db4c4d9fa99d8db198e859a9658168f5bcfefc1f15a5c76a6464ed75749"
	txCust590 = "a7f9a6f5c4f29554f4d48baf88eff250928768cc6a621f6e3b0fc7bc3106ab75"
	txCust508 = "51027af8e1108e38f36edb47fa29693eb1d75864d4c645a28f5f014e59ea522b"
)

type liveCase struct {
	name      string
	account   string // the principal, as G0 queries it
	tx        string
	entryHash string // the entry Accumulate recorded on the principal
}

var (
	live504 = liveCase{"cust504", "acc://pv2-cust-504.acme/data", txCust504, "5569594d001cd53652d5628bdf7d0faa9f783a73f89fa9066006203d9d6a08f6"}
	live590 = liveCase{"cust590", "acc://pv2-cust-590.acme/data", txCust590, ""} // entry hash asserted from the record below
	live508 = liveCase{"cust508", "acc://pv2-cust-508.acme/data", txCust508, "8e4f5c9d108802d207d5ab9e784131d806d4ec2089b90b3ef0b93589d331cd32"}
)

func loadLiveJSON(t *testing.T, c liveCase, kind string) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("testdata/g2_effect_c5d4_%s_%s.json", c.name, kind))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// partitionedClient answers like the v3 API: a chain query scoped to an ACCOUNT is served by that account's own
// partition (one record, un-collated); a default query scoped to a message ID is the collated answer.
type partitionedClient struct {
	principal string
	chain     map[string]interface{} // the principal partition's chain-entry answer
	collated  map[string]interface{} // the collated message-ID answer
	asked     []string
}

func (c *partitionedClient) Query(ctx context.Context, scope string, query map[string]interface{}) (map[string]interface{}, error) {
	c.asked = append(c.asked, fmt.Sprintf("%s %v", scope, query["queryType"]))
	switch query["queryType"] {
	case "chain":
		if !strings.EqualFold(strings.TrimSuffix(scope, "/"), c.principal) {
			return map[string]interface{}{"jsonrpc": "2.0", "error": map[string]interface{}{
				"code": float64(-33404), "message": "not found", "data": map[string]interface{}{"code": "notFound"}}}, nil
		}
		return c.chain, nil
	case "default":
		return c.collated, nil
	}
	return nil, fmt.Errorf("unexpected query %v", query)
}

func (c *partitionedClient) QueryRaw(ctx context.Context, scope string, query map[string]interface{}) ([]byte, error) {
	resp, err := c.Query(ctx, scope, query)
	if err != nil {
		return nil, err
	}
	return json.Marshal(resp)
}

func (c *partitionedClient) GetEndpoint() string { return "recorded-kermit" }

func effectLayer(client RPCClientInterface) *G2Layer {
	return &G2Layer{
		g1Layer:      &G1Layer{g0Layer: &G0Layer{client: client, queryBuilder: QueryBuilder{}}, client: client},
		queryBuilder: QueryBuilder{},
	}
}

// governed is the G1 result G2 starts from, with the fields G0 derives for this transaction.
func governed(c liveCase) *G1Result {
	return &G1Result{G0Result: G0Result{
		EntryHashExec:     c.tx,
		TxHash:            c.tx,
		Scope:             c.account,
		Chain:             "main",
		ExpandedMessageID: "acc://" + c.tx + "@" + strings.TrimPrefix(c.account, "acc://"),
		G0ProofComplete:   true,
	}}
}

func liveClient(t *testing.T, c liveCase) *partitionedClient {
	return &partitionedClient{principal: c.account, chain: loadLiveJSON(t, c, "principal_chain"), collated: loadLiveJSON(t, c, "collated_msgid")}
}

// principalValue is the chain-entry answer's value: the principal partition's message record.
func principalValue(t *testing.T, m map[string]interface{}) map[string]interface{} {
	t.Helper()
	return m["result"].(map[string]interface{})["value"].(map[string]interface{})
}

// The defect: a WriteData executed because the FOREIGN authority's signature arrived. Accumulate recorded the
// writeData result on the principal's partition; the effect must verify from it.
func TestG2EffectOfAForeignAuthorityTriggeredWriteDataVerifies(t *testing.T) {
	for _, c := range []liveCase{live504, live590} {
		t.Run(c.name, func(t *testing.T) {
			client := liveClient(t, c)
			recorded := principalValue(t, client.chain)["result"].(map[string]interface{})["entryHash"].(string)
			if c.entryHash != "" && recorded != c.entryHash {
				t.Fatalf("the captured record names entry %s, the test expects %s", recorded, c.entryHash)
			}
			rec, err := effectLayer(client).queryRecordedEffect(context.Background(), governed(c))
			if err != nil {
				t.Fatalf("the principal's record could not be read: %v", err)
			}
			v := verifyRecordedEffect(rec, c.tx, nil)
			if !v.Verified {
				t.Fatalf("effect not verified: %v", v.Details["failure"])
			}
			if v.ExpectedValue == nil || *v.ExpectedValue != recorded || v.ComputedValue == nil || *v.ComputedValue != recorded {
				t.Fatalf("expected/computed %v/%v, want the recorded entry %s", v.ExpectedValue, v.ComputedValue, recorded)
			}
			if got := v.Details["status"]; got != "delivered/201" {
				t.Fatalf("status detail %v", got)
			}
			if got := v.Details["recorded_account"]; got != c.account {
				t.Fatalf("recorded_account detail %v, want %s", got, c.account)
			}
		})
	}
}

// The control: the customer's partition sorts first, so the collated answer was always right. The effect the new
// read produces is identical, field for field, to the one the collated read produced - it is hashed into g2Hash, so
// a stored G2 result does not move.
func TestG2EffectOfAnOwnPartitionRecordIsUnchanged(t *testing.T) {
	c := live508
	client := liveClient(t, c)
	rec, err := effectLayer(client).queryRecordedEffect(context.Background(), governed(c))
	if err != nil {
		t.Fatal(err)
	}
	got := verifyRecordedEffect(rec, c.tx, nil)
	if !got.Verified {
		t.Fatalf("control effect not verified: %v", got.Details["failure"])
	}
	if got.ExpectedValue == nil || *got.ExpectedValue != c.entryHash {
		t.Fatalf("control entry %v, want %s", got.ExpectedValue, c.entryHash)
	}

	raw, err := json.Marshal(client.collated["result"])
	if err != nil {
		t.Fatal(err)
	}
	old, err := decodeRecordedEffect(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := verifyRecordedEffect(old, c.tx, nil)
	if !want.Verified {
		t.Fatalf("control collated effect not verified: %v", want.Details["failure"])
	}
	if !reflect.DeepEqual(got, want) {
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(want)
		t.Fatalf("the effect (hashed into g2Hash) moved:\n new %s\n old %s", a, b)
	}
}

// The collated answer for the same transactions says unknown. That record, if it is ever the one handed to the
// check, is refused by the same name as before: the check was not loosened.
func TestG2EffectOfACollatedUnknownResultIsStillRefused(t *testing.T) {
	for _, c := range []liveCase{live504, live590} {
		raw, err := json.Marshal(loadLiveJSON(t, c, "collated_msgid")["result"])
		if err != nil {
			t.Fatal(err)
		}
		rec, err := decodeRecordedEffect(raw)
		if err != nil {
			t.Fatal(err)
		}
		v := verifyRecordedEffect(rec, c.tx, nil)
		if v.Verified {
			t.Fatalf("%s: an unknown result verified", c.name)
		}
		if f, _ := v.Details["failure"].(string); !strings.Contains(f, `recorded a "unknown" result, not the writeData the approved body specifies`) {
			t.Fatalf("%s: refused under another name: %q", c.name, f)
		}
	}
}

// What Accumulate recorded on the principal that DISAGREES with the approved body still fails, under the same names
// as before - the new source is not a way to accept less.
func TestG2EffectTheRecordedResultMustStillAgreeWithTheApprovedBody(t *testing.T) {
	c := live504
	wrong := strings.Repeat("ab", 32)
	for name, tc := range map[string]struct {
		mut  func(value map[string]interface{})
		want string
	}{
		"another entry recorded": {func(v map[string]interface{}) {
			v["result"].(map[string]interface{})["entryHash"] = wrong
		}, "Accumulate recorded entry " + wrong + "; the approved body's entry is " + c.entryHash},
		"the principal recorded no result": {func(v map[string]interface{}) {
			v["result"] = map[string]interface{}{"type": "unknown"}
		}, `recorded a "unknown" result, not the writeData the approved body specifies`},
		"a failed status": {func(v map[string]interface{}) {
			v["status"], v["statusNo"] = "failed", float64(400)
		}, "was not delivered successfully (failed/400)"},
		"pending": {func(v map[string]interface{}) {
			v["status"], v["statusNo"] = "pending", float64(0)
		}, "was not delivered successfully (pending/0)"},
		"recorded on another account": {func(v map[string]interface{}) {
			v["result"].(map[string]interface{})["accountUrl"] = "acc://someone-else.acme/data"
		}, "the entry was recorded on acc://someone-else.acme/data, not on the transaction's principal"},
		"another result type": {func(v map[string]interface{}) {
			v["result"] = map[string]interface{}{"type": "addCredits"}
		}, `recorded a "addCredits" result`},
	} {
		t.Run(name, func(t *testing.T) {
			client := liveClient(t, c)
			tc.mut(principalValue(t, client.chain))
			rec, err := effectLayer(client).queryRecordedEffect(context.Background(), governed(c))
			if err != nil {
				t.Fatalf("the record is well formed, so it must read: %v", err)
			}
			v := verifyRecordedEffect(rec, c.tx, nil)
			if v.Verified {
				t.Fatal("verified")
			}
			if f, _ := v.Details["failure"].(string); !strings.Contains(f, tc.want) {
				t.Fatalf("failure %q does not contain %q", f, tc.want)
			}
		})
	}
}

// The record must be the principal partition's record of THIS transaction's main-chain entry. Anything else is a
// named failure to read it - and the collated answer is never consulted instead (no fallback), even when it would
// have said writeData.
func TestG2EffectNeverFallsBackToTheCollatedAnswer(t *testing.T) {
	c := live508 // the collated answer for the control is a perfectly good writeData result
	wrong := strings.Repeat("cd", 32)
	for name, mutate := range map[string]func(m map[string]interface{}){
		"the principal's partition has no entry for the transaction": func(m map[string]interface{}) {
			delete(m, "result")
			m["error"] = map[string]interface{}{"code": float64(-33404), "message": "get entry index: not found", "data": map[string]interface{}{"code": "notFound"}}
		},
		"the answer is not a chain entry": func(m map[string]interface{}) {
			m["result"].(map[string]interface{})["recordType"] = "range"
		},
		"the entry is another transaction": func(m map[string]interface{}) {
			m["result"].(map[string]interface{})["entry"] = wrong
		},
		"the entry is in another chain": func(m map[string]interface{}) {
			m["result"].(map[string]interface{})["name"] = "scratch"
		},
		"the value is another message": func(m map[string]interface{}) {
			principalValue(t, m)["id"] = "acc://" + wrong + "@pv2-cust-508.acme/data"
		},
		"the value is on another account": func(m map[string]interface{}) {
			principalValue(t, m)["id"] = "acc://" + txCust508 + "@pv2-cust-507.acme/data"
		},
		"the value is absent": func(m map[string]interface{}) {
			delete(m["result"].(map[string]interface{}), "value")
		},
	} {
		t.Run(name, func(t *testing.T) {
			client := liveClient(t, c)
			mutate(client.chain)
			rec, err := effectLayer(client).queryRecordedEffect(context.Background(), governed(c))
			if err == nil {
				v := verifyRecordedEffect(rec, c.tx, nil)
				t.Fatalf("a record was returned (verified=%v) although the principal's partition did not give this transaction's record; asked %v", v.Verified, client.asked)
			}
			for _, a := range client.asked {
				if strings.HasSuffix(a, " default") {
					t.Fatalf("the collated message-ID answer was consulted instead: %v", client.asked)
				}
			}
		})
	}
}

// The chain-entry query is scoped to the principal's account, so the v3 API serves it from the principal's own
// partition. A scope on any other account (a key book, the identity) would be routed to another partition.
func TestG2EffectAsksTheAccountOfTheGovernedTransaction(t *testing.T) {
	c := live504
	client := liveClient(t, c)
	if _, err := effectLayer(client).queryRecordedEffect(context.Background(), governed(c)); err != nil {
		t.Fatal(err)
	}
	if len(client.asked) != 1 || client.asked[0] != c.account+" chain" {
		t.Fatalf("asked %v, want exactly one chain query on %s", client.asked, c.account)
	}
}
