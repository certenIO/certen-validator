package main

import (
	"context"
	"encoding/json"
	"testing"
)

// RB3-F36: a page's main-chain count comes from the v3 chain record, or not at all - it bounds the
// enumeration of the page's history, so a guessed count silently drops the entries that authorise a signer.
func TestTheChainCountIsTheChainRecordsOrNothing(t *testing.T) {
	var live map[string]interface{}
	// Kermit's answer to {"queryType":"chain","name":"main"} on 2026-09-27.
	if err := json.Unmarshal([]byte(`{"recordType":"chain","name":"main","type":"transaction","count":2,"state":[null,"de84"],"lastBlockTime":"2026-09-27T16:40:26Z"}`), &live); err != nil {
		t.Fatal(err)
	}
	if n, err := chainRecordCount(live); err != nil || n != 2 {
		t.Fatalf("the live chain record: (%d, %v)", n, err)
	}
	for name, body := range map[string]string{
		"a range response with no total":      `{"recordType":"range","records":[{},{},{}]}`,
		"a range response's total":            `{"recordType":"range","total":9,"records":[]}`,
		"a nested range total":                `{"range":{"total":9}}`,
		"a chain record with no count":        `{"recordType":"chain","name":"main"}`,
		"a negative count":                    `{"recordType":"chain","count":-1}`,
		"a fractional count":                  `{"recordType":"chain","count":1.5}`,
		"a count as a string":                 `{"recordType":"chain","count":"4"}`,
		"a record that is not a chain record": `{"recordType":"account","count":4}`,
	} {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatal(err)
		}
		if n, err := chainRecordCount(m); err == nil {
			t.Errorf("%s: counted %d", name, n)
		}
	}
}

// countClient answers every query with one raw JSON-RPC response.
type countClient struct{ raw string }

func (c countClient) Query(context.Context, string, map[string]interface{}) (map[string]interface{}, error) {
	var m map[string]interface{}
	err := json.Unmarshal([]byte(c.raw), &m)
	return m, err
}
func (c countClient) QueryRaw(context.Context, string, map[string]interface{}) ([]byte, error) {
	return []byte(c.raw), nil
}
func (c countClient) GetEndpoint() string { return "test" }

// Through the builder: a response that is not the chain record is an error, never a count from the
// records that happened to come back.
func TestTheBuilderDoesNotGuessAChainCount(t *testing.T) {
	am, err := NewArtifactManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	guess := NewAuthorityBuilder(countClient{`{"jsonrpc":"2.0","id":1,"result":{"recordType":"range","records":[{},{},{}]}}`}, am)
	if n, err := guess.getMainChainCount(context.Background(), "acc://page.acme/book/1"); err == nil {
		t.Fatalf("counted %d entries from a response that states no count", n)
	}
	record := NewAuthorityBuilder(countClient{`{"jsonrpc":"2.0","id":1,"result":{"recordType":"chain","name":"main","count":7}}`}, am)
	if n, err := record.getMainChainCount(context.Background(), "acc://page.acme/book/1"); err != nil || n != 7 {
		t.Fatalf("the chain record: (%d, %v)", n, err)
	}
}
