package main

import (
	"context"
	"encoding/json"
	"testing"
)

// countingSigClient serves one signature message, of a key type CERTEN does not verify, and counts
// how often it is asked for it.
type countingSigClient struct{ queries int }

func (c *countingSigClient) Query(context.Context, string, map[string]interface{}) (map[string]interface{}, error) {
	c.queries++
	return map[string]interface{}{"result": map[string]interface{}{
		"message": map[string]interface{}{
			"type": "signature",
			"signature": map[string]interface{}{
				"type":            "ecdsaSha256",
				"publicKey":       "04aa",
				"signature":       "30bb",
				"signer":          "acc://orchid-logistics-tcl1.acme/book/2",
				"transactionHash": "bc2aaf984525fe2b3117b4568d3c09c289fb79ae0b33902b5d8a68bc57c1ed58",
			},
		},
	}}, nil
}
func (c *countingSigClient) QueryRaw(ctx context.Context, scope string, q map[string]interface{}) ([]byte, error) {
	r, err := c.Query(ctx, scope, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(r)
}
func (c *countingSigClient) GetEndpoint() string { return "counting" }

// A signature type CERTEN does not verify is a capability limit. It stays UNAVAILABLE - never a
// rejection, so no threshold is computed over the remainder - but it is PERMANENT: evaluating it
// again re-queries the chain for the same answer. Live (intent 1875ae30, 2026-09-21) a book whose
// history held a dozen ecdsaSha256 signatures made G1 repeat every one of them three times.
func TestG1DoesNotRetryACapabilityLimit(t *testing.T) {
	am, err := NewArtifactManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	client := &countingSigClient{}
	g1 := NewG1Layer(client, am, "")

	res := g1.evaluateCandidateWithRetry(context.Background(),
		sigCandidate{MessageID: "acc://aa@orchid-logistics-tcl1.acme/book/2", MessageHash: "aa"},
		"acc://orchid-logistics-tcl1.acme/book/2", AuthoritySnapshot{}, "bc2aaf984525fe2b3117b4568d3c09c289fb79ae0b33902b5d8a68bc57c1ed58", "t")

	if res.Outcome != SigUnavailable {
		t.Fatalf("outcome %v (%s: %s); an unsupported key type must stay UNAVAILABLE, never rejected", res.Outcome, res.Stage, res.Reason)
	}
	if !res.Permanent {
		t.Fatalf("an unsupported key type was not marked permanent (%s: %s)", res.Stage, res.Reason)
	}
	if client.queries != 1 {
		t.Fatalf("queried the signature message %d times; a capability limit cannot change between attempts", client.queries)
	}
}
