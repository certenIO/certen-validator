package q5probe

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Q4: size the CERTEN-shaped point query — "the validator set at block N,
// provable to a signed anchor" — from real data.
func TestQ4_PointQueryArtifactSize(t *testing.T) {
	raw := rpc(t, map[string]any{
		"scope": "acc://dn.acme/network",
		"query": map[string]any{"queryType": "default", "includeReceipt": true},
	})
	var rec struct {
		Account json.RawMessage `json:"account"`
		Receipt struct {
			Entries []struct{} `json:"entries"`
		} `json:"receipt"`
	}
	require.NoError(t, json.Unmarshal(raw, &rec))

	acct, err := protocol.UnmarshalAccountJSON(rec.Account)
	require.NoError(t, err)
	state, err := acct.MarshalBinary()
	require.NoError(t, err)

	da, ok := acct.(*protocol.DataAccount)
	require.True(t, ok)
	var nd protocol.NetworkDefinition
	require.NoError(t, nd.UnmarshalBinary(da.Entry.GetData()[0]))
	ndb, err := nd.MarshalBinary()
	require.NoError(t, err)

	path := len(rec.Receipt.Entries) * 33

	t.Logf("kermit, %d validators / %d partitions:", len(nd.Validators), len(nd.Partitions))
	t.Logf("  NetworkDefinition (the payload)      : %5d B", len(ndb))
	t.Logf("  full dataAccount state (leaf preimage): %5d B", len(state))
	t.Logf("  BPT membership path                   : %5d B (%d steps)", path, len(rec.Receipt.Entries))
	t.Logf("  root-chain receipt for the BPT root    : ~ 264 B (8 steps, measured §9.1.2)")
	t.Logf("  signed anchor + quorum (3 validators)  : %5d B", 1043+165*3)
	t.Logf("  ------------------------------------------------")
	t.Logf("  POINT QUERY ARTIFACT TOTAL             : %5d B", len(state)+path+264+1043+165*3)
	t.Logf("")
	t.Logf("mainnet-scale (17-step BPT, 561 B path), per validator count:")
	for _, v := range []int{1, 8, 16, 32} {
		t.Logf("  V=%2d -> %5d B", v, len(state)+561+264+1043+165*v)
	}
}
