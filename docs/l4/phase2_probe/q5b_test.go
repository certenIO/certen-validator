package q5probe

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// How much does the anchor body vary? Sample real anchor-sequence entries
// across the whole chain, including ones adjacent to major-block closes.
func TestQ5b_AnchorSizeDistribution(t *testing.T) {
	idxs := []int{1, 100, 1000, 10000, 50000, 100000, 150000, 170000, 173000, 173300}
	var sizes []int
	maxR, maxU := 0, 0
	for _, i := range idxs {
		raw := rpc(t, map[string]any{
			"scope": "acc://dn.acme/anchors",
			"query": map[string]any{"queryType": "chain", "name": "anchor-sequence", "index": i, "expand": true},
		})
		var ae struct {
			Value struct {
				Message struct {
					Transaction json.RawMessage `json:"transaction"`
				} `json:"message"`
			} `json:"value"`
		}
		require.NoError(t, json.Unmarshal(raw, &ae))
		if len(ae.Value.Message.Transaction) == 0 {
			continue
		}
		txn := new(protocol.Transaction)
		if json.Unmarshal(ae.Value.Message.Transaction, txn) != nil || txn.Body == nil {
			continue
		}
		b, err := txn.Body.MarshalBinary()
		require.NoError(t, err)
		nr, nu := 0, 0
		if da, ok := txn.Body.(*protocol.DirectoryAnchor); ok {
			nr, nu = len(da.Receipts), len(da.Updates)
		}
		if nr > maxR {
			maxR = nr
		}
		if nu > maxU {
			maxU = nu
		}
		sizes = append(sizes, len(b))
		t.Logf("  anchor-sequence[%6d]  %s  %5d B  receipts=%d updates=%d",
			i, txn.Body.Type(), len(b), nr, nu)
	}
	require.NotEmpty(t, sizes)
	sort.Ints(sizes)
	sum := 0
	for _, s := range sizes {
		sum += s
	}
	t.Logf("")
	t.Logf("anchor body: min %d B  median %d B  max %d B  mean %d B  (n=%d)",
		sizes[0], sizes[len(sizes)/2], sizes[len(sizes)-1], sum/len(sizes), len(sizes))
	t.Logf("max receipts seen %d, max updates seen %d", maxR, maxU)

	// Record size as a function of validator count, using the measured
	// 165 B/signature and the median anchor body.
	median := sizes[len(sizes)/2]
	t.Logf("")
	t.Logf("MajorHeaderRecord ~= 34 B framing + %d B anchor + 165 B x V signatures", median+47)
	for _, v := range []int{1, 3, 8, 16, 32, 64} {
		per := 34 + median + 47 + 165*v
		t.Logf("  V=%2d -> %5d B/record | mainnet 822 blocks = %6.1f KB | kermit 417 = %6.1f KB",
			v, per, float64(822*per)/1024, float64(417*per)/1024)
	}
}
