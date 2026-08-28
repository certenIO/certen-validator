// Q5 probe (Phase 2). How big is one MajorHeaderRecord, really?
//
// Builds a real private.MajorHeaderRecord using the dagbft-integration types,
// populated from LIVE Kermit data: a real major-block IndexEntry, the real
// DirectoryAnchor that closed that window wrapped in a real SequencedMessage,
// and the real validator quorum signatures over it. Then marshals it and
// measures. Read-only: fetches over HTTP, writes nothing.
package q5probe

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/accumulatenetwork/accumulate/internal/api/private"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

const server = "https://kermit.accumulatenetwork.io/v3"

func rpc(t *testing.T, params any) json.RawMessage {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "query", "params": params,
	})
	resp, err := http.Post(server, "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var r struct {
		Result json.RawMessage  `json:"result"`
		Error  *json.RawMessage `json:"error"`
	}
	require.NoError(t, json.Unmarshal(raw, &r))
	require.Nil(t, r.Error, "rpc error: %s", func() string {
		if r.Error == nil {
			return ""
		}
		return string(*r.Error)
	}())
	return r.Result
}

func TestQ5_MajorHeaderRecordSize(t *testing.T) {
	rec := new(private.MajorHeaderRecord)

	// --- 1. the major-block index entry -------------------------------------
	raw := rpc(t, map[string]any{
		"scope": "acc://dn.acme/anchors",
		"query": map[string]any{"queryType": "chain", "name": "major-block", "index": 416, "expand": true},
	})
	var ce struct {
		Index uint64 `json:"index"`
		Value struct {
			Value *protocol.IndexEntry `json:"value"`
		} `json:"value"`
	}
	require.NoError(t, json.Unmarshal(raw, &ce))
	rec.Index = ce.Index
	rec.Entry = ce.Value.Value
	require.NotNil(t, rec.Entry)
	eb, err := rec.Entry.MarshalBinary()
	require.NoError(t, err)
	t.Logf("IndexEntry                  : %4d B  (source %d, block %d, rootIndexIndex %d)",
		len(eb), rec.Entry.Source, rec.Entry.BlockIndex, rec.Entry.RootIndexIndex)

	// --- 2. a real DirectoryAnchor from the anchor-sequence chain ------------
	raw = rpc(t, map[string]any{
		"scope": "acc://dn.acme/anchors",
		"query": map[string]any{"queryType": "chain", "name": "anchor-sequence", "index": 173000, "expand": true},
	})
	var ae struct {
		Value struct {
			Message struct {
				Transaction json.RawMessage `json:"transaction"`
			} `json:"message"`
		} `json:"value"`
	}
	require.NoError(t, json.Unmarshal(raw, &ae))
	txn := new(protocol.Transaction)
	require.NoError(t, json.Unmarshal(ae.Value.Message.Transaction, txn))
	tb, err := txn.Body.MarshalBinary()
	require.NoError(t, err)
	da, ok := txn.Body.(*protocol.DirectoryAnchor)
	require.True(t, ok, "expected a directoryAnchor")
	t.Logf("DirectoryAnchor body        : %4d B  (%d receipts, %d updates)",
		len(tb), len(da.Receipts), len(da.Updates))

	seq := new(messaging.SequencedMessage)
	seq.Message = &messaging.TransactionMessage{Transaction: txn}
	seq.Source = protocol.DnUrl()
	seq.Destination = protocol.DnUrl()
	seq.Number = 173001
	rec.Anchor = seq
	sb, err := seq.MarshalBinary()
	require.NoError(t, err)
	t.Logf("SequencedMessage (anchor)   : %4d B", len(sb))

	// --- 3. real validator quorum signatures --------------------------------
	raw = rpc(t, map[string]any{
		"scope": "acc://dn.acme/anchors",
		"query": map[string]any{"queryType": "chain", "name": "main", "index": 1000},
	})
	var me struct {
		Value struct {
			Signatures struct {
				Records []struct {
					Signatures struct {
						Records []struct {
							Message struct {
								Signature json.RawMessage `json:"signature"`
							} `json:"message"`
						} `json:"records"`
					} `json:"signatures"`
				} `json:"records"`
			} `json:"signatures"`
		} `json:"value"`
	}
	require.NoError(t, json.Unmarshal(raw, &me))

	sigBytes := 0
	for _, s := range me.Value.Signatures.Records {
		for _, m := range s.Signatures.Records {
			if len(m.Message.Signature) == 0 {
				continue
			}
			sig, err := protocol.UnmarshalSignatureJSON(m.Message.Signature)
			if err != nil {
				continue
			}
			ks, ok := sig.(protocol.KeySignature)
			if !ok {
				continue
			}
			rec.Signatures = append(rec.Signatures, ks)
			b, err := sig.MarshalBinary()
			require.NoError(t, err)
			sigBytes += len(b)
		}
	}
	require.NotEmpty(t, rec.Signatures, "need real signatures to size this honestly")
	t.Logf("KeySignatures               : %4d B for %d signers (%d B each)",
		sigBytes, len(rec.Signatures), sigBytes/len(rec.Signatures))

	// --- 4. the whole record ------------------------------------------------
	full, err := rec.MarshalBinary()
	require.NoError(t, err)
	t.Logf("")
	t.Logf("MajorHeaderRecord TOTAL     : %4d B  (%d updates in window)", len(full), len(rec.Updates))
	t.Logf("")

	// --- 5. what the spine costs at today's height --------------------------
	for _, n := range []struct {
		net   string
		major int
		vals  int
	}{{"kermit", 417, 3}, {"mainnet", 822, 1}} {
		per := len(full)
		if n.vals != len(rec.Signatures) {
			perSig := sigBytes / len(rec.Signatures)
			per = len(full) - sigBytes + perSig*n.vals
		}
		t.Logf("%-8s %3d major blocks x ~%d B = %.1f KB for the whole spine (at %d validators)",
			n.net, n.major, per, float64(n.major*per)/1024, n.vals)
	}

	_ = url.URL{}
	_ = hex.EncodeToString
	_ = fmt.Sprint
}
