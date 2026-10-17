// Command proofv2xvector captures, from a live network, the vector for a page on a partition other than the transaction's
// (RB9 Phase B, docs/proof/G1_CROSS_PARTITION.md D2): the partition the page lives on (from the routing table the network
// publishes), the latest block of that partition whose BlockValidatorAnchor the Directory executed, the page read as of that
// block with the receipt the node returns (waiting, within the partition's retention, for the block to become servable), the
// anchor message and its receipt into a Directory root, and the routing table the page was routed with. The block is only
// servable for about 945 seconds, so the vector is stored: it is the only way to test against a real foreign page later.
//
//	proofv2xvector -page acc://fdb-risk-tcl1.acme/book/2 -out pkg/proof/v2/testdata/xpartition/bvn2-fdb-risk-book2.json.gz
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Vector is the stored form.
type Vector struct {
	Format     string `json:"format"`
	Endpoint   string `json:"endpoint"`
	CapturedAt string `json:"capturedAt"`

	Page      string `json:"page"`      // the account captured
	Partition string `json:"partition"` // the partition ID the routing table gives it
	// DNLimit is the Directory block the selection was limited to: the latest Directory block when it was captured, standing in
	// for the Directory block that executed a transaction's own partition's anchor.
	DNLimit uint64 `json:"dnLimit"`
	Block   uint64 `json:"block"`   // B_Y
	Index   uint64 `json:"index"`   // the anchor's position in anchor(<partition>)-root
	DNBlock uint64 `json:"dnBlock"` // the Directory block that executed the anchor

	// Retained is the partition's advertised retained range when it was captured.
	RetainedEarliest uint64 `json:"retainedEarliest"`
	RetainedLatest   uint64 `json:"retainedLatest"`

	PageState proofv2.PageState `json:"pageState"` // trimmed to the anchor's state tree root
	// Untrimmed is the receipt exactly as the node served it (it runs past the anchor's root to the node's current root).
	ServedReceipt string `json:"servedReceipt"`

	Anchor       proofv2.PartitionAnchor `json:"anchor"`       // the anchor and a receipt to whichever Directory root the node chose
	AnchorTx     string                  `json:"anchorTx"`     // hex32
	StateRoot    string                  `json:"stateRoot"`    // hex32: the anchor's StateTreeAnchor
	RootChain    string                  `json:"rootChain"`    // hex32: the anchor's RootChainAnchor
	AnchorHeight uint64                  `json:"anchorHeight"` // the Directory root chain height AnchorAtHeight ends at
	AnchorAtH    proofv2.PartitionAnchor `json:"anchorAtHeight"`

	Routing json.RawMessage `json:"routing"` // network-status.routing, the table the page was routed with
}

func main() {
	endpoint := flag.String("endpoint", "https://kermit.accumulatenetwork.io/v3", "Accumulate v3 endpoint")
	page := flag.String("page", "", "the account to capture")
	out := flag.String("out", "", "gzip file to write")
	flag.Parse()
	if *page == "" || *out == "" {
		fmt.Println("FAIL: -page and -out are required")
		os.Exit(2)
	}
	if err := run(*endpoint, *page, *out); err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
}

func run(endpoint, page, out string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	c := jsonrpc.NewClient(endpoint)
	router, err := proof.LoadNetworkRouter(ctx, endpoint)
	if err != nil {
		return err
	}
	part, err := router.PartitionID(page)
	if err != nil {
		return err
	}
	routing, err := networkRouting(ctx, endpoint)
	if err != nil {
		return err
	}
	ret := &proofv2.ClientRetention{C: c}
	e, l, err := ret.Retained(ctx, part)
	if err != nil {
		return err
	}
	// The Directory block the selection is limited to: a few blocks behind the head, so the Directory has executed the anchors.
	dh, err := ret.Head(ctx, protocol.Directory)
	if err != nil {
		return err
	}
	dnLimit := dh - 3

	log := proofv2.NetLog{Net: c}
	pb, err := proofv2.SelectPartitionBlock(ctx, log, part, dnLimit, 0)
	if err != nil {
		return err
	}
	fmt.Printf("partition %s: retained [%d, %d]; anchor %d is block %d, executed by DN %d (limit DN %d)\n", part, e, l, pb.Index, pb.Block, pb.DNBlock, dnLimit)

	reader := &proofv2.PageReader{Net: c, Q: proof.NewHTTPQuerier(endpoint), Retention: ret}
	ps, err := reader.PageAt(ctx, page, part, pb.Block)
	if err != nil {
		return err
	}
	served := ps.Receipt
	trimmed, err := proofv2.BindToAnchor(ps, part, pb.Block, pb.Anchor.StateTreeAnchor)
	if err != nil {
		return err
	}
	trimmed.Partition = protocol.PartitionUrl(part).String()

	a, h, err := proofv2.AnchorAt(ctx, c, pb, 0)
	if err != nil {
		return err
	}
	// And the same anchor proven into the Directory root chain at the height of a minor-root run that certifies a later Directory
	// block, as a proof's certification asks for.
	// The Directory's root chain as it stands: a later root than the one the node anchored the anchor under, which the anchor is
	// proven into by asking for the receipt at that height.
	rr, err := c.Query(ctx, protocol.DnUrl().JoinPath(protocol.Ledger), &api.ChainQuery{Name: "root"})
	if err != nil {
		return fmt.Errorf("Directory root chain: %w", err)
	}
	rc, ok := rr.(*api.ChainRecord)
	if !ok {
		return fmt.Errorf("Directory root chain: got %T", rr)
	}
	height := rc.Count - 1
	ah, _, err := proofv2.AnchorAt(ctx, c, pb, height)
	if err != nil {
		return fmt.Errorf("anchor at root height %d: %w", height, err)
	}

	v := Vector{Format: "certen-xpartition-vector/1", Endpoint: endpoint, CapturedAt: time.Now().UTC().Format(time.RFC3339),
		Page: page, Partition: part, DNLimit: dnLimit, Block: pb.Block, Index: pb.Index, DNBlock: pb.DNBlock,
		RetainedEarliest: e, RetainedLatest: l, PageState: *trimmed, ServedReceipt: served,
		Anchor: a, AnchorTx: fmt.Sprintf("%x", h), StateRoot: fmt.Sprintf("%x", pb.Anchor.StateTreeAnchor), RootChain: fmt.Sprintf("%x", pb.Anchor.RootChainAnchor),
		AnchorHeight: height, AnchorAtH: ah, Routing: routing}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes): %s as of %s block %d, anchor %x at DN %d, root height %d\n", out, buf.Len(), page, part, pb.Block, h[:6], pb.DNBlock, height)
	return nil
}

// networkRouting reads network-status.routing as raw JSON: this module's typed client cannot decode the network-status of a
// network running a newer executor.
func networkRouting(ctx context.Context, endpoint string) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "network-status", "params": map[string]any{}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var env struct {
		Result struct {
			Routing json.RawMessage `json:"routing"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || len(env.Result.Routing) == 0 {
		return nil, fmt.Errorf("network-status carries no routing table: %v", err)
	}
	return env.Result.Routing, nil
}
