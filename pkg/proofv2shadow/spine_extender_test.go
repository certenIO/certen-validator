package proofv2shadow

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

type fakeChain struct {
	reg   *ledger.BLSRegistryRecord
	spine *ledger.AccumulateSpineLog
}

func (f *fakeChain) IntentCertificateContext() (string, *ledger.BLSRegistryRecord, error) {
	return "certen-testnet", f.reg, nil
}
func (f *fakeChain) CommittedAccumulateSpine() (*ledger.AccumulateSpineLog, error) {
	return f.spine, nil
}

func kermitShadow(t *testing.T) *Shadow {
	t.Helper()
	raw, err := os.ReadFile("../proof/testdata/incarnation/kermit.json")
	if err != nil {
		t.Fatal(err)
	}
	inc := new(proof.IncarnationEvidence)
	if err := json.Unmarshal(raw, inc); err != nil {
		t.Fatal(err)
	}
	gz, err := os.ReadFile("../proof/v2/testdata/archive.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	j, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	ar, err := proofv2.UnmarshalArchive(j)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	// An endpoint that refuses every call: Refresh finds nothing new, as on a network with no new major block.
	b, err := proofv2.NewBuilderFromArchive(jsonrpc.NewClient("http://127.0.0.1:1/v3"), nil, inc, ir.Incarnation, ar)
	if err != nil {
		t.Fatal(err)
	}
	return &Shadow{b: b, inc: inc, pin: ir.Incarnation, logf: t.Logf}
}

// The extender proposes no genesis (the admin quorum's act), then the major blocks in chunks the chain accepts in
// order, and nothing once the chain has verified every block this node walked. Each proposal is exactly what the
// consensus kind decodes and the chain's own spine functions accept.
func TestSpineExtenderBuildsTheChainSpine(t *testing.T) {
	s := kermitShadow(t)
	chain := &fakeChain{reg: &ledger.BLSRegistryRecord{Version: 1, AccumulateIncarnation: "0x" + hex.EncodeToString(s.pin[:])},
		spine: &ledger.AccumulateSpineLog{}}
	var sent [][]byte
	send := func(_ context.Context, tx []byte) error { sent = append(sent, tx); return nil }

	// No genesis: the extender proposes nothing, and says it awaits the admin quorum's.
	msg, err := s.extendOnce(context.Background(), chain, send)
	if err != nil || !strings.Contains(msg, "awaiting the admin-signed spine genesis") || len(sent) != 0 {
		t.Fatalf("no genesis: %q, %v, %d sent", msg, err, len(sent))
	}
	ir, err := s.inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	gen, set, err := proofv2.AcceptSpineGenesis(ir.Inputs, s.pin, 1)
	if err != nil {
		t.Fatal(err)
	}
	chain.spine = &ledger.AccumulateSpineLog{Genesis: gen, Sets: []ledger.AccumulateSpineSet{set}}

	walked := len(s.b.Archive().Majors)
	for i := 0; len(chain.spine.Checkpoints) < walked; i++ {
		if i > walked {
			t.Fatal("the extender is not converging")
		}
		n := len(sent)
		if _, err := s.extendOnce(context.Background(), chain, send); err != nil || len(sent) != n+1 {
			t.Fatalf("extension %d: %v", i, err)
		}
		x, ok := consensus.DecodeAccumulateSpineExtend(sent[n])
		if !ok || x.CheckShape() != nil || x.First != uint64(len(chain.spine.Checkpoints))+1 {
			t.Fatalf("extension %d does not decode as the next extension", i)
		}
		recs, err := x.MajorRecords()
		if err != nil {
			t.Fatal(err)
		}
		cps, sets, err := proofv2.ExtendSpine(chain.spine, recs, int64(2+i))
		if err != nil {
			t.Fatalf("the chain would refuse extension %d: %v", i, err)
		}
		chain.spine.Checkpoints = append(chain.spine.Checkpoints, cps...)
		chain.spine.Sets = append(chain.spine.Sets, sets...)
	}
	n := len(sent)
	if msg, err := s.extendOnce(context.Background(), chain, send); err != nil || msg != "" || len(sent) != n {
		t.Fatalf("a current chain: %q, %v, %d sent", msg, err, len(sent)-n)
	}

	// A registry under another incarnation is not this node's to propose for.
	chain.reg.AccumulateIncarnation = "0x" + strings.Repeat("ab", 32)
	if _, err := s.extendOnce(context.Background(), chain, send); err == nil || !strings.Contains(err.Error(), "not this node's pinned") {
		t.Fatalf("another incarnation: %v", err)
	}
}
