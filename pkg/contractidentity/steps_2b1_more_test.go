// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
	"github.com/certen/independant-validator/pkg/finality"
)

func TestB1Step16Hops(t *testing.T) {
	f := b1New(t, 11155111, world.VariantHops)
	step16 := []ci.StepID{ci.Step15, ci.Step16}
	hist := f.addr(f.spec.Roles.History)
	e, _ := f.m.EIP2935(11155111)
	W := e.Window
	bv := f.spec.Blocks.Attest.Number
	h1, h2 := f.spec.Blocks.Between[0].Number, f.spec.Blocks.Between[1].Number
	if h1-bv != W || h2-h1 != W/2 {
		t.Fatalf("world gaps %d %d, want %d %d", h1-bv, h2-h1, W, W/2)
	}
	r, _ := f.run(step16, nil, nil)
	b1Want(t, r, ci.JudgedAuthorizationAttest, "verified", "")
	if f.facts.B1.HopChain.Walked != 3 || !f.facts.B1.HeaderLinked {
		t.Fatalf("hop chain %+v linked %v", f.facts.B1.HopChain, f.facts.B1.HeaderLinked)
	}
	other := common.HexToHash("0x5555")
	refuse := func(name string, specEdit func(*world.Spec), edit func(c *ci.Container), status, code string, kv ...string) {
		t.Run(name, func(t *testing.T) {
			g := b1NewSpec(t, 11155111, world.VariantHops, specEdit)
			var container []byte
			if edit != nil {
				container = g.edit(edit)
			}
			r, _ := g.run(step16, container, nil)
			b1Want(t, r, ci.JudgedAuthorizationAttest, status, code, kv...)
		})
	}
	hopAcct := func(sp *world.Spec, i int) *world.AcctSpec {
		a := sp.Stations[world.HopStation(i)].Accounts[strings.ToLower(hist.Hex())]
		if a == nil {
			a = &world.AcctSpec{Storage: map[string]string{}}
			sp.Stations[world.HopStation(i)].Accounts[strings.ToLower(hist.Hex())] = a
		}
		if a.Storage == nil {
			a.Storage = map[string]string{}
		}
		return a
	}
	refuse("hop slot holds another block hash", func(sp *world.Spec) {
		hopAcct(sp, 1).Storage[strings.ToLower(ci.SlotIndex(bv%W).Hex())] = strings.ToLower(other.Hex())
	}, nil,
		"refused", "header_unlinked", "link", "hops", "index", "0", "reason", "slot_mismatch")
	refuse("hop slot empty", func(sp *world.Spec) {
		hopAcct(sp, 2).Storage[strings.ToLower(ci.SlotIndex(h1%W).Hex())] = strings.ToLower(common.Hash{}.Hex())
	}, nil,
		"refused", "header_unlinked", "index", "1", "reason", "slot_mismatch")
	refuse("history code is not the pin", func(sp *world.Spec) { hopAcct(sp, 2).Code = &world.CodeSpec{Hex: "0x00"} }, nil,
		"refused", "header_unlinked", "index", "1", "reason", "history_code_mismatch")
	refuse("hop headers swapped", nil, func(c *ci.Container) {
		h := c.Attest.Attest.HopHeaders
		h[0], h[1] = h[1], h[0]
	}, "refused", "header_unlinked", "index", "0", "reason", "gap_out_of_range")
	refuse("hop header duplicated", nil, func(c *ci.Container) {
		h := c.Attest.Attest.HopHeaders
		h[1] = h[0]
	}, "refused", "header_unlinked", "index", "1", "reason", "numbers_not_consecutive")
	refuse("first hop dropped: the first link is wider than W and is not the last", nil, func(c *ci.Container) {
		c.Attest.Attest.HopHeaders = c.Attest.Attest.HopHeaders[1:]
	}, "refused", "header_unlinked", "index", "0", "reason", "gap_out_of_range")
	refuse("no hop carried: W + W/2 + 7 across one link", nil, func(c *ci.Container) { c.Attest.Attest.HopHeaders = nil },
		"unproven", "attest_block_out_of_reach", "gap", big.NewInt(0).SetUint64(W+W/2+7).String(), "window", big.NewInt(0).SetUint64(W).String(),
		"hops_carried", "0", "last_hop", big.NewInt(0).SetUint64(bv).String())
	refuse("B_v is the settlement block under link 1", nil, func(c *ci.Container) { c.Attest.Attest.HeaderV = f.built.Inputs.Ctx.Settlement.Header },
		"refused", "attest_mismatch", "field", "order")
}

func b1Wrapper(t *testing.T, data []byte) string {
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(11155111), Nonce: 1, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1), Gas: 21000, To: &to, Data: data})
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b1Hex(raw)
}

func TestB1Step17And20(t *testing.T) {
	base := b1New(t, 11155111, world.VariantH0)
	i := b1AttestTxIndex(base)
	txp := func(m string) string { return "blocks.attest.txs." + big.NewInt(int64(i)).String() + "." + m }
	failedReceipt, err := (&types.Receipt{Type: 2, Status: 0, CumulativeGasUsed: 100000}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	other := common.HexToHash("0x7777").Hex()
	cases := []struct {
		name   string
		muts   []ci.Mutation
		status string
		code   string
		kv     []string
	}{
		{"tx of another transaction (not a call of A, no ProofExecuted log)", []ci.Mutation{world.Set(txp("role"), ""), world.Set(txp("seed"), 4242)}, "refused", "attest_mismatch", []string{"field", "tx_to"}},
		{"receipt without ProofExecuted", []ci.Mutation{world.Set("attestation.logs", []world.LogSpec{})}, "refused", "attest_mismatch", []string{"field", "log"}},
		{"receipt status 0", []ci.Mutation{world.Set(txp("receipt"), b1Hex(failedReceipt))}, "refused", "attest_mismatch", []string{"field", "status"}},
		{"tx.to a wrapper whose receipt carries the log", []ci.Mutation{world.Set(txp("wire"), b1Wrapper(t, []byte{1, 2, 3, 4}))}, "unproven", "attest_indirect_call",
			[]string{"to", "0x2222222222222222222222222222222222222222", "selector", "[1 2 3 4]"}},
		{"type-3 transaction", []ci.Mutation{world.Set(txp("wire"), "0x03c0")}, "unproven", "attest_tx_type_unsupported", []string{"type", "0x03"}},
		{"anchorId in the calldata differs from the log topic", []ci.Mutation{world.Set("attestation.anchor_id", other)}, "refused", "attest_mismatch", []string{"field", "anchor_id"}},
		{"operationCommitment differs from the record operationID", []ci.Mutation{world.Set("attestation.operation_commitment", other)}, "refused", "attest_mismatch", []string{"field", "flip"}},
		{"blob word 12 differs from M", []ci.Mutation{world.Set("attestation.blob.12", other)}, "refused", "attest_mismatch", []string{"field", "blob_layout"}},
		{"pkc zero", []ci.Mutation{world.Set("attestation.blob.13", common.Hash{}.Hex())}, "refused", "attest_mismatch", []string{"field", "blob_layout"}},
		// step 20: M changed consistently in the blob and the outer proof, so that the ties of step 17 hold and only the binding fails
		{"M not the hash of the proven fields", []ci.Mutation{world.Set("attestation.blob.12", other), world.Set("attestation.message_hash", other)}, "refused", "attest_mismatch", []string{"field", "message_hash"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := b1New(t, 11155111, world.VariantH0, c.muts...)
			r, _ := f.run(b1All, nil, nil)
			b1Want(t, r, ci.JudgedAuthorizationAttest, c.status, c.code, c.kv...)
		})
	}
	t.Run("transaction leaf altered", func(t *testing.T) {
		raw := base.edit(func(c *ci.Container) {
			c.Attest.Attest.TxLeaf = append(append([]byte(nil), c.Attest.Attest.TxLeaf...), 0)
		})
		r, _ := base.run(b1All, raw, nil)
		b1Want(t, r, ci.JudgedAuthorizationAttest, "refused", "proof_invalid", "root", "attest_post")
	})
	t.Run("receipt leaf altered", func(t *testing.T) {
		raw := base.edit(func(c *ci.Container) {
			c.Attest.Attest.ReceiptLeaf = append(append([]byte(nil), c.Attest.Attest.ReceiptLeaf...), 0)
		})
		r, _ := base.run(b1All, raw, nil)
		b1Want(t, r, ci.JudgedAuthorizationAttest, "refused", "proof_invalid", "root", "attest_post")
	})
	t.Run("txIndex points at another entry", func(t *testing.T) {
		raw := base.edit(func(c *ci.Container) { c.Attest.Attest.TxIndex++ })
		r, _ := base.run(b1All, raw, nil)
		b1Want(t, r, ci.JudgedAuthorizationAttest, "refused", "proof_invalid", "root", "attest_post")
	})
}

// A Stated settle part (F7): the attestation steps are judged from their own evidence and context-derived inputs only.
func TestB1AttestJudgedWhenSettleIsStated(t *testing.T) {
	f := b1New(t, 11155111, world.VariantH0)
	stated := func(c *ci.Container) {
		c.Settle = ci.Part{Tag: ci.TagStated, Stated: &ci.Stated{State: ci.StatedState, Reason: ci.StatedStateUnavailable, JudgedBlock: c.Leg.Number, JudgedHash: c.Leg.Hash}}
	}
	r, _ := f.run(b1All, f.edit(stated), nil)
	b1Want(t, r, ci.JudgedAuthorizationAttest, "verified", "")
	b1Want(t, r, ci.JudgedRecord, "unproven", "state_unavailable")
	if f.facts.A.Record.BundleID != ([32]byte{}) {
		t.Fatalf("the settle record is present under a Stated settle part")
	}
	if f.facts.B1.MessageHash == ([32]byte{}) || common.Hash(f.facts.B1.MessageRecomputed) != common.Hash(f.facts.B1.MessageHash) {
		t.Fatalf("step 20 did not bind M from the record proven at B_v: %x %x", f.facts.B1.MessageHash, f.facts.B1.MessageRecomputed)
	}
	g := b1New(t, 11155111, world.VariantH0, world.Set("attestation.blob.12", common.HexToHash("0x99").Hex()), world.Set("attestation.message_hash", common.HexToHash("0x99").Hex()))
	r, _ = g.run(b1All, g.edit(stated), nil)
	b1Want(t, r, ci.JudgedAuthorizationAttest, "refused", "attest_mismatch", "field", "message_hash")
}

// Step 22b: the nodes the steps of package 2b-1 visit are EXACTLY the reads of the algorithm. The oracle makes those reads independently
// (the transaction and receipt leaves, the history account and ring slot at every link, the anchor and slot 17 at B_v-pre) over a fresh node
// set; the nodes the real run visits beyond a run in which the steps of 2b-1 are stand-ins must be the oracle's nodes, no more, no fewer.
func TestB1VisitedNodesEqualTheReadsOfTheAlgorithm(t *testing.T) {
	for _, c := range []struct {
		chain   uint64
		variant string
	}{{11155111, world.VariantH0}, {11155111, world.VariantHops}, {421614, world.VariantHops}, {84532, world.VariantS6Silent}} {
		t.Run(strconv.FormatUint(c.chain, 10)+"/"+c.variant, func(t *testing.T) {
			f := b1New(t, c.chain, c.variant)
			f.run(b1All, nil, nil)
			real := f.visited
			f.run(nil, nil, nil)
			fake := f.visited
			key := func(b []byte) common.Hash { return crypto.Keccak256Hash(b) }
			set := func(nodes [][]byte) map[common.Hash]bool {
				m := map[common.Hash]bool{}
				for _, n := range nodes {
					m[key(n)] = true
				}
				return m
			}
			realSet, fakeSet := set(real), set(fake)
			got := map[common.Hash]bool{}
			for h := range realSet {
				if !fakeSet[h] {
					got[h] = true
				}
			}
			// the oracle
			cont, err := ci.Decode(f.built.Inputs.Container, ci.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			ns, err := ci.NewNodeSet(cont.Nodes)
			if err != nil {
				t.Fatal(err)
			}
			a := cont.Attest.Attest
			hv, _ := finality.ReadHeader(a.HeaderV)
			hp, _ := finality.ReadHeader(a.HeaderVParent)
			for _, root := range [][32]byte{hv.TransactionRoot, hv.ReceiptsRoot} {
				if _, err := ci.ReadIndexedLeaf(common.Hash(root), ns, uint64(a.TxIndex), ci.DefaultLimits().MaxNodeBytes); err != nil {
					t.Fatal(err)
				}
			}
			if a.Link == ci.LinkHops {
				e, _ := f.m.EIP2935(c.chain)
				hist := common.HexToAddress(e.Address)
				hs := []finality.HeaderFields{hv}
				for _, raw := range a.HopHeaders {
					h, _ := finality.ReadHeader(raw)
					hs = append(hs, h)
				}
				sh, _ := finality.ReadHeader(f.built.Inputs.Ctx.Settlement.Header)
				hs = append(hs, sh)
				for i := 0; i+1 < len(hs); i++ {
					acct, err := ci.ReadAccount(common.Hash(hs[i+1].StateRoot), ns, hist)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := ci.ReadSlot(acct.StorageRoot, ns, ci.SlotIndex(hs[i].Number%e.Window)); err != nil {
						t.Fatal(err)
					}
				}
			}
			acct, err := ci.ReadAccount(common.Hash(hp.StateRoot), ns, f.addr(f.spec.Roles.Anchor))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ci.ReadSlot(acct.StorageRoot, ns, ci.SlotIndex(17)); err != nil {
				t.Fatal(err)
			}
			want := map[common.Hash]bool{}
			for _, n := range ns.VisitedNodes() {
				if h := key(n); !fakeSet[h] {
					want[h] = true
				}
			}
			if len(got) == 0 || len(got) != len(want) {
				t.Fatalf("package 2b-1 visited %d nodes beyond package 2a, the algorithm reads %d", len(got), len(want))
			}
			for h := range want {
				if !got[h] {
					t.Fatalf("node %s is read by the algorithm and not visited by the steps", h.Hex())
				}
			}
		})
	}
}
