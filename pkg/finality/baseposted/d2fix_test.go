// Copyright 2026 Certen Protocol

package baseposted

import (
	"math"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// RB11-D2-FIX: the findings of the independent review V-D2-A1 (checkins/V-D2-A1.md) on base-sepolia/l1_posted/v1.

func d2fixSingle(parent, epochHash [32]byte, epochNum, ts uint64, txs [][]byte) []byte {
	enc, _ := rlp.EncodeToBytes(singularRLP{ParentHash: parent, EpochNum: epochNum, EpochHash: epochHash, Timestamp: ts, Txs: txs})
	b, _ := rlp.EncodeToBytes(append([]byte{0}, enc...))
	return b
}

var (
	d2fixParent = [32]byte(crypto.Keccak256Hash([]byte("parent")))
	d2fixEpoch  = [32]byte(crypto.Keccak256Hash([]byte("epoch hash")))
)

// synthBound builds a synthetic world whose batch carries batchTxs, whose block holds blockTxs and whose depositTxs are deposits.
func synthBound(t *testing.T, batchTxs, deposits, blockTxs [][]byte) *synth {
	t.Helper()
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, rawStream: d2fixSingle(d2fixParent, d2fixEpoch, 990, 1790000000, batchTxs)})
	s.body.Deposits = deposits
	s.l2.TransactionRoot = [32]byte(ethproof.TrieRoot(blockTxs))
	return s
}

// V-D2-A1 defect 1: only Deposits[0] was typed; every other entry of depositTxs was free, and transactionsRoot is taken over
// depositTxs || batch txs, so a prover moved any block transaction the batcher never posted into depositTxs.
func TestDepositTxsMustAllBeDepositsAndBatchTxsMustNotBe(t *testing.T) {
	dep0 := makeSynth(t, synthOpts{compression: "zlib", calldata: true}).body.Deposits[0]
	depX := l1InfoDeposit(991, d2fixEpoch) // a second deposit-typed transaction (0x7e)
	u1, u2 := userTx(1), userTx(2)
	cases := []struct {
		name                     string
		batch, deposits, blockTx [][]byte
		code, field              string
	}{
		{"a user tx the batch never carried is moved into depositTxs", [][]byte{u2}, [][]byte{dep0, u1}, [][]byte{dep0, u1, u2}, CodeBatchBindingMismatch, "deposit_txs"},
		{"an empty batch with every user tx in depositTxs", nil, [][]byte{dep0, u1, u2}, [][]byte{dep0, u1, u2}, CodeBatchBindingMismatch, "deposit_txs"},
		{"the last depositTxs entry is a user tx", nil, [][]byte{dep0, depX, u1}, [][]byte{dep0, depX, u1}, CodeBatchBindingMismatch, "deposit_txs"},
		{"an empty depositTxs entry", [][]byte{u1, u2}, [][]byte{dep0, {}}, [][]byte{dep0, u1, u2}, CodeBatchBindingMismatch, "deposit_txs"},
		{"the batch carries a deposit-typed tx", [][]byte{depX}, [][]byte{dep0}, [][]byte{dep0, depX}, CodeBatchBindingMismatch, "batch_txs"},
		{"the batch carries a deposit-typed tx between user txs", [][]byte{u1, depX, u2}, [][]byte{dep0}, [][]byte{dep0, u1, depX, u2}, CodeBatchBindingMismatch, "batch_txs"},
		{"the batch carries an empty tx", [][]byte{u1, {}}, [][]byte{dep0}, [][]byte{dep0, u1, {}}, CodeBatchBindingMismatch, "batch_txs"},
	}
	for _, c := range cases {
		_, err := synthBound(t, c.batch, c.deposits, c.blockTx).verify()
		t.Run(c.name, func(t *testing.T) { wantCode(t, err, c.code, map[string]string{"field": c.field}) })
	}
	// positive controls: several leading deposits are fine when they are all deposit-typed
	mustOKSynth(t, synthBound(t, [][]byte{u1, u2}, [][]byte{dep0}, [][]byte{dep0, u1, u2}))
	mustOKSynth(t, synthBound(t, [][]byte{u1, u2}, [][]byte{dep0, depX}, [][]byte{dep0, depX, u1, u2}))
	mustOKSynth(t, synthBound(t, nil, [][]byte{dep0, depX}, [][]byte{dep0, depX}))
}

func mustOKSynth(t *testing.T, s *synth) {
	t.Helper()
	if _, err := s.verify(); err != nil {
		t.Fatalf("a binding that must verify was refused: %v", err)
	}
}

// The builder splits an L2 block at the first non-deposit transaction; the lists it publishes are exactly the shape the verifier now requires.
func TestTheBuilderPublishesExactlyTheDepositListsTheVerifierAccepts(t *testing.T) {
	dep0 := l1InfoDeposit(990, d2fixEpoch)
	depX := l1InfoDeposit(991, d2fixEpoch)
	u1, u2 := userTx(1), userTx(2)
	for _, c := range []struct {
		block [][]byte
		want  int // number of leading deposits
	}{
		{[][]byte{dep0, u1, u2}, 1},
		{[][]byte{dep0, depX, u1, u2}, 2},
		{[][]byte{dep0}, 1},
		{[][]byte{dep0, u1, depX}, 1}, // a deposit after a user tx is not a leading one: the root then fails, never a typed-list pass
		{[][]byte{dep0, {}, u1}, 1},   // an empty transaction ends the run
	} {
		got := leadingDeposits(c.block)
		if len(got) != c.want {
			t.Fatalf("%d leading deposits, want %d", len(got), c.want)
		}
		for _, d := range got {
			if len(d) == 0 || d[0] != 0x7e {
				t.Fatalf("leadingDeposits published an entry that is not deposit-typed: %x", d)
			}
		}
	}
	// and the verifier accepts the published split of a block with two deposits
	block := [][]byte{dep0, depX, u1, u2}
	mustOKSynth(t, synthBound(t, [][]byte{u1, u2}, leadingDeposits(block), block))
}

// V-D2-A1 defect 4: the pin 300 is the Bedrock channel timeout; after Granite op-node uses 50 L1 blocks, selected by the time of
// the L1 block that holds the frame being ingested (ChainSpec.ChannelTimeout(origin.Time) in channel_bank.go IngestFrame).
func TestChannelTimeoutIsFiftyAfterGraniteThreeHundredBeforeAndSelectedByTheFrameBlockTime(t *testing.T) {
	// the synthetic L1 block n is timed 1790000000+n
	run := func(granite uint64, blocks ...uint64) error {
		s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, nFrames: len(blocks), frameBlocks: blocks})
		s.bp.GraniteTime = granite // NEWSYM
		_, err := s.verify()
		return err
	}
	const past, far, edge = 1723478400, 1790000000 + 1_000_000, 1790000000 + 1100 // Granite long ago / after the world / block 1100 is its first block
	for _, gap := range []uint64{50} {
		if err := run(past, 1000, 1000+gap); err != nil {
			t.Fatalf("post-Granite gap %d: %v", gap, err)
		}
	}
	for _, gap := range []uint64{51, 250, 300, 301} {
		wantCode(t, run(past, 1000, 1000+gap), CodeChannelTimedOut, nil)
	}
	for _, gap := range []uint64{51, 250, 300} {
		if err := run(far, 1000, 1000+gap); err != nil {
			t.Fatalf("pre-Granite gap %d: %v", gap, err)
		}
	}
	wantCode(t, run(far, 1000, 1301), CodeChannelTimedOut, nil)
	// the switch: block 1099 is before Granite, block 1100 (time == granite_time) is the first after it
	if err := run(edge, 1000, 1099); err != nil {
		t.Fatalf("both frames before Granite: %v", err)
	}
	wantCode(t, run(edge, 1000, 1100), CodeChannelTimedOut, nil)
	wantCode(t, run(edge, 1000, 1150), CodeChannelTimedOut, nil) // selecting by the FIRST frame block would accept (gap 150 <= 300)
	if err := run(edge, 1100, 1150); err != nil {
		t.Fatalf("both frames after Granite within 50: %v", err)
	}
}

// V-D2-A1 defect 3: isthmus_time is parsed and required but no l1_posted rule compares it. Its role is pinned here: it is an
// informational pin of this kind (the section is shared with the finalized kind, which refuses a pre-Isthmus header), and no
// value of it changes any verdict of l1_posted, accepting or refusing.
func TestIsthmusTimeIsAnInformationalPinOfL1PostedNoVerdictDependsOn(t *testing.T) {
	verdicts := func(isthmus uint64) [3]string {
		var out [3]string
		for i, s := range []*synth{
			makeSynth(t, synthOpts{compression: "zlib", calldata: true}),
			makeSynth(t, synthOpts{compression: "zlib", calldata: true, nFrames: 2, frameBlocks: []uint64{1000, 1100}}),          // timed out
			makeSynth(t, synthOpts{compression: "zlib", calldata: true, epochNum: 1001, frameBlocks: []uint64{1001 + 3600 + 1}}), // outside the window: the completing frame is one past epoch + sequence_window_size (R12-SPEC-Q1, no lower bound)
		} {
			s.bp.IsthmusTime = isthmus
			v, err := s.verify()
			out[i] = string(CanonicalVerdict(v, err))
		}
		return out
	}
	base := verdicts(1744905600)
	for _, ts := range []uint64{1, 1723478400, 1790000000, 1790000000 + 5000, math.MaxUint64} {
		if got := verdicts(ts); got != base {
			t.Fatalf("isthmus_time %d changed a verdict:\n%v\n%v", ts, got, base)
		}
	}
	if !strings.HasSuffix(base[0], `"result":"ok"}`) || !strings.Contains(base[1], "channel_timed_out") || !strings.Contains(base[2], "batch_outside_sequencing_window") {
		t.Fatalf("the controls do not cover accept and both refusals: %v", base)
	}
}

// V-D2-A1 defect 4 (pins): the two new pins are required, non-zero, read, and equal op-node's values for Base Sepolia.
func TestTheGranitePinsAreRequiredAndTheEmbeddedValuesAreOpNodes(t *testing.T) {
	good := baseSection(t)
	bp, err := ParsePins(pinsWith(t, good))
	if err != nil {
		t.Fatal(err)
	}
	if bp.GraniteTime != 1723478400 || bp.ChannelTimeoutGranite != 50 || bp.ChannelTimeout != 300 {
		t.Fatalf("granite_time %d channel_timeout_granite %d channel_timeout %d", bp.GraniteTime, bp.ChannelTimeoutGranite, bp.ChannelTimeout)
	} // NEWSYM
	_ = bp
	for _, key := range []string{"granite_time", "channel_timeout_granite"} {
		m := baseSection(t)
		m[key] = 0
		_, err := ParsePins(pinsWith(t, m))
		wantCode(t, err, finality.CodePinsCorrupt, map[string]string{"key": "base_sepolia." + key})
		m = baseSection(t)
		delete(m, key)
		_, err = ParsePins(pinsWith(t, m))
		wantCode(t, err, finality.CodePinsCorrupt, map[string]string{"key": "base_sepolia." + key})
	}
}
