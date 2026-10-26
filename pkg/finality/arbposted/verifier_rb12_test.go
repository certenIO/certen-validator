// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

func TestABlobPayloadThatIsNotAnRLPStringIsUndecodable(t *testing.T) {
	blobs := encodeBlobs([]byte("payload"))
	if got, err := decodeBlobs(blobs); err != nil || string(got) != "payload" {
		t.Fatalf("control: %q %v", got, err)
	}
	blobs[0][1] = 0xc0 // the first data byte now opens an RLP list, not a string
	if got, err := decodeBlobs(blobs); err == nil {
		t.Fatalf("a list where the payload string must be was decoded to %q", got)
	}
}

func TestEmptySegmentsCarryNoKindAndAreSkipped(t *testing.T) {
	one, err := rlp.EncodeToBytes([]byte{7, 1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	stream := append(append([]byte{0x80}, one...), 0x80)
	segs, exceeded := splitSegments(stream, 5)
	if exceeded || len(segs) != 1 || segs[0].kind != 7 || string(segs[0].body) != string([]byte{1, 2, 3}) {
		t.Fatalf("segments %+v exceeded=%v", segs, exceeded)
	}
	segs, exceeded = splitSegments([]byte{0x80, 0x80}, 5)
	if exceeded || len(segs) != 0 {
		t.Fatalf("only empty segments: %+v %v", segs, exceeded)
	}
}

func TestParseL2MsgStopsABatchAtAnOversizedNestedMessage(t *testing.T) {
	mk := func(n int) []byte {
		m := make([]byte, n)
		m[0], m[1] = l2SignedTx, 0xc1
		return m
	}
	batch := func(msgs ...[]byte) []byte {
		out := []byte{l2Batch}
		for _, m := range msgs {
			out = binary.BigEndian.AppendUint64(out, uint64(len(m)))
			out = append(out, m...)
		}
		return out
	}
	parse := func(msg []byte) ([][]byte, bool) {
		return parseL2Msg(msg, common.Address{}, nil, big.NewInt(0), 0, false)
	}
	small := mk(3)
	if txs, ok := parse(batch(small)); !ok || len(txs) != 1 {
		t.Fatalf("one small message: %d %v", len(txs), ok)
	}
	if txs, ok := parse(batch(mk(maxL2MessageSize))); !ok || len(txs) != 1 {
		t.Fatalf("a nested message of exactly the maximum size is parsed: %d %v", len(txs), ok)
	}
	if txs, ok := parse(batch(small, mk(maxL2MessageSize+1), small)); !ok || len(txs) != 1 {
		t.Fatalf("a nested message above the maximum ends the batch with the messages before it: %d %v", len(txs), ok)
	}
}

func TestMaxBatchBeyondLimitReadsOnlyAnIntegerLiteralAboveTheLimit(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{`{}`, false},
		{`not json`, false},
		{`{"max_uncompressed_batch": 100}`, false},
		{fmt.Sprintf(`{"max_uncompressed_batch": %d}`, MaxUncompressedBatchLimit), false},
		{fmt.Sprintf(`{"max_uncompressed_batch": %d}`, MaxUncompressedBatchLimit+1), true},
		{`{"max_uncompressed_batch": 99999999999999999999999999}`, true},
		{`{"max_uncompressed_batch": 1.5}`, false},
		{`{"max_uncompressed_batch": "x"}`, false},
	} {
		if got := maxBatchBeyondLimit([]byte(c.in)); got != c.want {
			t.Fatalf("%s: %v want %v", c.in, got, c.want)
		}
	}
}

func TestVerifyReturnsTheFirstFailureOfEachStageUnchanged(t *testing.T) {
	p := pinsWith(t, func(map[string]any) {})
	junk := []byte("junk")
	_, wantJunk := finality.DecodeContainer(junk, finality.DefaultLimits())
	if wantJunk == nil {
		t.Fatal("control: junk decoded as a container")
	}
	if _, err := New().Verify(p, finality.BlockRef{}, junk); err == nil || canon(err) != canon(wantJunk) {
		t.Fatalf("junk evidence: %v, want %s", err, canon(wantJunk))
	}
	hash := [32]byte{9, 9}
	enc, err := finality.Container{Header: finality.ContainerHeader{Kind: KindName, Chain: finality.ChainArbitrumSepolia, Level: finality.LevelL1Posted, BlockNumber: 77, BlockHash: hash}, Body: []byte{0}}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	ref := finality.BlockRef{Chain: finality.ChainArbitrumSepolia, Number: 77, Hash: hash}
	noArb := pinsWith(t, func(top map[string]any) { delete(top, "arb_sepolia") })
	_, wantArb := loadArbPins(noArb)
	if _, err := New().Verify(noArb, ref, enc); wantArb == nil || err == nil || canon(err) != canon(wantArb) {
		t.Fatalf("no arb section: %v, want %v", err, wantArb)
	}
	noSep := pinsWith(t, func(top map[string]any) { delete(top, "eth_sepolia") })
	_, _, wantSep := ethl1Pins(noSep)
	if _, err := New().Verify(noSep, ref, enc); wantSep == nil || err == nil || canon(err) != canon(wantSep) {
		t.Fatalf("no eth_sepolia section: %v, want %v", err, wantSep)
	}
}

func TestBlockTxTypesFourIsStandardAndFiveIsUnsupported(t *testing.T) {
	tx4 := []byte{0x04, 0xc1, 0x80}
	e := calldataEvidence([][]byte{{0x6a, 0xc0}, tx4}, payloadOf(seg(segL2Message, signedTxMsg(tx4))), 9, h40, common.Hash{})
	if _, err := runState(t, e, nil, nil); err != nil {
		t.Fatalf("a set-code (type 4) transaction is a standard transaction: %s", canon(err))
	}
	a := legacyTx(1)
	e = calldataEvidence([][]byte{{0x6a, 0xc0}, {0x05, 0xc0}, a}, payloadOf(seg(segL2Message, signedTxMsg(a))), 9, h40, common.Hash{})
	_, err := runState(t, e, nil, nil)
	if canon(err) != want("l1_posted_content_not_found", "reason", "unsupported_tx_type", "batch", uint64(9), "tx_type", uint64(5)) {
		t.Fatalf("type 5: %s", canon(err))
	}
}

func TestInnerCodeNamesTheFaultItWasGiven(t *testing.T) {
	if got := innerCode(&ethl1.Fault{Code: "finality_pin_window"}); got != "finality_pin_window" {
		t.Fatalf("ethl1 fault: %q", got)
	}
	if got := innerCode(finality.NewState("l1_posted_not_found")); got != "l1_posted_not_found" {
		t.Fatalf("named state: %q", got)
	}
	if got := innerCode(errors.New("plain")); got != "unknown" {
		t.Fatalf("plain error: %q", got)
	}
}

func TestVerifyReturnsTheHeaderReadFaultOfAWellFormedBody(t *testing.T) {
	p := pinsWith(t, func(map[string]any) {})
	e := Evidence{LC: ethl1.LC{Profile: ethl1.ProfileLC, AnchorKind: 1, AnchorPeriod: 5, AnchorBody: ethl1.LB{SSZ: []byte{1, 2}}, Links: []ethl1.LB{{Layout: ethl1.LayoutGloas, SSZ: []byte{3}}}, FinalUpdate: ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: []byte{4}}},
		L1Spine: [][]byte{{1}, {2}}, StateBlock: 7, BlockTxs: [][]byte{{5}, {6}}, BatchSeq: 8, Header40: [5]uint64{1, 2, 3, 4, 5}, DataKind: DataCalldata, Calldata: []byte{9, 9},
		Nodes: [][]byte{{0xc0}}}
	hash := [32]byte{9, 9}
	enc, err := finality.Container{Header: finality.ContainerHeader{Kind: KindName, Chain: finality.ChainArbitrumSepolia, Level: finality.LevelL1Posted, BlockNumber: 77, BlockHash: hash}, Body: e.Encode()}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	_, wantErr := finality.ReadHeader(nil)
	if wantErr == nil {
		t.Fatal("control: an empty header was read")
	}
	_, err = New().Verify(p, finality.BlockRef{Chain: finality.ChainArbitrumSepolia, Number: 77, Hash: hash}, enc)
	if err == nil || canon(err) != canon(wantErr) {
		t.Fatalf("an unreadable header: %v, want %s", err, canon(wantErr))
	}
}

func TestAnImplementationAccountWhoseProofNodesAreMissingIsAStateProofFault(t *testing.T) {
	a := legacyTx(1)
	good := calldataEvidence([][]byte{{0x6a, 0xc0}, a}, payloadOf(seg(segL2Message, signedTxMsg(a))), 9, h40, common.Hash{})
	if _, err := runState(t, good, nil, nil); err != nil {
		t.Fatalf("control: %s", canon(err))
	}
	_, err := runState(t, good, nil, func(s *synthState) {
		for i, n := range s.nodes { // the node set no longer holds the implementation account's leaf
			if bytes.Contains(n, testImplCode[:]) {
				s.nodes[i] = []byte{0xc0}
			}
		}
	})
	if canon(err) != want(CodeStateProofInvalid, "which", "account") {
		t.Fatalf("an implementation account without its proof node: %s", canon(err))
	}
}
