// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// denimTs is the second of Base Sepolia block 50410156 (2026-10-26T08:38:20Z), long after denim_time: five consecutive L2 blocks
// carry it (R11-base-denim, RB11-D-POST).
const denimTs = uint64(1793003900)

func TestADenimBlockIsBoundToTheBatchWithItsParentHashNotTheFirstBatchOfItsSecond(t *testing.T) {
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, batchTs: denimTs, sameSecondBefore: 4})
	denimPins(s.bp)
	v, err := s.verify()
	if err != nil {
		t.Fatalf("the fifth block of a timestamp second must verify, the four batches before it carry the same second: %v", err)
	}
	if v.Level != finality.LevelL1Posted || v.Fields["batch_type"] != uint64(0) || v.Fields["parent_hash_bits"] != uint64(256) {
		t.Fatalf("%+v", v)
	}
}

func TestADenimBlockWhoseParentMatchesNoBatchOfItsSecondIsAParentMismatchNotAbsent(t *testing.T) {
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, batchTs: denimTs, sameSecondBefore: 2})
	denimPins(s.bp)
	s.l2.ParentHash = crypto.Keccak256Hash([]byte("a parent no batch of this second names"))
	_, err := s.verify()
	wantCode(t, err, CodeBatchBindingMismatch, map[string]string{"field": "parent_hash"})
}

func TestADenimBlockWhoseSecondHasNoBatchIsAbsent(t *testing.T) {
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, batchTs: denimTs})
	denimPins(s.bp)
	s.l2.Timestamp = denimTs + 1
	_, err := s.verify()
	wantCode(t, err, CodeBatchNotFound, map[string]string{"timestamp": "1793003901", "n_batches": "3"})
}

func TestASpanBatchThatWouldProduceADenimBlockIsRefusedWithANamedState(t *testing.T) {
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, span: true, batchTs: denimTs})
	denimPins(s.bp)
	_, err := s.verify()
	wantCode(t, err, CodeBatchFormat, map[string]string{"type": "span_post_denim"})
}

func TestADenimBlockPostedByAnotherSenderThanTheSystemConfigBatcherIsRefused(t *testing.T) {
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, batchTs: denimTs, sameSecondBefore: 3, chainBatch: testKey("someone else")})
	denimPins(s.bp)
	_, err := s.verify()
	wantCode(t, err, CodeBatcherSender, map[string]string{})
}

func TestAPreDenimBlockKeepsTheTimestampKeyedLookup(t *testing.T) {
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, span: true, batchTs: 1790000000})
	denimPins(s.bp)
	v, err := s.verify()
	if err != nil || v.Fields["batch_type"] != uint64(1) {
		t.Fatalf("a span batch below denim_time is judged as before: %+v %v", v, err)
	}
	s2 := makeSynth(t, synthOpts{compression: "zlib", calldata: true, batchTs: 1790000000, sameSecondBefore: 1})
	denimPins(s2.bp)
	_, err = s2.verify()
	wantCode(t, err, CodeBatchBindingMismatch, map[string]string{"field": "parent_hash"})
}

func TestAStraddledSecondIsFoundInTheChannelWhoseBatchHasTheParentHash(t *testing.T) {
	first := makeSynth(t, synthOpts{compression: "zlib", calldata: true, batchTs: denimTs, channelLabel: "channel one", parentLabel: "parent one", frameBlocks: []uint64{1000}})
	second := makeSynth(t, synthOpts{compression: "zlib", calldata: true, batchTs: denimTs, channelLabel: "channel two", parentLabel: "parent two", frameBlocks: []uint64{1001}})
	st := NewMemStore()
	putSynth(t, st, first)
	putSynth(t, st, second)
	bp := newPins()
	denimPins(bp)
	txs, err := (&Builder{Store: st}).load(context.Background(), bp)
	if err != nil || len(txs) != 2 {
		t.Fatalf("%d txs, %v", len(txs), err)
	}
	ref, _, bt, _ := findChannel(txs, bp, second.l2)
	if ref == nil || ref.ID != second.body.ChannelID || bt == nil || bt.ParentHash != second.l2.ParentHash {
		t.Fatalf("the later channel carries the batch with this parent hash: %v %v", ref, bt)
	}
	ref, _, bt, _ = findChannel(txs, bp, first.l2)
	if ref == nil || ref.ID != first.body.ChannelID || bt == nil || bt.ParentHash != first.l2.ParentHash {
		t.Fatalf("%v %v", ref, bt)
	}
	other := second.l2
	other.ParentHash = crypto.Keccak256Hash([]byte("neither"))
	if ref, _, _, _ := findChannel(txs, bp, other); ref != nil {
		t.Fatalf("a parent hash no channel names finds no channel: %v", ref)
	}
}

func TestADenimBuildIsRefusedUnderPinsWithoutTheCapabilityAndPendingUnderPinsWithIt(t *testing.T) {
	post := makeSynth(t, synthOpts{compression: "zlib", calldata: true, batchTs: 1792605600})
	pins := embeddedPinsWithout(t, "post_denim")
	_, _, err := (&Builder{Pins: pins, Store: NewMemStore()}).Build(context.Background(), &ethproof.Settlement{Header: post.l2Raw}, 0, finality.LevelL1Posted)
	wantCode(t, err, CodeBatchFormat, map[string]string{"type": "post_denim"})
	emb, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	ad, pend, err := (&Builder{Pins: emb, Store: NewMemStore()}).Build(context.Background(), &ethproof.Settlement{Header: post.l2Raw}, 0, finality.LevelL1Posted)
	if err != nil || ad != nil || pend == nil || pend.Reason != "l1_posted_unproven" {
		t.Fatalf("with the capability a denim block is searched like any other: %v %v %v", ad, pend, err)
	}
}

func TestTheEmbeddedPinsCarryThePostDenimCapability(t *testing.T) {
	emb, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	bp, err := ParsePins(emb)
	if err != nil {
		t.Fatal(err)
	}
	pd := bp.PostDenim
	if pd == nil || len(pd.BatchTypes) != 1 || pd.BatchTypes[0] != 0 || pd.BlockIntervalMS != 200 || pd.BlocksPerSecond != 5 ||
		"0x"+hex.EncodeToString(pd.BaseTimePredeploy[:]) != "0x4200000000000000000000000000000000000030" || "0x"+hex.EncodeToString(pd.BaseTimeSelector[:]) != "0x86bdf394" {
		t.Fatalf("%+v", pd)
	}
	without, err := ParsePins(embeddedPinsWithout(t, "post_denim"))
	if err != nil || without.PostDenim != nil {
		t.Fatalf("pins without the row parse and carry no capability: %+v %v", without, err)
	}
}

func TestAMalformedPostDenimRowIsAPinsCorruption(t *testing.T) {
	good := map[string]any{"batch_types": []any{0}, "block_interval_ms": 200, "blocks_per_second": 5,
		"base_time_predeploy": "0x4200000000000000000000000000000000000030", "base_time_selector": "0x86bdf394"}
	cases := []struct {
		name string
		edit func(m map[string]any)
	}{
		{"batch_types empty", func(m map[string]any) { m["batch_types"] = []any{} }},
		{"batch_types span", func(m map[string]any) { m["batch_types"] = []any{0, 1} }},
		{"batch_types duplicate", func(m map[string]any) { m["batch_types"] = []any{0, 0} }},
		{"interval zero", func(m map[string]any) { m["block_interval_ms"] = 0 }},
		{"per second zero", func(m map[string]any) { m["blocks_per_second"] = 0 }},
		{"interval times count is not a second", func(m map[string]any) { m["blocks_per_second"] = 4 }},
		{"interval times count wraps modulo 2^64 to a second (RB12-F23)", func(m map[string]any) { m["block_interval_ms"] = 1000; m["blocks_per_second"] = uint64(1<<61 + 1) }},
		{"predeploy short", func(m map[string]any) { m["base_time_predeploy"] = "0x4200" }},
		{"predeploy upper case", func(m map[string]any) { m["base_time_predeploy"] = "0x42000000000000000000000000000000000000AA" }},
		{"selector short", func(m map[string]any) { m["base_time_selector"] = "0x86bdf3" }},
		{"unknown key", func(m map[string]any) { m["extra"] = 1 }},
		{"not an object", nil},
	}
	for _, c := range cases {
		row := map[string]any{}
		for k, v := range good {
			row[k] = v
		}
		var val any = row
		if c.edit != nil {
			c.edit(row)
		} else {
			val = []any{1}
		}
		raw := embeddedPinsWith(t, "post_denim", val)
		pins, err := finality.ParsePinsOverride(raw)
		if err != nil {
			t.Fatalf("%s: the framework parse: %v", c.name, err)
		}
		_, err = ParsePins(pins)
		se, ok := finality.AsNamed(err)
		if !ok || se.Code != finality.CodePinsCorrupt || fmt.Sprint(se.Fields["key"]) != "base_sepolia.post_denim" {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// embeddedPinsWith returns the framework pins whose base_sepolia section has key set to val (nil value: the key removed).
func embeddedPinsWith(t *testing.T, key string, val any) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(finality.EmbeddedPinsBytes(), &m); err != nil {
		t.Fatal(err)
	}
	var sec map[string]json.RawMessage
	if err := json.Unmarshal(m["base_sepolia"], &sec); err != nil {
		t.Fatal(err)
	}
	if val == nil {
		delete(sec, key)
	} else {
		b, err := json.Marshal(val)
		if err != nil {
			t.Fatal(err)
		}
		sec[key] = b
	}
	m["base_sepolia"], _ = json.Marshal(sec)
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func embeddedPinsWithout(t *testing.T, key string) *finality.Pins {
	t.Helper()
	p, err := finality.ParsePinsOverride(embeddedPinsWith(t, key, nil))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
