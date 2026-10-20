// Copyright 2026 Certen Protocol

package arbposted

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
)

// The fixes of the independent completeness review V-E2-A1: a delayed-origin judgement must prove some content, a top-level sequencer
// message is capped like Nitro's ParseL2Transactions, Kind.Verify binds the BlockRef to the container and to its own header, and
// the numeric pins whose absence used to load as 0 are refused by name.

// ---- 1. a delayed message that derives nothing proves nothing --------------------------------------------------------------

// delayedFixture is a Bridge holding delayed message k (and its predecessor) and a batch that consumed it with one delayed segment.
func delayedFixture(msg Delayed) (map[uint64]common.Hash, common.Hash) {
	prev := crypto.Keccak256Hash([]byte("prev"))
	mh := DelayedMessageHash(msg)
	accK := crypto.Keccak256Hash(prev[:], mh[:])
	return map[uint64]common.Hash{msg.K: accK, msg.K - 1: prev}, accK
}

func TestDelayedMessageDerivingNothingIsNotContent(t *testing.T) {
	k := uint64(41)
	user := common.HexToAddress("0x1111111111111111111111111111111111111111")
	pl := payloadOf(seg(segDelayed, nil), seg(segAdvanceTime, []byte{1}))
	h := [5]uint64{100, 200, 300, 400, k + 1}
	// kind 3 whose data is an empty batch derives zero transactions in Nitro
	empty := Delayed{MsgKind: msgKindL2Message, Sender: user, MsgBlockNumber: 10, MsgTimestamp: 20, Data: []byte{l2Batch}, K: k}
	if txs, ok := deriveDelayed(421614, empty); !ok || len(txs) != 0 {
		t.Fatalf("fixture: the empty batch must derive no transactions, got %d ok=%v", len(txs), ok)
	}
	dm, accK := delayedFixture(empty)
	noContent := string(contentNotFound(ContentNoStandardTransactions, "batch", uint64(3)).Canonical())
	for name, txs := range map[string][][]byte{
		"only the internal start-block transaction": {{0x6a, 0xc0}},
		"no transactions at all":                    nil,
		"internal and retry transactions only":      {{0x6a, 0xc0}, {0x68, 0xc0}},
	} {
		e := calldataEvidence(txs, pl, 3, h, accK)
		d := empty
		e.Delayed = &d
		v, err := runState(t, e, dm, nil)
		if err == nil {
			t.Errorf("%s: accepted as l1_posted through delayed index %v", name, v.Fields["delayed_message_index"])
			continue
		}
		if got := canon(err); got != noContent {
			t.Errorf("%s:\n got  %s\n want %s", name, got, noContent)
		}
	}
}

// A block that holds a transaction the message does not derive is still the delayed-origin state, not the empty-content state: the
// new guard sits after the byte-for-byte comparison.
func TestDelayedMismatchKeepsItsOwnState(t *testing.T) {
	k := uint64(41)
	user := common.HexToAddress("0x1111111111111111111111111111111111111111")
	pl := payloadOf(seg(segDelayed, nil), seg(segAdvanceTime, []byte{1}))
	h := [5]uint64{100, 200, 300, 400, k + 1}
	empty := Delayed{MsgKind: msgKindL2Message, Sender: user, MsgBlockNumber: 10, MsgTimestamp: 20, Data: []byte{l2Batch}, K: k}
	dm, accK := delayedFixture(empty)
	txs := [][]byte{{0x6a, 0xc0}, legacyTx(1)}
	e := calldataEvidence(txs, pl, 3, h, accK)
	d := empty
	e.Delayed = &d
	_, err := runState(t, e, dm, nil)
	// runState gives the block header the nonce 7
	want := string(delayedUnproven([]uint64{0x6a, 0}, 7, "k", k, "message_kind", uint8(msgKindL2Message)).Canonical())
	if got := canon(err); got != want {
		t.Errorf("\n got  %s\n want %s", got, want)
	}
}

// ---- 2. a top-level sequencer message is capped like ParseL2Transactions ---------------------------------------------------

// quietBatch is a batch message holding exactly the transaction a, then an oversize length prefix (which ends the batch quietly), then
// zero padding up to total bytes: the whole message is `total` bytes long and derives [a] whenever the size cap lets it through.
func quietBatch(a []byte, total int) []byte {
	m := batchMsg(signedTxMsg(a))
	m = binary.BigEndian.AppendUint64(m, maxL2MessageSize+1)
	for len(m) < total {
		m = append(m, 0)
	}
	return m
}

func TestTopLevelSequencerMessageCapIsExactlyMaxL2MessageSize(t *testing.T) {
	a := legacyTx(1)
	for _, c := range []struct {
		total int
		ok    bool
	}{{maxL2MessageSize - 1, true}, {maxL2MessageSize, true}, {maxL2MessageSize + 1, false}, {maxL2MessageSize + 50, false}} {
		m := quietBatch(a, c.total)
		if len(m) != c.total {
			t.Fatalf("fixture length %d, want %d", len(m), c.total)
		}
		txs, ok := parseL2(m, 0)
		if ok != c.ok || (ok && (len(txs) != 1 || string(txs[0]) != string(a))) || (!ok && txs != nil) {
			t.Errorf("parseL2 of a %d-byte message: ok=%v txs=%d, want ok=%v", c.total, ok, len(txs), c.ok)
		}
	}
}

func TestOversizeTopLevelMessageMatchesNoBlockButKeepsItsOrdinal(t *testing.T) {
	a := legacyTx(1)
	blockTxs := [][]byte{{0x6a, 0xc0}, a}
	// at the cap: matched at ordinal 0
	v, err := runState(t, calldataEvidence(blockTxs, payloadOf(seg(segL2Message, quietBatch(a, maxL2MessageSize))), 9, h40, common.Hash{}), nil, nil)
	if err != nil || v.Fields["message_ordinal"] != uint64(0) {
		t.Fatalf("a message of exactly %d bytes: verdict %v err %v", maxL2MessageSize, v.Fields, canon(err))
	}
	// one byte over: dropped; the batch holds one message and one segment, none matches
	_, err = runState(t, calldataEvidence(blockTxs, payloadOf(seg(segL2Message, quietBatch(a, maxL2MessageSize+1))), 9, h40, common.Hash{}), nil, nil)
	noMatch := string(contentNotFound(ContentNoMatchingMessage, "batch", uint64(9), "messages_scanned", uint64(1), "segments", uint64(1)).Canonical())
	if got := canon(err); got != noMatch {
		t.Errorf("a message of %d bytes:\n got  %s\n want %s", maxL2MessageSize+1, got, noMatch)
	}
	// the dropped message still occupies ordinal 0: the block's real message is found at ordinal 1 of 2
	v, err = runState(t, calldataEvidence(blockTxs, payloadOf(seg(segL2Message, quietBatch(a, maxL2MessageSize+1)), seg(segL2Message, batchMsg(signedTxMsg(a)))), 9, h40, common.Hash{}), nil, nil)
	if err != nil || v.Fields["message_ordinal"] != uint64(1) || v.Fields["messages"] != uint64(2) {
		t.Errorf("the dropped message keeps its ordinal: verdict %v err %v", v.Fields, canon(err))
	}
}

// ---- 3. Kind.Verify binds the BlockRef --------------------------------------------------------------------------------------

func liveCase(t *testing.T) (*finality.Pins, finality.BlockRef, finality.Container) {
	t.Helper()
	var c vecCase
	if err := json.Unmarshal(readVec(t, "cases/valid_live.json"), &c); err != nil {
		t.Fatal(err)
	}
	pins, err := finality.ParsePinsOverride(readVec(t, c.Pins))
	if err != nil {
		t.Fatal(err)
	}
	ref := refOf(t, c.Leg)
	cont, err := finality.DecodeContainer(evidenceOf(t, c), finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New().Verify(pins, ref, evidenceOf(t, c)); err != nil {
		t.Fatalf("baseline: %s", canon(err))
	}
	return pins, ref, cont
}

func TestKindVerifyBindsTheBlockRefToTheContainerAndItsHeader(t *testing.T) {
	pins, ref, cont := liveCase(t)
	recode := func(number uint64, hash [32]byte) []byte {
		c := cont
		c.Header.BlockNumber, c.Header.BlockHash = number, hash
		out, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	otherHash := ref.Hash
	otherHash[0] ^= 0xff
	mismatch := func(field string, want, got any) string {
		return string(finality.BlockMismatch(field, want, got).Canonical())
	}
	for _, c := range []struct {
		name string
		ref  finality.BlockRef
		ev   []byte
		want string
	}{
		{"BlockRef number differs from the container", finality.BlockRef{Chain: ref.Chain, Number: ref.Number + 5, Hash: ref.Hash, HeaderRLP: ref.HeaderRLP},
			recode(ref.Number, ref.Hash), mismatch("blockNumber", ref.Number+5, ref.Number)},
		{"BlockRef hash differs from the container", finality.BlockRef{Chain: ref.Chain, Number: ref.Number, Hash: otherHash, HeaderRLP: ref.HeaderRLP},
			recode(ref.Number, ref.Hash), mismatch("blockHash", otherHash, ref.Hash)},
		{"BlockRef hash is not the hash of its header (container agrees with the BlockRef)", finality.BlockRef{Chain: ref.Chain, Number: ref.Number, Hash: otherHash, HeaderRLP: ref.HeaderRLP},
			recode(ref.Number, otherHash), mismatch("blockHash", otherHash, ref.Hash)},
		{"BlockRef number is not the number of its header (container agrees with the BlockRef)", finality.BlockRef{Chain: ref.Chain, Number: ref.Number + 5, Hash: ref.Hash, HeaderRLP: ref.HeaderRLP},
			recode(ref.Number+5, ref.Hash), mismatch("blockNumber", ref.Number+5, ref.Number)},
	} {
		_, err := New().Verify(pins, c.ref, c.ev)
		if got := canon(err); got != c.want {
			t.Errorf("%s:\n got  %s\n want %s", c.name, got, c.want)
		}
	}
}

// ---- 4. numeric pins that are absent are refused, not read as 0 ---------------------------------------------------------------

func TestAbsentOrNullNumericPinsAreRefusedByName(t *testing.T) {
	for _, c := range []struct{ field, key string }{
		{"bold_genesis_l2_block", "bold_genesis_l2_block"},
		{"layout.acc_array_slot", "acc_array_slot"},
		{"layout.delayed_acc_array_slot", "delayed_acc_array_slot"},
	} {
		for _, how := range []string{"absent", "null"} {
			p := pinsWith(t, func(top map[string]any) {
				a := arbOf(top)
				target := a
				if c.key != c.field {
					target = a["layout"].(map[string]any)
				}
				if how == "absent" {
					delete(target, c.key)
				} else {
					target[c.key] = nil
				}
			})
			a, err := loadArbPins(p)
			if want := string(PinMismatch(c.field).Canonical()); canon(err) != want || a != nil {
				t.Errorf("%s %s: got %s (pins %v), want %s", c.field, how, canon(err), a != nil, want)
			}
		}
	}
}
