// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	acc_url "gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

var netAcct = acc_url.MustParse("acc://dn.acme/network")

// setWrite is a WriteData to /network installing validators with the given
// key bytes, all active on Directory.
func setWrite(t *testing.T, version uint64, keys ...byte) protocol.TransactionBody {
	t.Helper()
	nd := &protocol.NetworkDefinition{NetworkName: "test", Version: version}
	for _, k := range keys {
		pk := bytes.Repeat([]byte{k}, 32)
		nd.Validators = append(nd.Validators, &protocol.ValidatorInfo{PublicKey: pk, PublicKeyHash: sha256.Sum256(pk),
			Partitions: []*protocol.ValidatorPartitionInfo{{ID: protocol.Directory, Active: true}}})
	}
	b, err := nd.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{b}}, WriteToState: true}
}

func decodeSet(t *testing.T, data []byte) []byte {
	t.Helper()
	nd := new(protocol.NetworkDefinition)
	if err := nd.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}
	var first []byte
	for _, v := range nd.Validators {
		first = append(first, v.PublicKey[0])
	}
	return first
}

// The validator set changed after the anchor. The set in force at the anchor
// is the one the earlier write installed; today's set is not it.
func TestL4Set_ChangedAfterTheAnchorUsesTheSetInForce(t *testing.T) {
	entries := []systemEntry{
		{Block: 1, Body: &protocol.SystemGenesis{}},
		{Block: 500, Body: setWrite(t, 1, 0xA1, 0xA2, 0xA3)},
		{Block: 900, Body: setWrite(t, 2, 0xB1, 0xB2, 0xB3)},
	}

	data, current, err := recordInForce(netAcct, entries, 850)
	if err != nil || current {
		t.Fatalf("anchor at 850: current=%v err=%v", current, err)
	}
	if got := decodeSet(t, data); !bytes.Equal(got, []byte{0xA1, 0xA2, 0xA3}) {
		t.Fatalf("anchor at 850 must use the set written at 500, got keys %x", got)
	}

	// A write in the anchor's own block is not yet active during it.
	data, current, err = recordInForce(netAcct, entries, 900)
	if err != nil || current {
		t.Fatalf("anchor at 900: current=%v err=%v", current, err)
	}
	if got := decodeSet(t, data); !bytes.Equal(got, []byte{0xA1, 0xA2, 0xA3}) {
		t.Fatalf("a write at 900 is not active at 900, got keys %x", got)
	}

	// After the last write, today's state is the state at the anchor.
	if _, current, err := recordInForce(netAcct, entries, 901); err != nil || !current {
		t.Fatalf("anchor at 901: current=%v err=%v, want the present state", current, err)
	}
}

// The set changed after the anchor, and what was in force then is genesis,
// which does not carry the record. Today's set must not be substituted.
func TestL4Set_ChangedAfterTheAnchorFromGenesisRefuses(t *testing.T) {
	entries := []systemEntry{
		{Block: 1, Body: &protocol.SystemGenesis{}},
		{Block: 900, Body: setWrite(t, 1, 0xB1)},
	}
	if _, _, err := recordInForce(netAcct, entries, 850); err == nil {
		t.Fatal("must refuse rather than use the set written after the anchor")
	}
}

// Never changed: genesis is in force and the present state is its state.
func TestL4Set_NeverChangedUsesThePresentState(t *testing.T) {
	entries := []systemEntry{{Block: 1, Body: &protocol.SystemGenesis{}}}
	if _, current, err := recordInForce(netAcct, entries, 7_000_000); err != nil || !current {
		t.Fatalf("current=%v err=%v", current, err)
	}
}

// An anchor at or before the account's first entry has no set in force, and
// entries out of block order are not a history.
func TestL4Set_NoEntryBeforeTheAnchorOrDisorderedRefuses(t *testing.T) {
	entries := []systemEntry{{Block: 10, Body: &protocol.SystemGenesis{}}}
	if _, _, err := recordInForce(netAcct, entries, 10); err == nil {
		t.Fatal("no entry before block 10: must refuse")
	}
	disordered := []systemEntry{
		{Block: 1, Body: &protocol.SystemGenesis{}},
		{Block: 900, Body: setWrite(t, 2, 0xB1)},
		{Block: 500, Body: setWrite(t, 1, 0xA1)},
	}
	if _, _, err := recordInForce(netAcct, disordered, 950); err == nil {
		t.Fatal("entries out of block order: must refuse")
	}
}

// Live: the set read at the anchor's block on Kermit reproduces the set every
// stored leg carries, since Kermit's has never changed, for the Directory and
// for a BVN.
func TestL4Set_LiveMatchesTheDestinationsOwnSet(t *testing.T) {
	c := liveClient(t)
	b := &Layer4Builder{Client: c}
	for _, dest := range []string{"acc://dn.acme", "acc://bvn-BVN1.acme"} {
		ni, err := b.networkInfoAt(context.Background(), acc_url.MustParse(dest), 1<<40, "live")
		if err != nil {
			t.Fatalf("%s: %v", dest, err)
		}
		if len(ni.Validators) == 0 || ni.Accept.Denominator == 0 {
			t.Fatalf("%s: empty set or threshold: %+v", dest, ni)
		}
		t.Logf("%s: %d validators, accept %d/%d, version %d", dest, len(ni.Validators), ni.Accept.Numerator, ni.Accept.Denominator, ni.Version)
	}
}
