// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"errors"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func withLedgers(f *fakeNet, version protocol.ExecutorVersion, partitions ...string) {
	for _, p := range partitions {
		u := protocol.PartitionUrl(p).JoinPath(protocol.Ledger)
		f.part[strings.ToLower(u.Hostname())] = p
		f.acct.add(&protocol.SystemLedger{Url: u, ExecutorVersion: version})
	}
}

// The executor version in force at each partition's block is captured as the partition's system ledger, at the same block as its other
// pages (RB9 Phase C1b-2), with the role system-ledger.
func TestCollectCapturesEveryPartitionsSystemLedgerAtItsBlock(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	withLedgers(f, protocol.ExecutorVersionV2Baikonur, "BVN1", "BVN2", "BVN3")
	c, err := f.collect()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"BVN1", "BVN2", "BVN3"} {
		led := pageByURL(t, *c, "acc://bvn-"+p+".acme/ledger")
		if led.Block != c.Partitions[p].Block || !hasRoleOf(c, led.URL, proofv2.RoleSystemLedger) || led.Partition != "acc://bvn-"+p+".acme" {
			t.Fatalf("%s: block %d (partition block %d), partition %q, roles %v", led.URL, led.Block, c.Partitions[p].Block, led.Partition, led.Roles)
		}
	}
}

// A ledger before Baikonur is the named state the capture ends with, after everything else is captured.
func TestCollectRefusesAnExecutorBeforeBaikonurByName(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	withLedgers(f, protocol.ExecutorVersionV2, "BVN1")
	c, err := f.collect()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateExecutorVersionUnsupported || ns.Partition != "BVN1" || ns.Block != 1000 {
		t.Fatalf("executor version 5: %v", err)
	}
	if c == nil || len(c.Pages) == 0 {
		t.Fatal("the captured pages were dropped with the named state")
	}
}

// A ledger the partition does not serve is a note naming the partition and block, never an assumed version.
func TestCollectNotesALedgerItCannotRead(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	c, err := f.collect()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range c.Notes {
		found = found || strings.HasPrefix(n, proofv2.StateExecutorVersionUnproven+"{BVN1,1000}")
	}
	if !found {
		t.Fatalf("notes %v", c.Notes)
	}
}
