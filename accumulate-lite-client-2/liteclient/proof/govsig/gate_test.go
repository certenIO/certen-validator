// Copyright 2026 Certen Protocol

package govsig_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The pinned activation table is R8 M5, verbatim. A change here is a change to what the verifier proves, so it is
// pinned by a test that states the numbers.
func TestActivationTableIsR8M5(t *testing.T) {
	want := map[string]int64{"directory": 9_538_105, "bvn1": 12_491_272, "bvn2": 12_492_057, "bvn3": 12_491_127}
	got := govsig.KermitActivations()
	if len(got) != len(want) {
		t.Fatalf("table has %d rows, R8 M5 has %d", len(got), len(want))
	}
	for p, b := range want {
		if got[p].Block != b || got[p].Version != protocol.ExecutorVersionV2Kourou {
			t.Errorf("%s: %+v, R8 M5 says v2-kourou at block %d", p, got[p], b)
		}
	}
	if got["directory"].Time != "2026-09-21T15:30:10Z" {
		t.Errorf("the Directory's activation time is %q", got["directory"].Time)
	}
}

// Both sides of the gate, for every gated type, on every partition in the table.
func TestExecutorGateBothSides(t *testing.T) {
	gated := []protocol.SignatureType{protocol.SignatureTypeRsaSha256, protocol.SignatureTypeEcdsaSha256, protocol.SignatureTypeTypedData}
	for part, act := range govsig.KermitActivations() {
		for _, ty := range gated {
			// before the activation: the named state, with the type, partition and block it was judged at
			for _, blk := range []int64{1, act.Block - 1, act.Block} {
				err := govsig.CheckExecutorGate(ty, govsig.EthRuleNone, govsig.Where{Partition: part, Block: blk})
				var un govsig.ExecutorVersionUnproven
				if !errors.As(err, &un) {
					t.Fatalf("%v at %s block %d (activation %d) must be g1_executor_version_unproven, got %v", ty, part, blk, act.Block, err)
				}
				if un.Type != ty.String() || un.Partition != part || un.Block != blk || un.Needs != protocol.ExecutorVersionV2Vandenberg.String() {
					t.Fatalf("the named state must carry what it was judged at, got %+v", un)
				}
				if un.Reason() != "g1_executor_version_unproven" {
					t.Fatalf("reason %q", un.Reason())
				}
			}
			// after the activation: proven
			for _, blk := range []int64{act.Block + 1, act.Block + 1_000_000} {
				if err := govsig.CheckExecutorGate(ty, govsig.EthRuleNone, govsig.Where{Partition: part, Block: blk}); err != nil {
					t.Fatalf("%v at %s block %d is after the activation and must pass: %v", ty, part, blk, err)
				}
			}
		}
	}
}

// Blocks are per partition: a Directory-sized block number says nothing about a BVN.
func TestGateIsPerPartition(t *testing.T) {
	// 10,000,000 is after the Directory's activation (9,538,105) and long before BVN1's (12,491,272).
	where := func(p string) govsig.Where { return govsig.Where{Partition: p, Block: 10_000_000} }
	if err := govsig.CheckExecutorGate(protocol.SignatureTypeEcdsaSha256, govsig.EthRuleNone, where("directory")); err != nil {
		t.Fatalf("directory: %v", err)
	}
	if err := govsig.CheckExecutorGate(protocol.SignatureTypeEcdsaSha256, govsig.EthRuleNone, where("bvn1")); !errors.As(err, new(govsig.ExecutorVersionUnproven)) {
		t.Fatalf("bvn1 at block 10,000,000 is before its activation: %v", err)
	}
	// spellings of the Directory
	for _, spell := range []string{"Directory", "DN", "dn"} {
		if err := govsig.CheckExecutorGate(protocol.SignatureTypeEcdsaSha256, govsig.EthRuleNone, govsig.Where{Partition: spell, Block: 10_000_000}); err != nil {
			t.Errorf("%q must name the Directory: %v", spell, err)
		}
	}
}

// Unknown partition or block, or a partition outside the table, is the same named state: never acceptance.
func TestGateUnknownWhereIsNamed(t *testing.T) {
	for _, w := range []govsig.Where{{}, {Partition: "bvn1"}, {Block: 99_999_999}, {Partition: "bvn9", Block: 99_999_999}} {
		err := govsig.CheckExecutorGate(protocol.SignatureTypeTypedData, govsig.EthRuleNone, w)
		if !errors.As(err, new(govsig.ExecutorVersionUnproven)) {
			t.Errorf("%+v must be g1_executor_version_unproven, got %v", w, err)
		}
	}
}

// Always-registered types need no gate, anywhere, including with no location at all.
func TestAlwaysRegisteredTypesNeedNoGate(t *testing.T) {
	for _, ty := range []protocol.SignatureType{protocol.SignatureTypeLegacyED25519, protocol.SignatureTypeED25519,
		protocol.SignatureTypeRCD1, protocol.SignatureTypeBTC, protocol.SignatureTypeBTCLegacy, protocol.SignatureTypeETH} {
		for _, w := range []govsig.Where{{}, {Partition: "bvn1", Block: 5}, {Partition: "directory", Block: 99_999_999}} {
			rule := govsig.EthRuleNone
			if ty == protocol.SignatureTypeETH {
				rule = govsig.EthRuleV1DER
				if w.Block == 99_999_999 {
					continue // DER eth after the proven activation is the one gate-not-met case, tested below
				}
			}
			if err := govsig.CheckExecutorGate(ty, rule, w); err != nil {
				t.Errorf("%v at %+v: %v", ty, w, err)
			}
		}
	}
}

// eth: the raw r||s rule is v2-baikonur; the DER form could only be accepted below it.
func TestEthRuleGate(t *testing.T) {
	act := govsig.KermitActivations()["bvn2"].Block
	if err := govsig.CheckExecutorGate(protocol.SignatureTypeETH, govsig.EthRuleV2RSV, govsig.Where{Partition: "bvn2", Block: act - 1}); !errors.As(err, new(govsig.ExecutorVersionUnproven)) {
		t.Errorf("v2 rule before the activation must be unproven, got %v", err)
	}
	if err := govsig.CheckExecutorGate(protocol.SignatureTypeETH, govsig.EthRuleV2RSV, govsig.Where{Partition: "bvn2", Block: act + 1}); err != nil {
		t.Errorf("v2 rule after the activation: %v", err)
	}
	if err := govsig.CheckExecutorGate(protocol.SignatureTypeETH, govsig.EthRuleV1DER, govsig.Where{Partition: "bvn2", Block: act - 1}); err != nil {
		t.Errorf("the DER form before the activation is not gated: %v", err)
	}
	err := govsig.CheckExecutorGate(protocol.SignatureTypeETH, govsig.EthRuleV1DER, govsig.Where{Partition: "bvn2", Block: act + 1})
	if !errors.As(err, new(govsig.ExecutorGateNotMet)) {
		t.Errorf("the DER form after a proven v2-baikonur+ executor cannot have been recorded, got %v", err)
	}
}

// End to end through Verify: a real ecdsa signature before the activation is the named state; after, it verifies.
func TestVerifyAppliesTheGate(t *testing.T) {
	for _, ty := range []protocol.SignatureType{protocol.SignatureTypeRsaSha256, protocol.SignatureTypeEcdsaSha256, protocol.SignatureTypeTypedData} {
		k, err := sigfixture.NewKey(ty, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		txn := sigfixture.Txn("acc://probe.acme/data", "gate")
		sig, err := sigfixture.Sign(k, txn, sigfixture.Opts{})
		if err != nil {
			t.Fatal(err)
		}
		act := govsig.KermitActivations()["bvn3"].Block
		e := env(txn)
		e.Where = govsig.Where{Partition: "bvn3", Block: act - 1}
		_, err = govsig.Verify(sig, e)
		var un govsig.ExecutorVersionUnproven
		if !errors.As(err, &un) || un.Block != act-1 || un.Partition != "bvn3" || un.Type != ty.String() {
			t.Errorf("%v before the activation: %v", ty, err)
		}
		e.Where = govsig.Where{Partition: "bvn3", Block: act + 1}
		if _, err := govsig.Verify(sig, e); err != nil {
			t.Errorf("%v after the activation: %v", ty, err)
		}
		e.Where = govsig.Where{}
		if _, err := govsig.Verify(sig, e); !errors.As(err, new(govsig.ExecutorVersionUnproven)) {
			t.Errorf("%v with no location: %v", ty, err)
		}
		// an invalid signature is invalid wherever it is; the gate never turns a rejection into an unproven state
		other := sigfixture.Txn("acc://probe.acme/data", "other")
		eo := env(other)
		eo.Where = govsig.Where{Partition: "bvn3", Block: act - 1}
		if _, err := govsig.Verify(sig, eo); !errors.As(err, new(govsig.SignatureInvalid)) {
			t.Errorf("%v: a wrong-transaction signature must be invalid even before the activation, got %v", ty, err)
		}
		_ = fmt.Sprint(ty)
	}
}
