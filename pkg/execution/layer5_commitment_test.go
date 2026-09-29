package execution

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

func h32(b [32]byte) string { return "0x" + hex.EncodeToString(b[:]) }

// v82Commitment is a self-consistent V8.2 commitment over root: what the anchor derived and the quorum signed.
func v82Commitment(chainID int64, root [32]byte) *AnchorCommitment {
	opID, setRoot := [32]byte{0x0b}, [32]byte{0x5e}
	bundle := contracts.DeriveV8_2BatchBundleID(chainID, root, 3, opID, 42, testAccSet, testIncarnation)
	msg := contracts.ComputeEvmMessageHashV8_2_Pre(chainID, bundle, root, opID, setRoot, testAccSet, testIncarnation)
	return &AnchorCommitment{Version: "v8_2", BundleID: h32(bundle), LeafCount: 3, BatchOperationID: h32(opID),
		AccumulateBlockHeight: 42, CertenSetRoot: h32(setRoot), MessageHash: h32(msg),
		AccumulateSetRoot: h32(testAccSet), Incarnation: h32(testIncarnation)}
}

func v81Commitment(chainID int64, root [32]byte) *AnchorCommitment {
	opID, setRoot := [32]byte{0x0b}, [32]byte{0x5e}
	bundle := contracts.DeriveV8_1BatchBundleID(chainID, root, 3, opID, 42)
	msg := contracts.ComputeEvmMessageHashV6_1_Pre(chainID, bundle, root, opID, setRoot)
	return &AnchorCommitment{Version: "v8_1", BundleID: h32(bundle), LeafCount: 3, BatchOperationID: h32(opID),
		AccumulateBlockHeight: 42, CertenSetRoot: h32(setRoot), MessageHash: h32(msg)}
}

func TestAnchorCommitment_ReDerivesBothGenerations(t *testing.T) {
	root := [32]byte{0x0e}
	if err := v82Commitment(84532, root).Verify(84532, h32(root)); err != nil {
		t.Fatalf("v8.2: %v", err)
	}
	if err := v81Commitment(84532, root).Verify(84532, h32(root)); err != nil {
		t.Fatalf("v8.1: %v", err)
	}
	other := [32]byte{0x99}
	for name, mut := range map[string]func(c *AnchorCommitment){
		"leaf count":         func(c *AnchorCommitment) { c.LeafCount = 4 },
		"height":             func(c *AnchorCommitment) { c.AccumulateBlockHeight++ },
		"batch op id":        func(c *AnchorCommitment) { c.BatchOperationID = h32(other) },
		"Accumulate set":     func(c *AnchorCommitment) { c.AccumulateSetRoot = h32(other) },
		"incarnation":        func(c *AnchorCommitment) { c.Incarnation = h32(other) },
		"CERTEN set":         func(c *AnchorCommitment) { c.CertenSetRoot = h32(other) },
		"message":            func(c *AnchorCommitment) { c.MessageHash = h32(other) },
		"bundle":             func(c *AnchorCommitment) { c.BundleID = h32(other) },
		"zero members":       func(c *AnchorCommitment) { c.LeafCount = 0 },
		"no set":             func(c *AnchorCommitment) { c.AccumulateSetRoot = "" },
		"zero incarnation":   func(c *AnchorCommitment) { c.Incarnation = h32([32]byte{}) },
		"unknown generation": func(c *AnchorCommitment) { c.Version = "v9" },
		"claimed as v8.1":    func(c *AnchorCommitment) { c.Version = "v8_1" },
	} {
		c := v82Commitment(84532, root)
		mut(c)
		if err := c.Verify(84532, h32(root)); err == nil {
			t.Errorf("v8.2 %s: accepted", name)
		}
	}
	if err := v82Commitment(84532, root).Verify(11155111, h32(root)); err == nil {
		t.Error("a commitment re-derived on another chain")
	}
	if err := v82Commitment(84532, root).Verify(84532, h32(other)); err == nil {
		t.Error("a commitment re-derived under another root")
	}
	c := v81Commitment(84532, root)
	c.AccumulateSetRoot = h32(testAccSet)
	if err := c.Verify(84532, h32(root)); err == nil {
		t.Error("a V8.1 commitment claiming an Accumulate set was accepted")
	}
}

// The committed set is checked against the proof's OWN Directory leg - the real Kermit fixture's - under the anchor's
// incarnation, and the incarnation against the verifier's pin. Named states for what is not established; an error only
// for what is proven wrong.
func TestCheckAccumulateCommitment_States(t *testing.T) {
	dn := kermitCertenProof().LiteClientProof.CompleteProof.Layer4DN
	root := [32]byte{0x0e}
	l5 := &Layer5{ChainID: 84532, BatchRoot: h32(root), Commitment: v82Commitment(84532, root)}
	pin := testIncarnation

	if st, err := CheckAccumulateCommitment(l5, dn, &pin); err != nil || st != AccumulateSetCommittedVerified {
		t.Fatalf("pinned: %s %v", st, err)
	}
	if st, err := CheckAccumulateCommitment(l5, dn, nil); err != nil || st != AccumulateSetCommittedUnpinned {
		t.Fatalf("unpinned: %s %v", st, err)
	}
	foreign := pin
	foreign[0] ^= 1
	if _, err := CheckAccumulateCommitment(l5, dn, &foreign); !errors.Is(err, ErrAccumulateSetNotCommitted) {
		t.Fatalf("a proof about another Accumulate chain was accepted under the pin: %v", err)
	}
	// The anchor committed a set other than the one this proof's L4 used.
	wrong := *l5
	wc := *l5.Commitment
	other := testAccSet
	other[3] ^= 1
	wc.AccumulateSetRoot = h32(other)
	wrong.Commitment = &wc
	if _, err := CheckAccumulateCommitment(&wrong, dn, &pin); !errors.Is(err, ErrAccumulateSetNotCommitted) {
		t.Fatalf("a proof whose L4 used an uncommitted set was accepted: %v", err)
	}
	// A proof whose L4 carries a different set than the one committed (one validator substituted).
	sub := *dn
	sub.ValidatorSet = append(sub.ValidatorSet[:0:0], dn.ValidatorSet...)
	sub.ValidatorSet[0].PublicKey = "aa" + sub.ValidatorSet[0].PublicKey[2:]
	if _, err := CheckAccumulateCommitment(l5, &sub, &pin); !errors.Is(err, ErrAccumulateSetNotCommitted) {
		t.Fatalf("a substituted validator set was accepted: %v", err)
	}
	if st, err := CheckAccumulateCommitment(&Layer5{Commitment: v81Commitment(84532, root)}, dn, &pin); err != nil || st != AccumulateSetNotCommittedV8_1 {
		t.Fatalf("v8.1: %s %v", st, err)
	}
	if st, err := CheckAccumulateCommitment(&Layer5{}, dn, &pin); err != nil || st != AccumulateCommitmentNotRecorded {
		t.Fatalf("not recorded: %s %v", st, err)
	}
	if st, err := CheckAccumulateCommitment(nil, dn, &pin); err != nil || st != AccumulateCommitmentNotRecorded {
		t.Fatalf("no layer 5: %s %v", st, err)
	}
}

// The governance half and the anchor must name one batch operation id.
func TestLayer5_CommitmentAndGovernanceNameOneBatch(t *testing.T) {
	root := [32]byte{0x0e}
	l5 := &Layer5{ChainID: 84532, AnchorTx: "0x" + hex.EncodeToString(make([]byte, 31)) + "01", BlockNumber: 7,
		BatchRoot: h32(root)[2:], LeafHash: h32(root)[2:], Commitment: v82Commitment(84532, root)}
	if err := l5.Commitment.Verify(l5.ChainID, l5.BatchRoot); err != nil {
		t.Fatal(err)
	}
	l5.Governance = &BatchGovernance{Version: "v2", BatchOperationID: h32([32]byte{0xcc})}
	if err := l5.VerifyOffline(); err == nil {
		t.Fatal("a layer 5 whose governance and anchor name different batch operation ids verified")
	}
}
