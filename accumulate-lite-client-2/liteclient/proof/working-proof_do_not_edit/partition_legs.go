// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"fmt"
	"sort"
	"strings"
)

// Governance can span partitions, so a proof needs a leg per signer partition.
//
// PHASE7_DELEGATION_PLAN section 2: DelegatedSignature.RoutingLocation() returns
// the INNERMOST signer's location and Accumulate routes by account URL, so a
// delegated signer - or a second key book in a multi-sig - may live on a
// different BVN than the principal. Corpus case F is exactly that: the principal
// on BVN1, the delegated signer on BVN2. One BVN leg cannot cover it.
//
// WHY THIS IS "PRIMARY PLUS ADDITIONAL" AND NOT A LIST.
//
// The obvious shape is Layer1 []Layer1 / Layer2 []Layer2 / Layer4BVN []*Layer4.
// It is the wrong one here, for two reasons that both have evidence behind them:
//
//   - PHASE7_RUNBOOK.md Gate 4 requires that a single-partition proof build
//     "byte-identical to the Phase 0 baseline". A list marshals as
//     "layer1":[{...}] where every existing proof has "layer1":{...}. Those are
//     not the same bytes, so the list shape fails the gate by construction.
//
//   - Every stored proof holds layer1/layer2/layer3 as singular objects in
//     per-layer rows (pkg/proof/chained_proof_storage.go), and the testdata
//     fixtures are the same document. Changing the shape would make all of them
//     unreadable, which would silently retire the offline verification that
//     Phase 6 had just established for them.
//
// So the principal's partition stays exactly where it is, and further
// partitions travel in AdditionalLegs, which is omitempty and therefore absent -
// not empty - on a single-partition proof. Code reads Legs(), which presents
// both as one canonically ordered list; nothing downstream needs to know which
// leg happened to be written first.

// PartitionLeg is one signer partition's evidence: the signature's inclusion on
// that partition's chain, that partition's anchor into the DN, and the
// validator quorum over it.
//
// L3 and L4-DN are deliberately absent. There is one Directory, so those are
// single however many partitions signed.
type PartitionLeg struct {
	// Partition is the partition ID this leg is for, e.g. "BVN2". It is stated
	// rather than derived because the leg is meaningless without knowing which
	// partition's validators signed it, and a reader must not have to infer that
	// from the signing set.
	Partition string `json:"partition"`

	// Account is the signer account whose inclusion this leg proves. Recorded so
	// a reader can tell WHY this partition is in the proof at all - under
	// delegation the answer is not obvious from the principal.
	Account string `json:"account"`

	Layer1    Layer1  `json:"layer1"`
	Layer2    Layer2  `json:"layer2"`
	Layer4BVN *Layer4 `json:"layer4Bvn,omitempty"`
}

// Legs returns every partition leg, the principal's first-written one included,
// in CANONICAL ORDER: sorted by partition ID.
//
// The ordering is load-bearing, not cosmetic. It is the same reason
// summarizeL4Leg sorts its signers: two validators reading identical chain data
// must produce identical bytes, or govRoot differs between them and TX2 reverts
// intermittently and unreproducibly - close to the worst failure mode available
// here. Partition discovery order depends on which signature was resolved first,
// which is not stable.
func (p *ChainedProof) Legs() []PartitionLeg {
	if p == nil {
		return nil
	}
	out := make([]PartitionLeg, 0, 1+len(p.AdditionalLegs))
	out = append(out, PartitionLeg{
		Partition: p.principalPartition(),
		Account:   p.Input.Account,
		Layer1:    p.Layer1,
		Layer2:    p.Layer2,
		Layer4BVN: p.Layer4BVN,
	})
	out = append(out, p.AdditionalLegs...)

	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(out[i].Partition) < strings.ToLower(out[j].Partition)
	})
	return out
}

// principalPartition is the partition the first-written leg belongs to.
//
// It prefers the L4 leg's own Partition, which is what the validators who signed
// it call themselves, over Input.BVN, which is what the caller asked for. When
// they disagree the signed value is the true one - and Verify rejects the
// disagreement rather than letting this quietly pick a side.
func (p *ChainedProof) principalPartition() string {
	if p.Layer4BVN != nil && p.Layer4BVN.Partition != "" {
		return p.Layer4BVN.Partition
	}
	return p.Input.BVN
}

// SignerPartitions lists the distinct partitions this proof carries a leg for,
// in canonical order.
func (p *ChainedProof) SignerPartitions() []string {
	legs := p.Legs()
	out := make([]string, 0, len(legs))
	for _, l := range legs {
		out = append(out, l.Partition)
	}
	return out
}

// AddLeg records an additional signer partition.
//
// It refuses a duplicate partition rather than appending one. Two legs for one
// partition would be counted twice by anything iterating Legs(), and the second
// would silently shadow or contradict the first - and since a leg carries a
// validator quorum, two disagreeing legs for one partition is precisely the
// situation a proof must not paper over.
func (p *ChainedProof) AddLeg(leg PartitionLeg) error {
	if leg.Partition == "" {
		return fmt.Errorf("partition leg: missing partition ID; a leg whose partition is " +
			"unknown cannot be checked against the quorum that signed it")
	}
	if leg.Layer4BVN == nil {
		return fmt.Errorf("partition leg %s: missing L4 leg; a partition leg without a signed "+
			"anchor is not proof-grade", leg.Partition)
	}
	for _, existing := range p.Legs() {
		if strings.EqualFold(existing.Partition, leg.Partition) {
			return fmt.Errorf("partition leg %s: already present; a proof carries at most one "+
				"leg per partition", leg.Partition)
		}
	}
	p.AdditionalLegs = append(p.AdditionalLegs, leg)

	// Kept sorted on the way in as well as on the way out, so the STORED bytes
	// are canonical too. Sorting only in Legs() would leave two validators
	// producing different JSON for the same proof.
	sort.SliceStable(p.AdditionalLegs, func(i, j int) bool {
		return strings.ToLower(p.AdditionalLegs[i].Partition) <
			strings.ToLower(p.AdditionalLegs[j].Partition)
	})
	return nil
}

// verifyLegBinding checks that one partition leg's L4 binds the L1/L2 beneath
// it. Extracted so every leg gets the identical treatment - the principal's leg
// included, rather than the principal's being checked by one code path and the
// rest by another.
func verifyLegBinding(leg PartitionLeg) error {
	if leg.Layer4BVN == nil {
		return fmt.Errorf("L4 leg missing for partition %s: a proof without a signed anchor "+
			"for a partition that signed it is not proof-grade", leg.Partition)
	}
	if err := leg.Layer4BVN.VerifyOffline(); err != nil {
		return fmt.Errorf("L4 leg for %s invalid: %w", leg.Partition, err)
	}
	if strings.EqualFold(leg.Layer4BVN.Partition, "Directory") {
		return fmt.Errorf("L4 leg for %s is signed by Directory, expected a block validator partition",
			leg.Partition)
	}
	if !strings.EqualFold(leg.Layer4BVN.Partition, leg.Partition) {
		return fmt.Errorf("L4 leg claims partition %s but the leg is recorded as %s - the "+
			"signing set and the leg disagree about which partition this is",
			leg.Layer4BVN.Partition, leg.Partition)
	}
	if !strings.EqualFold(leg.Layer4BVN.StateTreeAnchor, leg.Layer2.BVNStateTreeAnchor) {
		return fmt.Errorf("L4 bind failed for %s: layer4Bvn.stateTreeAnchor=%s != layer2.bvnStateTreeAnchor=%s",
			leg.Partition, leg.Layer4BVN.StateTreeAnchor, leg.Layer2.BVNStateTreeAnchor)
	}
	if !strings.EqualFold(leg.Layer4BVN.RootChainAnchor, leg.Layer1.BVNRootChainAnchor) {
		return fmt.Errorf("L4 bind failed for %s: layer4Bvn.rootChainAnchor=%s != layer1.bvnRootChainAnchor=%s",
			leg.Partition, leg.Layer4BVN.RootChainAnchor, leg.Layer1.BVNRootChainAnchor)
	}
	if leg.Layer4BVN.MinorBlockIndex != leg.Layer1.BVNMinorBlockIndex {
		return fmt.Errorf("L4 bind failed for %s: layer4Bvn.minorBlockIndex=%d != layer1.bvnMinorBlockIndex=%d",
			leg.Partition, leg.Layer4BVN.MinorBlockIndex, leg.Layer1.BVNMinorBlockIndex)
	}
	return nil
}

// PrincipalLegForSummary returns the leg the govRoot summary treats as the
// principal's.
//
// It is exported for the govRoot builder, which must single out one leg because
// that is where the v1 payload shape kept it. Which leg is principal is a
// property of the proof - its own Input.BVN, or the one leg it has - and never
// of the order the legs were discovered in, so two validators reading the same
// proof pick the same one.
func (p *ChainedProof) PrincipalLegForSummary() *PartitionLeg {
	if p == nil {
		return nil
	}
	legs := p.Legs()
	if len(legs) == 0 {
		return nil
	}
	want := p.principalPartition()
	for i := range legs {
		if strings.EqualFold(legs[i].Partition, want) {
			return &legs[i]
		}
	}
	// No leg matches the proof's own partition. That is a disagreement between
	// the proof and its evidence, and picking one anyway would hide it.
	return nil
}
