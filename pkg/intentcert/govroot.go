// Package intentcert builds the per-intent commitment CERTEN's quorum certifies (RB5 owner decision D3): govRoot v2
// over the proof's L1-L4 and the canonical G0-G2, and, from it, the per-intent message every validator signs.
package intentcert

import (
	"encoding/json"
	"fmt"

	lcproof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/proof"
)

// GovRootV2Inputs are the per-intent facts govRoot v2 commits.
type GovRootV2Inputs struct {
	Lite        *lcproof.CompleteProof
	G0          *proof.G0Result
	G1          *proof.G1Result
	G2          *proof.G2Result
	KeyPageURL  string
	KeyBookURL  string
	OperationID [32]byte
}

// GovRootV2 returns govRoot v2 and its slots. Every input is required; nothing is left silently zero.
func GovRootV2(in GovRootV2Inputs) ([32]byte, contracts.AccumulateGovRootInputs, error) {
	var slots contracts.AccumulateGovRootInputs
	lc := in.Lite
	if lc == nil {
		return [32]byte{}, slots, fmt.Errorf("govRoot v2: no L1-L4 proof")
	}
	for _, l := range []struct {
		name string
		b    []byte
	}{{"L1 account hash", lc.AccountHash}, {"L2 BPT root", lc.BPTRoot}, {"L3 block hash", lc.BlockHash}} {
		if len(l.b) != 32 {
			return [32]byte{}, slots, fmt.Errorf("govRoot v2: the %s is %d bytes, not 32", l.name, len(l.b))
		}
	}
	copy(slots.L1AccountHash[:], lc.AccountHash)
	copy(slots.L2BPTRoot[:], lc.BPTRoot)
	copy(slots.L3BlockHash[:], lc.BlockHash)
	if lc.ConsensusProof == nil {
		return [32]byte{}, slots, fmt.Errorf("govRoot v2: no L4 consensus proof")
	}
	l4, err := json.Marshal(lc.ConsensusProof)
	if err != nil {
		return [32]byte{}, slots, fmt.Errorf("govRoot v2: L4: %w", err)
	}
	slots.L4ConsensusProofH = contracts.HashL4ConsensusProof(l4)

	g0, err := proof.CanonicalG0JSONV2(in.G0)
	if err != nil {
		return [32]byte{}, slots, err
	}
	g1, err := proof.CanonicalG1JSONV2(in.G1)
	if err != nil {
		return [32]byte{}, slots, err
	}
	g2, err := proof.CanonicalG2JSONV2(in.G2)
	if err != nil {
		return [32]byte{}, slots, err
	}
	for level, js := range [][]byte{g0, g1, g2} {
		h, err := contracts.GovernanceHashV2(level, js)
		if err != nil {
			return [32]byte{}, slots, err
		}
		switch level {
		case 0:
			slots.G0CanonicalHash = h
		case 1:
			slots.G1CanonicalHash = h
		case 2:
			slots.G2CanonicalHash = h
		}
	}
	slots.KeypageURLHash = contracts.HashURLString(in.KeyPageURL)
	slots.KeybookURLHash = contracts.HashURLString(in.KeyBookURL)
	slots.OperationID = in.OperationID
	root, err := contracts.ComputeAccumulateGovRootV2(slots)
	return root, slots, err
}
