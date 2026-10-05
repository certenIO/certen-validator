// Copyright 2026 Certen Protocol
//
// The validator-set spine in CERTEN's consensus state (docs/proof/GOVROOT_V3.md "consensus-held spine"). These are pure,
// deterministic functions of their inputs: FinalizeBlock calls them with the committed spine log and a transaction's
// records, so every validator decides every spine transaction identically with no I/O.

package proofv2

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/network"
)

// SpineSetHash identifies a validator set: sha256(sha256(networkRecord) || sha256(globalsRecord)), hex.
func SpineSetHash(networkRecord, globalsRecord []byte) string {
	n, g := sha256.Sum256(networkRecord), sha256.Sum256(globalsRecord)
	h := sha256.Sum256(append(n[:], g[:]...))
	return hex.EncodeToString(h[:])
}

// AcceptSpineGenesis verifies a spine genesis against the Accumulate incarnation CERTEN's BLS registry is in force
// for: the inputs must recompute exactly that incarnation, which binds the genesis validator set to it.
func AcceptSpineGenesis(in proof.IncarnationInputs, registryIncarnation [32]byte, height int64) (*ledger.AccumulateSpineGenesis, ledger.AccumulateSpineSet, error) {
	id, err := proof.ComputeIncarnation(in)
	if err != nil {
		return nil, ledger.AccumulateSpineSet{}, err
	}
	if id != registryIncarnation {
		return nil, ledger.AccumulateSpineSet{}, fmt.Errorf("the genesis is incarnation %x, not the registry's %x", id, registryIncarnation)
	}
	if _, err := genesisValues(in.NetworkRecord, in.GlobalsRecord); err != nil {
		return nil, ledger.AccumulateSpineSet{}, err
	}
	set := ledger.AccumulateSpineSet{Hash: SpineSetHash(in.NetworkRecord, in.GlobalsRecord),
		NetworkRecord: hex.EncodeToString(in.NetworkRecord), GlobalsRecord: hex.EncodeToString(in.GlobalsRecord)}
	return &ledger.AccumulateSpineGenesis{Incarnation: "0x" + hex.EncodeToString(id[:]), Height: height,
		MinorBlockIndex: in.GenesisMinorBlockIndex, RootChainAnchor: hex.EncodeToString(in.GenesisRootChainAnchor[:]),
		StateTreeAnchor: hex.EncodeToString(in.GenesisStateTreeAnchor[:]), TimeUnix: in.GenesisTimeUnix, SetHash: set.Hash}, set, nil
}

// SpineAt rebuilds the spine as the chain verified it after major block n (n = 0: at genesis, before major block 1).
func SpineAt(l *ledger.AccumulateSpineLog, n uint64) (*Spine, error) {
	if l.Genesis == nil {
		return nil, fmt.Errorf("the chain has no Accumulate spine genesis")
	}
	if n == 0 {
		g, err := spineSet(l, l.Genesis.SetHash)
		if err != nil {
			return nil, err
		}
		return NewSpine(g, 1)
	}
	c, ok := l.Checkpoint(n)
	if !ok {
		return nil, fmt.Errorf("the chain has verified %d major blocks, not %d", len(l.Checkpoints), n)
	}
	g, err := spineSet(l, c.SetHash)
	if err != nil {
		return nil, err
	}
	var root, state [32]byte
	if err := hex32(c.RootChainAnchor, root[:]); err != nil {
		return nil, err
	}
	if err := hex32(c.StateTreeAnchor, state[:]); err != nil {
		return nil, err
	}
	return RestoreSpine(g, n+1, c.LastMinorBlock, root, state, c.NetworkUpdates)
}

// ExtendSpine verifies major records, the next ones in sequence after the chain's last checkpoint, and returns the
// checkpoints and any new validator sets to append. Any record that does not verify refuses the whole extension.
func ExtendSpine(l *ledger.AccumulateSpineLog, records []*api.MajorHeaderRecord, height int64) ([]ledger.AccumulateSpineCheckpoint, []ledger.AccumulateSpineSet, error) {
	if len(records) == 0 {
		return nil, nil, fmt.Errorf("an extension must carry at least one major block")
	}
	sp, err := SpineAt(l, uint64(len(l.Checkpoints)))
	if err != nil {
		return nil, nil, err
	}
	known := map[string]bool{}
	for _, s := range l.Sets {
		known[s.Hash] = true
	}
	var cps []ledger.AccumulateSpineCheckpoint
	var sets []ledger.AccumulateSpineSet
	for _, r := range records {
		if err := sp.Advance(r); err != nil {
			return nil, nil, fmt.Errorf("major block %d: %w", sp.NextMajor, err)
		}
		netRec, err := sp.Globals().Network.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		globRec, err := sp.Globals().Globals.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		h := SpineSetHash(netRec, globRec)
		if !known[h] {
			known[h] = true
			sets = append(sets, ledger.AccumulateSpineSet{Hash: h, NetworkRecord: hex.EncodeToString(netRec), GlobalsRecord: hex.EncodeToString(globRec)})
		}
		cps = append(cps, ledger.AccumulateSpineCheckpoint{Major: sp.NextMajor - 1, Height: height, LastMinorBlock: sp.LastMinorBlock,
			RootChainAnchor: hex.EncodeToString(sp.RootChainAnchor[:]), StateTreeAnchor: hex.EncodeToString(sp.StateTreeAnchor[:]),
			SetHash: h, NetworkUpdates: sp.NetworkUpdates()})
	}
	return cps, sets, nil
}

func spineSet(l *ledger.AccumulateSpineLog, h string) (*network.GlobalValues, error) {
	s, ok := l.SetByHash(h)
	if !ok {
		return nil, fmt.Errorf("the spine references validator set %s, which it does not hold", h)
	}
	nr, err := hex.DecodeString(s.NetworkRecord)
	if err != nil {
		return nil, err
	}
	gr, err := hex.DecodeString(s.GlobalsRecord)
	if err != nil {
		return nil, err
	}
	if SpineSetHash(nr, gr) != h {
		return nil, fmt.Errorf("the spine's validator set %s does not hash to its name", h)
	}
	return genesisValues(nr, gr)
}
