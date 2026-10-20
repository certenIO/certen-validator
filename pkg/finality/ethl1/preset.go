// Copyright 2026 Certen Protocol

package ethl1

// preset holds the consensus-specs preset constants the light-client objects and the period arithmetic depend on. The exported
// verifier always runs with mainnetPreset (the Sepolia values the spec pins); the official sync-protocol vectors of the
// consensus-specs release exist only for the minimal preset and drive the same code with a minimal preset from test code. Every
// function of the walker, the decoders and the committee code takes its sizes from the preset, never from a package constant.
type preset struct {
	slotsPerEpoch   uint64
	epochsPerPeriod uint64
	committeeSize   int
}

func mainnetPreset() preset {
	return preset{slotsPerEpoch: SlotsPerEpoch, epochsPerPeriod: EpochsPerPeriod, committeeSize: SyncCommitteeSize}
}

func (p preset) epochOf(slot uint64) uint64  { return slot / p.slotsPerEpoch }
func (p preset) periodOf(slot uint64) uint64 { return p.epochOf(slot) / p.epochsPerPeriod }

// committeeBytes is the SSZ size of a SyncCommittee: committeeSize pubkeys and the aggregate pubkey.
func (p preset) committeeBytes() int { return p.committeeSize*48 + 48 }

// aggregateBytes is the SSZ size of a SyncAggregate: the participation bits and the 96-byte signature.
func (p preset) aggregateBytes() int { return p.committeeSize/8 + 96 }

// floor is the smallest participant count n with 3n >= 2*committeeSize.
func (p preset) floor() int { return (2*p.committeeSize + 2) / 3 }

// Fixed sizes of the Gloas layout objects under this preset.
func (p preset) gloasBootstrapSize() int {
	return LightClientHeaderSize + p.committeeBytes() + 32*gloasCommitteeBranchLen
}
func (p preset) gloasUpdateSize() int {
	return LightClientHeaderSize + p.committeeBytes() + 32*gloasCommitteeBranchLen + LightClientHeaderSize + 32*gloasFinalityBranchLen + p.aggregateBytes() + 8
}
func (p preset) gloasFinalityUpdateSize() int {
	return 2*LightClientHeaderSize + 32*gloasFinalityBranchLen + p.aggregateBytes() + 8
}

// Fixed parts and minimum sizes of the electra layout objects under this preset (spec 3.2 e for the mainnet values).
func (p preset) electraBootstrapFixedSize() int {
	return 4 + p.committeeBytes() + 32*electraCommitteeBranchLen
}
func (p preset) electraUpdateFixedSize() int {
	return 4 + p.committeeBytes() + 32*electraCommitteeBranchLen + 4 + 32*electraFinalityBranchLen + p.aggregateBytes() + 8
}
func (p preset) electraFinalityUpdateFixedSize() int {
	return 4 + 4 + 32*electraFinalityBranchLen + p.aggregateBytes() + 8
}
