// Copyright 2026 Certen Protocol

package ethl1

import "sort"

// Protocol constants of the Ethereum beacon chain that the verifier is specified against (V2_SPEC_S7 sections 4.2, 5.2).
const (
	// ProfileLC is the only LC container profile.
	ProfileLC = "eth-lc/1"
	// SlotsPerEpoch and EpochsPerPeriod are the mainnet/Sepolia preset values.
	SlotsPerEpoch   = 32
	EpochsPerPeriod = 256
	// SyncCommitteeSize is the number of seats; MinParticipantsFloor is the smallest set-bit count with 3*n >= 2*512.
	SyncCommitteeSize    = 512
	MinParticipantsFloor = 342
	// SepoliaChainID is the execution chain id whose beacon chain the shipped pins describe.
	SepoliaChainID = 11155111
)

// Layout is the light-client container layout of a carried object (the LB layout byte of spec section 3.2).
type Layout uint8

const (
	// LayoutNone is the layout byte 0, valid only for the kind-1 SyncCommittee body.
	LayoutNone Layout = 0
	// LayoutElectra covers Electra and Fulu (variable-size headers with an ExecutionPayloadHeader); implemented by RB11-C1B.
	LayoutElectra Layout = 1
	// LayoutGloas is the fixed-size layout of Gloas (execution_block_hash plus an 11-node branch).
	LayoutGloas Layout = 2
)

// String is the layout name used in fault fields.
func (l Layout) String() string {
	switch l {
	case LayoutElectra:
		return "electra"
	case LayoutGloas:
		return "gloas"
	}
	return "none"
}

// Fork is one entry of the fork schedule. Layout is LayoutNone for the forks whose objects cannot occur in evidence.
type Fork struct {
	Name    string
	Epoch   uint64
	Version [4]byte
	Layout  Layout
}

// Network is the trusted network section of the pins.
type Network struct {
	ChainID               uint64
	GenesisValidatorsRoot [32]byte
	Forks                 []Fork
}

// Anchor is one ledger entry: a configured weak-subjectivity pin of one sync-committee period.
type Anchor struct {
	Period        uint64
	CommitteeRoot [32]byte
	BlockRoot     *[32]byte
	WSPEpochs     uint64
}

// Pins are the trust inputs of the L1 head verifier (the Sepolia part of spec section 4.2).
type Pins struct {
	Network         Network
	Anchors         []Anchor
	MinParticipants int
	MaxLinks        int
	MaxSpineHeaders int
}

// LB is one layout-tagged SSZ blob (spec section 3.2).
type LB struct {
	Layout Layout
	SSZ    []byte
}

// LC is the Ethereum L1-finality part of an evidence container (spec section 3.2).
type LC struct {
	Profile      string
	AnchorKind   uint8 // 1 committee_root, 2 block_root
	AnchorPeriod uint64
	AnchorRoot   [32]byte
	AnchorBody   LB
	Links        []LB
	FinalUpdate  LB
}

// FinalizedHead is the result of VerifyFinalizedHead. The execution number is not in a Gloas LC header; Covers finds it.
type FinalizedHead struct {
	Slot           uint64
	Epoch          uint64
	BeaconRoot     [32]byte
	ExecHash       [32]byte
	Participants   int
	PeriodsCrossed uint64
}

// L1Block is one header of a covered spine, read positionally from its raw RLP.
type L1Block struct {
	Hash      [32]byte
	Number    uint64
	StateRoot [32]byte
	Timestamp uint64
}

// forkAt returns the fork in force at epoch: the last entry with Epoch <= epoch. ok is false for an empty schedule.
func (n Network) forkAt(epoch uint64) (Fork, bool) {
	i := sort.Search(len(n.Forks), func(i int) bool { return n.Forks[i].Epoch > epoch })
	if i == 0 {
		return Fork{}, false
	}
	return n.Forks[i-1], true
}

// anchorFor returns the ledger entry of exactly this period.
func (p Pins) anchorFor(period uint64) (Anchor, bool) {
	for _, a := range p.Anchors {
		if a.Period == period {
			return a, true
		}
	}
	return Anchor{}, false
}

// ledgerHead is the largest period in the ledger (0 and false when empty).
func (p Pins) ledgerHead() (uint64, bool) {
	var head uint64
	for i, a := range p.Anchors {
		if i == 0 || a.Period > head {
			head = a.Period
		}
	}
	return head, len(p.Anchors) > 0
}
