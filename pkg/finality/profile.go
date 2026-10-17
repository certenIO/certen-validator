// Copyright 2026 Certen Protocol

package finality

import "fmt"

// ChainProfile fixes which levels a chain offers and, for each level it does not, why not. The not-applicable reasons are
// source facts from the RB11 research (R11-sepolia, R11-adiri), not assumptions; a chain whose only missing levels are
// not applicable is complete when it reaches its top level.
type ChainProfile struct {
	Chain uint64
	Name  string
	// Levels the chain offers, ascending. The last is the chain's top level and the worker's stopping point.
	Levels []Level
	// NotApplicable maps each level the chain does not offer to the published reason.
	NotApplicable map[Level]string
}

func (p ChainProfile) validate() error {
	if p.Chain == 0 || len(p.Levels) == 0 {
		return fmt.Errorf("finality: a profile needs a chain and at least one level")
	}
	prev := LevelNone
	for _, l := range p.Levels {
		if !l.Valid() || l <= prev {
			return fmt.Errorf("finality: chain %d levels must ascend and be real levels", p.Chain)
		}
		prev = l
	}
	for _, l := range Levels {
		_, na := p.NotApplicable[l]
		if p.Offers(l) == na {
			return fmt.Errorf("finality: chain %d level %s must be exactly one of offered or not applicable", p.Chain, l)
		}
	}
	return nil
}

// Offers reports whether the chain has the level.
func (p ChainProfile) Offers(l Level) bool {
	for _, o := range p.Levels {
		if o == l {
			return true
		}
	}
	return false
}

// Top is the chain's highest level.
func (p ChainProfile) Top() Level { return p.Levels[len(p.Levels)-1] }

// Next is the lowest offered level above l, or LevelNone when l is the top.
func (p ChainProfile) Next(l Level) Level {
	for _, o := range p.Levels {
		if o > l {
			return o
		}
	}
	return LevelNone
}

// NotApplicableFor returns the typed non-level for a level the chain does not offer.
func (p ChainProfile) NotApplicableFor(l Level) (*NotApplicable, bool) {
	reason, ok := p.NotApplicable[l]
	if !ok {
		return nil, false
	}
	return &NotApplicable{Chain: p.Chain, Level: l, Reason: reason}, true
}

// The four live chains (R11-sepolia, R11-base-sepolia, R11-arbitrum-sepolia, R11-adiri).
const (
	ChainSepolia         uint64 = 11155111
	ChainBaseSepolia     uint64 = 84532
	ChainArbitrumSepolia uint64 = 421614
	ChainAdiri           uint64 = 2017
)

// DefaultProfiles are the profiles of the four live chains.
func DefaultProfiles() []ChainProfile {
	return []ChainProfile{
		{
			Chain: ChainSepolia, Name: "ethereum-sepolia", Levels: []Level{LevelIncluded, LevelFinalized},
			NotApplicable: map[Level]string{LevelL1Posted: "Sepolia is the L1: its blocks are not posted to another chain"},
		},
		{
			Chain: ChainBaseSepolia, Name: "base-sepolia", Levels: []Level{LevelIncluded, LevelL1Posted, LevelFinalized},
			NotApplicable: map[Level]string{},
		},
		{
			Chain: ChainArbitrumSepolia, Name: "arbitrum-sepolia", Levels: []Level{LevelIncluded, LevelL1Posted, LevelFinalized},
			NotApplicable: map[Level]string{},
		},
		{
			Chain: ChainAdiri, Name: "telcoin-adiri", Levels: []Level{LevelIncluded, LevelFinalized},
			NotApplicable: map[Level]string{LevelL1Posted: "no L1 settlement exists for Telcoin Adiri (R11-adiri A6)"},
		},
	}
}
