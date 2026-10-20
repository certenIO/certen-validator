// Copyright 2026 Certen Protocol

package finality

// The (chain, level, kind) table of V2_SPEC_S7 section 1 as code. A chain id that is not a row has no S7 statement at all
// (finality_chain_unsupported, R5); a level a chain does not offer is level_not_applicable with the chain's published
// reason (never taken from a file); level 1 (included) is derived and has no kind.

// KindRow is one row of the table: the evidence kind that proves a stored level on a chain.
type KindRow struct {
	Chain uint64
	Level Level
	Kind  string
}

// The reasons of the two not-applicable cells, verbatim from section 1.
const (
	ReasonChainIsL1     NotApplicableReason = "this chain is the L1"
	ReasonNoL1Settlment NotApplicableReason = "no L1 settlement exists"
)

var kindTable = []KindRow{
	{ChainSepolia, LevelFinalized, "eth-sepolia/finalized/v1"},
	{ChainBaseSepolia, LevelL1Posted, "base-sepolia/l1_posted/v1"},
	{ChainBaseSepolia, LevelFinalized, "base-sepolia/finalized/v1"},
	{ChainArbitrumSepolia, LevelL1Posted, "arb-sepolia/l1_posted/v1"},
	{ChainArbitrumSepolia, LevelFinalized, "arb-sepolia/finalized/v1"},
	{ChainAdiri, LevelFinalized, "adiri/finalized/v1"},
}

// notApplicable are the cells of the table that are not kinds.
var notApplicableTable = map[uint64]map[Level]NotApplicableReason{
	ChainSepolia: {LevelL1Posted: ReasonChainIsL1},
	ChainAdiri:   {LevelL1Posted: ReasonNoL1Settlment},
}

// KindRows returns a copy of the table.
func KindRows() []KindRow { return append([]KindRow(nil), kindTable...) }

// ChainSupported reports whether chain is a row of the table.
func ChainSupported(chain uint64) bool {
	for _, r := range kindTable {
		if r.Chain == chain {
			return true
		}
	}
	return false
}

// IsRow reports whether (chain, level, kind) is a row of the table.
func IsRow(chain uint64, level Level, kind string) bool {
	for _, r := range kindTable {
		if r.Chain == chain && r.Level == level && r.Kind == kind {
			return true
		}
	}
	return false
}

// KindFor answers what the table says about a stored level on a chain: its kind, or the named state that explains why there
// is none: finality_chain_unsupported{chain} for a chain that is not a row, level_not_applicable{chain, level, reason} for a
// level the chain does not have (l1_posted on Sepolia and Adiri). Level 1 (included) is derived and has no kind.
func KindFor(chain uint64, level Level) (string, error) {
	if !ChainSupported(chain) {
		return "", ChainUnsupported(chain)
	}
	if !level.Stored() {
		return "", Malformed("level", ReasonLevelNotStored, int(level), 2)
	}
	for _, r := range kindTable {
		if r.Chain == chain && r.Level == level {
			return r.Kind, nil
		}
	}
	return "", NotApplicableState(chain, level, notApplicableTable[chain][level])
}

// LevelAvailability reports, for every level 1..3 of a supported chain, whether it is derived (1), a kind (2, 3) or not
// applicable, so a report can name each level without reading the file.
func LevelAvailability(chain uint64) (map[Level]string, error) {
	if !ChainSupported(chain) {
		return nil, ChainUnsupported(chain)
	}
	out := map[Level]string{LevelIncluded: ""}
	for _, l := range []Level{LevelL1Posted, LevelFinalized} {
		k, err := KindFor(chain, l)
		if err != nil {
			out[l] = ""
			continue
		}
		out[l] = k
	}
	return out, nil
}
