// Copyright 2026 Certen Protocol

package finality

import (
	"sort"
	"strings"

	"github.com/certen/independant-validator/pkg/metrics"
)

// CodePrefixDisabled is the named state of the capture-store PREFIX feature (the archive backfill: windows below the first scanned block)
// that a bad setting switched off on one chain (go_operational, class environment). The validator keeps running: the upgrader, every capture
// loop, every builder and the gap backfill of the live range are unchanged, and a leg that needs the prefix is named l1_capture_not_covering
// {prefix_state: off} as with an extension that was never switched on. The reason is the closed F14 name setting_invalid and refused says
// which way the number was refused; the value of the setting is never part of the state.
const CodePrefixDisabled = "finality_prefix_disabled"

// The ways a prefix number is refused (the closed names of finality_index_disabled).
const (
	PrefixRefusedNotInteger = IndexRefusedNotInteger // not an integer at all (text, a fraction, a hex or exponent form)
	PrefixRefusedOutOfRange = IndexRefusedOutOfRange // an integer below the setting's minimum or above its maximum, including one too large to read
)

// PrefixDisabledState builds finality_prefix_disabled for the setting variable on chain.
func PrefixDisabledState(chain uint64, variable, refused string) *StateError {
	return NewState(CodePrefixDisabled, "chain", chain, "variable", variable, "reason", DisabledSettingInvalid, "refused", refused)
}

// AnnouncePrefixDisabled logs every state, sets the gauge certen_finality_prefix_disabled for each and records, per chain, the joined
// states for /health/detailed (prefix_disabled_reason). It is called once per wiring and changes nothing else.
func AnnouncePrefixDisabled(logf func(format string, args ...any), states []*StateError) {
	byChain := map[uint64][]string{}
	for _, st := range states {
		chain, _ := st.Fields["chain"].(uint64)
		key, _ := st.Fields["variable"].(string)
		reason, _ := st.Fields["reason"].(string)
		logf("[FINALITY] prefix backfill DISABLED on chain %d, everything else in finality runs: %s", chain, st.Error())
		metrics.SetFinalityPrefixDisabled(chain, key, reason)
		byChain[chain] = append(byChain[chain], st.Error())
	}
	chains := make([]uint64, 0, len(byChain))
	for c := range byChain {
		chains = append(chains, c)
	}
	sort.Slice(chains, func(i, j int) bool { return chains[i] < chains[j] })
	for _, c := range chains {
		metrics.SetFinalityChainPrefixDisabledReason(c, strings.Join(byChain[c], "; "))
	}
}
