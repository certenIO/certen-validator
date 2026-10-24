// Copyright 2026 Certen Protocol

package baseposted

import "github.com/certen/independant-validator/pkg/finality"

// PrefixWindowState is where one requested window stands.
type PrefixWindowState string

const (
	PrefixWindowComplete          PrefixWindowState = "complete"           // every block is filled
	PrefixWindowOpen              PrefixWindowState = "open"               // blocks are still to be captured and none is proven unavailable
	PrefixWindowUnavailableProven PrefixWindowState = "unavailable_proven" // a block's blobs are proven gone: the leg needs a blob archive
	PrefixWindowRetentionExpired  PrefixWindowState = "retention_expired"  // a block's blobs are past retention and gone: likewise
)

// PrefixWindowStates counts the requested windows by state, from the unfilled pieces of the gap scan. A window with a block proven
// unavailable is that state whatever else is open in it (it cannot complete from these providers), proven unavailability outranking an
// expiry.
func PrefixWindowStates(wins []finality.PrefixWindow, pieces []finality.GapRange) map[PrefixWindowState]int {
	out := map[PrefixWindowState]int{PrefixWindowComplete: 0, PrefixWindowOpen: 0, PrefixWindowUnavailableProven: 0, PrefixWindowRetentionExpired: 0}
	for _, w := range wins {
		st := PrefixWindowComplete
		for _, p := range pieces {
			if p.From > w.To || p.To < w.From {
				continue
			}
			switch p.State {
			case finality.GapUnavailableProven:
				st = PrefixWindowUnavailableProven
			case finality.GapRetentionExpired:
				if st != PrefixWindowUnavailableProven {
					st = PrefixWindowRetentionExpired
				}
			case finality.GapOpen:
				if st == PrefixWindowComplete {
					st = PrefixWindowOpen
				}
			}
		}
		out[st]++
	}
	return out
}
