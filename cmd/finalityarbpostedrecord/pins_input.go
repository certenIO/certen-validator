// Copyright 2026 Certen Protocol

package main

import _ "embed"

// mainPinsAtSets234 is pkg/finality/pins/finality-pins.json exactly as it was when finality_arb_posted2, 3 and 4 were published (commits
// a86b6001, bbe841c5, e5b7c5c0 carry the same 11665 bytes). The pins are an input of those sets, so build2, build3 and build4 read this
// committed file and never finality.EmbeddedPinsBytes(), which grows after a set is published: a published set must reproduce from its own
// committed inputs (RB12 OPS-A2 item 19; TestBuild4WritesTheCommittedSetByteForByte).
//
//go:embed testdata/main_pins_at_sets_2_3_4.json
var mainPinsAtSets234 []byte
