// Copyright 2026 Certen Protocol

package basefinal

import (
	"math"
	"testing"
)

// RB12 EPSILON stage 2 (EPS-MUTKILL-1): ImplRow.Complete decides whether a game_impl row is usable, and a row that is not complete is
// treated as absent. Each condition of the layout half is judged alone: an unknown CWIA layout, a negative base or per-root length, a
// zero per-root length, the exact overflow edge of base + per_root * n, and the length equation itself.

func mkCompleteRow(cwia string, n, argsLen int) ImplRow {
	return ImplRow{
		Role:          RoleGameImpl,
		GameType:      1,
		Version:       "0.3.0",
		Impl:          [20]byte{1},
		CWIA:          cwia,
		NIntermediate: n,
		ArgsLen:       argsLen,
		IntervalPairs: [][2]uint64{{64, 16}},
		SlowDelay:     1,
		FastDelay:     1,
		ASR:           [20]byte{2},
	}
}

func TestImplRowCompleteJudgesTheCWIALayoutHalfOneConditionAtATime(t *testing.T) {
	maxInt := math.MaxInt // a variable: base + per_root * n is computed below the way Complete computes it, wrapping
	wrap := func(base, per, n int) int { return base + per*n }
	for _, c := range []struct {
		name   string
		layout *GameLayout // nil: the row names a layout that is not pinned
		n      int
		args   int
		want   bool
	}{
		{"the layout is not pinned (and a zero length equation would hold)", nil, 3, 0, false},
		{"the usual layout: 0x88 + 0x20 * n", &GameLayout{ArgsBaseLen: 0x88, ArgsPerRoot: 0x20}, 3, 0x88 + 0x20*3, true},
		{"the length is one more than the equation", &GameLayout{ArgsBaseLen: 0x88, ArgsPerRoot: 0x20}, 3, 0x88 + 0x20*3 + 1, false},
		{"the length is one less than the equation", &GameLayout{ArgsBaseLen: 0x88, ArgsPerRoot: 0x20}, 3, 0x88 + 0x20*3 - 1, false},
		{"a zero base length is a layout", &GameLayout{ArgsBaseLen: 0, ArgsPerRoot: 32}, 3, 96, true},
		{"a zero per-root length is a layout", &GameLayout{ArgsBaseLen: 50, ArgsPerRoot: 0}, 3, 50, true},
		{"a negative base length is no layout", &GameLayout{ArgsBaseLen: -1, ArgsPerRoot: 1}, 2, 1, false},
		{"a very negative base length is no layout", &GameLayout{ArgsBaseLen: -100, ArgsPerRoot: 100}, 2, 100, false},
		{"a negative per-root length is no layout", &GameLayout{ArgsBaseLen: 100, ArgsPerRoot: -1}, 2, 98, false},
		{"a very negative per-root length is no layout", &GameLayout{ArgsBaseLen: 1000, ArgsPerRoot: -100}, 2, 800, false},
		{"both lengths negative", &GameLayout{ArgsBaseLen: -4, ArgsPerRoot: -4}, 2, -12, false},
		{"base + per_root * n at the largest int is a layout", &GameLayout{ArgsBaseLen: 0, ArgsPerRoot: 1}, maxInt, maxInt, true},
		{"one past the largest int wraps and is no layout (per_root 1)", &GameLayout{ArgsBaseLen: 5, ArgsPerRoot: 1}, maxInt, wrap(5, 1, maxInt), false},
		{"one past the largest int wraps and is no layout (per_root 32)", &GameLayout{ArgsBaseLen: 0x88, ArgsPerRoot: 0x20}, maxInt/32 + 1, wrap(0x88, 0x20, maxInt/32+1), false},
		{"the last count that fits (per_root 32)", &GameLayout{ArgsBaseLen: 0x88, ArgsPerRoot: 0x20}, (maxInt - 0x88) / 0x20, 0x88 + 0x20*((maxInt-0x88)/0x20), true},
	} {
		layouts := map[string]GameLayout{}
		if c.layout != nil {
			layouts["cwia-1"] = *c.layout
		}
		row := mkCompleteRow("cwia-1", c.n, c.args)
		if got := row.Complete(layouts); got != c.want {
			t.Errorf("%s: Complete = %v, want %v", c.name, got, c.want)
		}
	}
	// A row whose other parts are complete is complete with a usable layout; and one that is not a game_impl row never is.
	ok := map[string]GameLayout{"cwia-1": {ArgsBaseLen: 0x88, ArgsPerRoot: 0x20}}
	if row := mkCompleteRow("cwia-1", 3, 0x88+0x20*3); !row.Complete(ok) {
		t.Fatal("the reference row is not complete")
	}
	notImpl := mkCompleteRow("cwia-1", 3, 0x88+0x20*3)
	notImpl.Role = "asr_impl"
	if notImpl.Complete(ok) {
		t.Error("a row of another role was complete")
	}
}
