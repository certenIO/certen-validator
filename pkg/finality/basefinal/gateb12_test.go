// Copyright 2026 Certen Protocol

package basefinal

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// A game row needs at least one intermediate root, and the args length that goes with it.
func TestAGameRowNeedsAtLeastOneIntermediateRootWithTheMatchingArgsLength(t *testing.T) {
	p := loadPins(t)
	var row ImplRow
	for _, r := range p.Impl {
		if r.Role == RoleGameImpl && r.Complete(p.Layouts) {
			row = r
		}
	}
	l := p.Layouts[row.CWIA]
	with := func(n int) bool {
		r := row
		r.NIntermediate = n
		r.ArgsLen = l.ArgsBaseLen + l.ArgsPerRoot*n
		return r.Complete(p.Layouts)
	}
	if with(0) || with(-1) {
		t.Error("a row without an intermediate root is complete")
	}
	if !with(1) || !with(2) {
		t.Error("a row with one or two intermediate roots is refused")
	}
}

func TestTheDirStoreNamesItsOwnFailuresAndRefusesAFileThatIsNotAWholeRow(t *testing.T) {
	ctx := context.Background()
	hash := [32]byte{1}
	// a directory that cannot be created is the refusal of the directory, not of the write that follows
	dir := t.TempDir()
	file := filepath.Join(dir, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (DirStore{Dir: filepath.Join(file, "sub")}).Put(ctx, 1, 1, hash, "i", []byte("d")); err == nil || !strings.HasPrefix(err.Error(), "mkdir") {
		t.Errorf("%v", err)
	}
	// a directory pattern that cannot be listed
	if _, err := (DirStore{Dir: "["}).Rows(ctx, 1, "i"); err == nil {
		t.Error("an unlistable directory must be an error, not no rows")
	}
	// a row file that cannot be read
	d2 := t.TempDir()
	if err := os.Mkdir(filepath.Join(d2, "d.cap"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := (DirStore{Dir: d2}).Rows(ctx, 1, "i"); err == nil {
		t.Error("an unreadable row file must be an error, not skipped")
	}
	// a file whose item cannot be read, though the bytes after it would parse as a row
	d3 := t.TempDir()
	var ww finality.Writer
	ww.LP([]byte{0xff}) // an item with a byte above ASCII: read in full, then refused
	ww.U64(1)
	ww.U64(2)
	ww.B32(hash)
	ww.LP([]byte("d"))
	if err := os.WriteFile(filepath.Join(d3, "weird.cap"), ww.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (DirStore{Dir: d3}).Rows(ctx, 1, "i"); err == nil {
		t.Error("a row file with an unreadable item must be refused")
	}
	// a file with a whole header and a data length that is not there
	d4 := t.TempDir()
	var w finality.Writer
	w.STR("i")
	w.U64(1)
	w.U64(2)
	w.B32(hash)
	cut := append(w.Bytes(), 0, 0, 0, 10)
	if err := os.WriteFile(filepath.Join(d4, "cut.cap"), cut, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (DirStore{Dir: d4}).Rows(ctx, 1, "i"); err == nil {
		t.Error("a row file whose data is cut short must be refused")
	}
}

func TestACaptureWithMoreCodeThanTheLimitIsRefusedByName(t *testing.T) {
	lim := finality.DefaultLimits()
	enc := func(n int) []byte {
		var w finality.Writer
		w.U64(1)
		w.B32([32]byte{})
		w.Fixed(make([]byte, 20))
		w.LP(make([]byte, n))
		w.Nodes(nil)
		return w.Bytes()
	}
	if _, err := DecodeGameCapture(enc(lim.MaxCodeBytes)); err != nil {
		t.Fatalf("code of exactly the limit: %v", err)
	}
	_, err := DecodeGameCapture(enc(lim.MaxCodeBytes + 1))
	if se, ok := finality.AsNamed(err); !ok || se.Code != finality.CodeEvidenceTooLarge || se.Fields["part"] != "capture.code" {
		t.Errorf("%v", err)
	}
}

// The game type of the uuid the capture proves is the type of the pinned implementation the game code embeds, 621 when the
// implementation is not pinned; the args are read only from a code long enough to hold them.
func TestCaptureGameProvesTheUUIDOfTheGameTypeOfItsPinnedImplementationAndReadsArgsOnlyFromLongEnoughCode(t *testing.T) {
	p := loadPins(t)
	o, err := BuildSynth(p, SynthSpec{Version: "0.3.0"})
	if err != nil {
		t.Fatal(err)
	}
	// the pins the capture runs on give the 0.3.0 implementation another game type than the default
	m := baseSection(t)
	for _, v := range m["impl_pins"].(map[string]any) {
		row := v.(map[string]any)
		if row["role"] == RoleGameImpl && row["version"] == "0.3.0" {
			row["game_type"] = 77
		}
	}
	pc, err := ParsePins(pinsWith(t, m))
	if err != nil {
		t.Fatal(err)
	}
	const typ = 77
	lay := p.Layouts[LayoutAggregateV1]
	tmplLen := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	code := o.Body.GameCode
	args := code[tmplLen : len(code)-2]
	var root [32]byte
	copy(root[:], args[20:52])
	dgfSlot := func(c []byte, gameType uint32) [32]byte {
		s := &scriptProof{world: o.World, head: 1000, code: c}
		if _, err := CaptureGame(context.Background(), s, &MemStore{}, pc, SynthAddrs.Game, 12); err != nil {
			t.Fatal(err)
		}
		if len(s.calls) < 4 || s.calls[3].addr != SynthAddrs.DGF || len(s.calls[3].slots) != 2 {
			t.Fatalf("%+v", s.calls)
		}
		return s.calls[3].slots[0]
	}
	// the pinned implementation of the code decides the type
	if got, want := dgfSlot(code, 0), mapSlot(gameUUID(typ, root, args[84:]), mapDGFGames); got != want {
		t.Errorf("pinned 0.3.0 implementation: %x, want %x", got, want)
	}
	// an implementation address no row pins leaves the default type
	other := append([]byte(nil), code...)
	other[len(lay.CloneHead)+2+len(lay.CloneMid)] ^= 0xff
	if got, want := dgfSlot(other, 0), mapSlot(gameUUID(621, root, args[84:]), mapDGFGames); got != want {
		t.Errorf("unpinned implementation: %x, want %x", got, want)
	}
	// code that is one byte short of holding the fixed args reads none of them; exactly long enough reads them
	short := append(append([]byte(nil), code[:tmplLen+2+84-3]...), code[len(code)-2:]...)
	if len(short) != tmplLen+2+84-1 {
		t.Fatalf("%d", len(short))
	}
	if got, want := dgfSlot(short, 0), mapSlot(gameUUID(621, [32]byte{}, nil), mapDGFGames); got != want {
		t.Errorf("one byte short: %x, want %x", got, want)
	}
	exact := append(append([]byte(nil), code[:tmplLen+2+84-2]...), code[len(code)-2:]...)
	if len(exact) != tmplLen+2+84 {
		t.Fatalf("%d", len(exact))
	}
	if got, want := dgfSlot(exact, 0), mapSlot(gameUUID(typ, root, nil), mapDGFGames); got != want {
		t.Errorf("exactly long enough: %x, want %x", got, want)
	}
	longer := append(append([]byte(nil), code[:tmplLen+2+84-1]...), code[len(code)-2:]...)
	if got, want := dgfSlot(longer, 0), mapSlot(gameUUID(typ, root, longer[tmplLen+84:len(longer)-2]), mapDGFGames); got != want {
		t.Errorf("one byte longer: %x, want %x", got, want)
	}
}

// A spine that reaches block 1 and then block 0 is a valid chain: block 1 is not where the chain ends.
func TestAnL2SpineDownToBlockZeroIsAccepted(t *testing.T) {
	p := loadPins(t)
	f, err := judgeSpec(t, p, SynthSpec{OutBlock: 600, Depth: 600})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if f["output_root_block"] != uint64(600) {
		t.Errorf("%v", f)
	}
}
