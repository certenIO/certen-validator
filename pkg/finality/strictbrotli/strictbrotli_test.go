// Copyright 2026 Certen Protocol

package strictbrotli

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"reflect"
	"testing"

	"github.com/andybalholm/brotli"
)

func compress(t testing.TB, data []byte, level, lgwin int) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := brotli.NewWriterOptions(&buf, brotli.WriterOptions{Quality: level, LGWin: lgwin})
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// plainState reads in with the library's Reader over a source that ends in io.EOF (what the standard use does) and returns the
// decoder's internal state number: the oracle for "the decoder reached the end of its stream". It reads the private field
// through reflection, which is allowed for reading and pins the library version the soundness argument is about.
func plainState(in []byte) int64 {
	rd := brotli.NewReader(bytes.NewReader(in))
	_, _ = io.Copy(io.Discard, rd)
	return reflect.ValueOf(rd).Elem().FieldByName("state").Int()
}

func doneState(t testing.TB) int64 {
	t.Helper()
	return plainState(compress(t, []byte("a complete stream"), 5, 22))
}

func corpus() map[string][]byte {
	rnd := rand.New(rand.NewSource(7))
	random := func(n int) []byte { b := make([]byte, n); rnd.Read(b); return b }
	text := bytes.Repeat([]byte("the sequencer committed to this batch; "), 300)
	mixed := append(append(random(3000), text...), random(2000)...)
	return map[string][]byte{
		"empty":        {},
		"one byte":     {0x42},
		"short":        []byte("0123456789abcdef0123456789abcdef"),
		"text":         text,
		"random 2k":    random(2000),
		"mixed":        mixed,
		"zeros 70k":    make([]byte, 70000),
		"random 100k":  random(100000), // incompressible: the stream spans several 32 KiB source reads
		"two metablks": append(random(40000), bytes.Repeat([]byte{9}, 40000)...),
	}
}

func points(n int) []int {
	if n <= 3000 {
		out := make([]int, n)
		for i := range out {
			out[i] = i
		}
		return out
	}
	seen := map[int]bool{}
	var out []int
	add := func(i int) {
		if i >= 0 && i < n && !seen[i] {
			seen[i] = true
			out = append(out, i)
		}
	}
	for i := 0; i < 300; i++ {
		add(i)
		add(n - 1 - i)
	}
	for i := 0; i < n; i += 997 {
		add(i)
		add(i + 32767)
		add(i + 32768)
		add(i + 32769)
	}
	return out
}

// Every complete stream is accepted and returns its data; every proper prefix is refused unless the library's own decoder says the
// prefix is itself a complete stream; one byte after a complete stream is refused as trailing.
func TestEveryTruncationIsRefusedAndEveryCompleteStreamAccepted(t *testing.T) {
	done := doneState(t)
	cut := 0
	for name, data := range corpus() {
		for _, level := range []int{0, 2, 5, 9} {
			for _, lgwin := range []int{10, 16, 22} {
				if len(data) > 100000 && (level > 5 || lgwin < 22) {
					continue // keep the corpus affordable; small inputs cover every level and window
				}
				c := compress(t, data, level, lgwin)
				got, exceeded, err := Decompress(c, len(data)+1)
				if err != nil || exceeded || !bytes.Equal(got, data) {
					t.Fatalf("%s q%d w%d: complete stream: err %v exceeded %v equal %v", name, level, lgwin, err, exceeded, bytes.Equal(got, data))
				}
				if _, _, err := Decompress(append(append([]byte(nil), c...), 0x00), len(data)+1); !errors.Is(err, ErrTrailing) {
					t.Fatalf("%s q%d w%d: one trailing byte: %v", name, level, lgwin, err)
				}
				if _, _, err := Decompress(append(append([]byte(nil), c...), c...), len(data)+1); !errors.Is(err, ErrTrailing) {
					t.Fatalf("%s q%d w%d: a second stream after the first: %v", name, level, lgwin, err)
				}
				for _, i := range points(len(c)) {
					prefix := c[:i]
					_, _, err := Decompress(prefix, len(data)+1)
					oracleDone := len(prefix) > 0 && plainState(prefix) == done
					if err == nil && !oracleDone {
						t.Fatalf("%s q%d w%d: a stream cut at %d of %d bytes was accepted although the decoder never finished it", name, level, lgwin, i, len(c))
					}
					if err != nil && oracleDone {
						t.Fatalf("%s q%d w%d: a prefix of %d bytes that is itself a complete stream was refused: %v", name, level, lgwin, i, err)
					}
					if err == nil {
						t.Fatalf("%s q%d w%d: a proper prefix of %d bytes is a complete stream (unexpected for this corpus)", name, level, lgwin, i)
					}
					cut++
				}
			}
		}
	}
	if cut < 20000 {
		t.Fatalf("only %d truncation points exercised", cut)
	}
}

func TestTheEmptyStreamIsRefusedAndTheLibraryAloneIsLenient(t *testing.T) {
	if _, _, err := Decompress(nil, 10); !errors.Is(err, ErrEmpty) {
		t.Fatalf("nil: %v", err)
	}
	if _, _, err := Decompress([]byte{}, 10); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty: %v", err)
	}
	// the defect this package exists for, pinned: the library returns a prefix and a nil error for a stream cut by one byte. If
	// a library update fixes it this test fails: re-derive the soundness argument in the package comment before relaxing it.
	msg := bytes.Repeat([]byte("0123456789"), 4)[:35]
	c := compress(t, msg, 5, 22)
	lenient, err := io.ReadAll(brotli.NewReader(bytes.NewReader(c[:len(c)-1])))
	if err != nil || len(lenient) >= len(msg) || len(lenient) == 0 {
		t.Fatalf("the library's behaviour on a stream cut by one byte changed (%d of %d bytes, err %v)", len(lenient), len(msg), err)
	}
	if _, _, err := Decompress(c[:len(c)-1], 100); err == nil {
		t.Fatal("the wrapper accepted a stream cut by one byte")
	}
}

func TestTheCapIsExactAndAnExcessStreamIsReportedNotRead(t *testing.T) {
	data := bytes.Repeat([]byte{7}, 5000)
	c := compress(t, data, 5, 22)
	if got, ex, err := Decompress(c, 5000); err != nil || ex || len(got) != 5000 {
		t.Fatalf("exactly the cap: %d %v %v", len(got), ex, err)
	}
	if got, ex, err := Decompress(c, 4999); err != nil || !ex || got != nil {
		t.Fatalf("one over: %d %v %v", len(got), ex, err)
	}
	// a stream cut short that already exceeds the cap is an excess report (the double fault is not parity-tested)
	if _, ex, _ := Decompress(c[:len(c)-1], 100); !ex {
		t.Fatal("a cut stream whose output already passes the cap was not reported as exceeding it")
	}
}

func TestGarbageNeverPanicsAndIsRefused(t *testing.T) {
	rnd := rand.New(rand.NewSource(11))
	done := doneState(t)
	for i := 0; i < 3000; i++ {
		b := make([]byte, 1+rnd.Intn(200))
		rnd.Read(b)
		if got, ex, err := Decompress(b, 1<<16); err == nil && !ex {
			// random bytes are essentially never a complete stream; when one is, the library's own decoder must agree
			if plainState(b) != done {
				t.Fatalf("accepted garbage %x (%d bytes out)", b, len(got))
			}
		}
	}
}

func TestClassifyAllCombinations(t *testing.T) {
	excessive := errors.New(libExcessive)
	other := errors.New("brotli: something else")
	for _, c := range []struct {
		name    string
		out     []byte
		err     error
		probed  bool
		wantOut bool
		wantEx  bool
		wantErr error
	}{
		{"complete", []byte{1}, excessive, true, true, false, nil},
		{"trailing byte before the probe", []byte{1}, excessive, false, false, false, ErrTrailing},
		{"incomplete (source error)", []byte{1}, ErrIncomplete, true, false, false, ErrIncomplete},
		{"other decode error", nil, other, true, false, false, other},
		{"no error and not over the cap", []byte{1}, nil, true, false, false, ErrIncomplete},
		{"over the cap with an error", make([]byte, 6), other, true, false, true, nil},
		{"over the cap without one", make([]byte, 6), nil, false, false, true, nil},
		{"exactly the cap, complete", make([]byte, 5), excessive, true, true, false, nil},
	} {
		out, ex, err := classify(c.out, c.err, c.probed, 5)
		if (out != nil) != c.wantOut || ex != c.wantEx || !errors.Is(err, c.wantErr) && err != c.wantErr {
			t.Errorf("%s: out %v exceeded %v err %v", c.name, out != nil, ex, err)
		}
	}
}
