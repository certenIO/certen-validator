// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/andybalholm/brotli"
)

func brotliChannel(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := brotli.NewWriterLevel(&b, 5)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return append([]byte{1}, b.Bytes()...)
}

// The OP channel decompression had the same leniency as the Arbitrum batch decoder: andybalholm/brotli answers a clean EOF when
// its source ends while the decoder still needs input, so a brotli channel cut by one byte decompressed to a PREFIX with a nil
// error, and the empty brotli stream decompressed to nothing. The reference decoder (and the OP derivation, which reads the
// channel through a standard Brotli reader) refuse both.
func TestABrotliChannelCutShortIsRefusedAtEveryByte(t *testing.T) {
	rnd := rand.New(rand.NewSource(5))
	data := make([]byte, 500)
	rnd.Read(data)
	ch := brotliChannel(t, data)
	got, err := decompress(ch, 1<<20)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("the complete channel: %v", err)
	}
	for i := 2; i < len(ch); i++ {
		if out, err := decompress(ch[:i], 1<<20); err == nil {
			t.Fatalf("a brotli channel cut to %d of %d bytes decompressed to %d bytes", i, len(ch), len(out))
		}
	}
}

func TestAnEmptyBrotliChannelStreamIsRefused(t *testing.T) {
	if out, err := decompress([]byte{1}, 1<<20); err == nil {
		t.Fatalf("the version byte alone decompressed to %d bytes", len(out))
	}
}

func TestAByteAfterTheBrotliChannelStreamIsRefused(t *testing.T) {
	ch := brotliChannel(t, []byte("a channel"))
	if _, err := decompress(append(append([]byte(nil), ch...), 0), 1<<20); err == nil {
		t.Fatal("a byte after the stream was accepted")
	}
}
