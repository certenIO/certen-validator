// Copyright 2026 Certen Protocol

package intent

import (
	"errors"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/accumulate"
)

// RB8-G (verifier defect 3): `repair lifecycle-rows` owes a row only for an intent its block carries. The block is searched
// with the same client and an intent is matched exactly as intentInBlock matches it (the id the discovery conversion builds).

func TestIntentsInBlockIsExactlyWhatIntentInBlockFinds(t *testing.T) {
	a := blockTx(strings.Repeat("a1", 32), "in-block-a", 10007772)
	b := blockTx(strings.Repeat("b2", 32), "in-block-b", 10007772)
	elsewhere := blockTx(strings.Repeat("c3", 32), "in-other-block", 10007773)
	notAnIntent := blockTx(strings.Repeat("d4", 32), "x", 10007772)
	delete(notAnIntent.IntentData, "replayData") // not a CERTEN intent of four blobs: discovery skips it

	got, err := IntentsInBlock(&blockClient{txs: []*accumulate.CertenTransaction{a, b, elsewhere, notAnIntent}}, 10007772)
	if err != nil {
		t.Fatal(err)
	}
	wantA, wantB := intentIDOf(t, a), intentIDOf(t, b)
	if len(got) != 2 || !got[wantA] || !got[wantB] || got[intentIDOf(t, elsewhere)] {
		t.Fatalf("block 10007772 lists %v; want exactly %s and %s", got, wantA, wantB)
	}

	// The same answer intentInBlock gives, one intent at a time.
	id := &IntentDiscovery{client: &blockClient{txs: []*accumulate.CertenTransaction{a, b, elsewhere}}, logger: log.New(io.Discard, "", 0)}
	for want := range got {
		if _, err := id.intentInBlock(10007772, want); err != nil {
			t.Errorf("intentInBlock does not find %s that IntentsInBlock lists: %v", want, err)
		}
	}
	if _, err := id.intentInBlock(10007772, intentIDOf(t, elsewhere)); !errors.Is(err, errIntentNotInBlock) {
		t.Errorf("intentInBlock found an intent of another block: %v", err)
	}
}

func TestIntentsInBlockSaysWhenTheBlockCannotBeSearched(t *testing.T) {
	_, err := IntentsInBlock(&failingSearchClient{failOn: 10007772}, 10007772)
	if err == nil || !strings.Contains(err.Error(), "10007772") {
		t.Fatalf("a block that could not be searched was reported as %v; an empty block is an answer, an unsearchable one is not", err)
	}
}
