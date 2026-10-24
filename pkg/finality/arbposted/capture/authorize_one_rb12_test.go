// Copyright 2026 Certen Protocol

package capture

import (
	"os"
	"regexp"
	"testing"
)

// RB12-TRAIN3-INT duty (1): ONE authorization function for the capturer. The live capture and the prefix scan register the same proof step, and
// that step judges a batch through Capturer.authorize (the field, which the Arbitrum wiring sets to AuthorizeBatch); no file of the capturer
// calls AuthorizeBatch directly, so a rule added for one path cannot be missing from the other.
func TestTheCapturerJudgesBatchesThroughTheOneAuthorizeField(t *testing.T) {
	direct := regexp.MustCompile(`\bAuthorizeBatch\(`)
	for _, file := range []string{"capturer.go", "prefix.go", "records.go", "contiguity.go", "source.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if direct.Match(src) {
			t.Errorf("%s calls AuthorizeBatch directly; the capturer judges through c.authorize()", file)
		}
	}
	c := &Capturer{}
	if c.authorize() == nil {
		t.Fatal("the default is AuthorizeBatch")
	}
	var called int
	c.Authorize = func(BatchRecord, [20]byte, uint64, []ProofView) Authorization { called++; return AuthForeign }
	if got := c.authorize()(BatchRecord{}, [20]byte{}, 0, nil); got != AuthForeign || called != 1 {
		t.Fatalf("the field is what the capturer calls: %v %d", got, called)
	}
}
