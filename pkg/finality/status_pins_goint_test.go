// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// RB12-GO-INT: the dbfix branch records the pins hash a builder judged under (pinsSha256) in every status row and e1-raise changed the
// pins file (and so PinsSHA256) in the meantime. The integrated tree must report the hash of ITS OWN pins file: a row written by the
// merged code names fdba733e... (the e1-raise pins), not the hash the dbfix branch was written against, and the figure is not a
// constant copied into the status code.
const mergedTreePinsSHA256 = "9f4fc10feca95909272c9f6eaef1a38d7a06110cfead0a88cb79e8ffd7a3d1cf"

func TestRB12GOINTTheStatusRowReportsThePinsHashOfTheMergedTree(t *testing.T) {
	sum := sha256.Sum256(EmbeddedPinsBytes())
	if got := hex.EncodeToString(sum[:]); got != mergedTreePinsSHA256 || PinsSHA256 != mergedTreePinsSHA256 {
		t.Fatalf("the embedded pins file hashes to %s, the constant is %s, the merged tree's pins are %s", got, PinsSHA256, mergedTreePinsSHA256)
	}
	p, err := EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	if h, src := p.Identity(); h != mergedTreePinsSHA256 || src != PinsSourceEmbedded {
		t.Fatalf("Identity %s %s", h, src)
	}
	row := VerifiedBuilderStatus(legID, ChainBaseSepolia, LevelL1Posted, 1, time.Unix(1_800_000_000, 0)).WithPins(p)
	raw, err := row.Document()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc["pinsSha256"]) != `"`+mergedTreePinsSHA256+`"` {
		t.Fatalf("the document says %s", doc["pinsSha256"])
	}
	// the upgrader stamps the rows it writes with the hash of the pins it was given
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	status := newMemStatus()
	cfg := UpgraderConfig{Status: status, Logf: f.logs.Logf, Now: f.clock.Now, Recorder: f.rec, Jitter: func(d time.Duration) time.Duration { return d }}
	u, err := NewUpgrader(f.src, f.store, f.reg, p, cfg)
	if err != nil {
		t.Fatal(err)
	}
	u.RunOnce(context.Background())
	if r := status.row(legID, LevelL1Posted); r.PinsSHA256 != mergedTreePinsSHA256 {
		t.Fatalf("the upgrader's row carries %q", r.PinsSHA256)
	}
}
