// Copyright 2026 Certen Protocol

package envvar

import (
	"math"
	"strconv"
	"testing"
	"time"
)

// A whole number of seconds that does not fit time.Duration used to wrap: 18446744074 s read as 0.29 s, so a build timeout of 0.29 s ended
// every build in finality_build_timeout. The largest representable value passes, one more is refused by name, and the default is kept.
func TestSecondsRefusesWhatWouldWrapTimeDuration(t *testing.T) {
	const key = "CERTEN_TEST_SECONDS_OVERFLOW"
	maxN := math.MaxInt64 / int64(time.Second)
	def := 7 * time.Second

	t.Setenv(key, strconv.FormatInt(maxN, 10))
	got, err := Seconds(key, def, 1)
	if err != nil || got != time.Duration(maxN)*time.Second || got <= 0 {
		t.Fatalf("the largest representable seconds must pass: got %v err %v", got, err)
	}
	for _, v := range []string{strconv.FormatInt(maxN+1, 10), "18446744074", "9223372037", strconv.FormatInt(math.MaxInt64, 10)} {
		t.Setenv(key, v)
		got, err := Seconds(key, def, 1)
		if err == nil {
			t.Fatalf("%s seconds must be refused, got %v", v, got)
		}
		if got != def {
			t.Fatalf("a refused value keeps the default: got %v", got)
		}
	}
}
