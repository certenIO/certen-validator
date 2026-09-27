// Copyright 2026 Certen Protocol

package accumulate

import (
	"log"
	"sync"

	"github.com/certen/independant-validator/pkg/envvar"
)

// LOG_LEVEL decides whether the block parser's per-entry and per-record lines are printed (RB3-F22).
//
// They were printed unconditionally - one line per entry of every block every validator reads - and made
// up over 70% of each container's log, so its retention (json-file 50 MB x 3) held about 30 minutes and
// execution evidence was gone within the hour. LOG_LEVEL was read into the config and applied nowhere.
// It is now "info" (the default: these lines are not printed) or "debug" (they are); any other value is
// refused, because no other level is implemented.

// LogLevelFromEnv reads LOG_LEVEL strictly.
func LogLevelFromEnv() (string, error) { return envvar.OneOf("LOG_LEVEL", "info", "info", "debug") }

var (
	debugOnce sync.Once
	debugOn   bool
)

// debugf prints only at LOG_LEVEL=debug. An unreadable LOG_LEVEL is refused at startup (main.checkEnvironment).
func debugf(format string, args ...interface{}) {
	debugOnce.Do(func() {
		lvl, err := LogLevelFromEnv()
		debugOn = err == nil && lvl == "debug"
	})
	if debugOn {
		log.Printf(format, args...)
	}
}
