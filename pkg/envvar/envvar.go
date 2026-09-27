// Copyright 2026 Certen Protocol

// Package envvar reads a validator's environment knobs the one way this codebase accepts: unset means
// the stated default, and a set value either parses and satisfies its bound or is refused by name.
//
// Each reader here replaces one that did something else with a value it could not read - returned the
// default, returned zero, or treated anything but one spelling as "off" - so an operator's typo ran the
// node on a number, or a switch position, nobody chose (RB3-F71 env part, the sweep that followed it).
package envvar

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func lookup(key string) (string, bool) {
	v := strings.TrimSpace(os.Getenv(key))
	return v, v != ""
}

func refuse(key, value, want string) error {
	return fmt.Errorf("%s=%q is not %s", key, value, want)
}

// Bool reads a switch. It accepts true/false, 1/0, yes/no and on/off in any case.
func Bool(key string, def bool) (bool, error) {
	v, ok := lookup(key)
	if !ok {
		return def, nil
	}
	switch strings.ToLower(v) {
	case "1", "t", "true", "yes", "y", "on":
		return true, nil
	case "0", "f", "false", "no", "n", "off":
		return false, nil
	}
	return def, refuse(key, v, "a switch (true/false, 1/0, yes/no, on/off)")
}

// Int reads an integer no smaller than min.
func Int(key string, def, min int) (int, error) {
	v, ok := lookup(key)
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min {
		return def, refuse(key, v, fmt.Sprintf("an integer of at least %d", min))
	}
	return n, nil
}

// Int64 reads a 64-bit integer no smaller than min.
func Int64(key string, def, min int64) (int64, error) {
	v, ok := lookup(key)
	if !ok {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < min {
		return def, refuse(key, v, fmt.Sprintf("an integer of at least %d", min))
	}
	return n, nil
}

// Uint64 reads an unsigned integer no smaller than min.
func Uint64(key string, def, min uint64) (uint64, error) {
	v, ok := lookup(key)
	if !ok {
		return def, nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n < min {
		return def, refuse(key, v, fmt.Sprintf("an unsigned integer of at least %d", min))
	}
	return n, nil
}

// Float reads a finite number no smaller than min.
func Float(key string, def, min float64) (float64, error) {
	v, ok := lookup(key)
	if !ok {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f != f || f < min || f > 1e300 {
		return def, refuse(key, v, fmt.Sprintf("a number of at least %g", min))
	}
	return f, nil
}

// Duration reads a Go duration (30s, 5m) no shorter than min.
func Duration(key string, def, min time.Duration) (time.Duration, error) {
	v, ok := lookup(key)
	if !ok {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < min {
		return def, refuse(key, v, fmt.Sprintf("a duration (e.g. 30s, 5m) of at least %v", min))
	}
	return d, nil
}

// Seconds reads a whole number of seconds, at least minSeconds.
func Seconds(key string, def time.Duration, minSeconds int) (time.Duration, error) {
	v, ok := lookup(key)
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < minSeconds {
		return def, refuse(key, v, fmt.Sprintf("a whole number of seconds, at least %d", minSeconds))
	}
	return time.Duration(n) * time.Second, nil
}

// OneOf reads a value that must be one of allowed (compared case-insensitively; returned lower-cased).
func OneOf(key, def string, allowed ...string) (string, error) {
	v, ok := lookup(key)
	if !ok {
		return def, nil
	}
	l := strings.ToLower(v)
	for _, a := range allowed {
		if l == strings.ToLower(a) {
			return strings.ToLower(a), nil
		}
	}
	return def, refuse(key, v, "one of "+strings.Join(allowed, "|"))
}

// Check runs every reader and returns one error naming each refused value, or nil.
func Check(readers ...func() error) error {
	var errs []error
	for _, r := range readers {
		if err := r(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
