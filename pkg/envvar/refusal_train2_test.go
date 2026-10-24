// Copyright 2026 Certen Protocol

package envvar

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// RB12-GO-INT F14: a startup that must not end the validator names the variable it refused WITHOUT echoing the value and without
// reading the error's text, so the refusal is a typed error. Its text is what the readers have always returned.

func TestRefusalsAreTypedKeepTheirTextAndCanBeFoundInAJoinedAndWrappedError(t *testing.T) {
	t.Setenv("X_TRAIN2_SWITCH", "maybe")
	t.Setenv("X_TRAIN2_NUMBER", "fast")
	t.Setenv("X_TRAIN2_FINE", "5")
	_, e1 := Bool("X_TRAIN2_SWITCH", true)
	_, e2 := Int("X_TRAIN2_NUMBER", 1, 1)
	_, e3 := Int("X_TRAIN2_FINE", 1, 1)
	if e3 != nil {
		t.Fatal(e3)
	}
	err := fmt.Errorf("finality configuration: %w", Check(func() error { return e1 }, func() error { return e3 }, func() error { return e2 }))

	got := Refusals(err)
	var keys []string
	for _, r := range got {
		keys = append(keys, r.Key)
	}
	if !reflect.DeepEqual(keys, []string{"X_TRAIN2_SWITCH", "X_TRAIN2_NUMBER"}) {
		t.Fatalf("the refused variables, in the order they were read: %v", keys)
	}
	if got[0].Error() != `X_TRAIN2_SWITCH="maybe" is not a switch (true/false, 1/0, yes/no, on/off)` {
		t.Fatalf("the text of the refusal changed: %s", got[0].Error())
	}
	if got[1].Error() != `X_TRAIN2_NUMBER="fast" is not an integer of at least 1` {
		t.Fatalf("the text of the refusal changed: %s", got[1].Error())
	}
	if got[0].Value != "maybe" || got[0].Want == "" {
		t.Fatalf("the refusal holds the value and what was wanted: %+v", got[0])
	}
}

func TestRefusalsOfAnErrorThatIsNoRefusalIsNothing(t *testing.T) {
	if Refusals(nil) != nil || Refusals(errors.New("x")) != nil || Refusals(fmt.Errorf("w: %w", errors.New("y"))) != nil {
		t.Fatal("a plain error is no refusal")
	}
}

// A package that bounds a value after the reader accepted it refuses it the same way.
func TestRefuseBuildsTheSameTypedRefusal(t *testing.T) {
	err := Refuse("X_TRAIN2_BATCH", "101", "an integer from 1 to 100")
	rs := Refusals(err)
	if len(rs) != 1 || rs[0].Key != "X_TRAIN2_BATCH" || !strings.Contains(err.Error(), `X_TRAIN2_BATCH="101" is not an integer from 1 to 100`) {
		t.Fatalf("%v %v", rs, err)
	}
}

// A refused switch says so: a switch is not to be guessed on or off, which is another correction than a number out of range.
func TestRefusalOfASwitchIsMarkedAsOne(t *testing.T) {
	t.Setenv("X_TRAIN2_SW", "maybe")
	t.Setenv("X_TRAIN2_NUM", "fast")
	_, e1 := Bool("X_TRAIN2_SW", true)
	_, e2 := Int("X_TRAIN2_NUM", 1, 1)
	_, e3 := Float("X_TRAIN2_NUM", 1, 0)
	if r := Refusals(e1); len(r) != 1 || !r[0].Switch {
		t.Fatalf("%v", r)
	}
	for _, e := range []error{e2, e3} {
		if r := Refusals(e); len(r) != 1 || r[0].Switch {
			t.Fatalf("%v", r)
		}
	}
}
