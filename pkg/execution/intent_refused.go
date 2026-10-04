// Copyright 2026 Certen Protocol

package execution

// IntentRefusedError is a refusal by name before any chain transaction because the intent itself cannot be settled as
// submitted - its own defect, such as an account of another generation than the chain's (RB6-F10). Not a failure of
// CERTEN to settle it (a missed deadline, an uncertified intent): those are failed settlements.
type IntentRefusedError struct{ Err error }

func (e *IntentRefusedError) Error() string { return e.Err.Error() }
func (e *IntentRefusedError) Unwrap() error { return e.Err }
