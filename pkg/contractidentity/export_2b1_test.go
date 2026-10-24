// Copyright 2026 Certen Protocol

package contractidentity

// B1Step hands the external tests of package 2b-1 one real step function, so that a test can run exactly the steps it is about and
// stand-ins for the rest (the package tests cannot be internal: the world package imports this one).
func B1Step(id StepID) StepFunc {
	switch id {
	case Step15:
		return b1Step15
	case Step16:
		return b1Step16
	case Step17:
		return b1Step17
	case Step20:
		return b1Step20
	}
	return nil
}
