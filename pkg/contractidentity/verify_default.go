// Copyright 2026 Certen Protocol

package contractidentity

// DefaultRegistrars is the composition of the four step packages: 2a (steps 1c-14), 2b-1 (15, 16, 17, 20), 2b-2 (18, 18b, 19, 22) and 2c
// (21, 23, 24). Steps 0-1b, 2 and the 22b node accounting belong to the skeleton (runner.go).
func DefaultRegistrars() []Registrar {
	return []Registrar{RegisterSteps2a, RegisterSteps2b1, RegisterSteps2b2, RegisterSteps2c}
}

// NewDefaultVerifier is the S8 Verifier that every caller uses: all 25 steps registered by their packages. NewVerifier returns an error
// when any step has no function, so a package that is added to the specification but not composed here cannot ship a verifier that
// quietly passes.
func NewDefaultVerifier(opts ...Option) (*StepVerifier, error) {
	reg, err := BuildRegistry(DefaultRegistrars()...)
	if err != nil {
		return nil, err
	}
	return NewVerifier(reg, opts...)
}
