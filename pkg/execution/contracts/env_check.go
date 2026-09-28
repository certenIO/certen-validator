// Copyright 2026 Certen Protocol

package contracts

// CheckEnv reads the validator set this package commits into the set root - addresses, powers and
// threshold - so an absent, unreadable or contradictory setting stops the node at boot (RB3-F21), not at
// its first quorum.
func CheckEnv() error {
	_, err := computeV6_1ValidatorSetRoot()
	return err
}
