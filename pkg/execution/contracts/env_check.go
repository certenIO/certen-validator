// Copyright 2026 Certen Protocol

package contracts

// CheckEnv reads the validator-set threshold this package commits into the set root, so a value that
// does not parse stops the node at boot.
func CheckEnv() error {
	_, _, err := resolveThreshold()
	return err
}
