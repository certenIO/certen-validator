// Copyright 2026 Certen Protocol

package ethrpc

// CheckEnv reads this package's environment knobs, so a value that does not parse stops the node at boot.
func CheckEnv() error {
	_, err := CooldownFromEnv()
	return err
}
