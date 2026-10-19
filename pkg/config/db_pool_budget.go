// Copyright 2026 Certen Protocol

package config

import "fmt"

// DefaultDatabaseMaxConns is the pool a validator opens when DATABASE_MAX_CONNS is not set.
//
// The seven validators share one PostgreSQL whose max_connections is 100. The default used to be 25 each, 7 x 25 = 175
// against 100: nothing failed while the validators were quiet, and the day all seven were busy at once some would be
// refused "too many clients already" (found in RB8-F, 2026-10-18; not the cause of that day's lifecycle defect). 12 each
// is 84, which fits and leaves the server's remainder for the services that share it. An explicit DATABASE_MAX_CONNS is
// the operator's and is never second-guessed here; a pool that does not fit is said so at start (PoolBudget).
const DefaultDatabaseMaxConns = 12

// PoolBudget is the arithmetic of one PostgreSQL shared by a fleet of validators: how many connections they can ask for
// together against how many the server allows.
type PoolBudget struct {
	// PerValidator is one validator's pool (DATABASE_MAX_CONNS).
	PerValidator int
	// Validators is the configured fleet: ConfiguredValidatorCount.
	Validators int
	// ServerMax is the server's max_connections as it reports it; 0 when it could not be read.
	ServerMax int
}

// ConfiguredValidatorCount is the number of validators this configuration names: the peers it attests with
// (ATTESTATION_PEERS lists every other validator and never itself) plus this one.
func ConfiguredValidatorCount(attestationPeers []string) int {
	return len(attestationPeers) + 1
}

// Demand is the most connections the fleet can hold together.
func (b PoolBudget) Demand() int { return b.PerValidator * b.Validators }

// Warning is the one loud line said at start when the fleet can ask for more connections than the server allows, and ""
// when it fits or when either number is unknown (a budget that cannot be computed is not a budget that is exceeded). It
// names both numbers. It never fails a start: the pools are the operator's, and the server's limit may be raised.
func (b PoolBudget) Warning() string {
	if b.PerValidator <= 0 || b.Validators <= 0 || b.ServerMax <= 0 || b.Demand() <= b.ServerMax {
		return ""
	}
	remedy := fmt.Sprintf("Set DATABASE_MAX_CONNS to at most %d per validator", b.ServerMax/b.Validators)
	if b.ServerMax/b.Validators < 1 {
		remedy = "No per-validator pool fits"
	}
	return fmt.Sprintf("🚨 [DB-POOL] the fleet can ask PostgreSQL for more connections than it allows: DATABASE_MAX_CONNS=%d x %d validators "+
		"(ATTESTATION_PEERS names %d peers, plus this one) = %d, but the server's max_connections is %d. Validators that are busy together "+
		"will be refused \"too many clients already\". %s, or raise max_connections on the server (the other services sharing it need room too).",
		b.PerValidator, b.Validators, b.Validators-1, b.Demand(), b.ServerMax, remedy)
}
