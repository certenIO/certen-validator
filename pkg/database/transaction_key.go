// Copyright 2025 Certen Protocol

package database

import (
	"regexp"
	"strings"
)

var (
	// accumulateTxID is an Accumulate transaction ID: acc://<64 hex>@<principal>.
	accumulateTxID = regexp.MustCompile(`^acc://([0-9a-fA-F]{64})@`)
	bareTxHash     = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

// TransactionHashKey is the form Accumulate transactions are stored under in proof_artifacts,
// batch_transactions, intent_lifecycle and certen_anchor_proofs: the bare transaction hash, lower-case.
// Clients name a transaction by its transaction ID (acc://<hash>@<principal>), so a lookup by
// transaction takes the hash out of it. Any other value is only trimmed, so a key that is not an
// Accumulate hash is still matched exactly.
func TransactionHashKey(value string) string {
	value = strings.TrimSpace(value)
	if m := accumulateTxID.FindStringSubmatch(value); m != nil {
		return strings.ToLower(m[1])
	}
	if bareTxHash.MatchString(value) {
		return strings.ToLower(value)
	}
	return value
}
