// Copyright 2026 Certen Protocol

package contractidentity

// Limits are the DoS bounds of the CIE1 container (Freeze inventory item 1c, plus the bounds the verifier steps name). A value above a
// bound is the refusal evidence_too_large{part,count,limit}; it never truncates and never degrades. Marker † = a round number nobody
// measured: raising it is a verifier release (and a new specification revision), never a configuration.
type Limits struct {
	// MaxContainerBytes: the whole container (MaxReplayEvidenceBytes precedent, Q1). part "container".
	MaxContainerBytes int // 4194304
	// MaxKindBytes: the kind STR (item 1a row 2). part "kind".
	MaxKindBytes int // 64
	// MaxCodes / MaxCodeBytes: pkg/finality codec.go:43-50. part "codes".
	MaxCodes     int // 16
	MaxCodeBytes int // 262144
	// MaxNodes / MaxNodeBytes: Q1 (†). part "nodes". A state or storage trie node above 4096 B is proof_invalid at the walk, not at decode.
	MaxNodes     int // 16384 †
	MaxNodeBytes int // 131072 †
	// MaxHeaderBytes: each of headerV, headerVParent, every hop header and every spine header (†, r3). part "attest", "hopHeaders", "spine".
	MaxHeaderBytes int // 4096 †
	// MaxLeafBytes: txLeaf and receiptLeaf (max_attest_leaf_bytes, †). part "attest".
	MaxLeafBytes int // 131072 †
	// MaxAttestHops / MaxAttestSpine: Q1 (†). part "hopHeaders" / "spine".
	MaxAttestHops  int // 16 †
	MaxAttestSpine int // 4096 †
	// MaxBlockTxs / MaxBlockTxsBytes: count and total length of the block transaction list (†, Q1, M15). part "blockTxs".
	MaxBlockTxs      int // 4096 †
	MaxBlockTxsBytes int // 1048576 †
	// MaxFailures / MaxText: provider failures of a Stated part and the length of every Stated STR (MaxReplayProviderFailures,
	// MaxReplayTextBytes). part "failures".
	MaxFailures int // 64
	MaxText     int // 1024
	// MaxValidators: validatorList length read at the attest and settle stations (Q1). Not a codec bound; the verifier's read plan.
	MaxValidators int // 64
	// MaxString: the account strings adiURL and governingBook, in bytes (Q1; step 6). Not a codec bound.
	MaxString int // 1024
	// MaxBatchLegs: legs decoded from a batch settlement call (step 14, †). Not a codec bound.
	MaxBatchLegs int // 64 †
	// MaxPKCList: entries of a setRootHistory row's pkcList (step 21c, †). Not a codec bound.
	MaxPKCList int // 256 †
}

// DefaultLimits are the item 1c values. They are the only limits a verifier uses.
func DefaultLimits() Limits {
	return Limits{
		MaxContainerBytes: 4194304,
		MaxKindBytes:      64,
		MaxCodes:          16,
		MaxCodeBytes:      262144,
		MaxNodes:          16384,
		MaxNodeBytes:      131072,
		MaxHeaderBytes:    4096,
		MaxLeafBytes:      131072,
		MaxAttestHops:     16,
		MaxAttestSpine:    4096,
		MaxBlockTxs:       4096,
		MaxBlockTxsBytes:  1048576,
		MaxFailures:       64,
		MaxText:           1024,
		MaxValidators:     64,
		MaxString:         1024,
		MaxBatchLegs:      64,
		MaxPKCList:        256,
	}
}
