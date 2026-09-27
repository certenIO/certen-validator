package execution

import (
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/ethereum/go-ethereum/common"
)

// Logger interface for logging operations
type Logger interface {
	Printf(format string, v ...interface{})
}

// LegExecution represents a single leg to execute
type LegExecution struct {
	LegID         string
	Target        common.Address
	Value         *big.Int
	Data          []byte
	ChainID       int64          // Target chain for this leg
	Chain         string         // Chain name (e.g., "ethereum sepolia", "arbitrum sepolia")
	SourceAddress common.Address // User's Abstract Account address (from leg.From)
	AccountOwner  common.Address // Owner wallet address for account factory deployment
	// Deadline is the leg's signed deadline_timestamp (unix seconds); 0 when it declares none. The leg
	// must not execute after it (PendingBatchIntent.Deadline).
	Deadline int64
	// RB-4: events the user signed as required proof of a contract call's success.
	// Present only for contract-call legs (Data non-empty). The validator refuses to
	// attest success unless every one appears in the inclusion-proven receipt logs.
	ExpectedEvents []ExpectedEvent
}

// IsContractCall reports whether this leg executes arbitrary calldata (a contract
// call) rather than a plain native/ERC-20 value transfer. RB-4: contract calls are
// gated on their committed events, not merely on non-revert.
func (l LegExecution) IsContractCall() bool {
	return len(l.Data) > 0
}

// contractCallsAllowed reports whether this deployment executes arbitrary contract calls. The
// definition lives in consensus (ContractCallsAllowed), which enforces it at batch admission.
func contractCallsAllowed() bool { return consensus.ContractCallsAllowed() }

// decodeHexBytes decodes a hex string (with or without "0x" prefix) into bytes.
// "" and "0x" decode to an empty (non-nil) slice. RB-1: used to parse the raw
// executionPayload.callData so keccak256(result) matches the producer's dataHash.
func decodeHexBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return []byte{}, nil
	}
	return hex.DecodeString(s)
}
