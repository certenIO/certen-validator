// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"fmt"
	"strings"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// Header is an L1 block header as captured: the raw RLP exactly as hashed, with the fields the capturer needs read from the
// provider's JSON (the capturer never trusts them for anything the verifier decides: the verifier re-reads the RLP).
type Header struct {
	Number     uint64
	Hash       [32]byte
	ParentHash [32]byte
	Timestamp  uint64
	RLP        []byte
}

// Log is an eth_getLogs entry.
type Log struct {
	Address     [20]byte
	Topics      [][32]byte
	Data        []byte
	BlockNumber uint64
	BlockHash   [32]byte
	TxHash      [32]byte
	TxIndex     uint64
	LogIndex    uint64
}

// Tx is a transaction: Raw is the consensus encoding (type byte || rlp for typed), already checked to hash to Hash.
type Tx struct {
	Hash                [32]byte
	BlockHash           [32]byte
	BlockNumber         uint64
	Index               uint64
	Type                uint8
	Raw                 []byte
	Input               []byte
	BlobVersionedHashes [][32]byte
}

// SlotProof is one storage proof of an eth_getProof answer.
type SlotProof struct {
	Key   [32]byte
	Value [32]byte
	Proof [][]byte
}

// Proof is an eth_getProof answer.
type Proof struct {
	Address      [20]byte
	AccountProof [][]byte
	StorageHash  [32]byte
	CodeHash     [32]byte
	Slots        []SlotProof
}

// L1Source is the parent-chain (Ethereum Sepolia) read side. Every method may be served by any provider: nothing it returns is
// evidence (the verifier re-verifies everything), so providers are tried in order and a failure names the providers.
type L1Source interface {
	HeadNumber(ctx context.Context) (uint64, error)
	// Header returns the header of the block with this number as the first answering provider has it, checked
	// keccak256(rlp) == the hash the provider states.
	Header(ctx context.Context, number uint64) (Header, error)
	// Logs returns the logs of address with topic0 (and topic1 when non-nil) in [from, to].
	Logs(ctx context.Context, address [20]byte, topic0 [32]byte, topic1 *[32]byte, from, to uint64) ([]Log, error)
	TxByHash(ctx context.Context, hash [32]byte) (Tx, error)
	// GetProof is eth_getProof(address, slots, number). accept judges each provider's answer (the capturer verifies it against
	// the header's state root); an answer accept refuses counts as that provider's failure. The error, when no provider
	// answered acceptably, is a *ProviderErrors.
	GetProof(ctx context.Context, address [20]byte, slots [][32]byte, number uint64, accept func(*Proof) error) (*Proof, error)
}

// Sidecar is one blob of an L1 block with its KZG commitment and blob proof.
type Sidecar struct {
	Blob       []byte // 131072
	Commitment [48]byte
	Proof      [48]byte
}

// BeaconSource serves the blobs of the L1 block at a beacon slot.
type BeaconSource interface {
	// Sidecars returns, for each wanted versioned hash, the blob whose commitment hashes to it (selection is BY versioned hash,
	// never by index). A missing hash is an error. The error is a *BeaconError when the endpoint answered with a status.
	Sidecars(ctx context.Context, slot uint64, wanted [][32]byte) (map[[32]byte]Sidecar, error)
}

// ProviderFailure is one provider's failure, redacted.
type ProviderFailure struct {
	Provider string // host label only, never a path or credentials
	Err      string // pkg/ethrpc RedactText of the error text
}

func (f ProviderFailure) String() string { return f.Provider + ": " + f.Err }

// ProviderErrors is every provider's failure for one call. Its text is redacted.
type ProviderErrors struct {
	Op       string
	Failures []ProviderFailure
}

func (e *ProviderErrors) Error() string {
	parts := make([]string, len(e.Failures))
	for i, f := range e.Failures {
		parts[i] = f.String()
	}
	return ethrpc.RedactText(fmt.Sprintf("%s: no provider answered: %s", e.Op, strings.Join(parts, "; ")))
}

// Strings returns the failures as "provider: error" strings (the l1_proof_window_unavailable providers field).
func (e *ProviderErrors) Strings() []string {
	out := make([]string, len(e.Failures))
	for i, f := range e.Failures {
		out[i] = f.String()
	}
	return out
}

// BeaconError is a beacon endpoint failure with the HTTP status (0: transport error).
type BeaconError struct {
	Slot   uint64
	Status int
	Err    string // redacted
}

func (e *BeaconError) Error() string {
	return ethrpc.RedactText(fmt.Sprintf("beacon slot %d: http %d: %s", e.Slot, e.Status, e.Err))
}
