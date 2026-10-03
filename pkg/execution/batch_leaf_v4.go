// Copyright 2026 Certen Protocol

package execution

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// The v4 batch leaf (RB5-F57), for CertenAccountV7_3 as factory V11 creates it. v3 bound who, what, which intent and
// which authority, but no time: the account's only time check read the proof's timestamp/expiresAt, which whoever
// submits the proof chooses, so an unconsumed member could be executed after its signed deadline. v4 binds the member's
// execution window - notBefore and notAfter, unix seconds - into the leaf, and the account refuses block.timestamp
// outside it, from the leaf's own values (LeafNotYetValid / LeafExpired). A member past its deadline can then never
// execute, so its non-settlement (D4 status 3) is final by construction.

// BatchLeafDomainV4 must equal CertenAccountV7_3.LEAF_DOMAIN.
const BatchLeafDomainV4 = "certen:batchleaf:v4"

// ErrNoMemberWindow: a v4 leaf binds the member's execution window, and the member has none that every validator
// computes alike yet - its Accumulate commit time is not known, or it states no deadline. It waits until it has one.
var ErrNoMemberWindow = errors.New("the member has no execution window every validator computes alike")

// ComputeBatchLeafV4 mirrors CertenAccountV7_3.computeLeaf:
//
//	keccak256(abi.encodePacked(
//	    "certen:batchleaf:v4", chainId, adiURLHash, executionCommitment, operationID, bytes32 authorityBook,
//	    uint64 authorityPage, uint64 notBefore, uint64 notAfter
//	))
//
// Each uint64 is 8 bytes big-endian under encodePacked. The preimage is 16 bytes longer than v3's and starts with a
// different domain literal, so a v4 leaf is never a v3 leaf.
func ComputeBatchLeafV4(chainID int64, in BatchLeafInput) [32]byte {
	return ethcrypto.Keccak256Hash(batchLeafV4Preimage(chainID, in))
}

func batchLeafV4Preimage(chainID int64, in BatchLeafInput) []byte {
	chainIDBytes := make([]byte, 32)
	big.NewInt(chainID).FillBytes(chainIDBytes)
	adiHash := in.ADIURLHash()
	u64 := func(v uint64) []byte {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v)
		return b
	}

	packed := make([]byte, 0, len(BatchLeafDomainV4)+184)
	packed = append(packed, []byte(BatchLeafDomainV4)...)
	packed = append(packed, chainIDBytes...)
	packed = append(packed, adiHash[:]...)
	packed = append(packed, in.ExecutionCommitment[:]...)
	packed = append(packed, in.OperationID[:]...)
	packed = append(packed, in.AuthorityBook[:]...)
	packed = append(packed, u64(in.AuthorityPage)...)
	packed = append(packed, u64(in.NotBefore)...)
	packed = append(packed, u64(in.NotAfter)...)
	return packed
}

// ComputeAccountLeaf is the member's leaf as the account generation its chain is on computes it (AccountLeafVersionOf):
// v3 for a CertenAccountV7_2 chain, v4 for a CertenAccountV7_3 chain. A chain on no version is refused by name, and a
// v4 leaf without its window is refused (ErrNoMemberWindow) - there is no other version to fall back to.
func ComputeAccountLeaf(chainID int64, in BatchLeafInput) ([32]byte, error) {
	v, err := AccountLeafVersionOf(chainID)
	if err != nil {
		return [32]byte{}, err
	}
	return computeLeafAs(v, chainID, in)
}

// computeLeafAs is the member's leaf of the given account leaf version.
func computeLeafAs(v AccountLeafVersion, chainID int64, in BatchLeafInput) ([32]byte, error) {
	switch v {
	case AccountLeafV3:
		return ComputeBatchLeafV3(chainID, in), nil
	case AccountLeafV4:
		if in.NotAfter == 0 {
			return [32]byte{}, fmt.Errorf("%w: member %s (%s) on chain %d has no notAfter for its v4 leaf",
				ErrNoMemberWindow, in.IntentID, in.ADIURL, chainID)
		}
		return ComputeBatchLeafV4(chainID, in), nil
	default:
		return [32]byte{}, fmt.Errorf("%w: %q on chain %d", ErrUnknownAccountLeafVersion, v, chainID)
	}
}
