package contracts

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// CreateBatchAnchorV8_1Signature is the V8.1 (and V7) batch anchor call. V8.2 replaced it
// (CreateBatchAnchorV8_2Signature); it is decoded to verify anchors created before the V8.2 rollout.
const CreateBatchAnchorV8_1Signature = "createBatchAnchor(bytes32,bytes32,uint256,bytes32,uint256)"

var (
	// CreateBatchAnchorV8_1Selector is 0x34597e5a.
	CreateBatchAnchorV8_1Selector = selector(CreateBatchAnchorV8_1Signature)
	// CreateBatchAnchorV8_2Selector is the seven-argument call's selector.
	CreateBatchAnchorV8_2Selector = selector(CreateBatchAnchorV8_2Signature)
)

func selector(sig string) [4]byte {
	var s [4]byte
	copy(s[:], crypto.Keccak256([]byte(sig))[:4])
	return s
}

// BatchAnchorVersion names which anchor generation a createBatchAnchor call was made to.
type BatchAnchorVersion string

const (
	BatchAnchorV8_1 BatchAnchorVersion = "v8_1"
	BatchAnchorV8_2 BatchAnchorVersion = "v8_2"
)

// BatchAnchorCall is a decoded createBatchAnchor call of either generation. AccumulateSetRoot and Incarnation are zero
// on a V8.1 call, which committed neither.
type BatchAnchorCall struct {
	Version           BatchAnchorVersion
	BundleID          [32]byte
	Root              [32]byte
	LeafCount         uint64
	BatchOperationID  [32]byte
	Height            uint64
	AccumulateSetRoot [32]byte
	Incarnation       [32]byte
}

// DecodeCreateBatchAnchor reads createBatchAnchor calldata of either generation, chosen by its selector, and requires
// the bundle id to be the one the contract itself derives from the other arguments - so a decoded call is one the
// anchor would have accepted, never a well-formed call to a different derivation.
func DecodeCreateBatchAnchor(chainID int64, data []byte) (*BatchAnchorCall, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("calldata is %d bytes, not a createBatchAnchor call", len(data))
	}
	var sel [4]byte
	copy(sel[:], data[:4])
	c := &BatchAnchorCall{}
	var words int
	switch sel {
	case CreateBatchAnchorV8_1Selector:
		c.Version, words = BatchAnchorV8_1, 5
	case CreateBatchAnchorV8_2Selector:
		c.Version, words = BatchAnchorV8_2, 7
	default:
		return nil, fmt.Errorf("calldata selector %x is not createBatchAnchor", sel)
	}
	if len(data) != 4+words*32 {
		return nil, fmt.Errorf("%s createBatchAnchor calldata is %d bytes, want %d", c.Version, len(data), 4+words*32)
	}
	w := func(i int) []byte { return data[4+32*i : 4+32*(i+1)] }
	uint64At := func(i int) (uint64, error) {
		if !bytes.Equal(w(i)[:24], make([]byte, 24)) {
			return 0, fmt.Errorf("calldata word %d does not fit in 64 bits", i)
		}
		return new(big.Int).SetBytes(w(i)).Uint64(), nil
	}
	copy(c.BundleID[:], w(0))
	copy(c.Root[:], w(1))
	copy(c.BatchOperationID[:], w(3))
	var err error
	if c.LeafCount, err = uint64At(2); err != nil {
		return nil, err
	}
	if c.Height, err = uint64At(4); err != nil {
		return nil, err
	}
	var want [32]byte
	if c.Version == BatchAnchorV8_2 {
		copy(c.AccumulateSetRoot[:], w(5))
		copy(c.Incarnation[:], w(6))
		want = DeriveV8_2BatchBundleID(chainID, c.Root, c.LeafCount, c.BatchOperationID, c.Height, c.AccumulateSetRoot, c.Incarnation)
	} else {
		want = DeriveV8_1BatchBundleID(chainID, c.Root, c.LeafCount, c.BatchOperationID, c.Height)
	}
	if want != c.BundleID {
		return nil, fmt.Errorf("%s createBatchAnchor names bundle %x, but its arguments derive %x on chain %d",
			c.Version, c.BundleID[:8], want[:8], chainID)
	}
	return c, nil
}

// DeriveV8_1BatchBundleID is keccak256(abi.encodePacked("certen:batchbundle:v1", chainId, batchRoot, leafCount,
// batchOperationID, height)) - CertenAnchorV8_1's derivation, pinned against Solidity by
// execution.TestBatchTree_BundleIDMatchesSolidity through execution.DeriveBatchBundleID.
func DeriveV8_1BatchBundleID(chainID int64, root [32]byte, leafCount uint64, opID [32]byte, height uint64) [32]byte {
	var c, l, h [32]byte
	big.NewInt(chainID).FillBytes(c[:])
	new(big.Int).SetUint64(leafCount).FillBytes(l[:])
	new(big.Int).SetUint64(height).FillBytes(h[:])
	var out [32]byte
	copy(out[:], crypto.Keccak256([]byte("certen:batchbundle:v1"), c[:], root[:], l[:], opID[:], h[:]))
	return out
}
