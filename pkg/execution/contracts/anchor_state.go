package contracts

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// AnchorState is `anchors(bundleId)` of either batch anchor generation. CertenAnchorV8_1 returns fifteen fields;
// CertenAnchorV8_2 appends the Accumulate validator set root and incarnation (seventeen). The V8.1 layout is exactly
// V8.2's first fifteen fields - checked from both compiled artifacts (RUNLOG_RB5) and pinned by
// TestDecodeAnchorsReturn_BothGenerations. AccumulateSetRoot and Incarnation are zero on a V8.1 anchor, which
// committed neither.
type AnchorState struct {
	Version               BatchAnchorVersion
	BundleID              [32]byte
	MerkleRoot            [32]byte
	AdiURLHash            [32]byte
	OperationCommitment   [32]byte
	CrossChainCommitment  [32]byte
	GovernanceRoot        [32]byte
	ExecutionCommitment   [32]byte
	OperationID           [32]byte
	AccumulateBlockHeight *big.Int
	Timestamp             *big.Int
	Validator             common.Address
	Valid                 bool
	ProofExecuted         bool
	GovernanceExecuted    bool
	GovernanceLevel       uint8
	AccumulateSetRoot     [32]byte
	Incarnation           [32]byte
}

var anchorsGetter = func() abi.Method {
	parsed, err := abi.JSON(strings.NewReader(CertenAnchorV8_2BatchABI))
	if err != nil {
		panic(fmt.Sprintf("CertenAnchorV8_2 batch ABI: %v", err))
	}
	m, ok := parsed.Methods["anchors"]
	if !ok || len(m.Outputs) != 17 {
		panic("CertenAnchorV8_2 batch ABI has no seventeen-field anchors getter")
	}
	return m
}()

// AnchorsCallData is the calldata of anchors(bundleId) - the same selector on both generations.
func AnchorsCallData(bundleID [32]byte) []byte {
	in, err := anchorsGetter.Inputs.Pack(bundleID)
	if err != nil {
		panic(err) // a bytes32 always packs
	}
	return append(append([]byte{}, anchorsGetter.ID...), in...)
}

// DecodeAnchorsReturn decodes anchors(bundleId)'s return data by its length: 15 words is a V8.1 anchor, 17 a V8.2
// anchor; anything else is not an anchor this code knows and is refused.
func DecodeAnchorsReturn(ret []byte) (*AnchorState, error) {
	outputs := anchorsGetter.Outputs
	s := &AnchorState{}
	switch len(ret) {
	case 15 * 32:
		outputs, s.Version = outputs[:15], BatchAnchorV8_1
	case 17 * 32:
		s.Version = BatchAnchorV8_2
	default:
		return nil, fmt.Errorf("anchors() returned %d bytes: neither a V8.1 (15 fields) nor a V8.2 (17 fields) anchor", len(ret))
	}
	v, err := outputs.Unpack(ret)
	if err != nil {
		return nil, fmt.Errorf("anchors() return data does not decode as %s: %w", s.Version, err)
	}
	b32 := func(i int) [32]byte { return *abi.ConvertType(v[i], new([32]byte)).(*[32]byte) }
	s.BundleID, s.MerkleRoot, s.AdiURLHash, s.OperationCommitment = b32(0), b32(1), b32(2), b32(3)
	s.CrossChainCommitment, s.GovernanceRoot, s.ExecutionCommitment, s.OperationID = b32(4), b32(5), b32(6), b32(7)
	s.AccumulateBlockHeight = *abi.ConvertType(v[8], new(*big.Int)).(**big.Int)
	s.Timestamp = *abi.ConvertType(v[9], new(*big.Int)).(**big.Int)
	s.Validator = *abi.ConvertType(v[10], new(common.Address)).(*common.Address)
	s.Valid = *abi.ConvertType(v[11], new(bool)).(*bool)
	s.ProofExecuted = *abi.ConvertType(v[12], new(bool)).(*bool)
	s.GovernanceExecuted = *abi.ConvertType(v[13], new(bool)).(*bool)
	s.GovernanceLevel = *abi.ConvertType(v[14], new(uint8)).(*uint8)
	if s.Version == BatchAnchorV8_2 {
		s.AccumulateSetRoot, s.Incarnation = b32(15), b32(16)
	}
	return s, nil
}
