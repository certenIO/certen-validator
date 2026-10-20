// Copyright 2026 Certen Protocol

package ethl1

import (
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
)

// SSZ for the Gloas light-client containers. Every Gloas container is fixed-size, so no SSZ library is needed: a blob is
// valid iff its length is exactly the fixed size, and then its encoding is the unique encoding of its decoding.
const (
	// BeaconBlockHeaderSize is slot(8) + proposer_index(8) + parent_root + state_root + body_root.
	BeaconBlockHeaderSize = 112
	// GloasExecutionBranchLen is the depth of EXECUTION_BLOCK_HASH_GINDEX_GLOAS (2856).
	GloasExecutionBranchLen = 11
	// LightClientHeaderSize is beacon(112) + execution_block_hash(32) + 11 * 32.
	LightClientHeaderSize = BeaconBlockHeaderSize + 32 + 32*GloasExecutionBranchLen
	// SyncCommitteeSize is 512 * 48 + 48 (aggregate_pubkey).
	SyncCommitteeBytes = SyncCommitteeSize*48 + 48
	// Branch lengths at the Gloas gindices.
	gloasFinalityBranchLen   = 9
	gloasCommitteeBranchLen  = 11
	syncAggregateSize        = SyncCommitteeSize/8 + 96
	LightClientBootstrapSize = LightClientHeaderSize + SyncCommitteeBytes + 32*gloasCommitteeBranchLen
	LightClientUpdateSize    = LightClientHeaderSize + SyncCommitteeBytes + 32*gloasCommitteeBranchLen +
		LightClientHeaderSize + 32*gloasFinalityBranchLen + syncAggregateSize + 8
	LightClientFinalityUpdateSize = LightClientHeaderSize + LightClientHeaderSize + 32*gloasFinalityBranchLen + syncAggregateSize + 8

	// Generalized indices (CS gloas light-client sync-protocol.md and frozen earlier values).
	gindexFinalizedRootGloas  = 735
	gindexCurrentCommitteeGlo = 2945
	gindexNextCommitteeGloas  = 2946
	gindexExecHashGloas       = 2856
	gindexExecHashDeneb       = 812 // EXECUTION_BLOCK_HASH_GINDEX_DENEB (pre-Gloas header brought forward)
	gindexExecHashCapella     = 412 // EXECUTION_BLOCK_HASH_GINDEX
)

// beaconHeader is a decoded BeaconBlockHeader.
type beaconHeader struct {
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    [32]byte
	StateRoot     [32]byte
	BodyRoot      [32]byte
}

func decodeBeaconHeader(b []byte) beaconHeader {
	var h beaconHeader
	h.Slot = binary.LittleEndian.Uint64(b[0:8])
	h.ProposerIndex = binary.LittleEndian.Uint64(b[8:16])
	copy(h.ParentRoot[:], b[16:48])
	copy(h.StateRoot[:], b[48:80])
	copy(h.BodyRoot[:], b[80:112])
	return h
}

func sha2(a, b []byte) [32]byte {
	var buf [64]byte
	copy(buf[:32], a)
	copy(buf[32:], b)
	return sha256.Sum256(buf[:])
}

// hashTreeRootBeaconHeader is hash_tree_root(BeaconBlockHeader): five 32-byte leaves padded with zero chunks to eight.
func hashTreeRootBeaconHeader(h beaconHeader) [32]byte {
	var l [8][32]byte
	binary.LittleEndian.PutUint64(l[0][:8], h.Slot)
	binary.LittleEndian.PutUint64(l[1][:8], h.ProposerIndex)
	l[2], l[3], l[4] = h.ParentRoot, h.StateRoot, h.BodyRoot
	a := sha2(l[0][:], l[1][:])
	b := sha2(l[2][:], l[3][:])
	c := sha2(l[4][:], l[5][:])
	d := sha2(l[6][:], l[7][:])
	ab := sha2(a[:], b[:])
	cd := sha2(c[:], d[:])
	return sha2(ab[:], cd[:])
}

// hashTreeRootPubkey is hash_tree_root(Bytes48): two chunks, the second zero-padded.
func hashTreeRootPubkey(pk []byte) [32]byte {
	var second [32]byte
	copy(second[:16], pk[32:48])
	return sha2(pk[0:32], second[:])
}

// hashTreeRootSyncCommittee is hash_tree_root(SyncCommittee) of its 24,624-byte SSZ: the root of the 512-pubkey vector
// mixed with the root of aggregate_pubkey.
func hashTreeRootSyncCommittee(b []byte) [32]byte {
	return hashTreeRootSyncCommitteeN(b, SyncCommitteeSize)
}

// hashTreeRootSyncCommitteeN is the same for a committee of n seats (n a power of two): n*48+48 bytes.
func hashTreeRootSyncCommitteeN(b []byte, n int) [32]byte {
	level := make([][32]byte, n)
	for i := 0; i < n; i++ {
		level[i] = hashTreeRootPubkey(b[i*48 : i*48+48])
	}
	for len(level) > 1 {
		next := make([][32]byte, len(level)/2)
		for i := range next {
			next[i] = sha2(level[2*i][:], level[2*i+1][:])
		}
		level = next
	}
	agg := hashTreeRootPubkey(b[n*48 : n*48+48])
	return sha2(level[0][:], agg[:])
}

func floorLog2(x uint64) int { return bits.Len64(x) - 1 }

// isValidMerkleBranch is the Phase 0 is_valid_merkle_branch.
func isValidMerkleBranch(leaf [32]byte, branch [][32]byte, depth int, index uint64, root [32]byte) bool {
	v := leaf
	for i := 0; i < depth; i++ {
		if (index>>uint(i))&1 == 1 {
			v = sha2(branch[i][:], v[:])
		} else {
			v = sha2(v[:], branch[i][:])
		}
	}
	return v == root
}

// IsValidNormalizedMerkleBranch is the Altair is_valid_normalized_merkle_branch: the leading len(branch)-depth nodes of the
// branch must be zero (a header carried forward from an earlier fork has a longer, zero-extended branch).
func IsValidNormalizedMerkleBranch(leaf [32]byte, branch [][32]byte, gindex uint64, root [32]byte) bool {
	depth := floorLog2(gindex)
	index := gindex % (uint64(1) << uint(depth))
	numExtra := len(branch) - depth
	if numExtra < 0 {
		return false
	}
	var zero [32]byte
	for i := 0; i < numExtra; i++ {
		if branch[i] != zero {
			return false
		}
	}
	return isValidMerkleBranch(leaf, branch[numExtra:], depth, index, root)
}

// lcHeader is a decoded LightClientHeader of either layout. Shape is the layout it was parsed by. For the Gloas shape
// ExecHash is the execution_block_hash field and Branch has 11 nodes; for the Electra shape ExecHash is
// execution.block_hash, Exec holds the whole SSZ ExecutionPayloadHeader (584 fixed bytes then extra_data) and Branch has 4.
type lcHeader struct {
	Shape    Layout
	Beacon   beaconHeader
	ExecHash [32]byte
	Branch   [][32]byte
	Exec     []byte
}

func decodeBranch(b []byte, n int) [][32]byte {
	out := make([][32]byte, n)
	for i := range out {
		copy(out[i][:], b[i*32:i*32+32])
	}
	return out
}

func decodeLCHeader(b []byte) lcHeader {
	var h lcHeader
	h.Shape = LayoutGloas
	h.Beacon = decodeBeaconHeader(b[:BeaconBlockHeaderSize])
	copy(h.ExecHash[:], b[BeaconBlockHeaderSize:BeaconBlockHeaderSize+32])
	h.Branch = decodeBranch(b[BeaconBlockHeaderSize+32:LightClientHeaderSize], GloasExecutionBranchLen)
	return h
}

func (h lcHeader) isEmpty() bool {
	var zero [32]byte
	if h.Beacon != (beaconHeader{}) || h.ExecHash != zero {
		return false
	}
	for _, n := range h.Branch {
		if n != zero {
			return false
		}
	}
	// LightClientHeader() has every execution field zero and an empty extra_data; its SSZ still carries the extra_data offset (584), so the
	// offset bytes are not part of the comparison (consensus-specs compares decoded values)
	if h.Shape == LayoutElectra && (len(h.Exec) != electraExecFixed || !allZero(h.Exec[:electraExecExtraOffAt]) || !allZero(h.Exec[electraExecExtraOffAt+4:])) {
		return false
	}
	return true
}

// syncAggregate is the decoded SyncAggregate: Bits has committeeSize/8 bytes.
type syncAggregate struct {
	Bits      []byte
	Signature [96]byte
}

func decodeSyncAggregate(b []byte, pr preset) syncAggregate {
	var s syncAggregate
	nb := pr.committeeSize / 8
	s.Bits = append([]byte(nil), b[:nb]...)
	copy(s.Signature[:], b[nb:nb+96])
	return s
}

func (s syncAggregate) count() int {
	n := 0
	for _, x := range s.Bits {
		n += bits.OnesCount8(x)
	}
	return n
}

func (s syncAggregate) bit(i int) bool { return s.Bits[i/8]>>(uint(i)%8)&1 == 1 }

// bootstrapObj is a decoded LightClientBootstrap.
type bootstrapObj struct {
	Shape           Layout
	Header          lcHeader
	Committee       []byte // committeeBytes, aliasing the input
	CommitteeBranch [][32]byte
}

func decodeBootstrap(b []byte, pr preset) bootstrapObj {
	var o bootstrapObj
	o.Shape = LayoutGloas
	o.Header = decodeLCHeader(b[:LightClientHeaderSize])
	o.Committee = b[LightClientHeaderSize : LightClientHeaderSize+pr.committeeBytes()]
	o.CommitteeBranch = decodeBranch(b[LightClientHeaderSize+pr.committeeBytes():], gloasCommitteeBranchLen)
	return o
}

// updateObj is a decoded LightClientUpdate or LightClientFinalityUpdate (no next committee).
type updateObj struct {
	Shape            Layout
	Attested         lcHeader
	NextCommittee    []byte // nil for a finality update
	NextBranch       [][32]byte
	Finalized        lcHeader
	FinalityBranch   [][32]byte
	Aggregate        syncAggregate
	SignatureSlot    uint64
	hasNextContainer bool
}

func decodeUpdate(b []byte, pr preset) updateObj {
	var u updateObj
	u.Shape = LayoutGloas
	o := 0
	u.Attested = decodeLCHeader(b[o : o+LightClientHeaderSize])
	o += LightClientHeaderSize
	u.NextCommittee = b[o : o+pr.committeeBytes()]
	o += pr.committeeBytes()
	u.NextBranch = decodeBranch(b[o:], gloasCommitteeBranchLen)
	o += 32 * gloasCommitteeBranchLen
	u.Finalized = decodeLCHeader(b[o : o+LightClientHeaderSize])
	o += LightClientHeaderSize
	u.FinalityBranch = decodeBranch(b[o:], gloasFinalityBranchLen)
	o += 32 * gloasFinalityBranchLen
	u.Aggregate = decodeSyncAggregate(b[o:o+pr.aggregateBytes()], pr)
	o += pr.aggregateBytes()
	u.SignatureSlot = binary.LittleEndian.Uint64(b[o : o+8])
	u.hasNextContainer = true
	return u
}

func decodeFinalityUpdate(b []byte, pr preset) updateObj {
	var u updateObj
	u.Shape = LayoutGloas
	o := 0
	u.Attested = decodeLCHeader(b[o : o+LightClientHeaderSize])
	o += LightClientHeaderSize
	u.Finalized = decodeLCHeader(b[o : o+LightClientHeaderSize])
	o += LightClientHeaderSize
	u.FinalityBranch = decodeBranch(b[o:], gloasFinalityBranchLen)
	o += 32 * gloasFinalityBranchLen
	u.Aggregate = decodeSyncAggregate(b[o:o+pr.aggregateBytes()], pr)
	o += pr.aggregateBytes()
	u.SignatureSlot = binary.LittleEndian.Uint64(b[o : o+8])
	return u
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func branchAllZero(br [][32]byte) bool {
	for _, n := range br {
		if n != ([32]byte{}) {
			return false
		}
	}
	return true
}
