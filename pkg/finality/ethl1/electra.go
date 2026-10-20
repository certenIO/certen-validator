// Copyright 2026 Certen Protocol

package ethl1

import "encoding/binary"

// The Electra layout (spec section 3.2): Electra and Fulu light-client objects. Their header is the Deneb LightClientHeader
//
//	{ beacon: BeaconBlockHeader (112), execution: ExecutionPayloadHeader (variable), execution_branch: Vector[Bytes32, 4] }
//
// so every container holding one is variable-size and is decoded through SSZ offsets, strictly: each offset is the exact
// value the fixed parts imply, each variable part lies inside the blob, and the blob ends where its last part ends. The only
// variable-length datum is ExecutionPayloadHeader.extra_data (ByteList[32]). Electra changed only the three BeaconState
// generalized indices (consensus-specs electra/light-client/sync-protocol.md): finalized root 169, current committee 86, next
// committee 87; the execution payload sits at gindex 25 of the BeaconBlockBody.
const (
	// ExecutionPayloadHeader (Deneb, Electra, Fulu: 17 fields): fixed part 584 bytes, extra_data offset at 436.
	electraExecFixed      = 584
	electraExecExtraOffAt = 436
	electraExecFieldCount = 17
	electraMaxExtraData   = 32
	// Offsets of the fields the verifier reads inside the fixed part.
	execOffParentHash = 0
	execOffFeeRecip   = 32
	execOffStateRoot  = 52
	execOffReceipts   = 84
	execOffLogsBloom  = 116
	execOffPrevRandao = 372
	execOffNumber     = 404
	execOffGasLimit   = 412
	execOffGasUsed    = 420
	execOffTimestamp  = 428
	execOffBaseFee    = 440
	execOffBlockHash  = 472
	execOffTxRoot     = 504
	execOffWithdrawal = 536
	execOffBlobGas    = 568
	execOffExcessBlob = 576

	electraExecBranchLen      = 4
	electraHeaderFixed        = BeaconBlockHeaderSize + 4 + 32*electraExecBranchLen // 244
	electraHeaderMin          = electraHeaderFixed + electraExecFixed               // 828
	electraHeaderMax          = electraHeaderMin + electraMaxExtraData              // 860
	electraFinalityBranchLen  = 7                                                   // floorlog2(169)
	electraCommitteeBranchLen = 6                                                   // floorlog2(86) = floorlog2(87)

	electraBootstrapFixed      = 4 + SyncCommitteeBytes + 32*electraCommitteeBranchLen // 24,820
	electraUpdateFixed         = 4 + SyncCommitteeBytes + 32*electraCommitteeBranchLen + 4 + 32*electraFinalityBranchLen + syncAggregateSize + 8
	electraFinalityUpdateFixed = 4 + 4 + 32*electraFinalityBranchLen + syncAggregateSize + 8

	// Minimum sizes of the electra layout (two minimum headers plus the fixed part), spec section 3.2 (e).
	electraMinBootstrap      = electraBootstrapFixed + electraHeaderMin
	electraMinUpdate         = electraUpdateFixed + 2*electraHeaderMin
	electraMinFinalityUpdate = electraFinalityUpdateFixed + 2*electraHeaderMin

	// Generalized indices of the Electra and Fulu forks.
	gindexFinalizedRootElectra  = 169
	gindexCurrentCommitteeElect = 86
	gindexNextCommitteeElectra  = 87
	gindexExecPayloadInBody     = 25
)

// gindices are the BeaconState generalized indices of a layout's light-client branches.
type gindices struct{ finalized, current, next uint64 }

func gindicesOf(l Layout) gindices {
	if l == LayoutElectra {
		return gindices{finalized: gindexFinalizedRootElectra, current: gindexCurrentCommitteeElect, next: gindexNextCommitteeElectra}
	}
	return gindices{finalized: gindexFinalizedRootGloas, current: gindexCurrentCommitteeGlo, next: gindexNextCommitteeGloas}
}

func le32(b []byte) int { return int(binary.LittleEndian.Uint32(b)) }

// decodeElectraHeader strictly decodes one SSZ LightClientHeader of the electra layout (the whole of b).
func decodeElectraHeader(b []byte, part string, index int) (lcHeader, *Fault) {
	if len(b) < electraHeaderMin || len(b) > electraHeaderMax {
		return lcHeader{}, EvidenceMalformed(part, index, "header_length", len(b), electraHeaderMin)
	}
	if off := le32(b[BeaconBlockHeaderSize:]); off != electraHeaderFixed {
		return lcHeader{}, EvidenceMalformed(part, index, "execution_offset", off, electraHeaderFixed)
	}
	exec := b[electraHeaderFixed:]
	if off := le32(exec[electraExecExtraOffAt:]); off != electraExecFixed {
		return lcHeader{}, EvidenceMalformed(part, index, "extra_data_offset", off, electraExecFixed)
	}
	if n := len(exec) - electraExecFixed; n > electraMaxExtraData {
		return lcHeader{}, EvidenceMalformed(part, index, "extra_data_length", n, electraMaxExtraData)
	}
	h := lcHeader{Shape: LayoutElectra, Beacon: decodeBeaconHeader(b[:BeaconBlockHeaderSize]), Exec: exec}
	copy(h.ExecHash[:], exec[execOffBlockHash:execOffBlockHash+32])
	h.Branch = decodeBranch(b[BeaconBlockHeaderSize+4:electraHeaderFixed], electraExecBranchLen)
	return h, nil
}

// executionHeaderRoot is hash_tree_root(ExecutionPayloadHeader) for the 17-field Deneb/Electra/Fulu container: seventeen
// leaves zero-padded to thirty-two. logs_bloom (ByteVector[256]) merkleizes as eight chunks; extra_data (ByteList[32])
// as one chunk mixed with its length; the uint64 and uint256 fields are their little-endian bytes zero-padded to a chunk.
func executionHeaderRoot(e []byte) [32]byte {
	var leaf [32][32]byte
	copy(leaf[0][:], e[execOffParentHash:execOffParentHash+32])
	copy(leaf[1][:], e[execOffFeeRecip:execOffFeeRecip+20])
	copy(leaf[2][:], e[execOffStateRoot:execOffStateRoot+32])
	copy(leaf[3][:], e[execOffReceipts:execOffReceipts+32])
	var bloom [8][32]byte
	for i := range bloom {
		copy(bloom[i][:], e[execOffLogsBloom+32*i:execOffLogsBloom+32*i+32])
	}
	leaf[4] = merkleize8(bloom)
	copy(leaf[5][:], e[execOffPrevRandao:execOffPrevRandao+32])
	copy(leaf[6][:8], e[execOffNumber:execOffNumber+8])
	copy(leaf[7][:8], e[execOffGasLimit:execOffGasLimit+8])
	copy(leaf[8][:8], e[execOffGasUsed:execOffGasUsed+8])
	copy(leaf[9][:8], e[execOffTimestamp:execOffTimestamp+8])
	extra := e[electraExecFixed:]
	var chunk, length [32]byte
	copy(chunk[:], extra)
	binary.LittleEndian.PutUint64(length[:8], uint64(len(extra)))
	leaf[10] = sha2(chunk[:], length[:])
	copy(leaf[11][:], e[execOffBaseFee:execOffBaseFee+32])
	copy(leaf[12][:], e[execOffBlockHash:execOffBlockHash+32])
	copy(leaf[13][:], e[execOffTxRoot:execOffTxRoot+32])
	copy(leaf[14][:], e[execOffWithdrawal:execOffWithdrawal+32])
	copy(leaf[15][:8], e[execOffBlobGas:execOffBlobGas+8])
	copy(leaf[16][:8], e[execOffExcessBlob:execOffExcessBlob+8])
	level := leaf[:]
	for len(level) > 1 {
		next := make([][32]byte, len(level)/2)
		for i := range next {
			next[i] = sha2(level[2*i][:], level[2*i+1][:])
		}
		level = next
	}
	return level[0]
}

func merkleize8(c [8][32]byte) [32]byte {
	level := c[:]
	for len(level) > 1 {
		next := make([][32]byte, len(level)/2)
		for i := range next {
			next[i] = sha2(level[2*i][:], level[2*i+1][:])
		}
		level = next
	}
	return level[0]
}

// decodeElectraBootstrap strictly decodes a LightClientBootstrap of the electra layout:
// offset(header) || current_sync_committee (24,624) || current_sync_committee_branch (6 nodes) || header.
func decodeElectraBootstrap(b []byte) (bootstrapObj, *Fault) {
	if len(b) < electraMinBootstrap {
		return bootstrapObj{}, EvidenceMalformed("anchor_body", 0, "length", len(b), electraMinBootstrap)
	}
	if off := le32(b); off != electraBootstrapFixed {
		return bootstrapObj{}, EvidenceMalformed("anchor_body", 0, "header_offset", off, electraBootstrapFixed)
	}
	h, f := decodeElectraHeader(b[electraBootstrapFixed:], "anchor_body", 0)
	if f != nil {
		return bootstrapObj{}, f
	}
	return bootstrapObj{
		Shape: LayoutElectra, Header: h,
		Committee:       b[4 : 4+SyncCommitteeBytes],
		CommitteeBranch: decodeBranch(b[4+SyncCommitteeBytes:electraBootstrapFixed], electraCommitteeBranchLen),
	}, nil
}

// decodeElectraUpdate strictly decodes a LightClientUpdate of the electra layout:
// offset(attested) || next_sync_committee || next_sync_committee_branch (6) || offset(finalized) || finality_branch (7) ||
// sync_aggregate (160) || signature_slot (8) || attested_header || finalized_header.
func decodeElectraUpdate(b []byte, index int) (updateObj, *Fault) {
	if len(b) < electraMinUpdate {
		return updateObj{}, EvidenceMalformed("link", index, "length", len(b), electraMinUpdate)
	}
	finOffAt := 4 + SyncCommitteeBytes + 32*electraCommitteeBranchLen
	if off := le32(b); off != electraUpdateFixed {
		return updateObj{}, EvidenceMalformed("link", index, "attested_offset", off, electraUpdateFixed)
	}
	fin := le32(b[finOffAt:])
	if fin < electraUpdateFixed+electraHeaderMin || fin > electraUpdateFixed+electraHeaderMax || fin > len(b) {
		return updateObj{}, EvidenceMalformed("link", index, "finalized_offset", fin, len(b))
	}
	att, f := decodeElectraHeader(b[electraUpdateFixed:fin], "link", index)
	if f != nil {
		return updateObj{}, f
	}
	fh, f := decodeElectraHeader(b[fin:], "link", index)
	if f != nil {
		return updateObj{}, f
	}
	o := 4
	u := updateObj{Shape: LayoutElectra, Attested: att, Finalized: fh, hasNextContainer: true}
	u.NextCommittee = b[o : o+SyncCommitteeBytes]
	o += SyncCommitteeBytes
	u.NextBranch = decodeBranch(b[o:o+32*electraCommitteeBranchLen], electraCommitteeBranchLen)
	o += 32*electraCommitteeBranchLen + 4
	u.FinalityBranch = decodeBranch(b[o:o+32*electraFinalityBranchLen], electraFinalityBranchLen)
	o += 32 * electraFinalityBranchLen
	u.Aggregate = decodeSyncAggregate(b[o : o+syncAggregateSize])
	o += syncAggregateSize
	u.SignatureSlot = binary.LittleEndian.Uint64(b[o : o+8])
	return u, nil
}

// decodeElectraFinalityUpdate strictly decodes a LightClientFinalityUpdate of the electra layout:
// offset(attested) || offset(finalized) || finality_branch (7) || sync_aggregate || signature_slot || attested || finalized.
func decodeElectraFinalityUpdate(b []byte) (updateObj, *Fault) {
	if len(b) < electraMinFinalityUpdate {
		return updateObj{}, EvidenceMalformed("final_update", 0, "length", len(b), electraMinFinalityUpdate)
	}
	if off := le32(b); off != electraFinalityUpdateFixed {
		return updateObj{}, EvidenceMalformed("final_update", 0, "attested_offset", off, electraFinalityUpdateFixed)
	}
	fin := le32(b[4:])
	if fin < electraFinalityUpdateFixed+electraHeaderMin || fin > electraFinalityUpdateFixed+electraHeaderMax || fin > len(b) {
		return updateObj{}, EvidenceMalformed("final_update", 0, "finalized_offset", fin, len(b))
	}
	att, f := decodeElectraHeader(b[electraFinalityUpdateFixed:fin], "final_update", 0)
	if f != nil {
		return updateObj{}, f
	}
	fh, f := decodeElectraHeader(b[fin:], "final_update", 0)
	if f != nil {
		return updateObj{}, f
	}
	u := updateObj{Shape: LayoutElectra, Attested: att, Finalized: fh}
	o := 8
	u.FinalityBranch = decodeBranch(b[o:o+32*electraFinalityBranchLen], electraFinalityBranchLen)
	o += 32 * electraFinalityBranchLen
	u.Aggregate = decodeSyncAggregate(b[o : o+syncAggregateSize])
	o += syncAggregateSize
	u.SignatureSlot = binary.LittleEndian.Uint64(b[o : o+8])
	return u, nil
}
