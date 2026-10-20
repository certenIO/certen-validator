// Copyright 2026 Certen Protocol

package ethl1

// HashTreeRootSyncCommittee is hash_tree_root(SyncCommittee) of its 24,624-byte SSZ encoding. Any other length is a
// finality_evidence_malformed fault; the function never panics.
func HashTreeRootSyncCommittee(b []byte) ([32]byte, error) {
	if len(b) != SyncCommitteeBytes {
		return [32]byte{}, EvidenceMalformed("sync_committee", 0, "length", len(b), SyncCommitteeBytes)
	}
	return hashTreeRootSyncCommittee(b), nil
}

// DecodeLC decodes the LC part of an evidence container under the link bound of these pins (Pins.MaxLinks), so a caller cannot
// decode with a bound other than the one VerifyFinalizedHead enforces.
func (p Pins) DecodeLC(b []byte) (LC, error) { return DecodeLC(b, p.MaxLinks) }

// HashTreeRootBeaconBlockHeader is hash_tree_root(BeaconBlockHeader) of its 112-byte SSZ encoding.
func HashTreeRootBeaconBlockHeader(b []byte) ([32]byte, error) {
	if len(b) != BeaconBlockHeaderSize {
		return [32]byte{}, EvidenceMalformed("beacon_block_header", 0, "length", len(b), BeaconBlockHeaderSize)
	}
	return hashTreeRootBeaconHeader(decodeBeaconHeader(b)), nil
}

// ValidateContainer strictly validates one SSZ blob of the Gloas layout against its fixed size. kind is one of
// "BeaconBlockHeader" (112), "LightClientHeader" (496), "SyncCommittee" (24,624), "LightClientBootstrap" (25,472),
// "LightClientUpdate" (26,424) or "LightClientFinalityUpdate" (1,448). Every Gloas container is fixed-size, so the length is
// the whole of the validation: there are no offsets, padding bits or optional parts, and the encoding of the decoding is
// the input.
func ValidateContainer(kind string, b []byte) error {
	want, ok := map[string]int{
		"BeaconBlockHeader": BeaconBlockHeaderSize, "LightClientHeader": LightClientHeaderSize, "SyncCommittee": SyncCommitteeBytes,
		"LightClientBootstrap": LightClientBootstrapSize, "LightClientUpdate": LightClientUpdateSize,
		"LightClientFinalityUpdate": LightClientFinalityUpdateSize,
	}[kind]
	if !ok {
		return EvidenceMalformed("container", 0, "unknown_kind", 0, 0)
	}
	if len(b) != want {
		return EvidenceMalformed(kind, 0, "length", len(b), want)
	}
	return nil
}

// RootFromNormalizedBranch folds a leaf up a (zero-extended) branch to the generalized index gindex and returns the root
// the branch commits to. It is the construction side of IsValidNormalizedMerkleBranch, used by the vector generator.
func RootFromNormalizedBranch(leaf [32]byte, branch [][32]byte, gindex uint64) [32]byte {
	depth := floorLog2(gindex)
	index := gindex % (uint64(1) << uint(depth))
	extra := len(branch) - depth
	v := leaf
	for i := 0; i < depth; i++ {
		if (index>>uint(i))&1 == 1 {
			v = sha2(branch[extra+i][:], v[:])
		} else {
			v = sha2(v[:], branch[extra+i][:])
		}
	}
	return v
}

// SyncCommitteeSigningRoot is compute_signing_root(attested_header.beacon, compute_domain(DOMAIN_SYNC_COMMITTEE, version,
// genesis_validators_root)) for a 112-byte BeaconBlockHeader: the 32-byte message a sync committee signs.
func SyncCommitteeSigningRoot(beaconHeader []byte, version [4]byte, gvr [32]byte) ([32]byte, error) {
	root, err := HashTreeRootBeaconBlockHeader(beaconHeader)
	if err != nil {
		return [32]byte{}, err
	}
	return signingRoot(root, computeDomain(version, gvr)), nil
}
