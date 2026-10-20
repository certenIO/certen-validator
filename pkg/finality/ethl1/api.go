// Copyright 2026 Certen Protocol

package ethl1

import "fmt"

// HashTreeRootSyncCommittee is hash_tree_root(SyncCommittee) of its 24,624-byte SSZ encoding.
func HashTreeRootSyncCommittee(b []byte) [32]byte {
	if len(b) != SyncCommitteeBytes {
		panic(fmt.Sprintf("ethl1: SyncCommittee is %d bytes, got %d", SyncCommitteeBytes, len(b)))
	}
	return hashTreeRootSyncCommittee(b)
}

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
