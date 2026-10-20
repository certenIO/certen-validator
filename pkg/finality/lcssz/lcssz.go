// Copyright 2026 Certen Protocol

// Package lcssz locates and converts the parts of Ethereum light-client SSZ objects that the ledger tooling and the Sepolia
// builder need WITHOUT verifying anything: the next sync committee of a LightClientUpdate, the conversion of an update to the
// finality update that carries the same signature, and the slots of an object. It is the byte-level companion of
// pkg/finality/ethl1 (which verifies); every function here is pure, bounds-checked and returns an error for a blob that does
// not have the stated layout. Nothing it returns is trusted: callers hand the results to ethl1.VerifyFinalizedHead.
//
// Layouts (V2_SPEC_S7 3.2): Gloas objects are fixed-size (update 26,424 B, finality update 1,448 B, bootstrap 25,472 B); the
// electra layout (Electra and Fulu) is variable-size and decoded through SSZ offsets.
package lcssz

import (
	"encoding/binary"
	"fmt"
)

// Layout is the LB layout byte of the evidence container.
type Layout uint8

const (
	Electra Layout = 1
	Gloas   Layout = 2
)

// Sizes of the fixed parts. The numbers are those of ethl1 (ssz.go, electra.go); a test pins them to the real objects.
const (
	CommitteeBytes = 512*48 + 48 // SyncCommittee
	beaconHeader   = 112
	aggregate      = 512/8 + 96

	GloasUpdateSize         = 26424
	GloasFinalityUpdateSize = 1448
	GloasBootstrapSize      = 25472
	gloasHeader             = 496
	gloasNextBranch         = 11 * 32
	gloasFinalityBranch     = 9 * 32

	electraUpdateFixed         = 4 + CommitteeBytes + 6*32 + 4 + 7*32 + aggregate + 8 // 25,216
	electraFinalityUpdateFixed = 4 + 4 + 7*32 + aggregate + 8                         // 400
	electraBootstrapFixed      = 4 + CommitteeBytes + 6*32                            // 24,820
	electraHeaderFixed         = beaconHeader + 4 + 4*32                              // 244
	electraExecFixed           = 584
	electraExecNumberAt        = 404
	electraExecHashAt          = 472
)

// LayoutOfUpdate names the layout of a LightClientUpdate blob by its size: exactly 26,424 bytes is Gloas, anything longer is
// the electra layout. The decoders in ethl1 check the rest; a wrong guess is refused there, never accepted.
func LayoutOfUpdate(b []byte) Layout {
	if len(b) == GloasUpdateSize {
		return Gloas
	}
	return Electra
}

// LayoutOfFinalityUpdate is LayoutOfUpdate for a LightClientFinalityUpdate (1,448 bytes is Gloas).
func LayoutOfFinalityUpdate(b []byte) Layout {
	if len(b) == GloasFinalityUpdateSize {
		return Gloas
	}
	return Electra
}

// LayoutOfBootstrap is LayoutOfUpdate for a LightClientBootstrap (25,472 bytes is Gloas).
func LayoutOfBootstrap(b []byte) Layout {
	if len(b) == GloasBootstrapSize {
		return Gloas
	}
	return Electra
}

// NextCommittee returns the 24,624-byte next_sync_committee of a LightClientUpdate.
func NextCommittee(l Layout, update []byte) ([]byte, error) {
	switch l {
	case Gloas:
		if len(update) != GloasUpdateSize {
			return nil, fmt.Errorf("lcssz: a gloas update is %d bytes, got %d", GloasUpdateSize, len(update))
		}
		return update[gloasHeader : gloasHeader+CommitteeBytes], nil
	case Electra:
		if len(update) < electraUpdateFixed {
			return nil, fmt.Errorf("lcssz: an electra update is at least %d bytes, got %d", electraUpdateFixed, len(update))
		}
		return update[4 : 4+CommitteeBytes], nil
	}
	return nil, fmt.Errorf("lcssz: unknown layout %d", l)
}

// BootstrapCommittee returns the 24,624-byte current_sync_committee of a LightClientBootstrap.
func BootstrapCommittee(l Layout, boot []byte) ([]byte, error) {
	switch l {
	case Gloas:
		if len(boot) != GloasBootstrapSize {
			return nil, fmt.Errorf("lcssz: a gloas bootstrap is %d bytes, got %d", GloasBootstrapSize, len(boot))
		}
		return boot[gloasHeader : gloasHeader+CommitteeBytes], nil
	case Electra:
		if len(boot) < electraBootstrapFixed {
			return nil, fmt.Errorf("lcssz: an electra bootstrap is at least %d bytes, got %d", electraBootstrapFixed, len(boot))
		}
		return boot[4 : 4+CommitteeBytes], nil
	}
	return nil, fmt.Errorf("lcssz: unknown layout %d", l)
}

// UpdateToFinalityUpdate converts a LightClientUpdate to the LightClientFinalityUpdate that carries the same attested header,
// finalized header, finality branch, sync aggregate and signature slot (the next committee and its branch are dropped). It
// is the object the spec calls the update's finality projection; the signature stays valid because the signed message is the
// attested beacon header.
func UpdateToFinalityUpdate(l Layout, update []byte) ([]byte, error) {
	switch l {
	case Gloas:
		if len(update) != GloasUpdateSize {
			return nil, fmt.Errorf("lcssz: a gloas update is %d bytes, got %d", GloasUpdateSize, len(update))
		}
		out := make([]byte, 0, GloasFinalityUpdateSize)
		out = append(out, update[:gloasHeader]...) // attested
		finAt := gloasHeader + CommitteeBytes + gloasNextBranch
		out = append(out, update[finAt:finAt+gloasHeader]...)                                 // finalized
		out = append(out, update[finAt+gloasHeader:finAt+gloasHeader+gloasFinalityBranch]...) // finality branch
		out = append(out, update[finAt+gloasHeader+gloasFinalityBranch:]...)                  // aggregate + signature slot
		return out, nil
	case Electra:
		if len(update) < electraUpdateFixed {
			return nil, fmt.Errorf("lcssz: an electra update is at least %d bytes, got %d", electraUpdateFixed, len(update))
		}
		finOffAt := 4 + CommitteeBytes + 6*32
		attOff := int(binary.LittleEndian.Uint32(update))
		finOff := int(binary.LittleEndian.Uint32(update[finOffAt:]))
		if attOff != electraUpdateFixed || finOff < attOff || finOff > len(update) {
			return nil, fmt.Errorf("lcssz: electra update offsets %d,%d do not fit %d bytes", attOff, finOff, len(update))
		}
		att := update[attOff:finOff]
		fin := update[finOff:]
		branchAt := finOffAt + 4
		tail := update[branchAt : branchAt+7*32+aggregate+8]
		out := make([]byte, 0, electraFinalityUpdateFixed+len(att)+len(fin))
		out = binary.LittleEndian.AppendUint32(out, electraFinalityUpdateFixed)
		out = binary.LittleEndian.AppendUint32(out, uint32(electraFinalityUpdateFixed+len(att)))
		out = append(out, tail...)
		out = append(out, att...)
		out = append(out, fin...)
		return out, nil
	}
	return nil, fmt.Errorf("lcssz: unknown layout %d", l)
}

// FinalityUpdateSlots returns attested slot, finalized slot and signature slot of a LightClientFinalityUpdate.
func FinalityUpdateSlots(l Layout, fu []byte) (attested, finalized, signature uint64, err error) {
	switch l {
	case Gloas:
		if len(fu) != GloasFinalityUpdateSize {
			return 0, 0, 0, fmt.Errorf("lcssz: a gloas finality update is %d bytes, got %d", GloasFinalityUpdateSize, len(fu))
		}
		attested = binary.LittleEndian.Uint64(fu)
		finalized = binary.LittleEndian.Uint64(fu[gloasHeader:])
		signature = binary.LittleEndian.Uint64(fu[len(fu)-8:])
		return
	case Electra:
		min := electraFinalityUpdateFixed + 2*(electraHeaderFixed+electraExecFixed)
		if len(fu) < min {
			return 0, 0, 0, fmt.Errorf("lcssz: an electra finality update is at least %d bytes, got %d", min, len(fu))
		}
		attOff := int(binary.LittleEndian.Uint32(fu))
		finOff := int(binary.LittleEndian.Uint32(fu[4:]))
		if attOff != electraFinalityUpdateFixed || finOff <= attOff || finOff+8 > len(fu) {
			return 0, 0, 0, fmt.Errorf("lcssz: electra finality update offsets %d,%d do not fit %d bytes", attOff, finOff, len(fu))
		}
		attested = binary.LittleEndian.Uint64(fu[attOff:])
		finalized = binary.LittleEndian.Uint64(fu[finOff:])
		signature = binary.LittleEndian.Uint64(fu[electraFinalityUpdateFixed-8:])
		return
	}
	return 0, 0, 0, fmt.Errorf("lcssz: unknown layout %d", l)
}

// UpdateSlots returns attested slot, finalized slot and signature slot of a LightClientUpdate.
func UpdateSlots(l Layout, up []byte) (attested, finalized, signature uint64, err error) {
	fu, err := UpdateToFinalityUpdate(l, up)
	if err != nil {
		return 0, 0, 0, err
	}
	return FinalityUpdateSlots(l, fu)
}

// FinalizedExec returns what a finality update's finalized header says about its execution block: the hash always, and the
// block number only in the electra layout (a Gloas header carries only execution_block_hash). hasNumber reports which.
func FinalizedExec(l Layout, fu []byte) (hash [32]byte, number uint64, hasNumber bool, err error) {
	switch l {
	case Gloas:
		if len(fu) != GloasFinalityUpdateSize {
			return hash, 0, false, fmt.Errorf("lcssz: a gloas finality update is %d bytes, got %d", GloasFinalityUpdateSize, len(fu))
		}
		copy(hash[:], fu[gloasHeader+beaconHeader:gloasHeader+beaconHeader+32])
		return hash, 0, false, nil
	case Electra:
		if _, _, _, err = FinalityUpdateSlots(l, fu); err != nil {
			return hash, 0, false, err
		}
		finOff := int(binary.LittleEndian.Uint32(fu[4:]))
		ex := fu[finOff+electraHeaderFixed:]
		if len(ex) < electraExecFixed {
			return hash, 0, false, fmt.Errorf("lcssz: the finalized header is %d bytes, too short for an execution payload header", len(fu)-finOff)
		}
		copy(hash[:], ex[electraExecHashAt:electraExecHashAt+32])
		return hash, binary.LittleEndian.Uint64(ex[electraExecNumberAt:]), true, nil
	}
	return hash, 0, false, fmt.Errorf("lcssz: unknown layout %d", l)
}

// SplitFramedUpdates parses the framed /light_client/updates response body: per update a little-endian u64 length, a 4-byte
// fork digest and the SSZ object. The digest is returned beside the object for diagnostics only; it is never evidence.
func SplitFramedUpdates(body []byte) (objs [][]byte, digests [][4]byte, err error) {
	pos := 0
	for pos < len(body) {
		if pos+12 > len(body) {
			return nil, nil, fmt.Errorf("lcssz: updates frame truncated at %d", pos)
		}
		n := binary.LittleEndian.Uint64(body[pos:])
		if n < 4 || n > uint64(len(body)-pos-8) {
			return nil, nil, fmt.Errorf("lcssz: updates frame length %d at %d overruns the body", n, pos)
		}
		var d [4]byte
		copy(d[:], body[pos+8:pos+12])
		objs = append(objs, body[pos+12:pos+8+int(n)])
		digests = append(digests, d)
		pos += 8 + int(n)
	}
	return objs, digests, nil
}
