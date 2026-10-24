// Copyright 2026 Certen Protocol

package contractidentity

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/certen/independant-validator/pkg/finality"
)

// DigestDomain is the domain tag of the container digest. It appears in exactly this one preimage (Q2 item 4) and nowhere else.
const DigestDomain = "certen:contract-identity:v1"

func lp(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(b)), uint32(len(b)))
	return append(out, b...)
}

// DigestPreimage is lp(DigestDomain) || lp(d0) || lp(SHA-256(container)).
func DigestPreimage(d0 [32]byte, container []byte) []byte {
	sum := sha256.Sum256(container)
	var out []byte
	out = append(out, lp([]byte(DigestDomain))...)
	out = append(out, lp(d0[:])...)
	out = append(out, lp(sum[:])...)
	return out
}

// Digest is SHA-256(DigestPreimage): a storage-consistency check of the container against the leg it is about, never authenticity
// (Q2 item 4, as V2_SPEC_S7 2.6 states for D0). d0 is finality.LegBinding of the leg.
func Digest(d0 [32]byte, container []byte) [32]byte {
	return sha256.Sum256(DigestPreimage(d0, container))
}

// DigestOf is Digest under D0 = finality.LegBinding(chain, number, hash).
func DigestOf(chain, number uint64, hash [32]byte, container []byte) [32]byte {
	return Digest(finality.LegBinding(chain, number, hash), container)
}
