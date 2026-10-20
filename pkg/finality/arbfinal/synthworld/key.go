// Copyright 2026 Certen Protocol

package synthworld

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/crypto"
)

// ecdsaKey is a deterministic test key derived from a label (never a funded or real key; it only signs synthetic
// transactions whose signature the verifier does not check).
type ecdsaKey struct{ k *ecdsa.PrivateKey }

func newTxKey(label string) *ecdsaKey {
	seed := crypto.Keccak256([]byte("certen/arbfinal/synth/txkey/" + label))
	k, err := crypto.ToECDSA(seed)
	if err != nil {
		panic(err)
	}
	return &ecdsaKey{k: k}
}
