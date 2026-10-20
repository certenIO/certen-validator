// Copyright 2026 Certen Protocol

// Package kzgsetup holds the Ethereum KZG ceremony output the Base and Arbitrum blob checks run under, byte-identical to
// ethereum/consensus-specs v1.7.0-beta.4 presets/mainnet/trusted_setups/trusted_setup_4096.json (raw-file SHA-256 below,
// compared with the tag's file on 2026-10-20 and with the copies inside go-ethereum v1.17.7 and go-eth-kzg v1.5.0), and a
// verification context built only from bytes whose SHA-256 equals the pin the caller passes.
package kzgsetup

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	gokzg "github.com/crate-crypto/go-eth-kzg"
)

//go:embed trusted_setup_4096.json
var setupFile []byte

// SetupSHA256 is the raw-file SHA-256 of the embedded setup (V2_SPEC_S7 section 4.2 kzg_setup_sha256, verified 2026-10-20).
const SetupSHA256 = "f8e44a31ebf0a6d0734dcb301b0716e2c77f3ae18ed0cab0870fbcc2ca55616f"

// Context verifies and (for builders) computes blob proofs under the setup.
type Context struct{ ctx *gokzg.Context }

var (
	once    sync.Once
	shared  *Context
	initErr error
)

// Load returns the shared context, building it once (about 11 s the first time: the secure context checks every point). The
// embedded file must hash to wantSHA256 (the pin); a different pin is an error, never a different setup.
func Load(wantSHA256 string) (*Context, error) {
	sum := sha256.Sum256(setupFile)
	if hex.EncodeToString(sum[:]) != wantSHA256 {
		return nil, fmt.Errorf("kzg setup: the embedded file hashes to %x, the pin is %s", sum, wantSHA256)
	}
	once.Do(func() {
		var js gokzg.JSONTrustedSetup
		if err := json.Unmarshal(setupFile, &js); err != nil {
			initErr = err
			return
		}
		c, err := gokzg.NewContext4096(&js)
		if err != nil {
			initErr = err
			return
		}
		shared = &Context{ctx: c}
	})
	return shared, initErr
}

// VerifyBlob is verify_blob_kzg_proof(blob, commitment, proof).
func (c *Context) VerifyBlob(blob []byte, commitment, proof [48]byte) error {
	if len(blob) != gokzg.ScalarsPerBlob*gokzg.SerializedScalarSize {
		return fmt.Errorf("blob length %d", len(blob))
	}
	var b gokzg.Blob
	copy(b[:], blob)
	return c.ctx.VerifyBlobKZGProof(&b, gokzg.KZGCommitment(commitment), gokzg.KZGProof(proof))
}

// Commit computes the commitment of a blob (builders only).
func (c *Context) Commit(blob []byte) ([48]byte, error) {
	var b gokzg.Blob
	if len(blob) != len(b) {
		return [48]byte{}, fmt.Errorf("blob length %d", len(blob))
	}
	copy(b[:], blob)
	k, err := c.ctx.BlobToKZGCommitment(&b, 0)
	return [48]byte(k), err
}

// Prove computes the blob proof for a commitment (builders only).
func (c *Context) Prove(blob []byte, commitment [48]byte) ([48]byte, error) {
	var b gokzg.Blob
	if len(blob) != len(b) {
		return [48]byte{}, fmt.Errorf("blob length %d", len(blob))
	}
	copy(b[:], blob)
	p, err := c.ctx.ComputeBlobKZGProof(&b, gokzg.KZGCommitment(commitment), 0)
	return [48]byte(p), err
}
