// Copyright 2026 Certen Protocol

package consensus

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	cmtcrypto "github.com/cometbft/cometbft/crypto"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
)

// CometBFT key management (RB3-F95).
//
// A validator's consensus key (priv_validator_key.json) and P2P identity (node_key.json) used to be
// DERIVED from its name - sha256("certen-validator-key-" + chain + "-" + validatorID), a formula in a
// public repository - and deleted and re-derived on every boot, together with the double-sign state
// (priv_validator_state.json). Anyone could compute all seven consensus keys.
//
// The rules now:
//
//   - A key file is the key. It is never deleted, never overwritten, never re-derived from a name.
//   - A per-validator secret seed may back it: COMET_PRIVVAL_SEED (consensus key) and COMET_NODE_KEY_SEED
//     (P2P identity), 32-byte hex, held in the server's 0600 environment and the owner's backup, never
//     in the repository. With a seed, a lost file is re-created from it - identical - so deleting a file
//     cannot take a validator off the network; a file that disagrees with its seed is refused.
//   - No file and no seed: the node refuses to start. It never invents a key: a new key is a validator
//     the chain does not know, and a key from a formula is a key anyone can hold.
//   - The signing state is never deleted. Missing, it is created at height 0 - what CometBFT itself does
//     for a node that has never signed - and said so.
//   - The genesis is never generated here. Missing, the node refuses to start: a genesis written from
//     code on a wiped volume is a different chain.
//
// A key that is still the public formula's is named at every boot until it is rotated.

const (
	envPrivvalSeed = "COMET_PRIVVAL_SEED"
	envNodeKeySeed = "COMET_NODE_KEY_SEED"

	labelPrivval = "certen:comet-privval:v1"
	labelNodeKey = "certen:comet-node-key:v1"
)

// cometKeyPaths are the files a validator's CometBFT home holds.
type cometKeyPaths struct {
	privvalKey, privvalState, nodeKey, genesis string
}

func cometPaths(homeDir string) cometKeyPaths {
	return cometKeyPaths{
		privvalKey:   filepath.Join(homeDir, "config", "priv_validator_key.json"),
		privvalState: filepath.Join(homeDir, "data", "priv_validator_state.json"),
		nodeKey:      filepath.Join(homeDir, "config", "node_key.json"),
		genesis:      filepath.Join(homeDir, "config", "genesis.json"),
	}
}

// cometKeyReport is what ensureCometKeys established, for the boot log.
type cometKeyReport struct {
	PrivvalPubKey    cmtcrypto.PubKey
	NodeID           p2p.ID
	PrivvalFromSeed  bool // written from the seed on this boot (the file was missing)
	NodeKeyFromSeed  bool
	StateCreated     bool
	PrivvalIsFormula bool // still the public formula's key: rotate it
	NodeKeyIsFormula bool
}

// ensureCometKeys makes a validator's CometBFT home ready to start, by the rules above, or says why not.
// It only ever CREATES a missing file from its seed (or, for the signing state, at height 0); it never
// deletes or overwrites one.
func ensureCometKeys(homeDir, validatorID, chainID string, getenv func(string) string, logger *log.Logger) (*cometKeyReport, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	p := cometPaths(homeDir)
	rep := &cometKeyReport{}

	if _, err := os.Stat(p.genesis); err != nil {
		return nil, fmt.Errorf("CometBFT genesis %s: %w - the genesis is the chain's, provided by the operator; "+
			"it is never generated at boot", p.genesis, err)
	}

	privSeed, err := seedFromEnv(getenv, envPrivvalSeed)
	if err != nil {
		return nil, err
	}
	nodeSeed, err := seedFromEnv(getenv, envNodeKeySeed)
	if err != nil {
		return nil, err
	}

	// --- consensus key
	privKey, created, err := ensurePrivvalKey(p.privvalKey, privSeed)
	if err != nil {
		return nil, err
	}
	rep.PrivvalPubKey, rep.PrivvalFromSeed = privKey.PubKey(), created
	rep.PrivvalIsFormula = bytes.Equal(privKey.Bytes(), formulaKey(chainID, validatorID).Bytes())

	// --- signing state
	if _, err := os.Stat(p.privvalState); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(p.privvalState), 0o700); err != nil {
			return nil, fmt.Errorf("signing state directory: %w", err)
		}
		st := &privval.FilePVLastSignState{}
		if err := writeNewFile(p.privvalState, mustJSON(st)); err != nil {
			return nil, fmt.Errorf("create signing state %s: %w", p.privvalState, err)
		}
		rep.StateCreated = true
	} else if err != nil {
		return nil, fmt.Errorf("signing state %s: %w", p.privvalState, err)
	}

	// --- P2P identity
	nodePriv, nodeCreated, err := ensureNodeKey(p.nodeKey, nodeSeed)
	if err != nil {
		return nil, err
	}
	rep.NodeID, rep.NodeKeyFromSeed = p2p.PubKeyToID(nodePriv.PubKey()), nodeCreated
	rep.NodeKeyIsFormula = bytes.Equal(nodePriv.Bytes(), formulaKey(chainID, validatorID).Bytes())

	if logger != nil {
		logger.Printf("🔑 [COMET-KEYS] %s: consensus key %X (address %s)%s; node id %s%s",
			validatorID, rep.PrivvalPubKey.Bytes(), rep.PrivvalPubKey.Address(), fromSeedNote(rep.PrivvalFromSeed),
			rep.NodeID, fromSeedNote(rep.NodeKeyFromSeed))
		if rep.StateCreated {
			logger.Printf("⚠️ [COMET-KEYS] %s: no signing state was found; created at height 0 (a node that signed "+
				"before and lost this file can sign twice at a height it already signed)", validatorID)
		}
		if rep.PrivvalIsFormula {
			logger.Printf("🚨 [COMET-KEYS] %s: the consensus key is still the PUBLIC FORMULA key - anyone can derive it. "+
				"Rotate it (RB3-F95 runbook)", validatorID)
		}
		if rep.NodeKeyIsFormula {
			logger.Printf("🚨 [COMET-KEYS] %s: the P2P node key is still the PUBLIC FORMULA key. Rotate it (RB3-F95 runbook)", validatorID)
		}
	}
	return rep, nil
}

func fromSeedNote(created bool) string {
	if created {
		return " - re-created from its seed"
	}
	return ""
}

// seedFromEnv reads a 32-byte hex seed; unset is no seed, anything else malformed is refused.
func seedFromEnv(getenv func(string) string, name string) ([]byte, error) {
	raw := strings.TrimPrefix(strings.TrimSpace(getenv(name)), "0x")
	if raw == "" {
		return nil, nil
	}
	seed, err := hex.DecodeString(raw)
	if err != nil || len(seed) != 32 {
		// The value is a secret: named, never printed.
		return nil, fmt.Errorf("%s is not 32 bytes of hex", name)
	}
	return seed, nil
}

// keyFromSeed is the ed25519 key a seed backs: HMAC-SHA256(seed, label) as the ed25519 seed. A seed is exactly
// 32 bytes: HMAC zero-pads a shorter key, so "ab" and "ab00" would back one key (RB5-F24). Every entry point
// (seedFromEnv, validator-rotate's loadSeed and keygen) enforces it; this refuses anything else outright.
func keyFromSeed(seed []byte, label string) cmted25519.PrivKey {
	if len(seed) != 32 {
		panic(fmt.Sprintf("keyFromSeed: a seed is 32 bytes, not %d", len(seed)))
	}
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte(label))
	return cmted25519.PrivKey(ed25519.NewKeyFromSeed(mac.Sum(nil)))
}

// CometPrivvalKeyFromSeed is the consensus key a COMET_PRIVVAL_SEED backs - exactly what a node started with
// that seed writes. The rotation tool derives the new key's public half and possession proof from it.
func CometPrivvalKeyFromSeed(seed []byte) cmted25519.PrivKey { return keyFromSeed(seed, labelPrivval) }

// CometNodeKeyFromSeed is the P2P node key a COMET_NODE_KEY_SEED backs.
func CometNodeKeyFromSeed(seed []byte) cmted25519.PrivKey { return keyFromSeed(seed, labelNodeKey) }

// IsFormulaKey reports whether pub is the retired public-formula key of any validator-1..maxID on chainID -
// a key anyone can derive, which a rotation must never install.
func IsFormulaKey(chainID string, pub []byte, maxID int) (string, bool) {
	for i := 1; i <= maxID; i++ {
		id := fmt.Sprintf("validator-%d", i)
		if bytes.Equal(formulaKey(chainID, id).PubKey().Bytes(), pub) {
			return id, true
		}
	}
	return "", false
}

// formulaKey is the retired public-formula key, computed only to recognise it.
func formulaKey(chainID, validatorID string) cmted25519.PrivKey {
	s := sha256.Sum256([]byte(fmt.Sprintf("certen-validator-key-%s-%s", chainID, validatorID)))
	return cmted25519.PrivKey(ed25519.NewKeyFromSeed(s[:]))
}

func ensurePrivvalKey(path string, seed []byte) (cmted25519.PrivKey, bool, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		var k privval.FilePVKey
		if err := cmtjson.Unmarshal(raw, &k); err != nil {
			return nil, false, fmt.Errorf("consensus key %s does not decode: %w", path, err)
		}
		priv, ok := k.PrivKey.(cmted25519.PrivKey)
		if !ok || len(priv) != ed25519.PrivateKeySize {
			return nil, false, fmt.Errorf("consensus key %s is not an ed25519 key", path)
		}
		if !priv.PubKey().Equals(k.PubKey) || !bytes.Equal(k.Address, priv.PubKey().Address()) {
			return nil, false, fmt.Errorf("consensus key %s: its public key or address does not belong to its private key", path)
		}
		if seed != nil && !bytes.Equal(priv.Bytes(), keyFromSeed(seed, labelPrivval).Bytes()) {
			return nil, false, fmt.Errorf("consensus key %s is not the key %s backs; refusing to start rather than choose "+
				"(the file is left as it is)", path, envPrivvalSeed)
		}
		return priv, false, nil
	case errors.Is(err, fs.ErrNotExist):
		if seed == nil {
			return nil, false, fmt.Errorf("consensus key %s is missing and %s is not set; a validator never invents "+
				"its consensus key - restore the file or set its seed", path, envPrivvalSeed)
		}
		priv := keyFromSeed(seed, labelPrivval)
		k := privval.FilePVKey{Address: priv.PubKey().Address(), PubKey: priv.PubKey(), PrivKey: priv}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, false, err
		}
		if err := writeNewFile(path, mustJSON(k)); err != nil {
			return nil, false, fmt.Errorf("write consensus key %s from its seed: %w", path, err)
		}
		return priv, true, nil
	default:
		return nil, false, fmt.Errorf("consensus key %s: %w", path, err)
	}
}

func ensureNodeKey(path string, seed []byte) (cmted25519.PrivKey, bool, error) {
	_, statErr := os.Stat(path)
	switch {
	case statErr == nil:
		nk, err := p2p.LoadNodeKey(path)
		if err != nil {
			return nil, false, fmt.Errorf("node key %s does not decode: %w", path, err)
		}
		priv, ok := nk.PrivKey.(cmted25519.PrivKey)
		if !ok {
			return nil, false, fmt.Errorf("node key %s is not an ed25519 key", path)
		}
		if seed != nil && !bytes.Equal(priv.Bytes(), keyFromSeed(seed, labelNodeKey).Bytes()) {
			return nil, false, fmt.Errorf("node key %s is not the key %s backs; refusing to start rather than choose "+
				"(the file is left as it is)", path, envNodeKeySeed)
		}
		return priv, false, nil
	case errors.Is(statErr, fs.ErrNotExist):
		if seed == nil {
			return nil, false, fmt.Errorf("node key %s is missing and %s is not set; the node's identity is never "+
				"invented - its peers know it by id. Restore the file or set its seed", path, envNodeKeySeed)
		}
		priv := keyFromSeed(seed, labelNodeKey)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, false, err
		}
		if err := writeNewFile(path, mustJSON(&p2p.NodeKey{PrivKey: priv})); err != nil {
			return nil, false, fmt.Errorf("write node key %s from its seed: %w", path, err)
		}
		return priv, true, nil
	default:
		return nil, false, fmt.Errorf("node key %s: %w", path, statErr)
	}
}

func mustJSON(v interface{}) []byte {
	b, err := cmtjson.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("encode %T: %v", v, err))
	}
	return b
}

// writeNewFile writes a file that must not exist yet (O_EXCL), 0600, synced - so no call here can ever
// overwrite a key or a signing state that is already there.
func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
