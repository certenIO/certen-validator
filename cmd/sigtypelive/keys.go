package main

// The key store: one JSON file per key under keys/<adi>/ in the worktree. keys/ is gitignored (see .gitignore); only
// public values (public key, key hash) are ever copied into evidence.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

type keyFile struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Priv    string `json:"priv"`
	Pub     string `json:"pub"`
	KeyHash string `json:"keyHash"`
}

type keyStore struct{ dir string }

func (ks keyStore) path(name string) string { return filepath.Join(ks.dir, name+".json") }

// load returns the stored key called name, or (zero, false, nil) when none is stored.
func (ks keyStore) load(name string) (sigfixture.Key, bool, error) {
	b, err := os.ReadFile(ks.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return sigfixture.Key{}, false, nil
	}
	if err != nil {
		return sigfixture.Key{}, false, err
	}
	var kf keyFile
	if err := json.Unmarshal(b, &kf); err != nil {
		return sigfixture.Key{}, false, fmt.Errorf("%s: %w", ks.path(name), err)
	}
	t, ok2 := protocol.SignatureTypeByName(kf.Type)
	if !ok2 {
		return sigfixture.Key{}, false, fmt.Errorf("%s: unknown signature type %q", ks.path(name), kf.Type)
	}
	priv, err := hex.DecodeString(kf.Priv)
	if err != nil {
		return sigfixture.Key{}, false, fmt.Errorf("%s: private key is not hex", ks.path(name))
	}
	return sigfixture.Key{Type: t, Priv: priv}, true, nil
}

// loadOrCreate returns the key called name, generating and storing one when absent.
func (ks keyStore) loadOrCreate(name string, t protocol.SignatureType) (sigfixture.Key, error) {
	k, ok, err := ks.load(name)
	if err != nil {
		return k, err
	}
	if ok {
		if k.Type != t {
			return k, fmt.Errorf("stored key %s is %v, wanted %v", name, k.Type, t)
		}
		return k, nil
	}
	k, err = sigfixture.NewKey(t, rand.Reader)
	if err != nil {
		return k, err
	}
	pub, err := sigfixture.PublicKey(k)
	if err != nil {
		return k, err
	}
	kh, err := protocol.PublicKeyHash(pub, t)
	if err != nil {
		return k, err
	}
	if err := os.MkdirAll(ks.dir, 0o700); err != nil {
		return k, err
	}
	b, _ := json.MarshalIndent(keyFile{
		Name: name, Type: t.String(), Priv: hex.EncodeToString(k.Priv),
		Pub: hex.EncodeToString(pub), KeyHash: hex.EncodeToString(kh),
	}, "", " ")
	return k, os.WriteFile(ks.path(name), b, 0o600)
}

// pubAndHash returns the public key as signatures of k's type carry it, and the key-page entry hash.
func pubAndHash(k sigfixture.Key) (pub, hash []byte, err error) {
	pub, err = sigfixture.PublicKey(k)
	if err != nil {
		return nil, nil, err
	}
	hash, err = protocol.PublicKeyHash(pub, k.Type)
	return pub, hash, err
}
