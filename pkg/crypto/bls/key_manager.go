// Copyright 2025 Certen Protocol
//
// BLS Key Manager - Handles key generation, loading, and storage
// for validator BLS keys used in multi-validator consensus

package bls

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// KeyManager handles BLS key operations for a validator
type KeyManager struct {
	keyPath    string
	privateKey *PrivateKey
	publicKey  *PublicKey
}

// NewKeyManager creates a new key manager
func NewKeyManager(keyPath string) *KeyManager {
	return &KeyManager{
		keyPath: keyPath,
	}
}

// LoadOrGenerateKey loads an existing BLS key or generates a new one
// If the key file doesn't exist, generates a new key and saves it
func (km *KeyManager) LoadOrGenerateKey() error {
	if err := Initialize(); err != nil {
		return fmt.Errorf("initialize BLS: %w", err)
	}

	// Try to load existing key
	if km.keyPath != "" {
		if _, err := os.Stat(km.keyPath); err == nil {
			return km.LoadKey()
		}
	}

	// Generate new key
	return km.GenerateNewKey()
}

// LoadKey loads an existing BLS key from the key path
func (km *KeyManager) LoadKey() error {
	if km.keyPath == "" {
		return fmt.Errorf("no key path specified")
	}

	data, err := os.ReadFile(km.keyPath)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}

	// Key file contains hex-encoded private key
	keyBytes, err := hex.DecodeString(string(data))
	if err != nil {
		return fmt.Errorf("decode key hex: %w", err)
	}

	km.privateKey, err = PrivateKeyFromBytes(keyBytes)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	km.publicKey = km.privateKey.PublicKey()
	return nil
}

// GenerateNewKey generates a new BLS key pair
func (km *KeyManager) GenerateNewKey() error {
	var err error
	km.privateKey, km.publicKey, err = GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}

	// Save if path is specified
	if km.keyPath != "" {
		return km.SaveKey()
	}

	return nil
}

// GenerateFromSeed generates a deterministic key pair from a seed
// Useful for deriving keys from validator ID or other deterministic sources
func (km *KeyManager) GenerateFromSeed(seed []byte) error {
	var err error
	km.privateKey, km.publicKey, err = GenerateKeyPairFromSeed(seed)
	if err != nil {
		return fmt.Errorf("generate from seed: %w", err)
	}
	return nil
}

// GenerateFromValidatorID generates a deterministic key from validator ID
// This provides consistent key derivation across validator restarts
func (km *KeyManager) GenerateFromValidatorID(validatorID string, chainID string) error {
	// Create deterministic seed from validator ID and chain ID
	seed := sha256.Sum256([]byte(fmt.Sprintf("CERTEN_BLS_KEY_V1:%s:%s", validatorID, chainID)))
	return km.GenerateFromSeed(seed[:])
}

// SaveKey saves the private key to the key path
func (km *KeyManager) SaveKey() error {
	if km.keyPath == "" {
		return fmt.Errorf("no key path specified")
	}
	if km.privateKey == nil {
		return fmt.Errorf("no private key to save")
	}

	// Ensure directory exists
	dir := filepath.Dir(km.keyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}

	// Save as hex-encoded private key with restricted permissions
	keyHex := hex.EncodeToString(km.privateKey.Bytes())
	if err := os.WriteFile(km.keyPath, []byte(keyHex), 0600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}

	return nil
}

// GetPrivateKey returns the private key
func (km *KeyManager) GetPrivateKey() *PrivateKey {
	return km.privateKey
}

// GetPublicKey returns the public key
func (km *KeyManager) GetPublicKey() *PublicKey {
	return km.publicKey
}

// GetPublicKeyBytes returns the public key as bytes (for configuration)
func (km *KeyManager) GetPublicKeyBytes() []byte {
	if km.publicKey == nil {
		return nil
	}
	return km.publicKey.Bytes()
}

// GetPublicKeyHex returns the public key as a hex string
func (km *KeyManager) GetPublicKeyHex() string {
	if km.publicKey == nil {
		return ""
	}
	return km.publicKey.Hex()
}

// Sign signs a message with the private key
func (km *KeyManager) Sign(message []byte) (*Signature, error) {
	if km.privateKey == nil {
		return nil, fmt.Errorf("no private key loaded")
	}
	return km.privateKey.Sign(message), nil
}

// SignWithDomain signs a message with domain separation
func (km *KeyManager) SignWithDomain(message []byte, domain string) (*Signature, error) {
	if km.privateKey == nil {
		return nil, fmt.Errorf("no private key loaded")
	}
	return km.privateKey.SignWithDomain(message, domain), nil
}

// =============================================================================
// GLOBAL KEY MANAGEMENT - For use in main.go
// =============================================================================

var globalKeyManager *KeyManager

// InitializeValidatorBLSKey initializes the global validator BLS key
// Called from main.go during validator startup
func InitializeValidatorBLSKey(validatorID, chainID, keyPath string) (*KeyManager, error) {
	km := NewKeyManager(keyPath)

	// If key path exists, load it
	if keyPath != "" {
		if _, err := os.Stat(keyPath); err == nil {
			if err := km.LoadKey(); err != nil {
				return nil, fmt.Errorf("load BLS key: %w", err)
			}
			globalKeyManager = km
			return km, nil
		}
	}

	// Otherwise, generate deterministically from validator ID
	if err := km.GenerateFromValidatorID(validatorID, chainID); err != nil {
		return nil, fmt.Errorf("generate BLS key: %w", err)
	}

	// Save if path specified
	if keyPath != "" {
		if err := km.SaveKey(); err != nil {
			return nil, fmt.Errorf("save BLS key: %w", err)
		}
	}

	globalKeyManager = km
	return km, nil
}

// GetValidatorBLSKey returns the global validator BLS key manager
func GetValidatorBLSKey() *KeyManager {
	return globalKeyManager
}

// GetValidatorBLSPublicKey returns the global validator BLS public key as hex
// This is what should be used in ValidatorBlockBuilder config instead of "placeholder_bls_key"
func GetValidatorBLSPublicKey() string {
	if globalKeyManager == nil || globalKeyManager.publicKey == nil {
		return ""
	}
	return globalKeyManager.publicKey.Hex()
}

// GetPrivateKeyBytes returns the private key as bytes
func (km *KeyManager) GetPrivateKeyBytes() []byte {
	if km.privateKey == nil {
		return nil
	}
	return km.privateKey.Bytes()
}

// GetAddress returns an Ethereum-compatible address derived from the public key
// This is useful for identifying validators in Ethereum contracts
func (km *KeyManager) GetAddress() [20]byte {
	if km.publicKey == nil {
		return [20]byte{}
	}
	// Hash the public key and take first 20 bytes as address
	pubKeyBytes := km.publicKey.Bytes()
	hash := sha256.Sum256(pubKeyBytes)
	var addr [20]byte
	copy(addr[:], hash[:20])
	return addr
}
