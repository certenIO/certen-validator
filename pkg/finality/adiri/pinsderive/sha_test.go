// Copyright 2026 Certen Protocol

package pinsderive_test

import (
	"crypto/sha256"
	"encoding/hex"
)

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
