// Copyright 2025 Certen Protocol
//
// Intent Type Aliases - Canonical definitions are in consensus package
// This file provides backward compatibility aliases to prevent import cycles.

package protocol

import "github.com/certen/independant-validator/pkg/consensus"

// CertenIntent is an alias to the canonical type in the consensus package.
// DO NOT redefine this type here - it must remain an alias to ensure
// a single canonical definition throughout the codebase.
type CertenIntent = consensus.CertenIntent

// All raw* helper types moved to pkg/intent/conversion.go to avoid duplication.
// If you need to parse intent blobs, use the functions in that package.