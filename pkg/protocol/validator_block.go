// Copyright 2025 Certen Protocol
//
// Protocol types - Aliases to canonical consensus types
// ValidatorBlock is now defined canonically in consensus package
//
// NOTE: Do not re-define ValidatorBlock or related types here. They must remain
// aliases to ensure a single canonical definition in the consensus package.

package protocol

import "github.com/certen/independant-validator/pkg/consensus"

// ValidatorBlock is aliased from the canonical definition in consensus package.
// CRITICAL: This MUST remain an alias - never redefine this type here.
type ValidatorBlock = consensus.ValidatorBlock

// Related types are also aliased for compatibility
type AuthorizationLeaf = consensus.AuthorizationLeaf
type MerkleBranch = consensus.MerkleBranch
type ChainTarget = consensus.ChainTarget
type ExternalChainResult = consensus.ExternalChainResult
type SyntheticTx = consensus.SyntheticTx
type ResultAttestation = consensus.ResultAttestation
type GovernanceProof = consensus.GovernanceProof
type CrossChainProof = consensus.CrossChainProof
type ExecutionProof = consensus.ExecutionProof
type AccumulateAnchorReference = consensus.AccumulateAnchorReference