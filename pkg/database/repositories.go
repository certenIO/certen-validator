// Copyright 2025 Certen Protocol
//
// Repositories - Convenience wrapper for all database repositories
// Provides a single point of access to all repository types

package database

// Repositories holds all repository instances
type Repositories struct {
	Batches        *BatchRepository
	Anchors        *AnchorRepository
	Proofs         *ProofRepository
	ProofArtifacts *ProofArtifactRepository // NEW: Comprehensive proof artifact storage
	Attestations   *AttestationRepository
	Requests       *RequestRepository
	Consensus      *ConsensusRepository // Consensus entries and batch attestations
	Unified        *UnifiedRepository   // Multi-chain unified attestations and chain execution results
}

// NewRepositories creates all repositories with the given client
func NewRepositories(client *Client) *Repositories {
	return &Repositories{
		Batches:        NewBatchRepository(client),
		Anchors:        NewAnchorRepository(client),
		Proofs:         NewProofRepository(client),
		ProofArtifacts: NewProofArtifactRepository(client.DB()), // NEW: Uses raw *sql.DB
		Attestations:   NewAttestationRepository(client),
		Requests:       NewRequestRepository(client),
		Consensus:      NewConsensusRepository(client),
		Unified:        NewUnifiedRepository(client.DB()),       // Multi-chain unified tables
	}
}
