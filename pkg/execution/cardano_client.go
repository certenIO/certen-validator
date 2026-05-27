// HTTP client for the Cardano tx-server (certen-contracts/cardano/scripts/
// tx-server.ts). The server is a thin Node.js process running Lucid
// Evolution + Blockfrost; it builds and submits Cardano transactions on
// the Go validator's behalf.
//
// This split is intentional: Cardano transaction construction (UTXO
// selection, CBOR/Plutus Data encoding, fee + exec-unit estimation,
// witness assembly) is prohibitive to reimplement in Go and offers no
// security advantage — if the off-chain helper builds a bad tx, the
// on-chain Aiken validator rejects it. The Go validator keeps full
// authority over the security-critical work (BLS signing, commitment
// derivation, executor election).

package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// CardanoClient talks to the cardano-tx-server.
type CardanoClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewCardanoClient(baseURL string) *CardanoClient {
	if baseURL == "" {
		baseURL = "http://localhost:8787"
	}
	return &CardanoClient{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 5 * time.Minute},
	}
}

// =============================================================================
// Health probe
// =============================================================================

type CardanoHealth struct {
	OK                 bool   `json:"ok"`
	Network            string `json:"network"`
	Wallet             string `json:"wallet"`
	AnchorScriptHash   string `json:"anchor_script_hash"`
	AccountScriptHash  string `json:"account_script_hash"`
}

func (c *CardanoClient) Health(ctx context.Context) (*CardanoHealth, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/health", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tx-server unreachable: %w", err)
	}
	defer resp.Body.Close()
	var out CardanoHealth
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode health: %w", err)
	}
	return &out, nil
}

// =============================================================================
// TX1: create_anchor
// =============================================================================

type CardanoCreateAnchorRequest struct {
	BundleID             string `json:"bundle_id"`
	ADIURLHash           string `json:"adi_url_hash"`
	OperationCommitment  string `json:"operation_commitment"`
	CrossChainCommitment string `json:"cross_chain_commitment"`
	GovernanceRoot       string `json:"governance_root"`
	ExecutionCommitment  string `json:"execution_commitment"`
	OperationID          string `json:"operation_id"`
	MerkleRoot           string `json:"merkle_root"`
	ValidatorSetRoot     string `json:"validator_set_root"`
	DeploymentChainID    string `json:"deployment_chain_id"`
	BlockHeight          uint64 `json:"block_height"`
}

func (c *CardanoClient) CreateAnchor(ctx context.Context, req CardanoCreateAnchorRequest) (string, error) {
	body, err := c.post(ctx, "/tx/create-anchor", req)
	if err != nil {
		return "", err
	}
	return body.TxHash, nil
}

// =============================================================================
// TX2: execute_comprehensive_proof
// =============================================================================

type CardanoBLSProofJSON struct {
	ProofA              string `json:"proof_a"`
	ProofB              string `json:"proof_b"`
	ProofC              string `json:"proof_c"`
	Commitments         string `json:"commitments"`
	CommitmentPok       string `json:"commitment_pok"`
	MessageHash         string `json:"message_hash"`
	PubkeyCommitment    string `json:"pubkey_commitment"`
	SignedVotingPower   uint64 `json:"signed_voting_power"`
	TotalVotingPower    uint64 `json:"total_voting_power"`
	ThresholdNumerator  uint64 `json:"threshold_numerator"`
	ThresholdDenominator uint64 `json:"threshold_denominator"`
}

type CardanoGovernanceProofJSON struct {
	KeyBookURL         string   `json:"key_book_url"`
	KeyBookRoot        string   `json:"key_book_root"`
	KeyPageProofs      []string `json:"key_page_proofs"`
	AuthorityAddress   string   `json:"authority_address"`
	AuthorityLevel     uint64   `json:"authority_level"`
	RequiredSignatures uint64   `json:"required_signatures"`
	ProvidedSignatures uint64   `json:"provided_signatures"`
	ThresholdMet       bool     `json:"threshold_met"`
	Nonce              uint64   `json:"nonce"`
}

type CardanoComprehensiveProof struct {
	AnchorID                    string                     `json:"anchor_id"`
	LeafHash                    string                     `json:"leaf_hash"`
	ProofHashes                 []string                   `json:"proof_hashes"`
	BLSProof                    CardanoBLSProofJSON        `json:"bls_proof"`
	GovernanceProof             CardanoGovernanceProofJSON `json:"governance_proof"`
	OperationCommitment         string                     `json:"operation_commitment"`
	CrossChainCommitment        string                     `json:"cross_chain_commitment"`
	GovernanceRoot              string                     `json:"governance_root"`
	ExecutionCommitment         string                     `json:"execution_commitment"`
	ExpectedExecutionCommitment string                     `json:"expected_execution_commitment,omitempty"`
	ExpirationMs                uint64                     `json:"expiration_ms"`
}

type CardanoExecuteProofRequest struct {
	AnchorUTXORef string                    `json:"anchor_utxo_ref"`
	Proof         CardanoComprehensiveProof `json:"proof"`
}

func (c *CardanoClient) ExecuteComprehensiveProof(ctx context.Context, req CardanoExecuteProofRequest) (string, error) {
	body, err := c.post(ctx, "/tx/execute-proof", req)
	if err != nil {
		return "", err
	}
	return body.TxHash, nil
}

// =============================================================================
// TX3: execute_governance_proof_direct
// =============================================================================

type CardanoCall struct {
	Target          string   `json:"target"`
	Method          string   `json:"method"`
	Args            string   `json:"args"`
	DepositLovelace *big.Int `json:"-"`
	DepositStr      string   `json:"deposit_lovelace"`
	GasUnits        uint64   `json:"gas_units"`
	OpType          string   `json:"op_type"`
}

type CardanoAccountGovernanceProof struct {
	ADIURL                      string   `json:"adi_url"`
	AnchorID                    string   `json:"anchor_id"`
	MerkleProof                 []string `json:"merkle_proof"`
	KeyBookProof                struct {
		KeyBookURL     string `json:"key_book_url"`
		KeyBookRoot    string `json:"key_book_root"`
		HierarchyDepth uint64 `json:"hierarchy_depth"`
		KeyPageProofs  string `json:"key_page_proofs"`
		ValidFromSec   uint64 `json:"valid_from_sec"`
		ValidUntilSec  uint64 `json:"valid_until_sec"`
	} `json:"key_book_proof"`
	RoleProof struct {
		Level       uint64   `json:"level"`
		Permissions []string `json:"permissions"`
		RoleHash    string   `json:"role_hash"`
	} `json:"role_proof"`
	ThresholdProof struct {
		Numerator   uint64 `json:"numerator"`
		Denominator uint64 `json:"denominator"`
		VotingPower uint64 `json:"voting_power"`
	} `json:"threshold_proof"`
	ValidatorSignatures         string `json:"validator_signatures"`
	TimestampSec                uint64 `json:"timestamp_sec"`
	ExpiresAtSec                uint64 `json:"expires_at_sec"`
	Nonce                       uint64 `json:"nonce"`
	RequiredLevel               uint64 `json:"required_level"`
	ExpectedExecutionCommitment string `json:"expected_execution_commitment"`
	ProofHash                   string `json:"proof_hash"`
}

type CardanoExecuteGovernanceRequest struct {
	AccountUTXORef string                        `json:"account_utxo_ref"`
	AnchorUTXORef  string                        `json:"anchor_utxo_ref"`
	Proof          CardanoAccountGovernanceProof `json:"proof"`
	Calls          []CardanoCall                 `json:"calls"`
}

func (c *CardanoClient) ExecuteGovernanceProofDirect(ctx context.Context, req CardanoExecuteGovernanceRequest) (string, error) {
	// Serialize deposit_lovelace as string (JSON safe for big numbers).
	for i := range req.Calls {
		if req.Calls[i].DepositLovelace != nil {
			req.Calls[i].DepositStr = req.Calls[i].DepositLovelace.String()
		}
	}
	body, err := c.post(ctx, "/tx/execute-governance", req)
	if err != nil {
		return "", err
	}
	return body.TxHash, nil
}

// =============================================================================
// Internal HTTP helper
// =============================================================================

type cardanoTxResponse struct {
	OK     bool   `json:"ok"`
	TxHash string `json:"txHash"`
	Error  string `json:"error,omitempty"`
}

func (c *CardanoClient) post(ctx context.Context, path string, payload interface{}) (*cardanoTxResponse, error) {
	bs, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+path, bytes.NewReader(bs))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tx-server POST %s: %w", path, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var out cardanoTxResponse
	if jerr := json.Unmarshal(raw, &out); jerr != nil {
		return nil, fmt.Errorf("tx-server POST %s: status %d, body=%q", path, resp.StatusCode, string(raw))
	}
	if !out.OK || out.Error != "" {
		return nil, fmt.Errorf("tx-server POST %s: %s", path, out.Error)
	}
	return &out, nil
}
