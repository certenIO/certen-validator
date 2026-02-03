// Copyright 2025 Certen Protocol
//
// Anchor Configuration Loader
// Per ANCHOR_V3_IMPLEMENTATION_PLAN.md Phase 5 Task 5.4
//
// This package provides configuration loading for CertenAnchor V3
// from YAML files with environment variable substitution.

package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ==============================================================================
// Anchor Configuration Structures
// ==============================================================================

// AnchorConfig holds all anchor-specific configuration
type AnchorConfig struct {
	Environment string `yaml:"environment"`
	Version     string `yaml:"version"`

	Anchor     AnchorSettings     `yaml:"anchor"`
	Network    NetworkSettings    `yaml:"network"`
	Validator  ValidatorSettings  `yaml:"validator"`
	Database   DatabaseSettings   `yaml:"database"`
	Security   SecuritySettings   `yaml:"security"`
	Monitoring MonitoringSettings `yaml:"monitoring"`
	CometBFT   CometBFTSettings   `yaml:"cometbft"`
}

// AnchorSettings contains anchor contract and operation settings
type AnchorSettings struct {
	Contract     ContractSettings     `yaml:"contract"`
	Verification VerificationSettings `yaml:"verification"`
	Consensus    ConsensusSettings    `yaml:"consensus"`
	Gas          GasSettings          `yaml:"gas"`
	Batch        BatchSettings        `yaml:"batch"`
	Events       EventSettings        `yaml:"events"`
}

// ContractSettings contains smart contract configuration
type ContractSettings struct {
	Address         string `yaml:"address"`
	Network         string `yaml:"network"`
	ChainID         int64  `yaml:"chain_id"`
	DeploymentBlock int64  `yaml:"deployment_block"`
	ABIVersion      string `yaml:"abi_version"`
}

// VerificationSettings contains proof verification requirements
type VerificationSettings struct {
	RequireBLSZK                 bool   `yaml:"require_bls_zk"`
	RequireGovernanceProof       bool   `yaml:"require_governance_proof"`
	GovernanceVerifier           string `yaml:"governance_verifier"`
	RequireCrossChainVerification bool   `yaml:"require_cross_chain_verification"`
	MinGovernanceLevel           string `yaml:"min_governance_level"`
	StrictMerkleVerification     bool   `yaml:"strict_merkle_verification"`
}

// ConsensusSettings contains multi-validator consensus configuration
type ConsensusSettings struct {
	RequireQuorum              bool          `yaml:"require_quorum"`
	ValidatorCount             int           `yaml:"validator_count"`
	QuorumSize                 int           `yaml:"quorum_size"`
	QuorumFraction             float64       `yaml:"quorum_fraction"`
	AttestationTimeout         Duration      `yaml:"attestation_timeout"`
	AttestationRetryCount      int           `yaml:"attestation_retry_count"`
	AttestationRetryDelay      Duration      `yaml:"attestation_retry_delay"`
	EnableSignatureAggregation bool          `yaml:"enable_signature_aggregation"`
	BLSDomainAttestation       string        `yaml:"bls_domain_attestation"`
}

// GasSettings contains gas management configuration
type GasSettings struct {
	MaxGasPriceGwei     int64   `yaml:"max_gas_price_gwei"`
	GasLimitAnchor      int64   `yaml:"gas_limit_anchor"`
	GasLimitProof       int64   `yaml:"gas_limit_proof"`
	GasLimitGovernance  int64   `yaml:"gas_limit_governance"`
	EIP1559Enabled      bool    `yaml:"eip1559_enabled"`
	MaxPriorityFeeGwei  int64   `yaml:"max_priority_fee_gwei"`
	GasPriceMultiplier  float64 `yaml:"gas_price_multiplier"`
	MinGasPriceGwei     int64   `yaml:"min_gas_price_gwei"`
}

// BatchSettings contains batch processing configuration
type BatchSettings struct {
	MaxBatchSize    int      `yaml:"max_batch_size"`
	MaxBatchAge     Duration `yaml:"max_batch_age"`
	MinBatchSize    int      `yaml:"min_batch_size"`
	AutoCloseOnSize bool     `yaml:"auto_close_on_size"`
	AutoCloseOnAge  bool     `yaml:"auto_close_on_age"`
}

// EventSettings contains event watcher configuration
type EventSettings struct {
	Enabled            bool     `yaml:"enabled"`
	PollInterval       Duration `yaml:"poll_interval"`
	BlockLookback      int64    `yaml:"block_lookback"`
	ConfirmationBlocks int      `yaml:"confirmation_blocks"`
	MaxBlocksPerScan   int64    `yaml:"max_blocks_per_scan"`
	WatchedEvents      []string `yaml:"watched_events"`
}

// NetworkSettings contains network endpoint configuration
type NetworkSettings struct {
	Ethereum   EthereumNetworkSettings   `yaml:"ethereum"`
	Accumulate AccumulateNetworkSettings `yaml:"accumulate"`
	// Multi-chain support: map of chainID -> chain config
	EVMChains map[int64]*EVMChainConfig `yaml:"evm_chains"`
}

// EVMChainConfig contains configuration for a specific EVM chain
type EVMChainConfig struct {
	Name               string   `yaml:"name"`
	ChainID            int64    `yaml:"chain_id"`
	RPCURL             string   `yaml:"rpc_url"`
	WSURL              string   `yaml:"ws_url"`
	RPCTimeout         Duration `yaml:"rpc_timeout"`
	MaxConnections     int      `yaml:"max_connections"`
	MaxIdleConnections int      `yaml:"max_idle_connections"`

	// Contract addresses for this chain
	AnchorV4Address    string `yaml:"anchor_v4_address"`
	AnchorV3Address    string `yaml:"anchor_v3_address"`
	BLSVerifierAddress string `yaml:"bls_verifier_address"`
	AccountFactory     string `yaml:"account_factory_address"`

	// Gas settings (optional, falls back to global)
	MaxGasPriceGwei    int64 `yaml:"max_gas_price_gwei"`
	MaxPriorityFeeGwei int64 `yaml:"max_priority_fee_gwei"`
	GasLimitAnchor     int64 `yaml:"gas_limit_anchor"`

	// Explorer URL for logging/debugging
	ExplorerURL string `yaml:"explorer_url"`
}

// EthereumNetworkSettings contains Ethereum network configuration
type EthereumNetworkSettings struct {
	RPCURL             string   `yaml:"rpc_url"`
	WSURL              string   `yaml:"ws_url"`
	ChainID            int64    `yaml:"chain_id"`
	Name               string   `yaml:"name"`
	RPCTimeout         Duration `yaml:"rpc_timeout"`
	MaxConnections     int      `yaml:"max_connections"`
	MaxIdleConnections int      `yaml:"max_idle_connections"`
}

// AccumulateNetworkSettings contains Accumulate network configuration
type AccumulateNetworkSettings struct {
	APIURL     string   `yaml:"api_url"`
	CometDNURL string   `yaml:"comet_dn_url"`
	CometBVNURL string   `yaml:"comet_bvn_url"`
	Network    string   `yaml:"network"`
	APITimeout Duration `yaml:"api_timeout"`
}

// ValidatorSettings contains validator-specific configuration
type ValidatorSettings struct {
	ID                string   `yaml:"id"`
	Role              string   `yaml:"role"`
	BLSPrivateKeyPath string   `yaml:"bls_private_key_path"`
	BLSPublicKeyPath  string   `yaml:"bls_public_key_path"`
	Ed25519KeyPath    string   `yaml:"ed25519_key_path"`
	EthPrivateKey     string   `yaml:"eth_private_key"`
	AttestationPeers  []string `yaml:"attestation_peers"`
}

// DatabaseSettings contains database configuration
type DatabaseSettings struct {
	URL            string   `yaml:"url"`
	MaxConnections int      `yaml:"max_connections"`
	MinConnections int      `yaml:"min_connections"`
	MaxIdleTime    Duration `yaml:"max_idle_time"`
	MaxLifetime    Duration `yaml:"max_lifetime"`
	Required       bool     `yaml:"required"`
	LogQueries     bool     `yaml:"log_queries"`
	AutoMigrate    bool     `yaml:"auto_migrate"`
	MigrationPath  string   `yaml:"migration_path"`
}

// SecuritySettings contains security configuration
type SecuritySettings struct {
	TLS       TLSSettings       `yaml:"tls"`
	Auth      AuthSettings      `yaml:"auth"`
	RateLimit RateLimitSettings `yaml:"rate_limit"`
	CORS      CORSSettings      `yaml:"cors"`
}

// TLSSettings contains TLS configuration
type TLSSettings struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	MinVersion string `yaml:"min_version"`
}

// AuthSettings contains authentication configuration
type AuthSettings struct {
	Enabled   bool     `yaml:"enabled"`
	JWTSecret string   `yaml:"jwt_secret"`
	JWTExpiry Duration `yaml:"jwt_expiry"`
}

// RateLimitSettings contains rate limiting configuration
type RateLimitSettings struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerMinute int  `yaml:"requests_per_minute"`
	Burst             int  `yaml:"burst"`
}

// CORSSettings contains CORS configuration
type CORSSettings struct {
	Enabled        bool     `yaml:"enabled"`
	AllowedOrigins []string `yaml:"allowed_origins"`
	AllowedMethods []string `yaml:"allowed_methods"`
	AllowedHeaders []string `yaml:"allowed_headers"`
	MaxAge         int      `yaml:"max_age"`
}

// MonitoringSettings contains monitoring configuration
type MonitoringSettings struct {
	Metrics MetricsSettings `yaml:"metrics"`
	Health  HealthSettings  `yaml:"health"`
	Logging LoggingSettings `yaml:"logging"`
	Tracing TracingSettings `yaml:"tracing"`
}

// MetricsSettings contains Prometheus metrics configuration
type MetricsSettings struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

// HealthSettings contains health check configuration
type HealthSettings struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

// LoggingSettings contains logging configuration
type LoggingSettings struct {
	Level         string `yaml:"level"`
	Format        string `yaml:"format"`
	Output        string `yaml:"output"`
	IncludeCaller bool   `yaml:"include_caller"`
}

// TracingSettings contains OpenTelemetry tracing configuration
type TracingSettings struct {
	Enabled    bool    `yaml:"enabled"`
	Endpoint   string  `yaml:"endpoint"`
	SampleRate float64 `yaml:"sample_rate"`
}

// CometBFTSettings contains CometBFT configuration
type CometBFTSettings struct {
	Enabled   bool                   `yaml:"enabled"`
	ChainID   string                 `yaml:"chain_id"`
	P2P       CometBFTP2PSettings    `yaml:"p2p"`
	RPC       CometBFTRPCSettings    `yaml:"rpc"`
	Consensus CometBFTConsensusSettings `yaml:"consensus"`
}

// CometBFTP2PSettings contains P2P configuration
type CometBFTP2PSettings struct {
	Port            int    `yaml:"port"`
	MaxPeers        int    `yaml:"max_peers"`
	PersistentPeers string `yaml:"persistent_peers"`
}

// CometBFTRPCSettings contains RPC configuration
type CometBFTRPCSettings struct {
	Port          int    `yaml:"port"`
	ListenAddress string `yaml:"listen_address"`
}

// CometBFTConsensusSettings contains consensus timing configuration
type CometBFTConsensusSettings struct {
	TimeoutPropose   Duration `yaml:"timeout_propose"`
	TimeoutPrevote   Duration `yaml:"timeout_prevote"`
	TimeoutPrecommit Duration `yaml:"timeout_precommit"`
	TimeoutCommit    Duration `yaml:"timeout_commit"`
}

// ==============================================================================
// Duration Type for YAML Parsing
// ==============================================================================

// Duration wraps time.Duration for YAML unmarshaling
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML implements yaml.Marshaler
func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

// Duration returns the time.Duration value
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// ==============================================================================
// Configuration Loading
// ==============================================================================

// LoadAnchorConfig loads anchor configuration from a YAML file
// Environment variables in the format ${VAR_NAME} are substituted
func LoadAnchorConfig(path string) (*AnchorConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	// Substitute environment variables
	expanded := substituteEnvVars(string(data))

	var cfg AnchorConfig
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	return &cfg, nil
}

// LoadAnchorConfigWithDefaults loads config with sensible defaults
func LoadAnchorConfigWithDefaults(path string) (*AnchorConfig, error) {
	cfg, err := LoadAnchorConfig(path)
	if err != nil {
		return nil, err
	}

	// Apply defaults
	cfg.applyDefaults()

	return cfg, nil
}

// applyDefaults sets default values for unset fields
func (c *AnchorConfig) applyDefaults() {
	// Verification defaults
	if c.Anchor.Verification.MinGovernanceLevel == "" {
		c.Anchor.Verification.MinGovernanceLevel = "G0"
	}

	// Consensus defaults
	if c.Anchor.Consensus.ValidatorCount == 0 {
		c.Anchor.Consensus.ValidatorCount = 4
	}
	if c.Anchor.Consensus.QuorumSize == 0 {
		c.Anchor.Consensus.QuorumSize = 3
	}
	if c.Anchor.Consensus.QuorumFraction == 0 {
		c.Anchor.Consensus.QuorumFraction = 0.667
	}
	if c.Anchor.Consensus.AttestationTimeout == 0 {
		c.Anchor.Consensus.AttestationTimeout = Duration(30 * time.Second)
	}
	if c.Anchor.Consensus.AttestationRetryCount == 0 {
		c.Anchor.Consensus.AttestationRetryCount = 3
	}
	if c.Anchor.Consensus.AttestationRetryDelay == 0 {
		c.Anchor.Consensus.AttestationRetryDelay = Duration(5 * time.Second)
	}
	if c.Anchor.Consensus.BLSDomainAttestation == "" {
		c.Anchor.Consensus.BLSDomainAttestation = "CERTEN_ATTESTATION_V1"
	}

	// Gas defaults
	if c.Anchor.Gas.MaxGasPriceGwei == 0 {
		c.Anchor.Gas.MaxGasPriceGwei = 100
	}
	if c.Anchor.Gas.GasLimitAnchor == 0 {
		c.Anchor.Gas.GasLimitAnchor = 300000
	}
	if c.Anchor.Gas.GasLimitProof == 0 {
		c.Anchor.Gas.GasLimitProof = 500000
	}
	if c.Anchor.Gas.GasLimitGovernance == 0 {
		c.Anchor.Gas.GasLimitGovernance = 400000
	}
	if c.Anchor.Gas.GasPriceMultiplier == 0 {
		c.Anchor.Gas.GasPriceMultiplier = 1.1
	}
	if c.Anchor.Gas.MinGasPriceGwei == 0 {
		c.Anchor.Gas.MinGasPriceGwei = 1
	}

	// Batch defaults
	if c.Anchor.Batch.MaxBatchSize == 0 {
		c.Anchor.Batch.MaxBatchSize = 100
	}
	if c.Anchor.Batch.MaxBatchAge == 0 {
		c.Anchor.Batch.MaxBatchAge = Duration(5 * time.Minute)
	}
	if c.Anchor.Batch.MinBatchSize == 0 {
		c.Anchor.Batch.MinBatchSize = 1
	}

	// Event defaults
	if c.Anchor.Events.PollInterval == 0 {
		c.Anchor.Events.PollInterval = Duration(15 * time.Second)
	}
	if c.Anchor.Events.BlockLookback == 0 {
		c.Anchor.Events.BlockLookback = 100
	}
	if c.Anchor.Events.ConfirmationBlocks == 0 {
		c.Anchor.Events.ConfirmationBlocks = 12
	}
	if c.Anchor.Events.MaxBlocksPerScan == 0 {
		c.Anchor.Events.MaxBlocksPerScan = 1000
	}

	// Network defaults
	if c.Network.Ethereum.RPCTimeout == 0 {
		c.Network.Ethereum.RPCTimeout = Duration(30 * time.Second)
	}
	if c.Network.Ethereum.MaxConnections == 0 {
		c.Network.Ethereum.MaxConnections = 10
	}
	if c.Network.Ethereum.MaxIdleConnections == 0 {
		c.Network.Ethereum.MaxIdleConnections = 5
	}
	if c.Network.Accumulate.APITimeout == 0 {
		c.Network.Accumulate.APITimeout = Duration(30 * time.Second)
	}

	// Database defaults
	if c.Database.MaxConnections == 0 {
		c.Database.MaxConnections = 25
	}
	if c.Database.MinConnections == 0 {
		c.Database.MinConnections = 5
	}
	if c.Database.MaxIdleTime == 0 {
		c.Database.MaxIdleTime = Duration(5 * time.Minute)
	}
	if c.Database.MaxLifetime == 0 {
		c.Database.MaxLifetime = Duration(1 * time.Hour)
	}

	// Security defaults
	if c.Security.Auth.JWTExpiry == 0 {
		c.Security.Auth.JWTExpiry = Duration(24 * time.Hour)
	}
	if c.Security.RateLimit.RequestsPerMinute == 0 {
		c.Security.RateLimit.RequestsPerMinute = 100
	}
	if c.Security.RateLimit.Burst == 0 {
		c.Security.RateLimit.Burst = 20
	}

	// Monitoring defaults
	if c.Monitoring.Metrics.Port == 0 {
		c.Monitoring.Metrics.Port = 9090
	}
	if c.Monitoring.Metrics.Path == "" {
		c.Monitoring.Metrics.Path = "/metrics"
	}
	if c.Monitoring.Health.Port == 0 {
		c.Monitoring.Health.Port = 8081
	}
	if c.Monitoring.Health.Path == "" {
		c.Monitoring.Health.Path = "/health"
	}
	if c.Monitoring.Logging.Level == "" {
		c.Monitoring.Logging.Level = "info"
	}
	if c.Monitoring.Logging.Format == "" {
		c.Monitoring.Logging.Format = "json"
	}
	if c.Monitoring.Logging.Output == "" {
		c.Monitoring.Logging.Output = "stdout"
	}
}

// ==============================================================================
// Environment Variable Substitution
// ==============================================================================

// envVarPattern matches ${VAR_NAME} or ${VAR_NAME:-default}
var envVarPattern = regexp.MustCompile(`\$\{([^}:]+)(:-([^}]*))?\}`)

// substituteEnvVars replaces ${VAR_NAME} with environment variable values
func substituteEnvVars(content string) string {
	return envVarPattern.ReplaceAllStringFunc(content, func(match string) string {
		groups := envVarPattern.FindStringSubmatch(match)
		if len(groups) < 2 {
			return match
		}

		varName := groups[1]
		defaultValue := ""
		if len(groups) >= 4 {
			defaultValue = groups[3]
		}

		if value := os.Getenv(varName); value != "" {
			return value
		}
		return defaultValue
	})
}

// ==============================================================================
// Configuration Validation
// ==============================================================================

// ValidateAnchorConfig validates the anchor configuration for production use
func (c *AnchorConfig) ValidateAnchorConfig() error {
	var errors []string

	// Contract validation
	if c.Anchor.Contract.Address == "" || strings.HasPrefix(c.Anchor.Contract.Address, "${") {
		errors = append(errors, "anchor.contract.address is required")
	}
	if c.Anchor.Contract.ChainID == 0 {
		errors = append(errors, "anchor.contract.chain_id is required")
	}

	// Verification validation
	if c.Anchor.Verification.RequireGovernanceProof &&
		c.Anchor.Verification.GovernanceVerifier == "" {
		// Warning but not error - governance verification can be done off-chain
	}

	// Consensus validation
	if c.Anchor.Consensus.RequireQuorum {
		if c.Anchor.Consensus.QuorumSize <= 0 {
			errors = append(errors, "anchor.consensus.quorum_size must be positive when quorum is required")
		}
		if c.Anchor.Consensus.QuorumSize > c.Anchor.Consensus.ValidatorCount {
			errors = append(errors, "anchor.consensus.quorum_size cannot exceed validator_count")
		}
	}

	// Network validation
	if c.Network.Ethereum.RPCURL == "" || strings.HasPrefix(c.Network.Ethereum.RPCURL, "${") {
		errors = append(errors, "network.ethereum.rpc_url is required")
	}
	if c.Network.Ethereum.ChainID != c.Anchor.Contract.ChainID {
		errors = append(errors, "network.ethereum.chain_id must match anchor.contract.chain_id")
	}
	if c.Network.Accumulate.APIURL == "" || strings.HasPrefix(c.Network.Accumulate.APIURL, "${") {
		errors = append(errors, "network.accumulate.api_url is required")
	}

	// Validator validation
	if c.Validator.ID == "" || strings.HasPrefix(c.Validator.ID, "${") {
		errors = append(errors, "validator.id is required")
	}
	if c.Validator.EthPrivateKey == "" || strings.HasPrefix(c.Validator.EthPrivateKey, "${") {
		errors = append(errors, "validator.eth_private_key is required")
	}

	// Database validation
	if c.Database.Required {
		if c.Database.URL == "" || strings.HasPrefix(c.Database.URL, "${") {
			errors = append(errors, "database.url is required when database.required is true")
		}
	}

	// Security validation for production
	if c.Environment == "production" {
		if !c.Security.TLS.Enabled {
			errors = append(errors, "security.tls.enabled must be true for production")
		}
		if c.Security.Auth.JWTSecret == "" || strings.HasPrefix(c.Security.Auth.JWTSecret, "${") {
			errors = append(errors, "security.auth.jwt_secret is required for production")
		}
		if len(c.Security.Auth.JWTSecret) < 32 && !strings.HasPrefix(c.Security.Auth.JWTSecret, "${") {
			errors = append(errors, "security.auth.jwt_secret must be at least 32 characters for production")
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("anchor configuration validation failed:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

// ValidateForEnvironment validates configuration appropriate for the environment
func (c *AnchorConfig) ValidateForEnvironment() error {
	switch c.Environment {
	case "production":
		return c.ValidateAnchorConfig()
	case "testnet", "staging":
		return c.validateTestnet()
	case "development", "local":
		return c.validateDevelopment()
	default:
		return c.ValidateAnchorConfig()
	}
}

// validateTestnet performs relaxed validation for testnet
func (c *AnchorConfig) validateTestnet() error {
	var errors []string

	if c.Anchor.Contract.Address == "" || strings.HasPrefix(c.Anchor.Contract.Address, "${") {
		errors = append(errors, "anchor.contract.address is required")
	}
	if c.Network.Ethereum.RPCURL == "" || strings.HasPrefix(c.Network.Ethereum.RPCURL, "${") {
		errors = append(errors, "network.ethereum.rpc_url is required")
	}
	if c.Network.Accumulate.APIURL == "" || strings.HasPrefix(c.Network.Accumulate.APIURL, "${") {
		errors = append(errors, "network.accumulate.api_url is required")
	}

	if len(errors) > 0 {
		return fmt.Errorf("testnet configuration validation failed:\n  - %s", strings.Join(errors, "\n  - "))
	}
	return nil
}

// validateDevelopment performs minimal validation for development
func (c *AnchorConfig) validateDevelopment() error {
	// Very minimal validation for local development
	if c.Network.Accumulate.APIURL == "" || strings.HasPrefix(c.Network.Accumulate.APIURL, "${") {
		return fmt.Errorf("network.accumulate.api_url is required even for development")
	}
	return nil
}

// ==============================================================================
// Helper Methods
// ==============================================================================

// IsProduction returns true if this is a production configuration
func (c *AnchorConfig) IsProduction() bool {
	return c.Environment == "production"
}

// IsTestnet returns true if this is a testnet configuration
func (c *AnchorConfig) IsTestnet() bool {
	return c.Environment == "testnet" || c.Environment == "staging"
}

// GetQuorumSize calculates the required quorum size
func (c *AnchorConfig) GetQuorumSize() int {
	if c.Anchor.Consensus.QuorumSize > 0 {
		return c.Anchor.Consensus.QuorumSize
	}
	// Calculate from fraction: ceil(validator_count * quorum_fraction)
	return int(float64(c.Anchor.Consensus.ValidatorCount)*c.Anchor.Consensus.QuorumFraction + 0.5)
}

// GetAttestationTimeout returns the attestation timeout as time.Duration
func (c *AnchorConfig) GetAttestationTimeout() time.Duration {
	return c.Anchor.Consensus.AttestationTimeout.Duration()
}

// GetGasLimitForOperation returns the appropriate gas limit
func (c *AnchorConfig) GetGasLimitForOperation(operation string) int64 {
	switch operation {
	case "anchor", "createAnchor":
		return c.Anchor.Gas.GasLimitAnchor
	case "proof", "executeProof":
		return c.Anchor.Gas.GasLimitProof
	case "governance", "executeGovernance":
		return c.Anchor.Gas.GasLimitGovernance
	default:
		return c.Anchor.Gas.GasLimitProof // Default to proof limit
	}
}

// GetMaxGasPriceWei returns max gas price in Wei
func (c *AnchorConfig) GetMaxGasPriceWei() int64 {
	return c.Anchor.Gas.MaxGasPriceGwei * 1_000_000_000
}

// GetEVMChainConfig returns configuration for a specific EVM chain by chainID
// Falls back to default Ethereum config if chain not found
func (c *AnchorConfig) GetEVMChainConfig(chainID int64) *EVMChainConfig {
	if c.Network.EVMChains != nil {
		if cfg, ok := c.Network.EVMChains[chainID]; ok {
			return cfg
		}
	}

	// Fallback to default Ethereum config (for backward compatibility)
	return &EVMChainConfig{
		Name:               c.Network.Ethereum.Name,
		ChainID:            c.Network.Ethereum.ChainID,
		RPCURL:             c.Network.Ethereum.RPCURL,
		WSURL:              c.Network.Ethereum.WSURL,
		RPCTimeout:         c.Network.Ethereum.RPCTimeout,
		MaxConnections:     c.Network.Ethereum.MaxConnections,
		MaxIdleConnections: c.Network.Ethereum.MaxIdleConnections,
		AnchorV4Address:    c.Anchor.Contract.Address,
		MaxGasPriceGwei:    c.Anchor.Gas.MaxGasPriceGwei,
		MaxPriorityFeeGwei: c.Anchor.Gas.MaxPriorityFeeGwei,
		GasLimitAnchor:     c.Anchor.Gas.GasLimitAnchor,
	}
}

// GetSupportedChainIDs returns a list of all configured EVM chain IDs
func (c *AnchorConfig) GetSupportedChainIDs() []int64 {
	chainIDs := make([]int64, 0)

	// Always include the default Ethereum chain
	chainIDs = append(chainIDs, c.Network.Ethereum.ChainID)

	// Add all configured EVM chains
	if c.Network.EVMChains != nil {
		for chainID := range c.Network.EVMChains {
			// Avoid duplicates
			if chainID != c.Network.Ethereum.ChainID {
				chainIDs = append(chainIDs, chainID)
			}
		}
	}

	return chainIDs
}

// IsChainSupported returns true if the given chainID is configured
func (c *AnchorConfig) IsChainSupported(chainID int64) bool {
	// Check default Ethereum config
	if c.Network.Ethereum.ChainID == chainID {
		return true
	}

	// Check EVM chains map
	if c.Network.EVMChains != nil {
		if _, ok := c.Network.EVMChains[chainID]; ok {
			return true
		}
	}

	return false
}

// ==============================================================================
// Environment-based Config Loading (Compatibility)
// ==============================================================================

// LoadAnchorConfigFromEnv creates AnchorConfig from environment variables
// This provides compatibility with the existing env-based configuration
func LoadAnchorConfigFromEnv() (*AnchorConfig, error) {
	cfg := &AnchorConfig{
		Environment: getEnv("ENVIRONMENT", "development"),
		Version:     "3.0.0",

		Anchor: AnchorSettings{
			Contract: ContractSettings{
				Address:    getEnv("CERTEN_CONTRACT_ADDRESS", getEnv("ANCHOR_CONTRACT_ADDRESS", "")),
				Network:    getEnv("NETWORK_NAME", "devnet"),
				ChainID:    getEnvInt64("ETH_CHAIN_ID", 11155111),
				ABIVersion: "v3",
			},
			Verification: VerificationSettings{
				RequireBLSZK:                 getEnvBool("REQUIRE_BLS_ZK", true),
				RequireGovernanceProof:       getEnvBool("REQUIRE_GOVERNANCE_PROOF", true),
				GovernanceVerifier:           getEnv("GOVERNANCE_VERIFIER_ADDRESS", ""),
				RequireCrossChainVerification: getEnvBool("REQUIRE_CROSS_CHAIN_VERIFICATION", true),
				MinGovernanceLevel:           getEnv("MIN_GOVERNANCE_LEVEL", "G0"),
				StrictMerkleVerification:     getEnvBool("STRICT_MERKLE_VERIFICATION", true),
			},
			Consensus: ConsensusSettings{
				RequireQuorum:              getEnvBool("REQUIRE_QUORUM", true),
				ValidatorCount:             getEnvInt("VALIDATOR_COUNT", 4),
				QuorumSize:                 getEnvInt("ATTESTATION_REQUIRED_COUNT", 3),
				QuorumFraction:             0.667,
				AttestationTimeout:         Duration(time.Duration(getEnvInt("ATTESTATION_TIMEOUT_SECONDS", 30)) * time.Second),
				AttestationRetryCount:      getEnvInt("ATTESTATION_RETRY_COUNT", 3),
				AttestationRetryDelay:      Duration(5 * time.Second),
				EnableSignatureAggregation: true,
				BLSDomainAttestation:       "CERTEN_ATTESTATION_V1",
			},
			Gas: GasSettings{
				MaxGasPriceGwei:    getEnvInt64("MAX_GAS_PRICE_GWEI", 100),
				GasLimitAnchor:     getEnvInt64("GAS_LIMIT_ANCHOR", 300000),
				GasLimitProof:      getEnvInt64("GAS_LIMIT_PROOF", 500000),
				GasLimitGovernance: getEnvInt64("GAS_LIMIT_GOVERNANCE", 400000),
				EIP1559Enabled:     getEnvBool("EIP1559_ENABLED", true),
				MaxPriorityFeeGwei: getEnvInt64("MAX_PRIORITY_FEE_GWEI", 2),
				GasPriceMultiplier: 1.1,
				MinGasPriceGwei:    1,
			},
			Batch: BatchSettings{
				MaxBatchSize:    getEnvInt("MAX_BATCH_SIZE", 100),
				MaxBatchAge:     Duration(5 * time.Minute),
				MinBatchSize:    1,
				AutoCloseOnSize: true,
				AutoCloseOnAge:  true,
			},
			Events: EventSettings{
				Enabled:            getEnvBool("EVENT_WATCHER_ENABLED", true),
				PollInterval:       Duration(15 * time.Second),
				BlockLookback:      100,
				ConfirmationBlocks: getEnvInt("CONFIRMATION_BLOCKS", 12),
				MaxBlocksPerScan:   1000,
				WatchedEvents: []string{
					"AnchorCreated", "ProofExecuted", "ProofVerificationFailed",
					"GovernanceExecuted", "ValidatorRegistered", "ValidatorRemoved",
				},
			},
		},

		Network: NetworkSettings{
			Ethereum: EthereumNetworkSettings{
				RPCURL:             getEnv("ETHEREUM_URL", ""),
				WSURL:              getEnv("ETHEREUM_WS_URL", ""),
				ChainID:            getEnvInt64("ETH_CHAIN_ID", 11155111),
				Name:               getEnv("NETWORK_NAME", "devnet"),
				RPCTimeout:         Duration(30 * time.Second),
				MaxConnections:     10,
				MaxIdleConnections: 5,
			},
			Accumulate: AccumulateNetworkSettings{
				APIURL:     getEnv("ACCUMULATE_URL", ""),
				CometDNURL: getEnv("ACCUMULATE_COMET_DN", ""),
				CometBVNURL: getEnv("ACCUMULATE_COMET_BVN", ""),
				Network:    getEnv("ACCUMULATE_NETWORK", "devnet"),
				APITimeout: Duration(30 * time.Second),
			},
			// Multi-chain EVM support
			EVMChains: loadEVMChainsFromEnv(),
		},

		Validator: ValidatorSettings{
			ID:                getEnv("VALIDATOR_ID", "validator-default"),
			Role:              getEnv("VALIDATOR_ROLE", "validator"),
			BLSPrivateKeyPath: getEnv("BLS_PRIVATE_KEY_PATH", ""),
			BLSPublicKeyPath:  getEnv("BLS_PUBLIC_KEY_PATH", ""),
			Ed25519KeyPath:    getEnv("ED25519_KEY_PATH", ""),
			EthPrivateKey:     getEnv("ETH_PRIVATE_KEY", ""),
			AttestationPeers:  parseAttestationPeers(getEnv("ATTESTATION_PEERS", "")),
		},

		Database: DatabaseSettings{
			URL:            getEnv("DATABASE_URL", ""),
			MaxConnections: getEnvInt("DATABASE_MAX_CONNS", 25),
			MinConnections: getEnvInt("DATABASE_MIN_CONNS", 5),
			MaxIdleTime:    Duration(5 * time.Minute),
			MaxLifetime:    Duration(1 * time.Hour),
			Required:       getEnvBool("DATABASE_REQUIRED", false),
			LogQueries:     getEnvBool("DATABASE_LOG_QUERIES", false),
			AutoMigrate:    getEnvBool("DATABASE_AUTO_MIGRATE", false),
			MigrationPath:  getEnv("DATABASE_MIGRATION_PATH", "./migrations"),
		},

		Security: SecuritySettings{
			TLS: TLSSettings{
				Enabled:    getEnvBool("TLS_ENABLED", true),
				CertFile:   getEnv("TLS_CERT_FILE", ""),
				KeyFile:    getEnv("TLS_KEY_FILE", ""),
				MinVersion: "1.2",
			},
			Auth: AuthSettings{
				Enabled:   getEnvBool("AUTH_ENABLED", true),
				JWTSecret: getEnv("JWT_SECRET", ""),
				JWTExpiry: Duration(24 * time.Hour),
			},
			RateLimit: RateLimitSettings{
				Enabled:           getEnvBool("RATE_LIMIT_ENABLED", true),
				RequestsPerMinute: getEnvInt("RATE_LIMIT_REQUESTS", 100),
				Burst:             getEnvInt("RATE_LIMIT_BURST", 20),
			},
			CORS: CORSSettings{
				Enabled:        true,
				AllowedOrigins: strings.Split(getEnv("CORS_ORIGINS", "http://localhost:3000"), ","),
				AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
				AllowedHeaders: []string{"Authorization", "Content-Type", "X-Request-ID"},
				MaxAge:         86400,
			},
		},

		Monitoring: MonitoringSettings{
			Metrics: MetricsSettings{
				Enabled: true,
				Port:    getEnvInt("METRICS_PORT", 9090),
				Path:    "/metrics",
			},
			Health: HealthSettings{
				Enabled: true,
				Port:    getEnvInt("HEALTH_CHECK_PORT", 8081),
				Path:    "/health",
			},
			Logging: LoggingSettings{
				Level:         getEnv("LOG_LEVEL", "info"),
				Format:        getEnv("LOG_FORMAT", "json"),
				Output:        "stdout",
				IncludeCaller: true,
			},
			Tracing: TracingSettings{
				Enabled:    getEnvBool("TRACING_ENABLED", false),
				Endpoint:   getEnv("OTEL_ENDPOINT", ""),
				SampleRate: 0.1,
			},
		},

		CometBFT: CometBFTSettings{
			Enabled: getEnvBool("COMETBFT_ENABLED", true),
			ChainID: getEnv("COMETBFT_CHAIN_ID", "certen-validator"),
			P2P: CometBFTP2PSettings{
				Port:            getEnvInt("COMETBFT_P2P_PORT", 26656),
				MaxPeers:        getEnvInt("COMETBFT_MAX_PEERS", 50),
				PersistentPeers: getEnv("COMETBFT_P2P_PERSISTENT_PEERS", ""),
			},
			RPC: CometBFTRPCSettings{
				Port:          getEnvInt("COMETBFT_RPC_PORT", 26657),
				ListenAddress: getEnv("COMETBFT_RPC_LADDR", "127.0.0.1"),
			},
			Consensus: CometBFTConsensusSettings{
				TimeoutPropose:   Duration(3 * time.Second),
				TimeoutPrevote:   Duration(1 * time.Second),
				TimeoutPrecommit: Duration(1 * time.Second),
				TimeoutCommit:    Duration(5 * time.Second),
			},
		},
	}

	return cfg, nil
}

// Utility function for int64 parsing
func getEnvInt64Local(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// ==============================================================================
// Multi-Chain EVM Configuration
// ==============================================================================

// loadEVMChainsFromEnv loads multi-chain EVM configurations from environment variables
// Supports Ethereum Sepolia, Arbitrum Sepolia, Optimism Sepolia, Base Sepolia, Polygon Amoy
func loadEVMChainsFromEnv() map[int64]*EVMChainConfig {
	chains := make(map[int64]*EVMChainConfig)

	// Ethereum Sepolia (11155111) - Primary chain
	if rpc := getEnv("ETHEREUM_SEPOLIA_RPC_URL", getEnv("ETHEREUM_URL", "")); rpc != "" {
		chains[11155111] = &EVMChainConfig{
			Name:               "Ethereum Sepolia",
			ChainID:            11155111,
			RPCURL:             rpc,
			WSURL:              getEnv("ETHEREUM_SEPOLIA_WS_URL", ""),
			RPCTimeout:         Duration(30 * time.Second),
			MaxConnections:     10,
			MaxIdleConnections: 5,
			AnchorV4Address:    getEnv("SEPOLIA_ANCHORV4_ADDRESS", "0x6C664360f5451d61042289481A00Ce57BF322aa5"),
			AnchorV3Address:    getEnv("SEPOLIA_ANCHORV3_ADDRESS", "0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98"),
			BLSVerifierAddress: getEnv("SEPOLIA_BLSZKVERIFIER_ADDRESS", "0x631B6444216b981561034655349F8a28962DcC5F"),
			AccountFactory:     getEnv("SEPOLIA_ACCOUNTFACTORY_ADDRESS", "0xbd9D33310358C8A10254175dD297e2CA8cd623c3"),
			MaxGasPriceGwei:    getEnvInt64("SEPOLIA_MAX_GAS_PRICE_GWEI", 100),
			MaxPriorityFeeGwei: getEnvInt64("SEPOLIA_MAX_PRIORITY_FEE_GWEI", 2),
			GasLimitAnchor:     getEnvInt64("SEPOLIA_GAS_LIMIT_ANCHOR", 500000),
			ExplorerURL:        "https://sepolia.etherscan.io",
		}
	}

	// Arbitrum Sepolia (421614)
	if rpc := getEnv("ARBITRUM_SEPOLIA_RPC_URL", ""); rpc != "" {
		chains[421614] = &EVMChainConfig{
			Name:               "Arbitrum Sepolia",
			ChainID:            421614,
			RPCURL:             rpc,
			WSURL:              getEnv("ARBITRUM_SEPOLIA_WS_URL", ""),
			RPCTimeout:         Duration(30 * time.Second),
			MaxConnections:     10,
			MaxIdleConnections: 5,
			AnchorV4Address:    getEnv("ARBITRUM_SEPOLIA_ANCHORV4_ADDRESS", "0x52E8e8E5d5EE35ED52BA6B7BB2Cb2dc2D2b2c952"),
			AnchorV3Address:    getEnv("ARBITRUM_SEPOLIA_ANCHORV3_ADDRESS", "0x609987770BCEE4fB7F2e0e81685CE912c437f7f1"),
			BLSVerifierAddress: getEnv("ARBITRUM_SEPOLIA_BLSZKVERIFIER_ADDRESS", "0x488d2c2bB3d65a60eae9f72665fBaf191F38B7b7"),
			AccountFactory:     getEnv("ARBITRUM_SEPOLIA_ACCOUNTFACTORY_ADDRESS", "0xc9489206A9c8FA12129Fa1EFee8CcB47Ed93896d"),
			MaxGasPriceGwei:    getEnvInt64("ARBITRUM_MAX_GAS_PRICE_GWEI", 1),
			MaxPriorityFeeGwei: getEnvInt64("ARBITRUM_MAX_PRIORITY_FEE_GWEI", 0),
			GasLimitAnchor:     getEnvInt64("ARBITRUM_GAS_LIMIT_ANCHOR", 2000000),
			ExplorerURL:        "https://sepolia.arbiscan.io",
		}
	}

	// Optimism Sepolia (11155420)
	if rpc := getEnv("OPTIMISM_SEPOLIA_RPC_URL", ""); rpc != "" {
		chains[11155420] = &EVMChainConfig{
			Name:               "Optimism Sepolia",
			ChainID:            11155420,
			RPCURL:             rpc,
			WSURL:              getEnv("OPTIMISM_SEPOLIA_WS_URL", ""),
			RPCTimeout:         Duration(30 * time.Second),
			MaxConnections:     10,
			MaxIdleConnections: 5,
			AnchorV4Address:    getEnv("OPTIMISM_SEPOLIA_ANCHORV4_ADDRESS", "0x52E8e8E5d5EE35ED52BA6B7BB2Cb2dc2D2b2c952"),
			AnchorV3Address:    getEnv("OPTIMISM_SEPOLIA_ANCHORV3_ADDRESS", "0xc0e54d4D1A5B25e4Cc719Bec436c44241F2BA5d9"),
			BLSVerifierAddress: getEnv("OPTIMISM_SEPOLIA_BLSZKVERIFIER_ADDRESS", "0x609987770BCEE4fB7F2e0e81685CE912c437f7f1"),
			AccountFactory:     getEnv("OPTIMISM_SEPOLIA_ACCOUNTFACTORY_ADDRESS", "0xCc1fE1950c89A6fF1ef28cCF38bA151fF8abFD5C"),
			MaxGasPriceGwei:    getEnvInt64("OPTIMISM_MAX_GAS_PRICE_GWEI", 1),
			MaxPriorityFeeGwei: getEnvInt64("OPTIMISM_MAX_PRIORITY_FEE_GWEI", 0),
			GasLimitAnchor:     getEnvInt64("OPTIMISM_GAS_LIMIT_ANCHOR", 2000000),
			ExplorerURL:        "https://sepolia-optimism.etherscan.io",
		}
	}

	// Base Sepolia (84532)
	if rpc := getEnv("BASE_SEPOLIA_RPC_URL", ""); rpc != "" {
		chains[84532] = &EVMChainConfig{
			Name:               "Base Sepolia",
			ChainID:            84532,
			RPCURL:             rpc,
			WSURL:              getEnv("BASE_SEPOLIA_WS_URL", ""),
			RPCTimeout:         Duration(30 * time.Second),
			MaxConnections:     10,
			MaxIdleConnections: 5,
			AnchorV4Address:    getEnv("BASE_SEPOLIA_ANCHORV4_ADDRESS", ""),
			AnchorV3Address:    getEnv("BASE_SEPOLIA_ANCHORV3_ADDRESS", "0x609987770BCEE4fB7F2e0e81685CE912c437f7f1"),
			BLSVerifierAddress: getEnv("BASE_SEPOLIA_BLSZKVERIFIER_ADDRESS", "0x488d2c2bB3d65a60eae9f72665fBaf191F38B7b7"),
			AccountFactory:     getEnv("BASE_SEPOLIA_ACCOUNTFACTORY_ADDRESS", "0xc9489206A9c8FA12129Fa1EFee8CcB47Ed93896d"),
			MaxGasPriceGwei:    getEnvInt64("BASE_MAX_GAS_PRICE_GWEI", 1),
			MaxPriorityFeeGwei: getEnvInt64("BASE_MAX_PRIORITY_FEE_GWEI", 0),
			GasLimitAnchor:     getEnvInt64("BASE_GAS_LIMIT_ANCHOR", 2000000),
			ExplorerURL:        "https://sepolia.basescan.org",
		}
	}

	// Polygon Amoy (80002)
	if rpc := getEnv("POLYGON_AMOY_RPC_URL", ""); rpc != "" {
		chains[80002] = &EVMChainConfig{
			Name:               "Polygon Amoy",
			ChainID:            80002,
			RPCURL:             rpc,
			WSURL:              getEnv("POLYGON_AMOY_WS_URL", ""),
			RPCTimeout:         Duration(30 * time.Second),
			MaxConnections:     10,
			MaxIdleConnections: 5,
			AnchorV4Address:    getEnv("POLYGON_AMOY_ANCHORV4_ADDRESS", ""),
			AnchorV3Address:    getEnv("POLYGON_AMOY_ANCHORV3_ADDRESS", "0x609987770BCEE4fB7F2e0e81685CE912c437f7f1"),
			BLSVerifierAddress: getEnv("POLYGON_AMOY_BLSZKVERIFIER_ADDRESS", "0x488d2c2bB3d65a60eae9f72665fBaf191F38B7b7"),
			AccountFactory:     getEnv("POLYGON_AMOY_ACCOUNTFACTORY_ADDRESS", "0xc9489206A9c8FA12129Fa1EFee8CcB47Ed93896d"),
			MaxGasPriceGwei:    getEnvInt64("POLYGON_MAX_GAS_PRICE_GWEI", 50),
			MaxPriorityFeeGwei: getEnvInt64("POLYGON_MAX_PRIORITY_FEE_GWEI", 30),
			GasLimitAnchor:     getEnvInt64("POLYGON_GAS_LIMIT_ANCHOR", 500000),
			ExplorerURL:        "https://amoy.polygonscan.com",
		}
	}

	return chains
}
