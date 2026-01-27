package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the Certen validator service
type Config struct {
	// Network Configuration
	AccumulateURL      string
	AccumulateCometDN  string // CometBFT endpoint for DN (e.g., http://127.0.0.1:26657)
	AccumulateCometBVN  string // CometBFT endpoint for BVN (e.g., http://127.0.0.1:26757) - legacy single BVN
	AccumulateCometBVN0 string // CometBFT endpoint for BVN0
	AccumulateCometBVN1 string // CometBFT endpoint for BVN1
	AccumulateCometBVN2 string // CometBFT endpoint for BVN2
	AccumulateCometBVN3 string // CometBFT endpoint for BVN3 (Kermit network)
	EthereumURL        string
	EthChainID         int64

	// Server Configuration
	ListenAddr   string
	MetricsAddr  string
	HealthAddr   string

	// Database Configuration (URL-based, legacy)
	DatabaseURL         string
	DatabaseMaxConns    int
	DatabaseMinConns    int
	DatabaseMaxIdleTime int  // seconds
	DatabaseMaxLifetime int  // seconds
	DatabaseRequired    bool // If true, startup fails if database connection fails

	// Database Configuration (individual fields for client.go)
	DBHost           string
	DBPort           int
	DBUser           string
	DBPassword       string
	DBName           string
	DBSSLMode        string
	DBMaxOpenConns   int
	DBMaxIdleConns   int
	DBConnMaxLifetime time.Duration

	// Blockchain Configuration
	EthPrivateKey     string
	EthAccountAddress string

	// Ed25519 Key Configuration (E.5 remediation: Secure key management)
	Ed25519KeyPath string // Path to Ed25519 private key file
	DataDir        string // Base directory for data files

	// Contract Addresses
	AnchorContractAddress     string
	AccountAbstractionAddress string
	CertenContractAddress     string

	// Service Configuration
	ValidatorID   string
	ValidatorRole string
	LogLevel      string

	// CometBFT Network Configuration
	P2PPort int
	RPCPort int
	ChainID string // CometBFT chain ID for the validator network (e.g., "certen-validator")

	// Network Identification
	NetworkName string // Network name for anchoring (e.g., "mainnet", "sepolia", "devnet")

	// Governance Proof Configuration
	GovProofCLIPath string // Path to govproof CLI binary (optional - enables real G0/G1/G2 proofs)
	GovProofWorkDir string // Working directory for governance proof artifacts

	// Multi-Validator Attestation Configuration
	// Per Whitepaper Section 3.4.1 Component 4: Validator attestations
	AttestationPeers         []string // URLs of peer validators for attestation collection
	AttestationRequiredCount int      // Number of attestations required (2f+1)

	// Security Configuration
	JWTSecret   string
	CORSOrigins []string
	TLSEnabled  bool

	// Rate Limiting
	RateLimitRequests int
	RateLimitWindow   int

	// Firestore Configuration (for real-time UI sync)
	FirestoreEnabled        bool   // Enable Firestore sync
	FirebaseProjectID       string // Firebase/GCP project ID
	FirebaseCredentialsFile string // Path to service account JSON

	// Unified Multi-Chain Feature Flags
	// Per Unified Multi-Chain Architecture plan
	UseUnifiedOrchestrator bool   // Use unified orchestrator for proof cycles
	EnableMultiChain       bool   // Enable multi-chain execution strategies
	EnableUnifiedTables    bool   // Write to unified PostgreSQL tables
	FallbackToLegacy       bool   // Fall back to legacy if unified fails
	DefaultTargetChain     string // Default target chain (e.g., "ethereum", "sepolia")
}

// Load reads configuration from environment variables
//
// CRITICAL: This service only reads these specific variable names:
//   - ACCUMULATE_URL (not ACCUMULATE_URL_DEVNET or ACCUMULATE_URL_TESTNET)
//   - ETHEREUM_URL (not ETHEREUM_RPC_URL or ETHEREUM_SEPOLIA_URL)
//   - ETH_CHAIN_ID (not ETHEREUM_CHAIN_ID)
//   - ETH_PRIVATE_KEY, ANCHOR_CONTRACT_V2_ADDRESS, etc.
//
// All other *_URL variants in .env are ignored by this validator service.
//
// SECURITY: Required variables have no defaults and must be explicitly set.
// Call Validate() after Load() to ensure all required configuration is present.
func Load() (*Config, error) {
	cfg := &Config{
		// Network Configuration - REQUIRED, no defaults for production security
		AccumulateURL:      getEnv("ACCUMULATE_URL", ""),
		AccumulateCometDN:  getEnv("ACCUMULATE_COMET_DN", ""),  // DN CometBFT for L1-L3 proofs (optional, enables real proofs)
		AccumulateCometBVN:  getEnv("ACCUMULATE_COMET_BVN", ""),  // BVN CometBFT for L1-L3 proofs (legacy single BVN)
		AccumulateCometBVN0: getEnv("ACCUMULATE_COMET_BVN0", ""), // BVN0 CometBFT endpoint
		AccumulateCometBVN1: getEnv("ACCUMULATE_COMET_BVN1", ""), // BVN1 CometBFT endpoint
		AccumulateCometBVN2: getEnv("ACCUMULATE_COMET_BVN2", ""), // BVN2 CometBFT endpoint
		AccumulateCometBVN3: getEnv("ACCUMULATE_COMET_BVN3", ""), // BVN3 CometBFT endpoint (Kermit)
		EthereumURL:        getEnv("ETHEREUM_URL", ""),
		EthChainID:         getEnvInt64("ETH_CHAIN_ID", 11155111),

		// Server Configuration - safe defaults
		ListenAddr:  getEnv("API_HOST", "0.0.0.0") + ":" + getEnv("API_PORT", "8080"),
		MetricsAddr: getEnv("API_HOST", "0.0.0.0") + ":" + getEnv("METRICS_PORT", "9090"),
		HealthAddr:  getEnv("API_HOST", "0.0.0.0") + ":" + getEnv("HEALTH_CHECK_PORT", "8081"),

		// Database Configuration - REQUIRED, no default for security
		DatabaseURL:         getEnv("DATABASE_URL", ""),
		DatabaseMaxConns:    getEnvInt("DATABASE_MAX_CONNS", 25),
		DatabaseMinConns:    getEnvInt("DATABASE_MIN_CONNS", 5),
		DatabaseMaxIdleTime: getEnvInt("DATABASE_MAX_IDLE_TIME", 300),  // 5 minutes
		DatabaseMaxLifetime: getEnvInt("DATABASE_MAX_LIFETIME", 3600), // 1 hour
		DatabaseRequired:    getEnvBool("DATABASE_REQUIRED", false),   // If true, fail startup on DB error

		// Database Configuration - individual fields for client.go
		DBHost:            getEnv("DB_HOST", "localhost"),
		DBPort:            getEnvInt("DB_PORT", 5432),
		DBUser:            getEnv("DB_USER", "certen"),
		DBPassword:        getEnv("DB_PASSWORD", ""),
		DBName:            getEnv("DB_NAME", "certen_validator"),
		DBSSLMode:         getEnv("DB_SSL_MODE", "require"),
		DBMaxOpenConns:    getEnvInt("DB_MAX_OPEN_CONNS", 25),
		DBMaxIdleConns:    getEnvInt("DB_MAX_IDLE_CONNS", 5),
		DBConnMaxLifetime: getEnvDuration("DB_CONN_MAX_LIFETIME", time.Hour),

		// Blockchain Configuration - REQUIRED for production
		EthPrivateKey:     getEnv("ETH_PRIVATE_KEY", ""),
		EthAccountAddress: getEnv("ETH_ACCOUNT_ADDRESS", ""),

		// Ed25519 Key Configuration (E.5 remediation: Secure key management)
		Ed25519KeyPath: getEnv("ED25519_KEY_PATH", ""),         // Optional: Custom path to Ed25519 key file
		DataDir:        getEnv("DATA_DIR", "./data"),           // Base directory for data files

		// Contract Addresses
		AnchorContractAddress:     getEnv("ANCHOR_CONTRACT_ADDRESS", ""),
		AccountAbstractionAddress: getEnv("ACCOUNT_ABSTRACTION_ADDRESS", ""),
		CertenContractAddress:     getEnv("CERTEN_CONTRACT_ADDRESS", ""),

		// Service Configuration
		ValidatorID:   getEnv("VALIDATOR_ID", "validator-default"),
		ValidatorRole: getEnv("VALIDATOR_ROLE", "validator"),
		LogLevel:      getEnv("LOG_LEVEL", "info"),

		// CometBFT Network Configuration
		P2PPort: getEnvInt("COMETBFT_P2P_PORT", 26656),
		RPCPort: getEnvInt("COMETBFT_RPC_PORT", 26657),
		ChainID: getEnv("COMETBFT_CHAIN_ID", "certen-validator"),

		// Network Identification
		NetworkName: getEnv("NETWORK_NAME", "devnet"),

		// Governance Proof Configuration (optional - enables real G0/G1/G2 proofs)
		GovProofCLIPath: getEnv("GOV_PROOF_CLI_PATH", ""), // Path to compiled govproof binary
		GovProofWorkDir: getEnv("GOV_PROOF_WORK_DIR", "/tmp/gov_proofs"),

		// Multi-Validator Attestation Configuration
		AttestationPeers:         parseAttestationPeers(getEnv("ATTESTATION_PEERS", "")),
		AttestationRequiredCount: getEnvInt("ATTESTATION_REQUIRED_COUNT", 3), // 2f+1 for f=1

		// Security Configuration - REQUIRED, no weak defaults
		JWTSecret:   getEnv("JWT_SECRET", ""),
		CORSOrigins: strings.Split(getEnv("CORS_ORIGINS", "http://localhost:3000,http://localhost:3001"), ","),
		TLSEnabled:  getEnvBool("TLS_ENABLED", true), // Default to secure

		// Rate Limiting
		RateLimitRequests: getEnvInt("RATE_LIMIT_REQUESTS", 100),
		RateLimitWindow:   getEnvInt("RATE_LIMIT_WINDOW", 60),

		// Firestore Configuration (for real-time UI sync)
		FirestoreEnabled:        getEnvBool("FIRESTORE_ENABLED", false),
		FirebaseProjectID:       getEnv("FIREBASE_PROJECT_ID", ""),
		FirebaseCredentialsFile: getEnv("GOOGLE_APPLICATION_CREDENTIALS", ""),

		// Unified Multi-Chain Feature Flags
		// Per Unified Multi-Chain Architecture plan
		UseUnifiedOrchestrator: getEnvBool("FF_UNIFIED_ORCHESTRATOR", true),
		EnableMultiChain:       getEnvBool("FF_MULTI_CHAIN", true),
		EnableUnifiedTables:    getEnvBool("FF_UNIFIED_TABLES", true),
		FallbackToLegacy:       getEnvBool("FF_FALLBACK_LEGACY", true),
		DefaultTargetChain:     getEnv("DEFAULT_TARGET_CHAIN", "sepolia"),
	}

	return cfg, nil
}

// Validate checks that all required configuration is present and secure.
// This must be called after Load() before starting the service.
func (c *Config) Validate() error {
	var errors []string

	// Required network configuration
	if c.EthereumURL == "" {
		errors = append(errors, "ETHEREUM_URL is required but not set")
	}
	if c.AccumulateURL == "" {
		errors = append(errors, "ACCUMULATE_URL is required but not set")
	}

	// Required blockchain configuration
	if c.EthPrivateKey == "" {
		errors = append(errors, "ETH_PRIVATE_KEY is required but not set")
	}

	// Required contract addresses (at least one must be set for production)
	if c.CertenContractAddress == "" && c.AnchorContractAddress == "" {
		errors = append(errors, "CERTEN_CONTRACT_ADDRESS or ANCHOR_CONTRACT_ADDRESS is required")
	}

	// Database configuration validation
	if c.DatabaseURL == "" {
		errors = append(errors, "DATABASE_URL is required but not set")
	} else {
		// Validate database security settings
		if strings.Contains(c.DatabaseURL, "sslmode=disable") {
			errors = append(errors, "DATABASE_URL must use sslmode=require for production security")
		}
		if strings.Contains(c.DatabaseURL, "development") || strings.Contains(c.DatabaseURL, "password") {
			errors = append(errors, "DATABASE_URL appears to contain default/weak credentials - use secure credentials")
		}
	}

	// JWT secret validation
	if c.JWTSecret == "" {
		errors = append(errors, "JWT_SECRET is required but not set")
	} else {
		// Check for weak/default secrets
		weakSecrets := []string{"development", "secret", "password", "change-me", "changeme", "default", "test"}
		lowerSecret := strings.ToLower(c.JWTSecret)
		for _, weak := range weakSecrets {
			if strings.Contains(lowerSecret, weak) {
				errors = append(errors, "JWT_SECRET contains weak/default value - generate a secure random secret")
				break
			}
		}
		// Check minimum length
		if len(c.JWTSecret) < 32 {
			errors = append(errors, "JWT_SECRET must be at least 32 characters for security")
		}
	}

	// TLS should be enabled in production
	if !c.TLSEnabled {
		// This is a warning, not an error, but log it
		// In a stricter setup, this could be an error
		fmt.Println("WARNING: TLS_ENABLED is false - enable TLS for production security")
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

// ValidateForDevelopment performs relaxed validation suitable for local development.
// WARNING: Do not use this in production - use Validate() instead.
func (c *Config) ValidateForDevelopment() error {
	var errors []string

	// Only require the absolute minimum for development
	if c.AccumulateURL == "" {
		errors = append(errors, "ACCUMULATE_URL is required")
	}

	if len(errors) > 0 {
		return fmt.Errorf("development configuration validation failed:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

// Helper functions for environment variable parsing
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}


func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// parseAttestationPeers parses comma-separated peer URLs for attestation collection
// Example: "http://validator-2:8080,http://validator-3:8080,http://validator-4:8080"
func parseAttestationPeers(value string) []string {
	if value == "" {
		return nil
	}
	peers := strings.Split(value, ",")
	result := make([]string, 0, len(peers))
	for _, peer := range peers {
		peer = strings.TrimSpace(peer)
		if peer != "" {
			result = append(result, peer)
		}
	}
	return result
}
