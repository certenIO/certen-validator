// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package config provides centralized configuration management for the Accumulate lite client.
// It supports environment variables, configuration files, and sensible defaults.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config represents the complete configuration for the lite client
type Config struct {
	// Network configuration
	Network NetworkConfig `json:"network"`
	
	// Server configuration for API endpoints
	Server ServerConfig `json:"server"`
	
	// Logging configuration
	Logging LoggingConfig `json:"logging"`
	
	// Security configuration
	Security SecurityConfig `json:"security"`
	
	// Storage configuration
	Storage StorageConfig `json:"storage"`
	
	// Development/testing options
	Development DevelopmentConfig `json:"development"`
}

// NetworkConfig contains network-related settings
type NetworkConfig struct {
	// Primary V3 API endpoint
	V3Endpoint string `json:"v3_endpoint"`
	
	// Legacy V2 API endpoint (if needed)
	V2Endpoint string `json:"v2_endpoint"`
	
	// Explorer API endpoint
	ExplorerEndpoint string `json:"explorer_endpoint"`
	
	// Request timeout
	Timeout time.Duration `json:"timeout"`
	
	// Max retries for failed requests
	MaxRetries int `json:"max_retries"`
	
	// Retry backoff multiplier
	RetryBackoff time.Duration `json:"retry_backoff"`
}

// ServerConfig contains HTTP server settings
type ServerConfig struct {
	// Listen address for HTTP server
	Address string `json:"address"`
	
	// Listen port
	Port int `json:"port"`
	
	// Read timeout
	ReadTimeout time.Duration `json:"read_timeout"`
	
	// Write timeout
	WriteTimeout time.Duration `json:"write_timeout"`
	
	// Enable CORS
	EnableCORS bool `json:"enable_cors"`
	
	// Allowed CORS origins
	CORSOrigins []string `json:"cors_origins"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	// Log level (debug, info, warn, error)
	Level string `json:"level"`
	
	// Log format (json, text)
	Format string `json:"format"`
	
	// Output destination (stdout, stderr, file path)
	Output string `json:"output"`
	
	// Enable structured logging
	Structured bool `json:"structured"`
	
	// Enable request logging
	EnableRequestLogging bool `json:"enable_request_logging"`
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	// Enable rate limiting
	EnableRateLimit bool `json:"enable_rate_limit"`
	
	// Rate limit: requests per minute
	RateLimitRPM int `json:"rate_limit_rpm"`
	
	// Enable request validation
	EnableValidation bool `json:"enable_validation"`
	
	// Max request size in bytes
	MaxRequestSize int64 `json:"max_request_size"`
	
	// Allowed account URL patterns
	AllowedAccountPatterns []string `json:"allowed_account_patterns"`
}

// StorageConfig contains storage settings
type StorageConfig struct {
	// Storage type (memory, sqlite, postgres)
	Type string `json:"type"`
	
	// Connection string or file path
	ConnectionString string `json:"connection_string"`
	
	// Enable caching
	EnableCache bool `json:"enable_cache"`
	
	// Cache TTL
	CacheTTL time.Duration `json:"cache_ttl"`
	
	// Max cache size
	MaxCacheSize int `json:"max_cache_size"`
}

// DevelopmentConfig contains development/testing options
type DevelopmentConfig struct {
	// Enable debug mode
	Debug bool `json:"debug"`
	
	// Enable pprof endpoints
	EnablePprof bool `json:"enable_pprof"`
	
	// Enable metrics endpoints
	EnableMetrics bool `json:"enable_metrics"`
	
	// Test account URLs for integration tests
	TestAccounts []string `json:"test_accounts"`
	
	// Disable proof verification (testing only)
	DisableProofVerification bool `json:"disable_proof_verification"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Network: NetworkConfig{
			V3Endpoint:   "https://mainnet.accumulatenetwork.io/v3",
			V2Endpoint:   "https://mainnet.accumulatenetwork.io/v2",
			Timeout:      30 * time.Second,
			MaxRetries:   3,
			RetryBackoff: 1 * time.Second,
		},
		Server: ServerConfig{
			Address:      "localhost",
			Port:         8080,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			EnableCORS:   true,
			CORSOrigins:  []string{"*"},
		},
		Logging: LoggingConfig{
			Level:                "info",
			Format:               "text",
			Output:               "stdout",
			Structured:           false,
			EnableRequestLogging: true,
		},
		Security: SecurityConfig{
			EnableRateLimit:        true,
			RateLimitRPM:          100,
			EnableValidation:       true,
			MaxRequestSize:         1024 * 1024, // 1MB
			AllowedAccountPatterns: []string{"acc://*"},
		},
		Storage: StorageConfig{
			Type:         "memory",
			EnableCache:  true,
			CacheTTL:     5 * time.Minute,
			MaxCacheSize: 1000,
		},
		Development: DevelopmentConfig{
			Debug:                    false,
			EnablePprof:             false,
			EnableMetrics:           true,
			TestAccounts:            []string{"acc://RenatoDAP.acme", "acc://DefiDevs.acme"},
			DisableProofVerification: false,
		},
	}
}

// LoadConfig loads configuration from environment variables and config files
func LoadConfig() (*Config, error) {
	config := DefaultConfig()
	
	// Load from environment variables
	if err := loadFromEnv(config); err != nil {
		return nil, fmt.Errorf("failed to load from environment: %w", err)
	}
	
	// Load from config file if specified
	if configFile := os.Getenv("LITECLIENT_CONFIG_FILE"); configFile != "" {
		if err := loadFromFile(config, configFile); err != nil {
			return nil, fmt.Errorf("failed to load config file %s: %w", configFile, err)
		}
	}
	
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	return config, nil
}

// loadFromEnv loads configuration from environment variables
func loadFromEnv(config *Config) error {
	// Network configuration
	if v := os.Getenv("LITECLIENT_V3_ENDPOINT"); v != "" {
		config.Network.V3Endpoint = v
	}
	if v := os.Getenv("LITECLIENT_V2_ENDPOINT"); v != "" {
		config.Network.V2Endpoint = v
	}
	if v := os.Getenv("LITECLIENT_EXPLORER_ENDPOINT"); v != "" {
		config.Network.ExplorerEndpoint = v
	}
	if v := os.Getenv("LITECLIENT_TIMEOUT"); v != "" {
		if duration, err := time.ParseDuration(v); err == nil {
			config.Network.Timeout = duration
		}
	}
	if v := os.Getenv("LITECLIENT_MAX_RETRIES"); v != "" {
		if retries, err := strconv.Atoi(v); err == nil {
			config.Network.MaxRetries = retries
		}
	}
	
	// Server configuration
	if v := os.Getenv("LITECLIENT_ADDRESS"); v != "" {
		config.Server.Address = v
	}
	if v := os.Getenv("LITECLIENT_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			config.Server.Port = port
		}
	}
	if v := os.Getenv("LITECLIENT_CORS_ORIGINS"); v != "" {
		config.Server.CORSOrigins = strings.Split(v, ",")
	}
	
	// Logging configuration
	if v := os.Getenv("LITECLIENT_LOG_LEVEL"); v != "" {
		config.Logging.Level = v
	}
	if v := os.Getenv("LITECLIENT_LOG_FORMAT"); v != "" {
		config.Logging.Format = v
	}
	if v := os.Getenv("LITECLIENT_LOG_OUTPUT"); v != "" {
		config.Logging.Output = v
	}
	if v := os.Getenv("LITECLIENT_STRUCTURED_LOGGING"); v != "" {
		if structured, err := strconv.ParseBool(v); err == nil {
			config.Logging.Structured = structured
		}
	}
	
	// Security configuration
	if v := os.Getenv("LITECLIENT_RATE_LIMIT_RPM"); v != "" {
		if rpm, err := strconv.Atoi(v); err == nil {
			config.Security.RateLimitRPM = rpm
		}
	}
	if v := os.Getenv("LITECLIENT_MAX_REQUEST_SIZE"); v != "" {
		if size, err := strconv.ParseInt(v, 10, 64); err == nil {
			config.Security.MaxRequestSize = size
		}
	}
	
	// Storage configuration
	if v := os.Getenv("LITECLIENT_STORAGE_TYPE"); v != "" {
		config.Storage.Type = v
	}
	if v := os.Getenv("LITECLIENT_STORAGE_CONNECTION"); v != "" {
		config.Storage.ConnectionString = v
	}
	if v := os.Getenv("LITECLIENT_CACHE_TTL"); v != "" {
		if ttl, err := time.ParseDuration(v); err == nil {
			config.Storage.CacheTTL = ttl
		}
	}
	
	// Development configuration
	if v := os.Getenv("LITECLIENT_DEBUG"); v != "" {
		if debug, err := strconv.ParseBool(v); err == nil {
			config.Development.Debug = debug
		}
	}
	if v := os.Getenv("LITECLIENT_ENABLE_PPROF"); v != "" {
		if pprof, err := strconv.ParseBool(v); err == nil {
			config.Development.EnablePprof = pprof
		}
	}
	if v := os.Getenv("LITECLIENT_TEST_ACCOUNTS"); v != "" {
		config.Development.TestAccounts = strings.Split(v, ",")
	}
	
	return nil
}

// loadFromFile loads configuration from a JSON file
func loadFromFile(config *Config, filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	
	var fileConfig Config
	if err := json.Unmarshal(data, &fileConfig); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}
	
	// Merge file config into existing config
	mergeConfig(config, &fileConfig)
	
	return nil
}

// mergeConfig merges source config into target config (non-zero values only)
func mergeConfig(target, source *Config) {
	// This is a simplified merge - in production you'd want more sophisticated merging
	if source.Network.V3Endpoint != "" {
		target.Network.V3Endpoint = source.Network.V3Endpoint
	}
	if source.Network.V2Endpoint != "" {
		target.Network.V2Endpoint = source.Network.V2Endpoint
	}
	if source.Network.Timeout != 0 {
		target.Network.Timeout = source.Network.Timeout
	}
	if source.Server.Port != 0 {
		target.Server.Port = source.Server.Port
	}
	if source.Logging.Level != "" {
		target.Logging.Level = source.Logging.Level
	}
	// Add more fields as needed
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate network configuration
	if c.Network.V3Endpoint == "" {
		return fmt.Errorf("v3_endpoint is required")
	}
	if c.Network.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if c.Network.MaxRetries < 0 {
		return fmt.Errorf("max_retries must be non-negative")
	}
	
	// Validate server configuration
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	
	// Validate logging configuration
	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if !validLogLevels[c.Logging.Level] {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}
	
	// Validate security configuration
	if c.Security.RateLimitRPM <= 0 {
		return fmt.Errorf("rate_limit_rpm must be positive")
	}
	if c.Security.MaxRequestSize <= 0 {
		return fmt.Errorf("max_request_size must be positive")
	}
	
	// Validate storage configuration
	validStorageTypes := map[string]bool{
		"memory": true, "sqlite": true, "postgres": true,
	}
	if !validStorageTypes[c.Storage.Type] {
		return fmt.Errorf("invalid storage type: %s", c.Storage.Type)
	}
	
	return nil
}

// ToJSON returns the configuration as JSON
func (c *Config) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// GetServerAddress returns the full server address
func (c *Config) GetServerAddress() string {
	return fmt.Sprintf("%s:%d", c.Server.Address, c.Server.Port)
}

// IsProductionMode returns true if running in production mode
func (c *Config) IsProductionMode() bool {
	return !c.Development.Debug
}