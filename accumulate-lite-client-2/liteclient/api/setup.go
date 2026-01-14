package api

// NewMainnetClient creates a client configured for Accumulate mainnet
func NewMainnetClient() (*Client, error) {
	return NewClient(DefaultConfig())
}

// NewTestnetClient creates a client configured for Accumulate testnet
func NewTestnetClient() (*Client, error) {
	return NewClient(TestnetConfig())
}

// NewDevnetClient creates a client configured for local development
func NewDevnetClient() (*Client, error) {
	return NewClient(DevnetConfig())
}
