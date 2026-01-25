package ethereum

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	ethereum "github.com/ethereum/go-ethereum"
)

// Client represents an Ethereum client
type Client struct {
	client  *ethclient.Client
	chainID *big.Int
	url     string
}

// NewClient creates a new Ethereum client
func NewClient(url string, chainID int64) (*Client, error) {
	client, err := ethclient.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum: %w", err)
	}

	return &Client{
		client:  client,
		chainID: big.NewInt(chainID),
		url:     url,
	}, nil
}

// GetBalance gets the ETH balance of an address
func (c *Client) GetBalance(ctx context.Context, address common.Address) (*big.Int, error) {
	balance, err := c.client.BalanceAt(ctx, address, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get balance: %w", err)
	}
	return balance, nil
}

// GetNonce gets the nonce for an address
func (c *Client) GetNonce(ctx context.Context, address common.Address) (uint64, error) {
	nonce, err := c.client.PendingNonceAt(ctx, address)
	if err != nil {
		return 0, fmt.Errorf("failed to get nonce: %w", err)
	}
	return nonce, nil
}

// GetGasPrice gets the current gas price
func (c *Client) GetGasPrice(ctx context.Context) (*big.Int, error) {
	gasPrice, err := c.client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get gas price: %w", err)
	}
	return gasPrice, nil
}

// CreateTransactor creates a transactor from a private key
func (c *Client) CreateTransactor(privateKeyHex string) (*bind.TransactOpts, error) {
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, c.chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to create transactor: %w", err)
	}

	return auth, nil
}

// GetPublicAddress gets the public address from a private key
func GetPublicAddress(privateKeyHex string) (common.Address, error) {
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return common.Address{}, fmt.Errorf("failed to cast public key to ECDSA")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	return address, nil
}

// GeneratePrivateKey generates a new private key
func GeneratePrivateKey() (*ecdsa.PrivateKey, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	return privateKey, nil
}

// PrivateKeyToHex converts a private key to hex string
func PrivateKeyToHex(privateKey *ecdsa.PrivateKey) string {
	privateKeyBytes := crypto.FromECDSA(privateKey)
	return fmt.Sprintf("0x%x", privateKeyBytes)
}

// EstimateGas estimates gas for a transaction
func (c *Client) EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	gasLimit, err := c.client.EstimateGas(ctx, msg)
	if err != nil {
		return 0, fmt.Errorf("failed to estimate gas: %w", err)
	}
	return gasLimit, nil
}

// WaitForTransaction waits for a transaction to be mined
func (c *Client) WaitForTransaction(ctx context.Context, tx *types.Transaction) (*types.Receipt, error) {
	receipt, err := bind.WaitMined(ctx, c.client, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for transaction: %w", err)
	}
	return receipt, nil
}

// GetChainID returns the chain ID
func (c *Client) GetChainID() *big.Int {
	return c.chainID
}

// GetClient returns the underlying ethclient
func (c *Client) GetClient() *ethclient.Client {
	return c.client
}

// Health checks if the Ethereum client is healthy
func (c *Client) Health(ctx context.Context) error {
	_, err := c.client.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("ethereum health check failed: %w", err)
	}
	return nil
}

// ContractCallResult represents the result of a contract call
type ContractCallResult struct {
	TransactionHash string    `json:"transaction_hash"`
	BlockNumber     uint64    `json:"block_number"`
	BlockHash       string    `json:"block_hash"`
	GasUsed         uint64    `json:"gas_used"`
	GasCost         *big.Int  `json:"gas_cost"`
	Success         bool      `json:"success"`
	Timestamp       time.Time `json:"timestamp"`
	ReturnData      []byte    `json:"return_data,omitempty"`
}

// CallContract makes a read-only contract call
func (c *Client) CallContract(ctx context.Context, contractAddr common.Address, abiString string, methodName string, params ...interface{}) ([]interface{}, error) {
	// Parse the contract ABI
	contractABI, err := abi.JSON(strings.NewReader(abiString))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ABI: %w", err)
	}

	// Pack the method call
	callData, err := contractABI.Pack(methodName, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to pack method call: %w", err)
	}

	// Make the contract call
	result, err := c.client.CallContract(ctx, ethereum.CallMsg{
		To:   &contractAddr,
		Data: callData,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("contract call failed: %w", err)
	}

	// Unpack the result
	outputs, err := contractABI.Unpack(methodName, result)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack result: %w", err)
	}

	return outputs, nil
}

// SendContractTransaction sends a transaction to a contract
func (c *Client) SendContractTransaction(ctx context.Context, contractAddr common.Address, abiString string, privateKeyHex string, methodName string, gasLimit uint64, params ...interface{}) (*ContractCallResult, error) {
	// Parse the contract ABI
	contractABI, err := abi.JSON(strings.NewReader(abiString))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ABI: %w", err)
	}

	// Pack the method call
	callData, err := contractABI.Pack(methodName, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to pack method call: %w", err)
	}

	// Parse private key
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Get public address
	publicKeyECDSA := privateKey.Public().(*ecdsa.PublicKey)
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	// Get nonce
	nonce, err := c.client.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce: %w", err)
	}

	// Get gas price with minimum floor
	gasPrice, err := c.client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get gas price: %w", err)
	}
	// Enforce minimum 5 Gwei to ensure transactions get included
	minGasPrice := big.NewInt(5 * 1e9)
	if gasPrice.Cmp(minGasPrice) < 0 {
		gasPrice = minGasPrice
	}

	// Create transaction
	tx := types.NewTransaction(
		nonce,
		contractAddr,
		big.NewInt(0), // value
		gasLimit,
		gasPrice,
		callData,
	)

	// Sign transaction
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(c.chainID), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Send transaction
	err = c.client.SendTransaction(ctx, signedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to send transaction: %w", err)
	}

	// Wait for receipt (with timeout)
	receipt, err := c.WaitForTransaction(ctx, signedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	result := &ContractCallResult{
		TransactionHash: signedTx.Hash().Hex(),
		BlockNumber:     receipt.BlockNumber.Uint64(),
		BlockHash:       receipt.BlockHash.Hex(),
		GasUsed:         receipt.GasUsed,
		GasCost:         new(big.Int).Mul(gasPrice, big.NewInt(int64(receipt.GasUsed))),
		Success:         receipt.Status == types.ReceiptStatusSuccessful,
		Timestamp:       time.Now(),
	}

	return result, nil
}

// SendContractTransactionWithRetry sends a contract transaction with retry logic for gas price escalation
func (c *Client) SendContractTransactionWithRetry(ctx context.Context, contractAddr common.Address, abiString string, privateKeyHex string, methodName string, gasLimit uint64, maxRetries int, params ...interface{}) (*ContractCallResult, error) {
	// Parse the contract ABI
	contractABI, err := abi.JSON(strings.NewReader(abiString))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ABI: %w", err)
	}

	// Pack the method call
	callData, err := contractABI.Pack(methodName, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to pack method call: %w", err)
	}

	// Parse private key
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Get public address
	publicKeyECDSA := privateKey.Public().(*ecdsa.PublicKey)
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	// Retry loop with gas price escalation
	for attempt := 0; attempt < maxRetries; attempt++ {
		// Get fresh nonce and gas price for each attempt
		nonce, err := c.client.PendingNonceAt(ctx, fromAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to get nonce: %w", err)
		}

		// Get base gas price and escalate on retries
		baseGasPrice, err := c.client.SuggestGasPrice(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get gas price: %w", err)
		}

		// Enforce minimum 5 Gwei to ensure transactions get included
		minGasPrice := big.NewInt(5 * 1e9)
		if baseGasPrice.Cmp(minGasPrice) < 0 {
			baseGasPrice = minGasPrice
		}

		// Escalate gas price by 20% for each retry
		gasPrice := new(big.Int).Set(baseGasPrice)
		if attempt > 0 {
			multiplier := big.NewInt(int64(100 + (20 * attempt))) // 120%, 140%, etc.
			gasPrice = gasPrice.Mul(gasPrice, multiplier)
			gasPrice = gasPrice.Div(gasPrice, big.NewInt(100))
		}

		// Create transaction
		tx := types.NewTransaction(
			nonce,
			contractAddr,
			big.NewInt(0), // value
			gasLimit,
			gasPrice,
			callData,
		)

		// Sign transaction
		signedTx, err := types.SignTx(tx, types.NewEIP155Signer(c.chainID), privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to sign transaction: %w", err)
		}

		// Send transaction
		err = c.client.SendTransaction(ctx, signedTx)
		if err != nil {
			errStr := err.Error()
			// Check if this is a retryable error
			if strings.Contains(errStr, "replacement transaction underpriced") ||
			   strings.Contains(errStr, "nonce too low") ||
			   strings.Contains(errStr, "already known") {
				if attempt < maxRetries-1 {
					time.Sleep(2 * time.Second)
					continue
				}
			}
			return nil, fmt.Errorf("failed to send transaction after %d attempts: %w", attempt+1, err)
		}

		// Success! Wait for receipt
		receipt, err := c.WaitForTransaction(ctx, signedTx)
		if err != nil {
			return nil, fmt.Errorf("failed to get transaction receipt: %w", err)
		}

		result := &ContractCallResult{
			TransactionHash: signedTx.Hash().Hex(),
			BlockNumber:     receipt.BlockNumber.Uint64(),
			BlockHash:       receipt.BlockHash.Hex(),
			GasUsed:         receipt.GasUsed,
			GasCost:         new(big.Int).Mul(gasPrice, big.NewInt(int64(receipt.GasUsed))),
			Success:         receipt.Status == types.ReceiptStatusSuccessful,
			Timestamp:       time.Now(),
		}

		return result, nil
	}

	return nil, fmt.Errorf("failed to send transaction after %d attempts", maxRetries)
}

// GetBlock gets a block by number
func (c *Client) GetBlock(ctx context.Context, blockNumber *big.Int) (*types.Block, error) {
	block, err := c.client.BlockByNumber(ctx, blockNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get block: %w", err)
	}
	return block, nil
}

// GetLatestBlock gets the latest block
func (c *Client) GetLatestBlock(ctx context.Context) (*types.Block, error) {
	return c.GetBlock(ctx, nil)
}

// GetLatestBlockNumber returns the latest block number
// Used by confirmation tracker for calculating confirmations
func (c *Client) GetLatestBlockNumber(ctx context.Context) (int64, error) {
	block, err := c.GetLatestBlock(ctx)
	if err != nil {
		return 0, err
	}
	return block.Number().Int64(), nil
}

// GetBlockInfo returns the hash and timestamp of a specific block
// Used by confirmation tracker for updating anchor records
func (c *Client) GetBlockInfo(ctx context.Context, blockNumber int64) (hash string, timestamp time.Time, err error) {
	block, err := c.GetBlock(ctx, big.NewInt(blockNumber))
	if err != nil {
		return "", time.Time{}, err
	}
	return block.Hash().Hex(), time.Unix(int64(block.Time()), 0), nil
}