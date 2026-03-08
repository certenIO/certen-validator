// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package api

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Client wraps the Accumulate API client with helper methods
type Client struct {
	rpc      *jsonrpc.Client
	endpoint string
}

// NewClient creates a new API client
func NewClient(endpoint string) *Client {
	return &Client{
		rpc:      jsonrpc.NewClient(endpoint),
		endpoint: endpoint,
	}
}

// QueryAccount queries an account with optional proof
func (c *Client) QueryAccount(ctx context.Context, accountURL *url.URL, includeProof bool) (*api.AccountRecord, error) {
	query := &api.DefaultQuery{
		IncludeReceipt: &api.ReceiptOptions{ForAny: includeProof},
	}

	resp, err := c.rpc.Query(ctx, accountURL, query)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	accountResp, ok := resp.(*api.AccountRecord)
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", resp)
	}

	return accountResp, nil
}

// QueryAccountWithTimeout queries an account with a timeout
func (c *Client) QueryAccountWithTimeout(accountURL *url.URL, includeProof bool, timeout time.Duration) (*api.AccountRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return c.QueryAccount(ctx, accountURL, includeProof)
}

// GetNetworkStatus retrieves the network status
func (c *Client) GetNetworkStatus(ctx context.Context) (*api.NetworkStatus, error) {
	status, err := c.rpc.NetworkStatus(ctx, api.NetworkStatusOptions{})
	if err != nil {
		return nil, fmt.Errorf("network status query failed: %w", err)
	}

	return status, nil
}

// CheckHealth checks if the API is healthy
func (c *Client) CheckHealth() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to query a well-known account
	_, err := c.QueryAccount(ctx, protocol.DnUrl(), false)
	return err
}

// GetEndpoint returns the API endpoint
func (c *Client) GetEndpoint() string {
	return c.endpoint
}

// Query performs a query request
func (c *Client) Query(ctx context.Context, scope *url.URL, query api.Query) (api.Record, error) {
	return c.rpc.Query(ctx, scope, query)
}

// NetworkStatus gets the network status
func (c *Client) NetworkStatus(ctx context.Context, opts api.NetworkStatusOptions) (*api.NetworkStatus, error) {
	return c.rpc.NetworkStatus(ctx, opts)
}
