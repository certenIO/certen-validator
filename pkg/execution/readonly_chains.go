// Copyright 2026 Certen Protocol

package execution

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/config"
)

// ReadOnlyChains resolves chains for code that only READS: eth_call, eth_getTransactionByHash,
// eth_getTransactionReceipt, eth_getBlockByNumber.
//
// # WHY THIS EXISTS RATHER THAN A FLAG ON EthereumContractManager
//
// NewEthereumContractManager parses a private key and builds a transactor before it will hand back
// anything, so a read-only tool could not be constructed without one. cmd/anchorquorumbackfill — which
// issues nothing but calls — had to be given a freshly generated throwaway key to satisfy that
// constructor. A key that exists only to get past a type check is still a key: it ends up in an
// environment file, in a process listing, in a shell history.
//
// Making the manager's key optional would mean auditing every transact path for a nil transactor, and
// one missed path is a nil dereference in production. This is the smaller and safer shape: a separate
// accessor that CANNOT sign because it holds nothing to sign with. The compiler enforces it — there is no
// auth field to reach for.
type ReadOnlyChains struct {
	anchorCfg *config.AnchorConfig
	anchors   map[int64]common.Address

	mu      sync.Mutex
	clients map[int64]*ethclient.Client
}

// NewReadOnlyChains builds a read-only resolver over the same configuration the batch path uses.
func NewReadOnlyChains(anchorCfg *config.AnchorConfig, anchors map[int64]common.Address) (*ReadOnlyChains, error) {
	if anchorCfg == nil {
		return nil, fmt.Errorf("read-only chains require anchor configuration")
	}
	if len(anchors) == 0 {
		return nil, fmt.Errorf("read-only chains require at least one anchor address")
	}
	return &ReadOnlyChains{
		anchorCfg: anchorCfg,
		anchors:   anchors,
		clients:   make(map[int64]*ethclient.Client),
	}, nil
}

// NewReadOnlyChainsFromEnv reads CERTEN_ANCHOR_V8_<chainID> for each chain, exactly as
// NewEVMChainResolverFromEnv does — and notably without reading ETH_PRIVATE_KEY.
func NewReadOnlyChainsFromEnv(anchorCfg *config.AnchorConfig, chainIDs []int64) (*ReadOnlyChains, error) {
	out := make(map[int64]common.Address)
	for _, id := range chainIDs {
		key := fmt.Sprintf("CERTEN_ANCHOR_V8_%d", id)
		v := strings.TrimSpace(os.Getenv(key))
		if v == "" {
			continue
		}
		if !common.IsHexAddress(v) {
			return nil, fmt.Errorf("%s is not a valid address: %q", key, v)
		}
		out[id] = common.HexToAddress(v)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf(
			"no CERTEN_ANCHOR_V8_<chainId> variables set for chains %v; nothing can be read", chainIDs)
	}
	return NewReadOnlyChains(anchorCfg, out)
}

// ClientForChain returns the RPC client and anchor address for a chain.
func (r *ReadOnlyChains) ClientForChain(chainID int64) (*ethclient.Client, common.Address, error) {
	anchorAddr, ok := r.anchors[chainID]
	if !ok {
		return nil, common.Address{}, fmt.Errorf(
			"chain %d has no CertenAnchorV8 configured; refusing to read from another anchor", chainID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if c, cached := r.clients[chainID]; cached {
		return c, anchorAddr, nil
	}

	chainCfg := r.anchorCfg.GetEVMChainConfig(chainID)
	if chainCfg == nil || chainCfg.RPCURL == "" {
		return nil, common.Address{}, fmt.Errorf("no RPC configuration for chainId=%d", chainID)
	}
	client, err := ethclient.Dial(chainCfg.RPCURL)
	if err != nil {
		return nil, common.Address{}, fmt.Errorf("connecting to chain %d: %w", chainID, err)
	}
	r.clients[chainID] = client
	return client, anchorAddr, nil
}

// Close releases every client.
func (r *ReadOnlyChains) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.clients {
		c.Close()
	}
	r.clients = make(map[int64]*ethclient.Client)
}
