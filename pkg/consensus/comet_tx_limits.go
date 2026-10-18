package consensus

// The limits a transaction meets between a proposer and a committed block, and the named refusal when it exceeds them
// (C5-D1).
//
// WHAT WAS WRONG (production, 2026-10-18)
//
// The proof-v2 document travels inside the intent certificate, which is ONE transaction of this chain. Its `certify`
// member grows linearly with the time since the last Accumulate major block (00:00 and 12:00 UTC), so for the last
// hours of every 12-hour cycle the transaction was larger than 749,946 bytes, and every proposer's own CometBFT RPC refused
// it: `error reading request body: http: request body too large` (HTTP 400, JSON-RPC -32600). The intent was then marked
// failed on all seven validators. Every config builder started from config.DefaultConfig(), whose rpc.max_body_bytes is
// 1,000,000; BroadcastTxSync sends the transaction base64-encoded inside a JSON-RPC body (4 bytes per 3 plus the
// wrapper), so the largest transaction the RPC accepted was 749,946 bytes while the mempool accepts
// mempool.max_tx_bytes = 1 MiB and the evidence budget (pkg/proof/v2/xbudget.go) is written against 1 MiB.
//
// EVERY LIMIT ON THE PATH (cometbft v0.38.21)
//
//	rpc.max_body_bytes   config/config.go:448 default 1,000,000; enforced per request by http.MaxBytesReader
//	                     (rpc/jsonrpc/server/http_server.go:292, PreChecksHandler; node/node.go:706 sets it from the
//	                     config; the websocket read limit is the same number, node.go:729).
//	mempool.max_tx_bytes config/config.go:799 default 1 MiB; CheckTx refuses a larger transaction with
//	                     mempool.ErrTxTooLarge "Tx too large. Max size is X, but got Y"
//	                     (mempool/clist_mempool.go:239; the error type is mempool/errors.go:20).
//	mempool.max_txs_bytes config/config.go:797 default 1 GiB for the whole pool (clist_mempool.go:381): not per transaction.
//	mempool reactor      the p2p channel's RecvMessageCapacity is the size of a batch holding one transaction of
//	                     max_tx_bytes (mempool/reactor.go:72-85), so gossip carries exactly max_tx_bytes.
//	p2p                  packets are split at p2p.max_packet_msg_payload_size and a message is checked against its
//	                     channel's capacity only (p2p/conn/connection.go:895-897); nothing there limits a 1 MiB tx.
//	pre-check            the node builds the mempool with state.TxPreCheck (state/tx_filter.go:10): a transaction's
//	                     protobuf size may not exceed the block's data capacity, types.MaxDataBytesNoEvidence(
//	                     block.max_bytes, validators) (types/block.go:306; mempool/mempool.go:116 PreCheckMaxBytes,
//	                     "tx size is too big"). Default block.max_bytes is 22,020,096 (types/params.go:99); the chain's
//	                     genesis is the operator's, and this app issues no consensus-parameter updates.
//	ABCI CheckTx         ValidatorApp.CheckTx (abci_validator.go:511) puts no size limit of its own on a ValidatorBlock;
//	                     PrepareProposal returns the transactions it is given.
//
// TODAY the whole path accepts a transaction of at most 749,946 bytes (749,931 with a 19-digit request id): the RPC body
// binds, base64(n) + the 72-byte JSON-RPC wrapper <= 1,000,000. AFTER this change it accepts exactly
// mempool.max_tx_bytes = 1,048,576 bytes (the mempool binds) - on a chain whose genesis keeps CometBFT's default
// block.max_bytes, where the block's data capacity (22,018,588 bytes for seven validators) is twenty times that.
//
// This is a node-local configuration of the RPC server, not a consensus rule: no transaction, ABCI response, state or
// app-hash input changes, and a validator running the old limit still agrees with one running the new.
//
// A transaction larger than the path accepts is refused here BY NAME before it is sent, with its size and the limit
// that binds: tx_too_large{size,limit,bound}. It is never a truncated or dropped document.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/cometbft/cometbft/config"
	cmttypes "github.com/cometbft/cometbft/types"
)

// rpcEnvelopeAllowance is what a broadcast request's JSON-RPC body holds besides the base64 transaction:
// {"jsonrpc":"2.0","id":N,"method":"broadcast_tx_sync","params":{"tx":"..."}} - 72 bytes with a one-digit request id, 90
// with the widest. comet_tx_limits_test.go measures it from the engine's real client and requires the allowance to cover it.
const rpcEnvelopeAllowance = 1024

// rpcBodyLimitFor is the smallest rpc.max_body_bytes that admits a broadcast request for a transaction of maxTxBytes.
func rpcBodyLimitFor(maxTxBytes int) int64 {
	if maxTxBytes < 0 {
		maxTxBytes = 0
	}
	return int64(base64.StdEncoding.EncodedLen(maxTxBytes)) + rpcEnvelopeAllowance
}

// rpcRawTxFitting is the largest raw transaction a request body of bodyBytes admits (0 when none).
func rpcRawTxFitting(bodyBytes int64) int {
	if bodyBytes <= rpcEnvelopeAllowance {
		return 0
	}
	return int((bodyBytes - rpcEnvelopeAllowance) / 4 * 3)
}

// applyCometTxLimits makes a CometBFT configuration able to carry a transaction of its own mempool.max_tx_bytes through
// its RPC server. It only ever RAISES rpc.max_body_bytes. Every place this module builds a configuration calls it
// (TestNoCometBFTConfigIsBuiltWithoutTheTransactionLimits), and NewRealCometBFTEngine calls it on whatever
// configuration it is given.
func applyCometTxLimits(cfg *config.Config) {
	if need := rpcBodyLimitFor(cfg.Mempool.MaxTxBytes); cfg.RPC.MaxBodyBytes < need {
		cfg.RPC.MaxBodyBytes = need
	}
}

// transactionPathLimit is the largest raw transaction the path from the RPC to a committed block accepts under cfg, and
// the name of the limit that binds. blockMaxBytes and validators describe the chain (consensus_params.block.max_bytes,
// -1 for CometBFT's protocol maximum, and the validator count); zero means not known and that bound is not applied.
func transactionPathLimit(cfg *config.Config, blockMaxBytes int64, validators int) (int, string) {
	limit, bound := cfg.Mempool.MaxTxBytes, "mempool.max_tx_bytes"
	if n := rpcRawTxFitting(cfg.RPC.MaxBodyBytes); n < limit {
		limit, bound = n, "rpc.max_body_bytes"
	}
	if blockMaxBytes != 0 && validators > 0 {
		if blockMaxBytes < 0 {
			blockMaxBytes = int64(cmttypes.MaxBlockSizeBytes)
		}
		data := blockMaxBytes - cmttypes.MaxOverheadForBlock - cmttypes.MaxHeaderBytes - cmttypes.MaxCommitBytes(validators)
		if n := rawTxFittingBlockData(data); n < limit {
			limit, bound = n, "block.max_bytes"
		}
	}
	return limit, bound
}

// rawTxFittingBlockData is the largest raw transaction whose protobuf encoding in a block's data (a tag byte, a varint
// length and the bytes, as cmttypes.ComputeProtoSizeForTxs counts it - the size state.TxPreCheck judges) is within data
// bytes; 0 when none is.
func rawTxFittingBlockData(data int64) int {
	for n := data - 2; n > 0; n-- {
		if n+1+int64(uvarintLen(uint64(n))) <= data {
			return int(n)
		}
	}
	return 0
}

func uvarintLen(x uint64) int {
	n := 1
	for ; x >= 0x80; x >>= 7 {
		n++
	}
	return n
}

// ErrTxTooLarge is the named state of a transaction larger than the consensus path accepts.
var ErrTxTooLarge = errors.New("tx_too_large")

// TxTooLargeError is ErrTxTooLarge with what it was judged at: the transaction's size, the largest the path accepts,
// and which limit binds (mempool.max_tx_bytes, rpc.max_body_bytes or block.max_bytes). The transaction is not sent.
//
// Discovery treats it as processing_failed, neither permanent nor retried on the chained-proof queue
// (pkg/intent/tx_too_large_test.go): the certificate shrinks after the next Accumulate major block, but the same bytes
// can never be admitted.
type TxTooLargeError struct {
	Size  int
	Limit int
	Bound string
}

func (e *TxTooLargeError) Error() string {
	return fmt.Sprintf("tx_too_large{size=%d,limit=%d,bound=%s}: the transaction is %d bytes over what consensus accepts",
		e.Size, e.Limit, e.Bound, e.Size-e.Limit)
}

// Is makes errors.Is(err, ErrTxTooLarge) true for every TxTooLargeError.
func (e *TxTooLargeError) Is(target error) bool { return target == ErrTxTooLarge }

// checkTransactionFits is nil for a transaction of size bytes within limit, and the named refusal otherwise.
func checkTransactionFits(size, limit int, bound string) error {
	if size > limit {
		return &TxTooLargeError{Size: size, Limit: limit, Bound: bound}
	}
	return nil
}

// requireTransactionFits judges a transaction of size bytes against everything the engine's node enforces: its
// configuration and, once the node exists, the chain's block capacity from its genesis (block.max_bytes and the genesis
// validator count; a rotation changes the count, which moves the capacity by 111 bytes per validator (CometBFT's MaxCommitSigBytes 109 plus its protoEncodingOverhead 2) - CometBFT's own
// pre-check stays the authority and its refusal, "tx size is too big", is surfaced as it is).
func (e *RealCometBFTEngine) requireTransactionFits(size int) error {
	if e.cometCfg == nil {
		return errors.New("the engine has no CometBFT configuration to judge a transaction's size against")
	}
	var blockMaxBytes int64
	validators := 0
	if e.node != nil {
		if g := e.node.GenesisDoc(); g != nil && g.ConsensusParams != nil {
			blockMaxBytes, validators = g.ConsensusParams.Block.MaxBytes, len(g.Validators)
		}
	}
	limit, bound := transactionPathLimit(e.cometCfg, blockMaxBytes, validators)
	return checkTransactionFits(size, limit, bound)
}

// The three places this package builds a CometBFT configuration for a node, as functions of their inputs only (no files,
// keys or process environment are touched here), so each can be judged. Each ends in applyCometTxLimits.

// validatorChainCometConfig is NewValidatorChainEngine's configuration.
func validatorChainCometConfig(validatorID string, p2pPort, rpcPort int) *config.Config {
	cfg := config.DefaultConfig()
	cfg.RootDir = filepath.Join("/app", "data", "validator-chain", validatorID)
	cfg.P2P.ListenAddress = fmt.Sprintf("tcp://0.0.0.0:%d", p2pPort)
	cfg.RPC.ListenAddress = fmt.Sprintf("tcp://0.0.0.0:%d", rpcPort)
	cfg.Moniker = validatorID
	cfg.DBBackend = "goleveldb"
	cfg.TxIndex.Indexer = "kv" // Enable tx indexing for Tx query support
	applyCometTxLimits(cfg)
	return cfg
}

// unifiedCometConfig is NewUnifiedCometBFTEngine's configuration, the one every production validator runs, and the
// home directory it keeps its state in. getenv reads COMETBFT_P2P_PERSISTENT_PEERS and COMETBFT_P2P_SEEDS.
func unifiedCometConfig(validatorID string, getenv func(string) string, logger *log.Logger) (*config.Config, string) {
	// All validators use the same internal container ports - Docker handles external mapping
	p2pPort := 26656 // All validators listen on internal port 26656
	rpcPort := 26657 // All validators listen on internal port 26657

	// CometBFT home is a persistent Docker volume (validatorN_keys:/app/bft-keys).
	// DO NOT wipe the data dir on boot: blockstore.db / state.db / cs.wal must survive
	// restarts so CometBFT recovers to the same height as the persisted app ledger
	// (validator-ledger, recovered via ValidatorApp.RecoverState). Wiping it reset CometBFT
	// to genesis while the app recovered to height N, causing the handshake app-hash mismatch
	// (assertAppHashEqualsOneFromState) crash-loop on any restart after the fleet had
	// processed intents. Requires the FinalizeBlock AppHash fix (abci_validator.go) so the
	// persisted app-hash matches what CometBFT records. Node/priv-validator keys below are
	// still regenerated deterministically.
	homeDir := filepath.Join("/app", "bft-keys", validatorID)

	logger.Printf("💾 Using persistent CometBFT state at %s (survives restarts)", homeDir)

	cfg := config.DefaultConfig()
	cfg.SetRoot(homeDir)
	cfg.P2P.ListenAddress = fmt.Sprintf("tcp://0.0.0.0:%d", p2pPort)
	cfg.RPC.ListenAddress = fmt.Sprintf("tcp://0.0.0.0:%d", rpcPort)

	// Block production settings - Event-based (only create blocks when there are transactions)
	cfg.Consensus.CreateEmptyBlocks = false

	// Faster consensus timeouts for responsive block production
	cfg.Consensus.TimeoutPropose = 2 * time.Second
	cfg.Consensus.TimeoutProposeDelta = 200 * time.Millisecond
	cfg.Consensus.TimeoutPrevote = 500 * time.Millisecond
	cfg.Consensus.TimeoutPrevoteDelta = 200 * time.Millisecond
	cfg.Consensus.TimeoutPrecommit = 500 * time.Millisecond
	cfg.Consensus.TimeoutPrecommitDelta = 200 * time.Millisecond
	cfg.Consensus.TimeoutCommit = 1 * time.Second

	// Enable transaction indexing for Tx query support
	// This is required for polling transaction inclusion in blocks
	cfg.TxIndex.Indexer = "kv"

	cfg.Moniker = validatorID

	// Set up deterministic P2P configuration with persistent peers
	// Per BFT Resiliency Task 4: Each validator should have ALL other validators as persistent peers
	persistentPeers := getenv("COMETBFT_P2P_PERSISTENT_PEERS")
	if persistentPeers != "" {
		cfg.P2P.PersistentPeers = persistentPeers
		logger.Printf("🔗 Configured persistent peers: %s", persistentPeers)
	}

	// Seeds for initial peer discovery (alternative to persistent peers)
	seeds := getenv("COMETBFT_P2P_SEEDS")
	if seeds != "" {
		cfg.P2P.Seeds = seeds
		logger.Printf("🌱 Configured seeds: %s", seeds)
	}

	// Unconditional peer exchange for better network discovery
	cfg.P2P.PexReactor = true
	cfg.P2P.AddrBookStrict = false // Allow private IPs in Docker network

	// P2P network configuration to prevent pong timeouts and connection drops
	// These settings are critical for stable multi-validator consensus in Docker networks
	cfg.P2P.SendRate = 20000000 // 20 MB/s - increase from default 512KB/s
	cfg.P2P.RecvRate = 20000000 // 20 MB/s - increase from default 512KB/s
	cfg.P2P.FlushThrottleTimeout = 100 * time.Millisecond
	cfg.P2P.MaxPacketMsgPayloadSize = 1400                  // Default is 1024, increase for larger messages
	cfg.P2P.HandshakeTimeout = 30 * time.Second             // Increase from default 20s
	cfg.P2P.DialTimeout = 10 * time.Second                  // Increase from default 3s
	cfg.P2P.AllowDuplicateIP = true                         // Allow duplicate IPs in Docker network
	cfg.P2P.PersistentPeersMaxDialPeriod = 60 * time.Second // Keep trying persistent peers

	// A transaction of mempool.max_tx_bytes must get through the RPC server (comet_tx_limits.go).
	applyCometTxLimits(cfg)
	return cfg, homeDir
}

// productionCometConfig is NewProductionEngine's configuration.
func productionCometConfig(cfg EngineConfig, logger *log.Logger) *config.Config {
	cometConfig := config.DefaultConfig()
	cometConfig.SetRoot(cfg.HomeDir)
	cometConfig.P2P.ListenAddress = fmt.Sprintf("tcp://0.0.0.0:%d", cfg.P2PPort)
	cometConfig.RPC.ListenAddress = fmt.Sprintf("tcp://0.0.0.0:%d", cfg.RPCPort)
	cometConfig.Consensus.CreateEmptyBlocks = cfg.CreateEmptyBlocks
	cometConfig.Moniker = cfg.ValidatorID

	// Enable transaction indexing for Tx query support
	cometConfig.TxIndex.Indexer = "kv"

	// Set persistent peers from structured config
	if len(cfg.PersistentPeers) > 0 {
		cometConfig.P2P.PersistentPeers = strings.Join(cfg.PersistentPeers, ",")
		logger.Printf("🔗 [PRODUCTION-ENGINE] Configured persistent peers: %s", cometConfig.P2P.PersistentPeers)
	}
	applyCometTxLimits(cometConfig)
	return cometConfig
}
