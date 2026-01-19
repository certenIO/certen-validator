package ledger

import "time"

// ChainSummary represents a chain summary used in both system and anchor ledger responses
type ChainSummary struct {
	Name   string   `json:"name,omitempty"` // e.g. "main", "anchor(accumulate)-sequence"
	Type   string   `json:"type"`           // e.g. "block", "transaction", "anchor", "index"
	Height uint64   `json:"height"`
	Count  uint64   `json:"count"`
	Roots  []string `json:"roots"`
}

// SystemAccumulateAnchorRef represents a reference to an Accumulate anchor transaction
type SystemAccumulateAnchorRef struct {
	AccountURL string `json:"accountURL"`
	TxHash     string `json:"txHash"`
	MinorIndex uint64 `json:"minorIndex"`
	MajorIndex uint64 `json:"majorIndex"`
}

// ====== System Ledger Types ======

// SystemLedgerBlockMeta stores per-block metadata for the system ledger
type SystemLedgerBlockMeta struct {
	Height uint64    `json:"height"`
	Hash   string    `json:"hash"`
	Time   time.Time `json:"time"`

	// Optional link to Accumulate anchor that included this block (if any)
	AccumulateAnchorHash      string `json:"accumulateAnchorHash,omitempty"`
	AccumulateAnchorAccount   string `json:"accumulateAnchorAccount,omitempty"`
	AccumulateMinorBlockIndex uint64 `json:"accumulateMinorBlockIndex,omitempty"`
	AccumulateMajorBlockIndex uint64 `json:"accumulateMajorBlockIndex,omitempty"`
}

// UpstreamExecutor represents an upstream network executor version
type UpstreamExecutor struct {
	Partition string `json:"partition"`
	Version   string `json:"version"`
}

// SystemLedgerMeta stores global metadata for the system ledger
type SystemLedgerMeta struct {
	LatestHeight     uint64             `json:"latestHeight"`
	ExecutorVersion  string             `json:"executorVersion"`
	UpstreamVersions []UpstreamExecutor `json:"upstreamVersions"`
}

// SystemLedgerData represents the data field in system ledger query responses
type SystemLedgerData struct {
	Type                string             `json:"type"` // "systemLedger"
	URL                 string             `json:"url"`  // "certen://system/ledger"
	Index               uint64             `json:"index"`
	Timestamp           time.Time          `json:"timestamp"`
	ExecutorVersion     string             `json:"executorVersion"`
	BVNExecutorVersions []UpstreamExecutor `json:"bvnExecutorVersions"` // Name stays bvnExecutorVersions for 1:1 parity with Accumulate
}

// SystemLedgerState represents the complete system ledger query response
type SystemLedgerState struct {
	Type          string           `json:"type"` // "systemLedger"
	MainChain     ChainSummary     `json:"mainChain"`
	MerkleState   ChainSummary     `json:"merkleState"`
	Chains        []ChainSummary   `json:"chains"`
	Data          SystemLedgerData `json:"data"`
	ChainID       string           `json:"chainId"`
	LastBlockTime time.Time        `json:"lastBlockTime"`
}

// ====== Anchor Ledger Types ======

// AnchorTargetState stores per-target network state for the anchor ledger
type AnchorTargetState struct {
	TargetURL        string    `json:"url"` // e.g. "acc://dn.acme", "eth-mainnet"
	Received         uint64    `json:"received"`
	Delivered        uint64    `json:"delivered"`
	LastAnchorHeight uint64    `json:"lastAnchorHeight"`
	LastAnchorTxID   string    `json:"lastAnchorTxID"`
	LastAnchorTime   time.Time `json:"lastAnchorTime"`
}

// AnchorLedgerMeta stores global metadata for the anchor ledger
type AnchorLedgerMeta struct {
	LastSequenceNumber uint64    `json:"lastSequenceNumber"`
	LastMajorIndex     uint64    `json:"lastMajorIndex"`
	LastMajorTime      time.Time `json:"lastMajorTime"`
	LastBlockTime      time.Time `json:"lastBlockTime"`
}

// AnchorSequenceItem represents an item in the anchor sequence
type AnchorSequenceItem struct {
	URL       string `json:"url"`
	Received  uint64 `json:"received"`
	Delivered uint64 `json:"delivered"`
}

// AnchorLedgerData represents the data field in anchor ledger query responses
type AnchorLedgerData struct {
	Type                     string               `json:"type"` // "anchorLedger"
	URL                      string               `json:"url"`  // "certen://anchors"
	MinorBlockSequenceNumber uint64               `json:"minorBlockSequenceNumber"`
	MajorBlockIndex          uint64               `json:"majorBlockIndex"`
	MajorBlockTime           time.Time            `json:"majorBlockTime"`
	Sequence                 []AnchorSequenceItem `json:"sequence"`
}

// AnchorLedgerState represents the complete anchor ledger query response
type AnchorLedgerState struct {
	Type          string           `json:"type"` // "anchorLedger"
	MainChain     ChainSummary     `json:"mainChain"`
	MerkleState   ChainSummary     `json:"merkleState"`
	Chains        []ChainSummary   `json:"chains"`
	Data          AnchorLedgerData `json:"data"`
	ChainID       string           `json:"chainId"`
	LastBlockTime time.Time        `json:"lastBlockTime"`
}

// ====== Query Parameters ======

// SystemLedgerQueryParams represents query parameters for system ledger requests
type SystemLedgerQueryParams struct {
	Height *uint64 `json:"height,omitempty"` // if nil or "latest" use latest
}

// ====== ABCI State for CometBFT Recovery ======

// ABCIState stores the ABCI application state needed for CometBFT recovery after restart.
// This ensures Info() returns correct LastBlockHeight and LastBlockAppHash so CometBFT
// can sync properly with the application state.
type ABCIState struct {
	LastBlockHeight  int64  `json:"lastBlockHeight"`
	LastBlockAppHash []byte `json:"lastBlockAppHash"`
}

// ====== Anchor Targets Configuration ======

// AnchorTargets contains the fixed list of known anchor targets for iteration
var AnchorTargets = []string{
	"acc://dn.acme",
	"eth-mainnet",
	"btc-mainnet",
	// add more as needed
}