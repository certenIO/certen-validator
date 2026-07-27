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

	// ExecutionRulesVersion records WHICH rules produced the app hash above.
	//
	// The app hash depends on which transactions were accepted, so any change to
	// accept/reject semantics changes it. Replaying history under different
	// rules than committed it yields a different hash and CometBFT panics at
	// handshake before the node can serve — with no self-recovery. Persisting
	// the version lets a node detect that at startup and say so, instead of
	// dying on a hash comparison that names nothing.
	//
	// Zero means "written before this field existed"; treat as adopt-current.
	ExecutionRulesVersion uint64 `json:"executionRulesVersion,omitempty"`
}

// EntitlementPolicyState is the entitlement rule this chain applies, sealed at
// genesis and immutable thereafter.
//
// It lives in committed state rather than the environment because the gate's
// verdict decides whether a ValidatorBlock is accepted, and acceptance feeds
// the app hash. A rule that can change between two runs of the same binary lets
// a node disagree with its own committed past, which is unrecoverable: replay
// produces a different app hash than CometBFT recorded, and the node panics at
// handshake before it can serve.
//
// Keys are stored alongside the mode for the same reason — a node verifying
// with a different key set reaches a different verdict, which is the same
// divergence by another route.
type EntitlementPolicyState struct {
	Mode string `json:"mode"` // off | observe | enforce

	// Keys maps keyID -> hex-encoded ed25519 public key.
	Keys map[string]string `json:"keys,omitempty"`

	// SealedAtHeight records when the policy was fixed; 0 = genesis.
	SealedAtHeight int64 `json:"sealedAtHeight"`

	// Version increases with every accepted PolicyUpdate. It is what makes an
	// update non-replayable: an update carrying a version already applied is
	// refused.
	Version uint64 `json:"version"`

	// AdminKeys are the operator keys permitted to propose a PolicyUpdate,
	// keyID -> hex ed25519 public key. Sealed at genesis with everything else:
	// a chain whose admin set could be edited locally would let one node
	// authorise a rule change the others never agreed to.
	AdminKeys map[string]string `json:"adminKeys,omitempty"`

	// AdminThreshold is how many distinct admin signatures an update needs.
	// Turning enforcement on is as consequential as the payments it gates, so
	// it should not rest on a single key.
	AdminThreshold int `json:"adminThreshold,omitempty"`

	// Schedule is the APPEND-ONLY list of accepted rule changes.
	//
	// The rule in force at height H is DERIVED from this list — the latest entry
	// whose ActivationHeight <= H, or the genesis Mode/Keys above if there is
	// none. It is deliberately not a mutated "current mode" field.
	//
	// That distinction is the whole correctness argument. A mutated current
	// value reflects how far the chain has progressed, so replaying block 10
	// after the chain reached block 210 would judge block 10 by the rule active
	// at 210 — the same divergence that caused the 2026-07-27 outage, merely
	// relocated. A derived value depends only on (schedule, height), so block 10
	// is judged identically no matter when it is executed.
	//
	// Append-only also makes re-applying an update idempotent, which replay
	// requires: the second application finds the version already present and
	// changes nothing.
	Schedule []ScheduledPolicyChange `json:"schedule,omitempty"`
}

// ScheduledPolicyChange is one accepted rule change in the append-only schedule.
type ScheduledPolicyChange struct {
	Mode             string            `json:"mode"`
	Keys             map[string]string `json:"keys,omitempty"`
	ActivationHeight int64             `json:"activationHeight"`
	Version          uint64            `json:"version"`

	// ProposedAtHeight is where the update was accepted, kept for audit: "when
	// did enforcement begin and who authorised it" should be answerable from
	// the chain rather than from shell history.
	ProposedAtHeight int64 `json:"proposedAtHeight"`
}

// ====== Anchor Targets Configuration ======

// AnchorTargets contains the fixed list of known anchor targets for iteration
var AnchorTargets = []string{
	"acc://dn.acme",
	"eth-mainnet",
	"btc-mainnet",
	// add more as needed
}
