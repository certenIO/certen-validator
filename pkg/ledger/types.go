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

	// AdminReseals is the APPEND-ONLY record of every admin-set change: the v11 re-seal (consensus/admin_reseal.go)
	// and, from rules v12, every admin rotation the admin quorum in force authorised (consensus/admin_rotate.go). The
	// admin set in force at height H is the newest change recorded at a height below H, or AdminKeys/AdminThreshold
	// above if there is none - derived like Schedule, so a block is judged by the same admins however often it is
	// executed. AdminKeys/AdminThreshold stay the genesis seal.
	AdminReseals []AdminReseal `json:"adminReseals,omitempty"`

	// Schedule is the APPEND-ONLY list of accepted rule changes.
	//
	// The rule in force at height H is DERIVED from this list — the latest entry
	// whose ActivationUnix <= the block's time, or the genesis Mode/Keys above
	// if there is none. It is deliberately not a mutated "current mode" field.
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

// AdminReseal is one accepted change of the admin set: from Height+1 on, Keys/Threshold authorise.
//
// The fields rules v12 added are omitempty, so a record v11 wrote - the re-seal - serialises to exactly the bytes it
// always did, and a v11 record read back by v12 is the record v11 wrote.
type AdminReseal struct {
	Height    int64             `json:"height"`
	ID        string            `json:"id"`
	Keys      map[string]string `json:"keys"`
	Threshold int               `json:"threshold"`
	// Kind is the transaction kind that made the change: empty for the v11 re-seal (the only kind before v12),
	// "certen.admin.rotate/v1" for an admin rotation.
	Kind string `json:"kind,omitempty"`
	// Sequence is an admin rotation's ordinal: one more than the number of changes recorded before it, the re-seal
	// included. Zero on the re-seal, which carries none.
	Sequence uint64 `json:"sequence,omitempty"`
}

// ScheduledPolicyChange is one accepted rule change in the append-only schedule.
type ScheduledPolicyChange struct {
	Mode string            `json:"mode"`
	Keys map[string]string `json:"keys,omitempty"`
	// ActivationUnix is when the change takes effect, judged against ABCI BLOCK
	// TIME — not wall time, and not a block height.
	//
	// Block time is in the header, identical on every node, so it is as
	// deterministic as a height. A height is not equivalent: this chain
	// produces blocks only for real work, so "200 blocks" was weeks or never,
	// and any height-based window silently changes meaning as throughput does.
	// A time is stable regardless.
	//
	// On an idle chain the change simply takes effect at the first block at or
	// after this instant, which is the correct behaviour: nothing is being
	// gated in the meantime because nothing is happening.
	ActivationUnix int64  `json:"activationUnix"`
	Version        uint64 `json:"version"`

	// ProposedAtHeight is where the update was accepted, kept for audit: "when
	// did enforcement begin and who authorised it" should be answerable from
	// the chain rather than from shell history.
	ProposedAtHeight int64 `json:"proposedAtHeight"`
}

// ====== Validator consensus-key rotations (RB3-F95) ======

// ValidatorRotationLog is every validator consensus-key rotation this chain has accepted, oldest first.
// The validator set at a height is the genesis set with every rotation accepted below that height applied.
type ValidatorRotationLog struct {
	Rotations []ValidatorRotationRecord `json:"rotations"`
}

// ValidatorRotationRecord is one accepted rotation: the old key left the set and the new key took its power,
// effective (CometBFT) two blocks after Height.
type ValidatorRotationRecord struct {
	Version   uint64 `json:"version"`
	Height    int64  `json:"height"`      // the block that accepted it
	OldPubKey string `json:"old_pub_key"` // hex ed25519
	NewPubKey string `json:"new_pub_key"` // hex ed25519
	Power     int64  `json:"power"`
	ID        string `json:"id"` // folded into the app hash of Height
	// AdoptedHeight is the first block whose commit carries a signature by the new key: from then on the
	// rotated validator is known to be signing. Zero until then. Another rotation is refused while one is
	// not adopted, so a rotation whose new key is not running can never be compounded by a second one.
	AdoptedHeight int64 `json:"adopted_height,omitempty"`
}

// ====== Anchor Targets Configuration ======

// AnchorTargets contains the fixed list of known anchor targets for iteration
var AnchorTargets = []string{
	"acc://dn.acme",
	"eth-mainnet",
	"btc-mainnet",
	// add more as needed
}

// BLSRegistryLog is every version of CERTEN's BLS registry this chain has accepted, oldest first (RB5 D3). The
// registry in force at a height is the newest version accepted below it.
type BLSRegistryLog struct {
	Versions []BLSRegistryRecord `json:"versions"`
}

// BLSRegistryRecord is one accepted registry version: who CERTEN's BLS quorum is, by validator id, and the
// Accumulate incarnation the quorum attests under.
type BLSRegistryRecord struct {
	Version              uint64              `json:"version"`
	Height               int64               `json:"height"` // the block that accepted it
	Members              []BLSRegistryMember `json:"members"`
	ThresholdNumerator   uint64              `json:"threshold_numerator"`
	ThresholdDenominator uint64              `json:"threshold_denominator"`
	// AccumulateIncarnation is hex32 (docs/l4/INCARNATION_ANCHOR.md).
	AccumulateIncarnation string `json:"accumulate_incarnation"`
	// CertenSetRoot is the anchor's currentValidatorSetRoot for these members (hex32), derived at acceptance.
	CertenSetRoot string `json:"certen_set_root"`
	ID            string `json:"id"` // folded into the app hash of Height
}

// AnchorSetLog is every version of CERTEN's anchor set this chain has accepted, oldest first (rules v14, RB4-F35). The
// anchor set in force at a height is the newest version accepted below it.
type AnchorSetLog struct {
	Versions []AnchorSetRecord `json:"versions"`
}

// AnchorSetRecord is one accepted anchor-set version: the anchor contract every ValidatorBlock's chain target must name,
// per settlement chain.
type AnchorSetRecord struct {
	Version uint64           `json:"version"`
	Height  int64            `json:"height"` // the block that accepted it
	Anchors []AnchorSetEntry `json:"anchors"`
	ID      string           `json:"id"` // folded into the app hash of Height
}

// AnchorSetEntry is one chain's committed anchor.
type AnchorSetEntry struct {
	ChainID int64  `json:"chain_id"`
	Anchor  string `json:"anchor"` // EIP-55 checksummed 0x address
}

// BLSRegistryMember is one validator of the registry.
type BLSRegistryMember struct {
	ValidatorID string `json:"validator_id"`
	EVMAddress  string `json:"evm_address"` // lowercase 0x hex
	BLSPubKey   string `json:"bls_pub_key"` // lowercase hex, 96 bytes
	Power       uint64 `json:"power"`
}

// IntentQuorumLog is, for one operation, every committed intent signature grouped by the message and registry it
// was signed under, and the quorum certificate of each group that reached the registry's threshold (RB5 D3).
type IntentQuorumLog struct {
	OperationID string              `json:"operation_id"`
	Groups      []IntentQuorumGroup `json:"groups"`
}

// IntentQuorumGroup is the signatures over one message under one registry version.
type IntentQuorumGroup struct {
	Message         string `json:"message"` // 0x-hex32
	RegistryVersion uint64 `json:"registry_version"`
	// KeyPageURL is the ADI key page the message certifies (canonical spelling): the G1 snapshot page whose hash the
	// message commits through govRoot v2. Recorded so a validator can read back the page a certified intent's batch
	// leaf binds (RB5-F29); every block signing the message names this page, since the message commits its hash.
	KeyPageURL string `json:"key_page_url"`
	// KeyBookURL is the key book that page belongs to (canonical spelling), whose hash the message also commits.
	// A V8.2 leaf binds the (book, page) pair: an account's authority is a page OF a book (RB5-F30).
	KeyBookURL  string                   `json:"key_book_url"`
	Partials    []IntentPartial          `json:"partials"`
	Certificate *IntentQuorumCertificate `json:"certificate,omitempty"`
}

// IntentPartial is one validator's committed intent signature.
type IntentPartial struct {
	ValidatorID string `json:"validator_id"`
	Signature   string `json:"signature"` // hex G1
	Height      int64  `json:"height"`    // the block that committed it
}

// IntentQuorumCertificate is CERTEN's quorum over one intent message: the aggregate of the signers' signatures, the
// aggregate of their registered keys, and the power that signed, out of the registry's.
type IntentQuorumCertificate struct {
	OperationID          string   `json:"operation_id"`
	Message              string   `json:"message"`
	RegistryVersion      uint64   `json:"registry_version"`
	CertenSetRoot        string   `json:"certen_set_root"`
	Height               int64    `json:"height"`           // the block whose commit completed the quorum
	Signers              []string `json:"signers"`          // validator ids, in ascending EVM address order
	SignerAddresses      []string `json:"signer_addresses"` // ascending
	AggregateSignature   string   `json:"aggregate_signature"`
	AggregatePublicKey   string   `json:"aggregate_public_key"`
	SignedPower          string   `json:"signed_power"`
	TotalPower           string   `json:"total_power"`
	ThresholdNumerator   uint64   `json:"threshold_numerator"`
	ThresholdDenominator uint64   `json:"threshold_denominator"`
}
