// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/l1adapt"
)

// The names this kind judges under.
const (
	KindName = "base-sepolia/l1_posted/v1"
	Chain    = finality.ChainBaseSepolia
	// RoleSystemConfigImpl is the impl_pins role of the SystemConfig implementation (V2_SPEC_S7 section 4.2).
	RoleSystemConfigImpl = "syscfg_impl"
)

// Pins are the base_sepolia pieces of finality-pins.json this kind reads (V2_SPEC_S7 section 4.2). The section is kept raw
// by the framework (Pins.Sections) and parsed here; keys other chain kinds add (portal, game impl rows, max_l2_headers...) are
// ignored. The batcher is never a pin: it is proven from SystemConfig.batcherHash at each frame block.
type Pins struct {
	ChainID               uint64
	L1ChainID             uint64
	SystemConfig          [20]byte
	BatchInbox            [20]byte
	SeqWindowSize         uint64
	ChannelTimeout        uint64 // Bedrock value, in L1 blocks; in force for an L1 block whose time is before GraniteTime
	GraniteTime           uint64 // activation time of Granite (L1 block time, seconds): from it the channel timeout is ChannelTimeoutGranite
	ChannelTimeoutGranite uint64 // the post-Granite channel timeout, in L1 blocks (op-node params.ChannelTimeoutGranite = 50)
	MaxRLPBytesPerChannel uint64
	// IsthmusTime is INFORMATIONAL for l1_posted: nothing in this kind's judgement depends on it, because the only Isthmus changes
	// that touch a Base block are the header's withdrawalsRoot/requestsHash (not read here) and the operator-fee tail appended to
	// the L1-info deposit's calldata after the fields this kind reads (number at [28:36], hash at [100:132] are the Ecotone
	// layout in every later fork). It is required and non-zero because the base_sepolia section is shared with the finalized kind,
	// which refuses a pre-Isthmus header (the header-only output root, spec 5.5 O5).
	IsthmusTime            uint64
	DenimTime              uint64
	MaxBlobs               int
	L2GenesisTime          uint64
	L2BlockTime            uint64
	KZGSetupSHA256         string            // from Pins.KZGSetupPin: the shared section, or the legacy base_sepolia copy of a published pins file
	KZGSetupKey            string            // the pins key KZGSetupSHA256 was read from, for pins_corrupt reports
	SystemConfigImplHashes map[[32]byte]bool // impl_pins rows with role syscfg_impl
	// PostDenim is the capability row (base_sepolia.post_denim) that lets a block with timestamp >= DenimTime be judged: nil when the
	// pins file has none, and then every such block is batch_format_unsupported{post_denim} (a new binary on old pins fails closed).
	PostDenim *PostDenim
}

// PostDenim is what the verifier assumes of Base after the Denim fork (R11-base-denim): 200 ms blocks, five blocks per timestamp
// second, and singular batches only (op-node drops a span batch that would produce a Denim block, BatchDropReason::SpanPostDenim).
// BatchTypes is judged (the selected batch's type must be in it) and BlockIntervalMS * BlocksPerSecond must be one second. The
// BaseTime pair is carried so a later predicate on the BaseTime deposit needs no second pins change; ParsePins validates its shape and
// l1_posted does not yet judge it (TECH_DEBT O6: the schedule predicate is not part of l1_posted).
type PostDenim struct {
	BatchTypes        []uint8
	BlockIntervalMS   uint64
	BlocksPerSecond   uint64
	BaseTimePredeploy [20]byte
	BaseTimeSelector  [4]byte
}

// allowsBatchType is whether a batch of type t may carry a post-Denim block.
func (p *PostDenim) allowsBatchType(t uint8) bool {
	if p == nil {
		return false
	}
	for _, x := range p.BatchTypes {
		if x == t {
			return true
		}
	}
	return false
}

type rawPostDenim struct {
	BatchTypes        []uint8 `json:"batch_types"`
	BlockIntervalMS   uint64  `json:"block_interval_ms"`
	BlocksPerSecond   uint64  `json:"blocks_per_second"`
	BaseTimePredeploy string  `json:"base_time_predeploy"`
	BaseTimeSelector  string  `json:"base_time_selector"`
}

// parsePostDenim reads the capability row; ok is false for any malformed row (the caller names the key).
func parsePostDenim(raw json.RawMessage) (*PostDenim, bool) {
	var r rawPostDenim
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, false
	}
	// only singular batches (type 0) can carry a Denim block: a span batch is dropped by derivation, so a row naming one is corrupt
	if len(r.BatchTypes) != 1 || r.BatchTypes[0] != 0 {
		return nil, false
	}
	if r.BlockIntervalMS == 0 || r.BlocksPerSecond == 0 || r.BlockIntervalMS > 1000 || 1000%r.BlockIntervalMS != 0 || 1000/r.BlockIntervalMS != r.BlocksPerSecond {
		return nil, false
	}
	pre, ok := unhex(r.BaseTimePredeploy, 20)
	if !ok {
		return nil, false
	}
	sel, ok := unhex(r.BaseTimeSelector, 4)
	if !ok {
		return nil, false
	}
	out := &PostDenim{BatchTypes: append([]uint8(nil), r.BatchTypes...), BlockIntervalMS: r.BlockIntervalMS, BlocksPerSecond: r.BlocksPerSecond}
	copy(out.BaseTimePredeploy[:], pre)
	copy(out.BaseTimeSelector[:], sel)
	return out, true
}

type rawBasePins struct {
	ChainID               uint64                     `json:"chain_id"`
	L1ChainID             uint64                     `json:"l1_chain_id"`
	SystemConfig          string                     `json:"system_config"`
	BatchInbox            string                     `json:"batch_inbox"`
	SeqWindowSize         uint64                     `json:"seq_window_size"`
	ChannelTimeout        uint64                     `json:"channel_timeout"`
	GraniteTime           uint64                     `json:"granite_time"`
	ChannelTimeoutGranite uint64                     `json:"channel_timeout_granite"`
	MaxRLPBytesPerChannel uint64                     `json:"max_rlp_bytes_per_channel"`
	IsthmusTime           uint64                     `json:"isthmus_time"`
	DenimTime             uint64                     `json:"denim_time"`
	MaxBlobs              int                        `json:"max_blobs"`
	L2GenesisTime         uint64                     `json:"l2_genesis_time"`
	L2BlockTime           uint64                     `json:"l2_block_time"`
	KZGSetupSHA256        string                     `json:"kzg_setup_sha256"`
	ImplPins              map[string]json.RawMessage `json:"impl_pins"`
	PostDenim             json.RawMessage            `json:"post_denim"`
}

func unhex(s string, n int) ([]byte, bool) {
	if !strings.HasPrefix(s, "0x") || s != strings.ToLower(s) {
		return nil, false
	}
	b, err := hex.DecodeString(s[2:])
	return b, err == nil && len(b) == n
}

// ChannelTimeoutAt is op-node's ChainSpec.ChannelTimeout(t) (op-node/rollup/chain_spec.go): the Granite value when t >= GraniteTime,
// the Bedrock value before. t is the timestamp of the L1 block the frame is included in (op-node's origin.Time at IngestFrame).
func (p *Pins) ChannelTimeoutAt(l1Time uint64) uint64 {
	if l1Time >= p.GraniteTime {
		return p.ChannelTimeoutGranite
	}
	return p.ChannelTimeout
}

// ParsePins reads the base_sepolia section of the framework pins. An absent section is finality_pin_unknown; a malformed one
// is finality_pins_corrupt{bad_value, key}.
func ParsePins(p *finality.Pins) (*Pins, error) {
	var raw json.RawMessage
	if p != nil {
		raw = p.Sections["base_sepolia"]
	}
	if len(raw) == 0 {
		return nil, finality.NewState(finality.CodePinUnknown, "chain", uint64(Chain), "kind", "base_sepolia")
	}
	var r rawBasePins
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, finality.PinsCorrupt(finality.PinsBadValue, "key", "base_sepolia")
	}
	bad := func(key string) error { return finality.PinsCorrupt(finality.PinsBadValue, "key", "base_sepolia."+key) }
	out := &Pins{ChainID: r.ChainID, L1ChainID: r.L1ChainID, SeqWindowSize: r.SeqWindowSize, ChannelTimeout: r.ChannelTimeout,
		GraniteTime: r.GraniteTime, ChannelTimeoutGranite: r.ChannelTimeoutGranite, MaxRLPBytesPerChannel: r.MaxRLPBytesPerChannel, IsthmusTime: r.IsthmusTime, DenimTime: r.DenimTime, MaxBlobs: r.MaxBlobs, L2GenesisTime: r.L2GenesisTime, L2BlockTime: r.L2BlockTime,
		SystemConfigImplHashes: map[[32]byte]bool{}}
	if r.ChainID != uint64(Chain) {
		return nil, bad("chain_id")
	}
	if r.L1ChainID != ethl1.SepoliaChainID {
		return nil, bad("l1_chain_id")
	}
	sc, ok := unhex(strings.ToLower(r.SystemConfig), 20)
	if !ok {
		return nil, bad("system_config")
	}
	copy(out.SystemConfig[:], sc)
	bi, ok := unhex(strings.ToLower(r.BatchInbox), 20)
	if !ok {
		return nil, bad("batch_inbox")
	}
	copy(out.BatchInbox[:], bi)
	// Several zero pins are judged in sorted-name order, so the key a refusal names is a function of the file (RB12-OPS-A1, F4/N1: this
	// loop ranged over a Go map and named a random one of them).
	for _, z := range []struct {
		key string
		v   uint64
	}{{"channel_timeout", r.ChannelTimeout}, {"channel_timeout_granite", r.ChannelTimeoutGranite}, {"denim_time", r.DenimTime},
		{"granite_time", r.GraniteTime}, {"isthmus_time", r.IsthmusTime}, {"l2_block_time", r.L2BlockTime}, {"l2_genesis_time", r.L2GenesisTime},
		{"max_rlp_bytes_per_channel", r.MaxRLPBytesPerChannel}, {"seq_window_size", r.SeqWindowSize}} {
		if z.v == 0 {
			return nil, bad(z.key)
		}
	}
	if r.MaxBlobs <= 0 {
		return nil, bad("max_blobs")
	}
	var kerr error
	if out.KZGSetupSHA256, out.KZGSetupKey, kerr = p.KZGSetupPin("base_sepolia.kzg_setup_sha256", r.KZGSetupSHA256); kerr != nil {
		return nil, kerr
	}
	if k, ok := unhex("0x"+out.KZGSetupSHA256, 32); !ok || len(k) != 32 {
		return nil, finality.PinsCorrupt(finality.PinsBadValue, "key", out.KZGSetupKey)
	}
	for ch, row := range r.ImplPins {
		h, ok := unhex(ch, 32)
		if !ok {
			return nil, bad("impl_pins")
		}
		var role struct {
			Role string `json:"role"`
		}
		if err := json.Unmarshal(row, &role); err != nil {
			return nil, bad("impl_pins")
		}
		if role.Role == RoleSystemConfigImpl {
			out.SystemConfigImplHashes[[32]byte(h)] = true
		}
	}
	if len(out.SystemConfigImplHashes) == 0 {
		return nil, bad("impl_pins")
	}
	if len(r.PostDenim) != 0 {
		pd, ok := parsePostDenim(r.PostDenim)
		if !ok {
			return nil, bad("post_denim")
		}
		out.PostDenim = pd
	}
	return out, nil
}

// EthL1Pins is the L1 head verifier's view of the framework pins (used by the builder and the vector generator); the
// conversion is l1adapt's. Pins without a Sepolia section yield the zero value.
func EthL1Pins(p *finality.Pins) ethl1.Pins {
	out, err := l1adapt.PinsOf(p)
	if err != nil {
		return ethl1.Pins{}
	}
	return out
}
