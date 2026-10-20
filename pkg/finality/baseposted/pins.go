// Copyright 2026 Certen Protocol

package baseposted

import (
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
	ChainID                uint64
	L1ChainID              uint64
	SystemConfig           [20]byte
	BatchInbox             [20]byte
	SeqWindowSize          uint64
	ChannelTimeout         uint64
	MaxRLPBytesPerChannel  uint64
	IsthmusTime            uint64
	DenimTime              uint64
	MaxBlobs               int
	L2GenesisTime          uint64
	L2BlockTime            uint64
	KZGSetupSHA256         string            // from Pins.KZGSetupPin: the shared section, or the legacy base_sepolia copy of a published pins file
	KZGSetupKey            string            // the pins key KZGSetupSHA256 was read from, for pins_corrupt reports
	SystemConfigImplHashes map[[32]byte]bool // impl_pins rows with role syscfg_impl
}

type rawBasePins struct {
	ChainID               uint64                     `json:"chain_id"`
	L1ChainID             uint64                     `json:"l1_chain_id"`
	SystemConfig          string                     `json:"system_config"`
	BatchInbox            string                     `json:"batch_inbox"`
	SeqWindowSize         uint64                     `json:"seq_window_size"`
	ChannelTimeout        uint64                     `json:"channel_timeout"`
	MaxRLPBytesPerChannel uint64                     `json:"max_rlp_bytes_per_channel"`
	IsthmusTime           uint64                     `json:"isthmus_time"`
	DenimTime             uint64                     `json:"denim_time"`
	MaxBlobs              int                        `json:"max_blobs"`
	L2GenesisTime         uint64                     `json:"l2_genesis_time"`
	L2BlockTime           uint64                     `json:"l2_block_time"`
	KZGSetupSHA256        string                     `json:"kzg_setup_sha256"`
	ImplPins              map[string]json.RawMessage `json:"impl_pins"`
}

func unhex(s string, n int) ([]byte, bool) {
	if !strings.HasPrefix(s, "0x") || s != strings.ToLower(s) {
		return nil, false
	}
	b, err := hex.DecodeString(s[2:])
	return b, err == nil && len(b) == n
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
		MaxRLPBytesPerChannel: r.MaxRLPBytesPerChannel, IsthmusTime: r.IsthmusTime, DenimTime: r.DenimTime, MaxBlobs: r.MaxBlobs, L2GenesisTime: r.L2GenesisTime, L2BlockTime: r.L2BlockTime,
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
	for k, v := range map[string]uint64{"seq_window_size": r.SeqWindowSize, "channel_timeout": r.ChannelTimeout,
		"max_rlp_bytes_per_channel": r.MaxRLPBytesPerChannel, "l2_genesis_time": r.L2GenesisTime, "l2_block_time": r.L2BlockTime, "isthmus_time": r.IsthmusTime, "denim_time": r.DenimTime} {
		if v == 0 {
			return nil, bad(k)
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
