// Copyright 2026 Certen Protocol

package baseposted

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
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
	KZGSetupSHA256         string
	SystemConfigImplHashes map[[32]byte]bool // impl_pins rows with role syscfg_impl
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
		KZGSetupSHA256: r.KZGSetupSHA256, SystemConfigImplHashes: map[[32]byte]bool{}}
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
		"granite_time": r.GraniteTime, "channel_timeout_granite": r.ChannelTimeoutGranite, "max_rlp_bytes_per_channel": r.MaxRLPBytesPerChannel, "l2_genesis_time": r.L2GenesisTime, "l2_block_time": r.L2BlockTime, "isthmus_time": r.IsthmusTime, "denim_time": r.DenimTime} {
		if v == 0 {
			return nil, bad(k)
		}
	}
	if r.MaxBlobs <= 0 {
		return nil, bad("max_blobs")
	}
	if k, ok := unhex("0x"+r.KZGSetupSHA256, 32); !ok || len(k) != 32 {
		return nil, bad("kzg_setup_sha256")
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

// ethl1Pins converts the framework's Sepolia section into the L1 head verifier's pins.
func ethl1Pins(e *finality.EthSepoliaPins) ethl1.Pins {
	var p ethl1.Pins
	p.Network.ChainID = e.ChainID
	gvr, _ := unhex(e.GenesisValidatorsRoot, 32)
	copy(p.Network.GenesisValidatorsRoot[:], gvr)
	for _, f := range e.Forks {
		fk := ethl1.Fork{Name: f.Name, Epoch: f.Epoch}
		v, _ := unhex(f.Version, 4)
		copy(fk.Version[:], v)
		if f.Layout != nil {
			switch *f.Layout {
			case "electra":
				fk.Layout = ethl1.LayoutElectra
			case "gloas":
				fk.Layout = ethl1.LayoutGloas
			}
		}
		p.Network.Forks = append(p.Network.Forks, fk)
	}
	for _, a := range e.Anchors {
		an := ethl1.Anchor{Period: a.Period, WSPEpochs: a.WspEpochs}
		cr, _ := unhex(a.CommitteeRoot, 32)
		copy(an.CommitteeRoot[:], cr)
		if a.BlockRoot != "" {
			br, _ := unhex(a.BlockRoot, 32)
			var b32 [32]byte
			copy(b32[:], br)
			an.BlockRoot = &b32
		}
		p.Anchors = append(p.Anchors, an)
	}
	p.MinParticipants, p.MaxLinks, p.MaxSpineHeaders = e.MinParticipants, e.MaxLinks, e.MaxSpineHeaders
	return p
}

// stateOf adapts an L1 head fault to the framework's StateError with the same code and fields.
func stateOf(err error) error {
	if f, ok := err.(*ethl1.Fault); ok {
		s := finality.NewState(f.Code)
		for k, v := range f.Fields {
			s.Fields[k] = v
		}
		return s
	}
	return err
}

// EthL1Pins is the L1 head verifier's view of the framework pins (used by the vector generator).
func EthL1Pins(p *finality.Pins) ethl1.Pins {
	e, err := p.Sepolia()
	if err != nil {
		return ethl1.Pins{}
	}
	return ethl1Pins(e)
}
