// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// UsedKZGSetupSHA256 is the SHA-256 of the trusted-setup file the Go KZG backend (go-ethereum crypto/kzg4844, pure-Go
// go-eth-kzg) loads: its embedded trusted_setup.json, byte-identical to the Ethereum ceremony output at consensus-specs
// v1.7.0-beta.4 (presets/mainnet/trusted_setups/trusted_setup_4096.json), checked by TestKZGSetupIsTheCeremonyOutput. The pin
// `eth_sepolia.kzg_setup_sha256` must equal it, else the verifier refuses with pin_mismatch{field:"kzg_setup_sha256"}.
const UsedKZGSetupSHA256 = "f8e44a31ebf0a6d0734dcb301b0716e2c77f3ae18ed0cab0870fbcc2ca55616f"

// Layout pins (spec 4.2).
type layoutPins struct {
	Name                string `json:"name"`
	AssertionsSlot      uint64 `json:"assertions_slot"`
	AccArraySlot        uint64 `json:"acc_array_slot"`
	DelayedAccArraySlot uint64 `json:"delayed_acc_array_slot"`
}

// arbPins is the arb_sepolia section of the pins file (spec 4.2).
type arbPins struct {
	BoldGenesisAssertion string            `json:"bold_genesis_assertion"`
	BoldGenesisL2Block   uint64            `json:"bold_genesis_l2_block"`
	Bridge               string            `json:"bridge"`
	ChainID              uint64            `json:"chain_id"`
	Layout               layoutPins        `json:"layout"`
	LogicPins            map[string]string `json:"logic_pins"`
	MaxBlobs             int               `json:"max_blobs"`
	MaxHeaderChain       int               `json:"max_header_chain"`
	MaxSegments          int               `json:"max_segments"`
	MaxUncompressedBatch int               `json:"max_uncompressed_batch"`
	ParentChainID        uint64            `json:"parent_chain_id"`
	Rollup               string            `json:"rollup"`

	bridge common.Address
}

// Pin field names used in pin_mismatch / finality_pin_unknown.
const (
	pinSection = "arb_sepolia"
	pinKZG     = "kzg_setup_sha256"
)

func hexAddr(s string) (common.Address, bool) {
	if !strings.HasPrefix(s, "0x") || len(s) != 42 {
		return common.Address{}, false
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return common.Address{}, false
	}
	return common.BytesToAddress(b), true
}

// loadArbPins parses the arb_sepolia section. An absent section is finality_pin_unknown; a section that does not parse or
// whose values are outside their domain is pin_mismatch{field}.
func loadArbPins(p *finality.Pins) (*arbPins, error) {
	if p == nil {
		return nil, finality.NewState(finality.CodePinUnknown, "chain", finality.ChainArbitrumSepolia, "kind", pinSection)
	}
	raw, ok := p.Sections[pinSection]
	if !ok {
		return nil, finality.NewState(finality.CodePinUnknown, "chain", finality.ChainArbitrumSepolia, "kind", pinSection)
	}
	var a arbPins
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, PinMismatch("section")
	}
	if a.ChainID != finality.ChainArbitrumSepolia {
		return nil, PinMismatch("chain_id")
	}
	if a.ParentChainID != finality.ChainSepolia {
		return nil, PinMismatch("parent_chain_id")
	}
	var okb bool
	if a.bridge, okb = hexAddr(a.Bridge); !okb {
		return nil, PinMismatch("bridge")
	}
	if a.Layout.Name != "nitro-contracts-v3.1.0" {
		return nil, PinMismatch("layout")
	}
	if a.MaxBlobs <= 0 {
		return nil, PinMismatch("max_blobs")
	}
	if a.MaxSegments <= 0 {
		return nil, PinMismatch("max_segments")
	}
	if a.MaxUncompressedBatch <= 0 {
		return nil, PinMismatch("max_uncompressed_batch")
	}
	return &a, nil
}

// bridgeImplRole is the logic_pins role of the Bridge implementation.
const bridgeImplRole = "bridge_impl"

// pinnedBridgeImpl reports whether codeHash is pinned with the bridge_impl role.
func (a *arbPins) pinnedBridgeImpl(codeHash [32]byte) bool {
	return a.LogicPins["0x"+hex.EncodeToString(codeHash[:])] == bridgeImplRole
}

// ethl1Pins converts the Sepolia section of the pins file to the L1 head verifier's pins.
func ethl1Pins(p *finality.Pins) (ethl1.Pins, string, error) {
	var out ethl1.Pins
	e, err := p.Sepolia()
	if err != nil {
		return out, "", err
	}
	out.Network.ChainID = e.ChainID
	gvr, _ := hex.DecodeString(strings.TrimPrefix(e.GenesisValidatorsRoot, "0x"))
	copy(out.Network.GenesisValidatorsRoot[:], gvr)
	for _, f := range e.Forks {
		var fk ethl1.Fork
		fk.Name, fk.Epoch = f.Name, f.Epoch
		v, _ := hex.DecodeString(strings.TrimPrefix(f.Version, "0x"))
		copy(fk.Version[:], v)
		if f.Layout != nil {
			switch *f.Layout {
			case "electra":
				fk.Layout = ethl1.LayoutElectra
			case "gloas":
				fk.Layout = ethl1.LayoutGloas
			}
		}
		out.Network.Forks = append(out.Network.Forks, fk)
	}
	for _, a := range e.Anchors {
		var an ethl1.Anchor
		an.Period, an.WSPEpochs = a.Period, a.WspEpochs
		r, _ := hex.DecodeString(strings.TrimPrefix(a.CommitteeRoot, "0x"))
		copy(an.CommitteeRoot[:], r)
		if a.BlockRoot != "" {
			var br [32]byte
			b, _ := hex.DecodeString(strings.TrimPrefix(a.BlockRoot, "0x"))
			copy(br[:], b)
			an.BlockRoot = &br
		}
		out.Anchors = append(out.Anchors, an)
	}
	out.MinParticipants, out.MaxLinks, out.MaxSpineHeaders = e.MinParticipants, e.MaxLinks, e.MaxSpineHeaders
	return out, e.KZGSetupSHA256, nil
}
