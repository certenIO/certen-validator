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
	"github.com/certen/independant-validator/pkg/finality/l1adapt"
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
	// the keys of the sibling finalized kind's layout pins (pkg/finality/arbfinal): accepted and ignored here
	ConfigSlotOffset       uint64 `json:"config_slot_offset"`
	FastConfirmerShiftBits uint64 `json:"fast_confirmer_shift_bits"`
	FastConfirmerSlot      uint64 `json:"fast_confirmer_slot"`
	StatusShiftBits        uint64 `json:"status_shift_bits"`
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
	// ConfirmPath and ProxySlots are the arb_sepolia keys of the sibling arb-sepolia/finalized/v1 kind (pkg/finality/arbfinal). The
	// section is shared, this decoder refuses unknown keys, and neither key is read by this kind: they are accepted and ignored, so the
	// embedded pins (which carry both) load here.
	ConfirmPath json.RawMessage `json:"confirm_path"`
	ProxySlots  json.RawMessage `json:"proxy_slots"`

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
	// The three numeric pins whose value 0 is a possible value are judged by presence: an absent (or null) key decodes as 0 and must not
	// switch the pre-BoLD guard or a storage slot silently to 0.
	var present struct {
		BoldGenesisL2Block *uint64 `json:"bold_genesis_l2_block"`
		Layout             struct {
			AccArraySlot        *uint64 `json:"acc_array_slot"`
			DelayedAccArraySlot *uint64 `json:"delayed_acc_array_slot"`
		} `json:"layout"`
	}
	if err := json.Unmarshal(raw, &present); err != nil {
		return nil, PinMismatch("section")
	}
	switch {
	case present.BoldGenesisL2Block == nil:
		return nil, PinMismatch("bold_genesis_l2_block")
	case present.Layout.AccArraySlot == nil:
		return nil, PinMismatch("layout.acc_array_slot")
	case present.Layout.DelayedAccArraySlot == nil:
		return nil, PinMismatch("layout.delayed_acc_array_slot")
	}
	return &a, nil
}

// bridgeImplRole is the logic_pins role of the Bridge implementation.
const bridgeImplRole = "bridge_impl"

// pinnedBridgeImpl reports whether codeHash is pinned with the bridge_impl role.
func (a *arbPins) pinnedBridgeImpl(codeHash [32]byte) bool {
	return a.LogicPins["0x"+hex.EncodeToString(codeHash[:])] == bridgeImplRole
}

// ethl1Pins converts the Sepolia section of the pins file to the L1 head verifier's pins (l1adapt's conversion) and returns the
// KZG setup pin the blob kinds share.
func ethl1Pins(p *finality.Pins) (ethl1.Pins, string, error) {
	out, err := l1adapt.PinsOf(p)
	if err != nil {
		return out, "", err
	}
	e, _ := p.Sepolia()
	kzg, _, kerr := p.KZGSetupPin("eth_sepolia."+pinKZG, e.KZGSetupSHA256)
	if kerr != nil {
		return out, "", kerr
	}
	return out, kzg, nil
}
