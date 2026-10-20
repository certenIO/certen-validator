// Copyright 2026 Certen Protocol

package arbfinal

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// pinSection is the pins file section of this kind (V2_SPEC_S7 4.2).
const pinSection = "arb_sepolia"

// layoutPins is the storage layout of nitro-contracts v3.1.0 (annex A4). The acc/delayed array slots belong to the l1_posted
// kind (arbposted); they are accepted here so that the one shared section parses for both.
type layoutPins struct {
	Name                   string `json:"name"`
	AssertionsSlot         uint64 `json:"assertions_slot"`
	StatusShiftBits        uint64 `json:"status_shift_bits"`
	ConfigSlotOffset       uint64 `json:"config_slot_offset"`
	FastConfirmerSlot      uint64 `json:"fast_confirmer_slot"`
	FastConfirmerShiftBits uint64 `json:"fast_confirmer_shift_bits"`
	AccArraySlot           uint64 `json:"acc_array_slot"`
	DelayedAccArraySlot    uint64 `json:"delayed_acc_array_slot"`
}

type proxySlots struct {
	AdminLogic string `json:"admin_logic"`
	UserLogic  string `json:"user_logic"`
}

type confirmPathPins struct {
	Selectors map[string]string `json:"selectors"`
	Topics    map[string]string `json:"topics"`
}

// pinsJSON is the arb_sepolia section. Fields owned by the l1_posted kind are accepted and ignored.
type pinsJSON struct {
	BoldGenesisAssertion string            `json:"bold_genesis_assertion"`
	BoldGenesisL2Block   uint64            `json:"bold_genesis_l2_block"`
	Bridge               string            `json:"bridge"`
	ChainID              uint64            `json:"chain_id"`
	ConfirmPath          confirmPathPins   `json:"confirm_path"`
	Layout               layoutPins        `json:"layout"`
	LogicPins            map[string]string `json:"logic_pins"`
	MaxBlobs             int               `json:"max_blobs"`
	MaxHeaderChain       int               `json:"max_header_chain"`
	MaxSegments          int               `json:"max_segments"`
	MaxUncompressedBatch int               `json:"max_uncompressed_batch"`
	ParentChainID        uint64            `json:"parent_chain_id"`
	ProxySlots           proxySlots        `json:"proxy_slots"`
	Rollup               string            `json:"rollup"`
}

// Pins are the parsed arb_sepolia pins this kind reads.
type Pins struct {
	Rollup             common.Address
	BoldGenesisL2Block uint64
	MaxHeaderChain     int
	Layout             layoutPins
	AdminSlot          common.Hash
	UserSlot           common.Hash
	LogicPins          map[common.Hash]string
	Sel                selectors
	Topic              topics
}

type selectors struct {
	Confirm, Force, Fast, FastNew [4]byte
	WalletTx, WalletTxs           [4]byte
	WalletTxRefund, WalletTxsRef  [4]byte
}

type topics struct{ Confirmed, ForceConfirmed common.Hash }

func hexN(s string, n int) ([]byte, bool) {
	if !strings.HasPrefix(s, "0x") || len(s) != 2+2*n {
		return nil, false
	}
	b, err := hex.DecodeString(s[2:])
	return b, err == nil
}

// LoadPins parses the arb_sepolia section. An absent section is finality_pin_unknown; a section that does not parse or whose
// values are outside their domain is pin_mismatch{field}.
func LoadPins(p *finality.Pins) (*Pins, error) {
	if p == nil || p.Sections[pinSection] == nil {
		return nil, finality.NewState(finality.CodePinUnknown, "chain", finality.ChainArbitrumSepolia, "kind", pinSection)
	}
	var j pinsJSON
	dec := json.NewDecoder(bytes.NewReader(p.Sections[pinSection]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return nil, PinMismatch("section")
	}
	if j.ChainID != finality.ChainArbitrumSepolia {
		return nil, PinMismatch("chain_id")
	}
	if j.ParentChainID != finality.ChainSepolia {
		return nil, PinMismatch("parent_chain_id")
	}
	out := &Pins{BoldGenesisL2Block: j.BoldGenesisL2Block, MaxHeaderChain: j.MaxHeaderChain, Layout: j.Layout, LogicPins: map[common.Hash]string{}}
	rb, ok := hexN(j.Rollup, 20)
	if !ok {
		return nil, PinMismatch("rollup")
	}
	out.Rollup = common.BytesToAddress(rb)
	if j.Layout.Name != "nitro-contracts-v3.1.0" {
		return nil, PinMismatch("layout")
	}
	if j.Layout.AssertionsSlot == 0 || j.Layout.StatusShiftBits == 0 || j.Layout.StatusShiftBits > 248 || j.Layout.ConfigSlotOffset == 0 {
		return nil, PinMismatch("layout")
	}
	if j.Layout.FastConfirmerSlot == 0 || j.Layout.FastConfirmerShiftBits > 96 {
		return nil, PinMismatch("layout")
	}
	if j.MaxHeaderChain <= 0 {
		return nil, PinMismatch("max_header_chain")
	}
	if j.BoldGenesisL2Block == 0 {
		return nil, PinMismatch("bold_genesis_l2_block")
	}
	b, ok := hexN(j.ProxySlots.AdminLogic, 32)
	if !ok {
		return nil, PinMismatch("proxy_slots.admin_logic")
	}
	out.AdminSlot = common.BytesToHash(b)
	if b, ok = hexN(j.ProxySlots.UserLogic, 32); !ok {
		return nil, PinMismatch("proxy_slots.user_logic")
	}
	out.UserSlot = common.BytesToHash(b)
	for k, v := range j.LogicPins {
		kb, ok := hexN(k, 32)
		if !ok {
			return nil, PinMismatch("logic_pins")
		}
		out.LogicPins[common.BytesToHash(kb)] = v
	}
	for name, dst := range map[string]*[4]byte{
		"confirm_assertion": &out.Sel.Confirm, "force_confirm_assertion": &out.Sel.Force, "fast_confirm_assertion": &out.Sel.Fast,
		"fast_confirm_new_assertion": &out.Sel.FastNew, "wallet_execute_transaction": &out.Sel.WalletTx,
		"wallet_execute_transactions": &out.Sel.WalletTxs, "wallet_execute_transaction_with_gas_refunder": &out.Sel.WalletTxRefund,
		"wallet_execute_transactions_with_gas_refunder": &out.Sel.WalletTxsRef,
	} {
		sb, ok := hexN(j.ConfirmPath.Selectors[name], 4)
		if !ok || bytes.Equal(sb, []byte{0, 0, 0, 0}) { // a zero selector is also refused: it is what a call without a selector reads as
			return nil, PinMismatch("confirm_path.selectors." + name)
		}
		copy(dst[:], sb)
	}
	for name, dst := range map[string]*common.Hash{"assertion_confirmed": &out.Topic.Confirmed, "assertion_force_confirmed": &out.Topic.ForceConfirmed} {
		tb, ok := hexN(j.ConfirmPath.Topics[name], 32)
		if !ok {
			return nil, PinMismatch("confirm_path.topics." + name)
		}
		*dst = common.BytesToHash(tb)
	}
	return out, nil
}

// roleOf returns the logic_pins role of a code hash ("" when not pinned).
func (p *Pins) roleOf(h common.Hash) string { return p.LogicPins[h] }

// ethl1Pins converts the Sepolia section of the pins file to the L1 head verifier's pins.
func ethl1Pins(p *finality.Pins) (ethl1.Pins, error) {
	var out ethl1.Pins
	e, err := p.Sepolia()
	if err != nil {
		return out, err
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
			bb, _ := hex.DecodeString(strings.TrimPrefix(a.BlockRoot, "0x"))
			copy(br[:], bb)
			an.BlockRoot = &br
		}
		out.Anchors = append(out.Anchors, an)
	}
	out.MinParticipants, out.MaxLinks, out.MaxSpineHeaders = e.MinParticipants, e.MaxLinks, e.MaxSpineHeaders
	return out, nil
}

// EthL1Pins is the L1 head verifier's view of the Sepolia section of a pins file (used by the vector generator and the builder).
func EthL1Pins(p *finality.Pins) (ethl1.Pins, error) { return ethl1Pins(p) }
