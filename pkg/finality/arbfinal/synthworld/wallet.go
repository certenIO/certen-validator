// Copyright 2026 Certen Protocol

package synthworld

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// The ValidatorWallet identities of the wallet route (V2_SPEC_S7 5.7 O4, amendment r3, RB11-E1-RAISE). The two runtime codes are the
// REAL bytes (Ethereum Sepolia, 2026-10-23), so a synthetic world that proves a wallet proves it against the same code hashes the
// embedded pins carry:
//
//   - walletcode/proxy_runtime.hex: eth_getCode of a proxy created by createWallet([]) of the Arbitrum Sepolia ValidatorWalletCreator
//     0x894fC71fA0A666352824EC954B401573C861D664 (run on a fork of the public chain; that creator has created no wallet on the real
//     chain). It is the OpenZeppelin 4.7.3 TransparentUpgradeableProxy runtime, 2,147 bytes, no immutables; 67 of the 68 wallets
//     that other ValidatorWalletCreators of the same chain created have exactly this code hash.
//   - walletcode/logic_runtime.hex: eth_getCode of the creator's template() 0x579831De7576B8580A2BEaa5F56b4b32e1292419, 6,864 bytes;
//     it embeds its own address once (the DelegateCallAware immutable), so its code hash names this one deployment.
//
//go:embed walletcode/proxy_runtime.hex
var proxyRuntimeHex string

//go:embed walletcode/logic_runtime.hex
var logicRuntimeHex string

var (
	// WalletProxyCode and WalletLogicCode are the runtime codes above; their keccak256 are the pinned code hashes.
	WalletProxyCode     = mustHexBytes(proxyRuntimeHex)
	WalletLogicCode     = mustHexBytes(logicRuntimeHex)
	WalletProxyCodeHash = crypto.Keccak256Hash(WalletProxyCode)
	WalletLogicCodeHash = crypto.Keccak256Hash(WalletLogicCode)
	// WalletImpl is the pinned implementation (the creator's template); WalletImplSlot is the EIP-1967 implementation slot.
	WalletImpl     = common.HexToAddress("0x579831De7576B8580A2BEaa5F56b4b32e1292419")
	WalletImplSlot = common.HexToHash("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")

	// Other real Sepolia identities, for vectors that must be refused: the template of another ValidatorWalletCreator
	// (0x84f9c6735302c80fffcede963cc947436ce54359, code hash below) behind a wallet the same proxy code points at, and a proxy
	// of a different build (wallet 0xbd38d8c6652cda3bd1f339200c6b6c054d15631f, template 0x3043d707b688dbceebdd313e496cdf4b36e3a3c5).
	OtherTemplate         = common.HexToAddress("0x84f9c6735302c80fffcede963cc947436ce54359")
	OtherTemplateCodeHash = common.HexToHash("0xc42bd9c2122604622e304f25183e469dcc50b36137adb778a092072336e541fb")
	OtherProxyCodeHash    = common.HexToHash("0x5680833daf07cb0dbd0c5bdd5183905c06ce27d0f474caa9289428490ffd0f10")
)

func mustHexBytes(s string) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		panic(err)
	}
	return b
}

// WalletState configures the accounts the state at K gains in a wallet-route world, and the proofs the evidence carries for them.
// A nil Parts.Wallet builds none: the worlds of finality_arb_final1 and finality_arb_final2 carry no wallet proof and regenerate
// byte-identically. The zero WalletState is the valid wallet: the callee (the transaction's To) is a proxy of the pinned proxy code
// whose implementation slot holds the pinned template, whose account has the pinned logic code.
type WalletState struct {
	// Callee, when set, is the address the wallet accounts are built at instead of the transaction's To (a proof for another address).
	Callee *common.Address
	// CalleeCode is the code hash of the callee account (nil: WalletProxyCodeHash); CalleeEOA gives it no code at all; CalleeAbsent
	// gives it no account (the evidence carries an exclusion proof).
	CalleeCode   *common.Hash
	CalleeEOA    bool
	CalleeAbsent bool
	// ImplWord is the callee's implementation slot word (nil: the pinned template's address); ImplZero leaves the slot empty.
	ImplWord *common.Hash
	ImplZero bool
	// ImplCode is the code hash of the account the slot names (nil: WalletLogicCodeHash); ImplAbsent gives that address no account.
	ImplCode   *common.Hash
	ImplAbsent bool
	// Omit leaves proofs out of the evidence: "account" (the callee's account proof), "slot" (the implementation slot's storage proof),
	// "impl_account" (the implementation's account proof).
	Omit []string
	// AtS builds every wallet account in the state at S instead of the state at K (the verifier reads K); CalleeAtS builds only the callee
	// (its account and slot) there and ImplAtS only the implementation's account, the other going to K.
	AtS       bool
	CalleeAtS bool
	ImplAtS   bool
}

// walletBuild is what one state gains from a WalletState.
type walletBuild struct {
	accts  []acct
	absent []common.Address
	skip   map[common.Address]bool
}

func (b *walletBuild) merge(o *walletBuild) *walletBuild {
	if o == nil {
		return b
	}
	if b == nil {
		b = &walletBuild{skip: map[common.Address]bool{}}
	}
	b.accts = append(b.accts, o.accts...)
	b.absent = append(b.absent, o.absent...)
	for a := range o.skip {
		b.skip[a] = true
	}
	return b
}

// build returns the callee part (the proxy account and its implementation slot) and the implementation part (the account the slot
// names) separately, so that a world can put them in different states.
func (w *WalletState) build(to common.Address) (callee, impl *walletBuild) {
	if w == nil {
		return nil, nil
	}
	addr := to
	if w.Callee != nil {
		addr = *w.Callee
	}
	callee, impl = &walletBuild{skip: map[common.Address]bool{}}, &walletBuild{skip: map[common.Address]bool{}}
	implWord := word(WalletImpl)
	if w.ImplWord != nil {
		implWord = *w.ImplWord
	}
	implAddr := common.BytesToAddress(implWord[12:])
	proxy := acct{addr: addr, code: WalletProxyCodeHash, skip: map[common.Hash]bool{}}
	if w.CalleeCode != nil {
		proxy.code = *w.CalleeCode
	}
	switch {
	case w.CalleeAbsent:
		callee.absent = append(callee.absent, addr)
	case w.CalleeEOA:
		proxy.code = types.EmptyCodeHash
		callee.accts = append(callee.accts, proxy)
	default:
		if w.ImplZero {
			proxy.absent = []common.Hash{WalletImplSlot}
		} else {
			proxy.storage = map[common.Hash]common.Hash{WalletImplSlot: implWord}
		}
		callee.accts = append(callee.accts, proxy)
	}
	implCode := WalletLogicCodeHash
	if w.ImplCode != nil {
		implCode = *w.ImplCode
	}
	if !w.CalleeAbsent && !w.CalleeEOA && !w.ImplZero {
		if w.ImplAbsent {
			impl.absent = append(impl.absent, implAddr)
		} else {
			impl.accts = append(impl.accts, acct{addr: implAddr, code: implCode})
		}
	}
	for _, o := range w.Omit {
		switch o {
		case "account":
			callee.skip[addr] = true
		case "slot":
			for i := range callee.accts {
				if callee.accts[i].addr == addr {
					callee.accts[i].skip[WalletImplSlot] = true
				}
			}
		case "impl_account":
			impl.skip[implAddr] = true
		default:
			panic("unknown wallet proof to omit: " + o)
		}
	}
	return callee, impl
}

// builds returns what the state at S and the state at K gain; when S == K there is one state and it gains everything.
func (w *WalletState) builds(to common.Address, sameState bool) (forS, forK *walletBuild) {
	if w == nil {
		return nil, nil
	}
	callee, impl := w.build(to)
	calleeS, implS := w.AtS || w.CalleeAtS || sameState, w.AtS || w.ImplAtS || sameState
	if calleeS {
		forS = forS.merge(callee)
	} else {
		forK = forK.merge(callee)
	}
	if implS {
		forS = forS.merge(impl)
	} else {
		forK = forK.merge(impl)
	}
	return forS, forK
}

// WalletPinKeys are the pins the wallet route needs beyond the pins of a published set; the harness of a published set supplies them
// (the verifier has no default for a pin). The values are the ones the embedded pins file carries, which a test asserts.
func WalletPinKeys() (impl string, slot string, proxyHash string, logicHash string) {
	return WalletImpl.Hex(), WalletImplSlot.Hex(), WalletProxyCodeHash.Hex(), WalletLogicCodeHash.Hex()
}

// WithWalletPins returns a published set's pins file with the wallet pins added to its arb_sepolia section: the harness side of the
// pins amendment, so a published set's vectors are judged by a verifier that requires those pins without editing the set's files.
// The rest of the file is returned in the same key order and number text as it came.
func WithWalletPins(raw []byte) []byte {
	impl, slot, proxyHash, logicHash := WalletPinKeys()
	return rewriteArbSection(raw, func(sec map[string]any) bool {
		cp, ps, lp, ok := sectionsOf(sec)
		if !ok {
			return false
		}
		if cp["validator_wallet_impl"] == impl && ps["wallet_impl"] == slot &&
			lp[strings.ToLower(proxyHash)] == "validator_wallet_proxy" && lp[strings.ToLower(logicHash)] == "validator_wallet_logic" {
			return false // already carries them: the file stays byte for byte as it is
		}
		cp["validator_wallet_impl"] = impl
		ps["wallet_impl"] = slot
		lp[strings.ToLower(proxyHash)] = "validator_wallet_proxy"
		lp[strings.ToLower(logicHash)] = "validator_wallet_logic"
		return true
	})
}

// WithoutWalletPins is the inverse of WithWalletPins: the pins file as a published set stored it. The generators of the published
// sets use it so that they regenerate those sets byte-identically from the current embedded pins.
func WithoutWalletPins(raw []byte) []byte {
	_, _, proxyHash, logicHash := WalletPinKeys()
	return rewriteArbSection(raw, func(sec map[string]any) bool {
		cp, ps, lp, ok := sectionsOf(sec)
		if !ok {
			return false
		}
		_, a := cp["validator_wallet_impl"]
		_, b := ps["wallet_impl"]
		_, c := lp[strings.ToLower(proxyHash)]
		_, d := lp[strings.ToLower(logicHash)]
		if !a && !b && !c && !d {
			return false // a file that never carried them stays byte for byte as it is
		}
		delete(cp, "validator_wallet_impl")
		delete(ps, "wallet_impl")
		delete(lp, strings.ToLower(proxyHash))
		delete(lp, strings.ToLower(logicHash))
		return true
	})
}

// sectionsOf are the three objects of the arb_sepolia section that carry the wallet pins; a file that lacks one is not rewritten.
func sectionsOf(sec map[string]any) (cp, ps, lp map[string]any, ok bool) {
	var a, b, c bool
	cp, a = sec["confirm_path"].(map[string]any)
	ps, b = sec["proxy_slots"].(map[string]any)
	lp, c = sec["logic_pins"].(map[string]any)
	return cp, ps, lp, a && b && c
}

// rewriteArbSection applies f to the arb_sepolia section of a pins file; f reports whether it changed anything, and a file it did not
// change is returned as it came (no re-encoding).
func rewriteArbSection(raw []byte, f func(sec map[string]any) bool) []byte {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		panic(err)
	}
	sec, ok := doc["arb_sepolia"]
	if !ok {
		return raw // a pins file without the section stays as it is (a vector about exactly that)
	}
	var s map[string]any
	d := json.NewDecoder(strings.NewReader(string(sec)))
	d.UseNumber()
	if err := d.Decode(&s); err != nil {
		panic(err)
	}
	if !f(s) {
		return raw
	}
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	doc["arb_sepolia"] = b
	out, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return out
}
