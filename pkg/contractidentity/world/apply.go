// Copyright 2026 Certen Protocol

package world

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
)

// The mutation engine. The vocabulary is the CLOSED one of the published vector format (FORMAT.md, contractidentity.MutationOps); the
// world-level operations of the specification (set_storage, set_nonce, set_code, set_header_field, swap_account, ...) are built on
// `set_field` / `unset_field` of the target `world`, whose path is a dot path into world.json:
//
//	semantic  set_field / unset_field on target world   edit the Spec; Derive then re-derives every trie root, header hash, link,
//	                                                    proof and the container (a set_storage on the anchor at attest_post changes the
//	                                                    storage root, the account leaf, the state root, the header hash, the container
//	                                                    nodes and the settlement's parent links)
//	raw       set_byte replace_hex truncate append_hex  edit the derived container bytes; nothing is re-derived
//	          drop_node add_node reorder                (inconsistent evidence is forged on purpose)
//	          set_field / unset_field on container      structured edit of the container, re-encoded WITHOUT validation
//	          set_field / unset_field on context        edit one LegContext member
//	          set_field / unset_field on manifest, extension   edit the manifest document (its pin is recomputed) / the extension document
//	          set_pin on manifest                       make the pin the manifest bytes are loaded against that value (a stale pin: VS8-001)
//
// A header field can be forged without re-derivation through blocks.<name>.fields.<field> (an override of a derived header field); the
// first mutations of a vector may select the profile with set_field world `chain` (a chain id) and `variant` (h0, s6silent, hops).

// ---- constructors: one line per mutation ----

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

// Set is set_field on the world.
func Set(path string, value any) ci.Mutation {
	return ci.Mutation{Op: "set_field", Target: "world", Path: path, Value: raw(value)}
}

// Unset is unset_field on the world.
func Unset(path string) ci.Mutation {
	return ci.Mutation{Op: "unset_field", Target: "world", Path: path}
}

// AcctPath is the world path of an account of a station.
func AcctPath(station string, who common.Address) string {
	return "stations." + station + ".accounts." + strings.ToLower(who.Hex())
}

// SetStorage sets (or, with a zero value, deletes) one storage slot of an account at a station.
func SetStorage(station string, who common.Address, slot, value common.Hash) ci.Mutation {
	return Set(AcctPath(station, who)+".storage."+hh(slot), hh(value))
}

// SetNonce sets the nonce of an account at a station.
func SetNonce(station string, who common.Address, nonce uint64) ci.Mutation {
	return Set(AcctPath(station, who)+".nonce", nonce)
}

// SetBalance sets the balance (decimal) of an account at a station.
func SetBalance(station string, who common.Address, balance string) ci.Mutation {
	return Set(AcctPath(station, who)+".balance", balance)
}

// SetCode replaces the code of an account at a station.
func SetCode(station string, who common.Address, code CodeSpec) ci.Mutation {
	return Set(AcctPath(station, who)+".code", code)
}

// SetHeaderField overrides one derived header field (parentHash, stateRoot, transactionsRoot, receiptsRoot, logsBloom, timestamp, gasLimit,
// gasUsed, coinbase, extraData, baseFee) of a block: attest_parent, attest, settle or between.<i> (a forged field is NOT re-derived into
// anything else; the header hash changes and the links above it are re-derived from that hash).
func SetHeaderField(block, field, value string) ci.Mutation {
	return Set("blocks."+blockPath(block)+".fields."+field, value)
}

func blockPath(block string) string {
	if strings.HasPrefix(block, "between.") {
		return "between." + strings.TrimPrefix(block, "between.")
	}
	return block
}

// SwapAccount moves the account entry of a station from one address to another (an impostor at a different address with the same code and
// storage). It needs the Spec to copy the entry.
func SwapAccount(sp *Spec, station string, from, to common.Address) ([]ci.Mutation, error) {
	st := sp.Stations[station]
	if st == nil || st.Accounts[strings.ToLower(from.Hex())] == nil {
		return nil, fmt.Errorf("station %s has no account %s", station, from.Hex())
	}
	return []ci.Mutation{Set(AcctPath(station, to), st.Accounts[strings.ToLower(from.Hex())]), Unset(AcctPath(station, from))}, nil
}

// ---- generic JSON tree edits ----

func toTree(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return fromJSON(b)
}

func fromJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var t any
	if err := dec.Decode(&t); err != nil {
		return nil, err
	}
	return t, nil
}

func setPath(t any, path []string, val any, remove bool) (any, error) {
	if len(path) == 0 {
		if remove {
			return nil, fmt.Errorf("an empty path")
		}
		return val, nil
	}
	key, rest := path[0], path[1:]
	switch n := t.(type) {
	case map[string]any:
		if len(rest) == 0 {
			if remove {
				if _, ok := n[key]; !ok {
					return nil, fmt.Errorf("unset: no member %q", key)
				}
				delete(n, key)
			} else {
				n[key] = val
			}
			return n, nil
		}
		child, ok := n[key]
		if !ok || child == nil {
			if remove {
				return nil, fmt.Errorf("unset: no member %q", key)
			}
			child = map[string]any{}
		}
		c, err := setPath(child, rest, val, remove)
		if err != nil {
			return nil, err
		}
		n[key] = c
		return n, nil
	case []any:
		i, err := strconv.Atoi(key)
		if err != nil || i < 0 || i > len(n) || (i == len(n) && (remove || len(rest) != 0)) {
			return nil, fmt.Errorf("array index %q (length %d)", key, len(n))
		}
		if len(rest) == 0 {
			if remove {
				return append(n[:i:i], n[i+1:]...), nil
			}
			if i == len(n) {
				return append(n, val), nil
			}
			n[i] = val
			return n, nil
		}
		c, err := setPath(n[i], rest, val, remove)
		if err != nil {
			return nil, err
		}
		n[i] = c
		return n, nil
	}
	return nil, fmt.Errorf("cannot descend into a %T at %q", t, key)
}

func editTree(tree any, m ci.Mutation) (any, error) {
	var val any
	if m.Op == "set_field" {
		v, err := fromJSON(m.Value)
		if err != nil {
			return nil, fmt.Errorf("value: %w", err)
		}
		val = v
	}
	return setPath(tree, strings.Split(m.Path, "."), val, m.Op == "unset_field")
}

func strictInto(tree any, dst any) error {
	b, err := json.Marshal(tree)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// ---- Built / Apply ----

// Built is a world with every mutation of a vector applied: the inputs of a Verifier and the world they came from.
type Built struct {
	World  *World
	Inputs ci.Inputs
	// ManifestRaw / ExtensionRaw are the manifest and extension documents after the mutations (nil extension: none).
	ManifestRaw, ExtensionRaw []byte
	// ManifestPin is the hash the manifest bytes are loaded against: nil for the unmodified embedded manifest (the embedded pin), the hash of
	// the edited bytes when a mutation edited the manifest (the pin is recomputed, FORMAT.md) [C1].
	ManifestPin *[32]byte
	// Step0 is the step-0 refusal the manifest and extension documents produce (manifest_corrupt, manifest_shadow, manifest_unknown); nil when
	// they load. A vector about such a document is expressible only because Apply does NOT fail on it: the runner resolves the same refusal from
	// Inputs.ManifestRaw / ManifestPin / ExtensionRaw and the refusal is the vector's RESULT [C1]. Inputs.Manifest is then the base manifest.
	Step0 *ci.StateError
}

// Apply applies the mutations, in order, to the world of spec and returns the inputs. The mutations of target world come first in effect:
// they edit the Spec before it is derived. container, when not empty, replaces the derived container bytes before the container mutations
// (a vector file `<id>.container.hex`). The profile selectors `chain` and `variant` regenerate the Spec from the manifest.
func Apply(m *ci.Manifest, spec *Spec, muts []ci.Mutation, container []byte) (*Built, error) {
	for i, mu := range muts {
		if err := mu.Validate(); err != nil {
			return nil, fmt.Errorf("mutation %d: %w", i, err)
		}
	}
	// profile selectors
	chain, variant := spec.Chain, spec.Variant
	selected := false
	for _, mu := range muts {
		if mu.Target == "world" && mu.Op == "set_field" && (mu.Path == "chain" || mu.Path == "variant") {
			selected = true
			var v any
			_ = json.Unmarshal(mu.Value, &v)
			switch x := v.(type) {
			case float64:
				if mu.Path == "chain" {
					chain = uint64(x)
				}
			case string:
				if mu.Path == "variant" {
					variant = x
				}
				if mu.Path == "chain" {
					c, err := strconv.ParseUint(x, 10, 64)
					if err != nil {
						return nil, fmt.Errorf("chain %q", x)
					}
					chain = c
				}
			}
		}
	}
	if selected {
		var err error
		if spec, err = Generate(m, chain, variant); err != nil {
			return nil, err
		}
	}
	tree, err := toTree(spec)
	if err != nil {
		return nil, err
	}
	for i, mu := range muts {
		if mu.Target != "world" || (selected && (mu.Path == "chain" || mu.Path == "variant")) {
			continue
		}
		if tree, err = editTree(tree, mu); err != nil {
			return nil, fmt.Errorf("mutation %d (%s world %s): %w", i, mu.Op, mu.Path, err)
		}
	}
	var sp2 Spec
	if err := strictInto(tree, &sp2); err != nil {
		return nil, fmt.Errorf("the mutated world is not a world: %w", err)
	}
	w, err := Derive(m, &sp2)
	if err != nil {
		return nil, err
	}
	b := &Built{World: w}
	cbytes := w.ContainerBytes
	if len(container) > 0 {
		cbytes = container
	}
	ctx := w.Ctx
	manifestRaw := ci.EmbeddedManifestBytes()
	var extRaw []byte
	var mTree, eTree any
	var setPin *[32]byte
	for i, mu := range muts {
		switch mu.Target {
		case "container":
			if cbytes, err = applyContainer(cbytes, mu); err != nil {
				return nil, fmt.Errorf("mutation %d (%s container): %w", i, mu.Op, err)
			}
		case "context":
			if err = applyContext(&ctx, mu); err != nil {
				return nil, fmt.Errorf("mutation %d (%s context %s): %w", i, mu.Op, mu.Path, err)
			}
		case "manifest":
			if mu.Op == "set_pin" {
				var hv string
				_ = json.Unmarshal(mu.Value, &hv)
				p, perr := hex.DecodeString(hv)
				if perr != nil || len(p) != 32 {
					return nil, fmt.Errorf("mutation %d (set_pin manifest): the value is not a sha256", i)
				}
				var pp [32]byte
				copy(pp[:], p)
				setPin = &pp
				continue
			}
			if mTree == nil {
				if mTree, err = fromJSON(manifestRaw); err != nil {
					return nil, err
				}
			}
			if mTree, err = editTree(mTree, mu); err != nil {
				return nil, fmt.Errorf("mutation %d (manifest %s): %w", i, mu.Path, err)
			}
		case "extension":
			if eTree == nil {
				eTree = map[string]any{"schema": ci.ManifestSchema}
			}
			if eTree, err = editTree(eTree, mu); err != nil {
				return nil, fmt.Errorf("mutation %d (extension %s): %w", i, mu.Path, err)
			}
		}
	}
	mf := m
	var pin *[32]byte
	if mTree != nil {
		if manifestRaw, err = json.Marshal(mTree); err != nil {
			return nil, err
		}
		h := ci.ManifestHash(manifestRaw)
		pin = &h
	}
	if setPin != nil {
		pin = setPin // the vector is about the pin: it is NOT recomputed
	}
	if pin != nil {
		if mf, err = ci.LoadManifest(manifestRaw, *pin); err != nil {
			st, ok := ci.AsState(err)
			if !ok {
				return nil, fmt.Errorf("the edited manifest: %w", err)
			}
			b.Step0, mf = st, m
		}
	}
	if eTree != nil {
		if extRaw, err = json.Marshal(eTree); err != nil {
			return nil, err
		}
		if b.Step0 == nil {
			if mf, err = mf.WithExtension(extRaw); err != nil {
				st, ok := ci.AsState(err)
				if !ok {
					return nil, fmt.Errorf("the extension: %w", err)
				}
				b.Step0, mf = st, m
			}
		}
	}
	// the raw documents are carried whenever they describe the manifest the world was built on: the embedded one, or an edited copy of it
	var rawOut []byte
	if mTree != nil || m.SHA256 == ci.ManifestHash(ci.EmbeddedManifestBytes()) {
		rawOut = manifestRaw
	}
	b.Inputs = ci.Inputs{Ctx: ctx, Container: cbytes, Manifest: mf, ManifestRaw: rawOut, ManifestPin: pin, ExtensionRaw: extRaw}
	b.ManifestRaw, b.ExtensionRaw, b.ManifestPin = manifestRaw, extRaw, pin
	return b, nil
}

// ---- container (raw) ----

func decodeHex(s string) ([]byte, error) { return hex.DecodeString(s) }

func applyContainer(raw []byte, m ci.Mutation) ([]byte, error) {
	var hexValue string
	if len(m.Value) > 0 {
		_ = json.Unmarshal(m.Value, &hexValue)
	}
	switch m.Op {
	case "set_byte":
		b, err := decodeHex(hexValue)
		if err != nil || *m.Offset >= len(raw) {
			return nil, fmt.Errorf("set_byte offset %d of %d bytes", *m.Offset, len(raw))
		}
		out := append([]byte{}, raw...)
		out[*m.Offset] = b[0]
		return out, nil
	case "replace_hex":
		old, _ := decodeHex(m.Old)
		nw, _ := decodeHex(m.New)
		o := *m.Offset
		if o+len(old) > len(raw) || !bytes.Equal(raw[o:o+len(old)], old) {
			return nil, fmt.Errorf("replace_hex: the container does not hold %s at offset %d", m.Old, o)
		}
		return append(append(append([]byte{}, raw[:o]...), nw...), raw[o+len(old):]...), nil
	case "truncate":
		if *m.Length > len(raw) {
			return nil, fmt.Errorf("truncate to %d of %d bytes", *m.Length, len(raw))
		}
		return append([]byte{}, raw[:*m.Length]...), nil
	case "append_hex":
		b, _ := decodeHex(hexValue)
		return append(append([]byte{}, raw...), b...), nil
	}
	c, err := ci.Decode(raw, ci.DefaultLimits())
	if err != nil {
		return nil, fmt.Errorf("%s needs a container that decodes: %w", m.Op, err)
	}
	switch m.Op {
	case "drop_node":
		if *m.Index >= len(c.Nodes) {
			return nil, fmt.Errorf("drop_node index %d of %d nodes", *m.Index, len(c.Nodes))
		}
		c.Nodes = append(c.Nodes[:*m.Index:*m.Index], c.Nodes[*m.Index+1:]...)
		return ci.Encode(c, ci.DefaultLimits())
	case "add_node":
		n, _ := decodeHex(hexValue)
		c.Nodes = append(c.Nodes, n)
		sort.Slice(c.Nodes, func(i, j int) bool {
			return bytes.Compare(crypto.Keccak256(c.Nodes[i]), crypto.Keccak256(c.Nodes[j])) < 0
		})
		return ci.Encode(c, ci.DefaultLimits())
	case "reorder":
		rev := func(l [][]byte) { // reverse in place
			for i, j := 0, len(l)-1; i < j; i, j = i+1, j-1 {
				l[i], l[j] = l[j], l[i]
			}
		}
		a := c.Attest.Attest
		switch m.List {
		case "codes":
			for i, j := 0, len(c.Codes)-1; i < j; i, j = i+1, j-1 {
				c.Codes[i], c.Codes[j] = c.Codes[j], c.Codes[i]
			}
		case "nodes":
			rev(c.Nodes)
		case "hopHeaders", "spine", "blockTxs":
			if a == nil {
				return nil, fmt.Errorf("reorder %s: the attest part is not captured", m.List)
			}
			rev(map[string][][]byte{"hopHeaders": a.HopHeaders, "spine": a.Spine, "blockTxs": a.BlockTxs}[m.List])
		}
		return ci.EncodeUnvalidated(c), nil
	case "set_field", "unset_field":
		v := toContainerView(c)
		tree, err := toTree(v)
		if err != nil {
			return nil, err
		}
		if tree, err = editTree(tree, m); err != nil {
			return nil, err
		}
		var v2 containerView
		if err := strictInto(tree, &v2); err != nil {
			return nil, err
		}
		c2, err := v2.container()
		if err != nil {
			return nil, err
		}
		return ci.EncodeUnvalidated(c2), nil
	}
	return nil, fmt.Errorf("container operation %s", m.Op)
}

// containerView is the structured JSON form of a container (FORMAT.md): hex for byte strings, decimal strings for integers.
type containerView struct {
	Chain string `json:"chain"`
	Leg   struct {
		Number string `json:"number"`
		Hash   string `json:"hash"`
	} `json:"leg"`
	Codes []struct {
		Address string `json:"address"`
		Runtime string `json:"runtime"`
	} `json:"codes"`
	Settle partView `json:"settle"`
	Attest partView `json:"attest"`
	Nodes  []string `json:"nodes"`
}

type partView struct {
	Tag    string      `json:"tag"`
	Stated *statedView `json:"stated,omitempty"`
	Attest *attestView `json:"attest,omitempty"`
}

type statedView struct {
	State       string `json:"state"`
	Reason      string `json:"reason"`
	JudgedBlock string `json:"judged_block"`
	JudgedHash  string `json:"judged_hash"`
	Failures    []struct {
		Host  string `json:"host"`
		Error string `json:"error"`
	} `json:"failures"`
	Detail string `json:"detail"`
}

type attestView struct {
	Link          string   `json:"link"`
	HeaderV       string   `json:"header_v"`
	HeaderVParent string   `json:"header_v_parent"`
	HopHeaders    []string `json:"hop_headers"`
	Spine         []string `json:"spine"`
	TxIndex       string   `json:"tx_index"`
	TxLeaf        string   `json:"tx_leaf"`
	ReceiptLeaf   string   `json:"receipt_leaf"`
	BlockTxs      []string `json:"block_txs"`
}

func hexList(l [][]byte) []string {
	out := make([]string, len(l))
	for i, b := range l {
		out[i] = hex.EncodeToString(b)
	}
	return out
}

func unhexList(l []string) ([][]byte, error) {
	var out [][]byte
	for _, s := range l {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func toContainerView(c *ci.Container) containerView {
	var v containerView
	v.Chain = strconv.FormatUint(c.Chain, 10)
	v.Leg.Number, v.Leg.Hash = strconv.FormatUint(c.Leg.Number, 10), hex.EncodeToString(c.Leg.Hash[:])
	for _, k := range c.Codes {
		v.Codes = append(v.Codes, struct {
			Address string `json:"address"`
			Runtime string `json:"runtime"`
		}{hex.EncodeToString(k.Address[:]), hex.EncodeToString(k.Runtime)})
	}
	part := func(p ci.Part) partView {
		pv := partView{Tag: strconv.Itoa(int(p.Tag))}
		if s := p.Stated; s != nil {
			sv := &statedView{State: s.State, Reason: s.Reason, JudgedBlock: strconv.FormatUint(s.JudgedBlock, 10), JudgedHash: hex.EncodeToString(s.JudgedHash[:]), Detail: s.Detail}
			for _, f := range s.Failures {
				sv.Failures = append(sv.Failures, struct {
					Host  string `json:"host"`
					Error string `json:"error"`
				}{f.Host, f.Error})
			}
			pv.Stated = sv
		}
		if a := p.Attest; a != nil {
			pv.Attest = &attestView{Link: strconv.Itoa(int(a.Link)), HeaderV: hex.EncodeToString(a.HeaderV), HeaderVParent: hex.EncodeToString(a.HeaderVParent),
				HopHeaders: hexList(a.HopHeaders), Spine: hexList(a.Spine), TxIndex: strconv.FormatUint(uint64(a.TxIndex), 10), TxLeaf: hex.EncodeToString(a.TxLeaf),
				ReceiptLeaf: hex.EncodeToString(a.ReceiptLeaf), BlockTxs: hexList(a.BlockTxs)}
		}
		return pv
	}
	v.Settle, v.Attest = part(c.Settle), part(c.Attest)
	v.Nodes = hexList(c.Nodes)
	return v
}

func (v containerView) container() (*ci.Container, error) {
	c := &ci.Container{}
	var err error
	if c.Chain, err = strconv.ParseUint(v.Chain, 10, 64); err != nil {
		return nil, err
	}
	if c.Leg.Number, err = strconv.ParseUint(v.Leg.Number, 10, 64); err != nil {
		return nil, err
	}
	if h, err := hex.DecodeString(v.Leg.Hash); err != nil || len(h) != 32 {
		return nil, fmt.Errorf("leg hash")
	} else {
		copy(c.Leg.Hash[:], h)
	}
	for _, k := range v.Codes {
		a, err := hex.DecodeString(k.Address)
		if err != nil || len(a) != 20 {
			return nil, fmt.Errorf("code address %q", k.Address)
		}
		rt, err := hex.DecodeString(k.Runtime)
		if err != nil {
			return nil, err
		}
		code := ci.Code{Runtime: rt}
		copy(code.Address[:], a)
		c.Codes = append(c.Codes, code)
	}
	part := func(pv partView) (ci.Part, error) {
		tag, err := strconv.Atoi(pv.Tag)
		if err != nil {
			return ci.Part{}, err
		}
		p := ci.Part{Tag: ci.PartTag(tag)}
		if s := pv.Stated; s != nil {
			st := &ci.Stated{State: s.State, Reason: s.Reason, Detail: s.Detail}
			if st.JudgedBlock, err = strconv.ParseUint(s.JudgedBlock, 10, 64); err != nil {
				return p, err
			}
			if h, err := hex.DecodeString(s.JudgedHash); err != nil || len(h) != 32 {
				return p, fmt.Errorf("judged hash")
			} else {
				copy(st.JudgedHash[:], h)
			}
			for _, f := range s.Failures {
				st.Failures = append(st.Failures, ci.ProviderFailure{Host: f.Host, Error: f.Error})
			}
			p.Stated = st
		}
		if a := pv.Attest; a != nil {
			ap := &ci.AttestProof{}
			l, err := strconv.Atoi(a.Link)
			if err != nil {
				return p, err
			}
			ap.Link = uint8(l)
			ti, err := strconv.ParseUint(a.TxIndex, 10, 32)
			if err != nil {
				return p, err
			}
			ap.TxIndex = uint32(ti)
			for _, f := range []struct {
				s string
				d *[]byte
			}{{a.HeaderV, &ap.HeaderV}, {a.HeaderVParent, &ap.HeaderVParent}, {a.TxLeaf, &ap.TxLeaf}, {a.ReceiptLeaf, &ap.ReceiptLeaf}} {
				if *f.d, err = hex.DecodeString(f.s); err != nil {
					return p, err
				}
			}
			if ap.HopHeaders, err = unhexList(a.HopHeaders); err != nil {
				return p, err
			}
			if ap.Spine, err = unhexList(a.Spine); err != nil {
				return p, err
			}
			if ap.BlockTxs, err = unhexList(a.BlockTxs); err != nil {
				return p, err
			}
			p.Attest = ap
		}
		return p, nil
	}
	if c.Settle, err = part(v.Settle); err != nil {
		return nil, err
	}
	if c.Attest, err = part(v.Attest); err != nil {
		return nil, err
	}
	if c.Nodes, err = unhexList(v.Nodes); err != nil {
		return nil, err
	}
	return c, nil
}

// ---- context ----

type s6View struct {
	Contract        string `json:"contract"`
	LeafKey         string `json:"leaf_key"`
	SettlementBlock struct {
		Number string `json:"number"`
		Hash   string `json:"hash"`
	} `json:"settlement_block"`
	ProvenAt struct {
		Number string `json:"number"`
		Hash   string `json:"hash"`
	} `json:"proven_at"`
	CodeHash string `json:"code_hash"`
}

func applyContext(c *ci.LegContext, m ci.Mutation) error {
	path := strings.Split(m.Path, ".")
	unset := m.Op == "unset_field"
	var str string
	if !unset {
		if err := json.Unmarshal(m.Value, &str); err != nil && path[0] != "s6" && path[0] != "registry9" {
			return fmt.Errorf("the value is not a string: %w", err)
		}
	}
	setH := func(dst *[32]byte) error {
		*dst = [32]byte{}
		if unset {
			return nil
		}
		h, err := parseHash(str)
		*dst = [32]byte(h)
		return err
	}
	switch path[0] {
	case "settlement", "tx", "receipt", "s7":
		if len(path) != 1 || !unset {
			return fmt.Errorf("the context member %s is derived from the blocks: remove it with unset_field, change it by mutating the world", path[0])
		}
		switch path[0] {
		case "settlement":
			c.Settlement = nil
		case "tx":
			c.Tx = nil
		case "receipt":
			c.Receipt = nil
		default:
			c.S7 = nil
		}
	case "adi_url":
		c.ADIURL = str
	case "s6_status":
		c.S6Status = ci.S6Status(str)
	case "s6_reason":
		c.S6Reason = str
	case "s6_state":
		c.S6State = str
	case "batch":
		if len(path) != 2 {
			return fmt.Errorf("context path %s", m.Path)
		}
		switch path[1] {
		case "batchRoot":
			return setH(&c.Batch.BatchRoot)
		case "batchOperationID":
			return setH(&c.Batch.OperationID)
		case "accSetRoot":
			return setH(&c.Batch.AccSetRoot)
		case "incarnation":
			return setH(&c.Batch.Incarnation)
		}
		return fmt.Errorf("context path %s", m.Path)
	case "s6", "registry9":
		return applyViewed(c, path, m)
	default:
		return fmt.Errorf("context member %q", path[0])
	}
	return nil
}

func hexLower32(b [32]byte) string { return hx(b[:]) }

func applyViewed(c *ci.LegContext, path []string, m ci.Mutation) error {
	if len(path) == 1 && m.Op == "unset_field" {
		if path[0] == "s6" {
			c.S6 = nil
		} else {
			c.Registry9 = nil
		}
		return nil
	}
	var tree any
	var err error
	if path[0] == "s6" {
		v := s6View{}
		if c.S6 != nil {
			v.Contract, v.LeafKey, v.CodeHash = strings.ToLower(c.S6.Contract.Hex()), hexLower32(c.S6.LeafKey), hexLower32(c.S6.CodeHash)
			v.SettlementBlock.Number, v.SettlementBlock.Hash = strconv.FormatUint(c.S6.SettlementBlock.Number, 10), hexLower32(c.S6.SettlementBlock.Hash)
			v.ProvenAt.Number, v.ProvenAt.Hash = strconv.FormatUint(c.S6.ProvenAt.Number, 10), hexLower32(c.S6.ProvenAt.Hash)
		}
		tree, err = toTree(v)
	} else {
		r := Registry9Spec{}
		if c.Registry9 != nil {
			r = Registry9Spec{Num: c.Registry9.Num, Den: c.Registry9.Den, CertenSetRoot: hexLower32(c.Registry9.CertenSetRoot), SignerCommitment: hexLower32(c.Registry9.SignerCommitment)}
			for _, mem := range c.Registry9.Members {
				r.Members = append(r.Members, MemberSpec{Address: strings.ToLower(mem.Address.Hex()), Power: mem.Power, BLSKey: mem.BLSKey})
			}
		}
		tree, err = toTree(r)
	}
	if err != nil {
		return err
	}
	sub := m
	sub.Path = strings.Join(path[1:], ".")
	if len(path) == 1 { // set_field of the whole member
		v, err := fromJSON(m.Value)
		if err != nil {
			return err
		}
		tree = v
	} else if tree, err = editTree(tree, sub); err != nil {
		return err
	}
	if path[0] == "registry9" {
		var r Registry9Spec
		if err := strictInto(tree, &r); err != nil {
			return err
		}
		reg := &ci.Registry9{Num: r.Num, Den: r.Den}
		for _, mem := range r.Members {
			a, err := parseAddr(mem.Address)
			if err != nil {
				return err
			}
			reg.Members = append(reg.Members, ci.RegistryMember{Address: a, Power: mem.Power, BLSKey: mem.BLSKey})
		}
		for _, f := range []struct {
			s string
			d *[32]byte
		}{{r.CertenSetRoot, &reg.CertenSetRoot}, {r.SignerCommitment, &reg.SignerCommitment}} {
			h, err := parseHash(f.s)
			if err != nil {
				return err
			}
			*f.d = [32]byte(h)
		}
		c.Registry9 = reg
		return nil
	}
	var v s6View
	if err := strictInto(tree, &v); err != nil {
		return err
	}
	contract, err := parseAddr(v.Contract)
	if err != nil {
		return err
	}
	link := &ci.S6Link{Contract: contract}
	for _, f := range []struct {
		s string
		d *[32]byte
	}{{v.LeafKey, &link.LeafKey}, {v.CodeHash, &link.CodeHash}, {v.SettlementBlock.Hash, &link.SettlementBlock.Hash}, {v.ProvenAt.Hash, &link.ProvenAt.Hash}} {
		h, err := parseHash(f.s)
		if err != nil {
			return err
		}
		*f.d = [32]byte(h)
	}
	if link.SettlementBlock.Number, err = strconv.ParseUint(v.SettlementBlock.Number, 10, 64); err != nil {
		return err
	}
	if link.ProvenAt.Number, err = strconv.ParseUint(v.ProvenAt.Number, 10, 64); err != nil {
		return err
	}
	c.S6 = link
	return nil
}

// ---- the WorldBuilder of the vector runner ----

// Builder implements contractidentity.WorldBuilder over the embedded manifest (or Manifest when set).
type Builder struct{ Manifest *ci.Manifest }

// Build reads the set's world.json, applies the vector's mutations and returns the inputs of a Verifier.
func (b Builder) Build(world json.RawMessage, v ci.Vector, container []byte) (ci.Inputs, error) {
	m := b.Manifest
	if m == nil {
		var err error
		if m, err = ci.Embedded(); err != nil {
			return ci.Inputs{}, err
		}
	}
	dec := json.NewDecoder(bytes.NewReader(world))
	dec.DisallowUnknownFields()
	var spec Spec
	if err := dec.Decode(&spec); err != nil {
		return ci.Inputs{}, fmt.Errorf("world.json: %w", err)
	}
	built, err := Apply(m, &spec, v.Mutations, container)
	if err != nil {
		return ci.Inputs{}, err
	}
	return built.Inputs, nil
}

var _ ci.WorldBuilder = Builder{}

// ---- vector files ----

// VectorFile is the content of `<id>.json`: base is always H0.
func VectorFile(id string, muts []ci.Mutation, expected ci.Expected) ([]byte, error) {
	v := ci.Vector{ID: id, Base: "H0", Mutations: muts, Expected: expected}
	if v.Mutations == nil {
		v.Mutations = []ci.Mutation{}
	}
	if err := v.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(v, "", " ")
}

// WriteSet writes a published vector set: world.json (the Spec), one `<id>.json` per vector, the MATERIALISED files of every vector
// (`<id>.inputs.json`, `<id>.expected.json`, `<id>.inputs.container.hex` and the content-addressed `manifest.<sha256>.json` /
// `extension.<sha256>.json`, FORMAT.md) and the MANIFEST of sha256 lines (sorted by file name, LF line ends) [C2]. Every vector is built through
// Builder.Build from the world.json being written, so a runner without a world builder (TypeScript) judges exactly the inputs a Go runner
// with this world builder would build, and the whole set is computed before the first file is written: a vector that cannot be built leaves
// no partial set. It refuses to write into a directory that already has a MANIFEST (a published set is never edited).
func WriteSet(dir string, spec *Spec, vectors []ci.Vector) error {
	if _, err := os.Stat(filepath.Join(dir, "MANIFEST")); err == nil {
		return fmt.Errorf("%s is a published set: a published set is never edited, write a new one", dir)
	}
	files := map[string][]byte{}
	wj, err := spec.MarshalIndent()
	if err != nil {
		return err
	}
	files["world.json"] = append(wj, '\n')
	put := func(name string, content []byte) error {
		if prev, dup := files[name]; dup && !bytes.Equal(prev, content) {
			return fmt.Errorf("file %s is produced twice with different content", name)
		}
		files[name] = content
		return nil
	}
	for _, v := range vectors {
		b, err := VectorFile(v.ID, v.Mutations, v.Expected)
		if err != nil {
			return err
		}
		if err := put(v.ID+".json", append(b, '\n')); err != nil {
			return err
		}
		in, err := Builder{}.Build(files["world.json"], v, nil)
		if err != nil {
			return fmt.Errorf("vector %s: %w", v.ID, err)
		}
		mf, err := ci.Materialise(v.ID, in, v.Expected)
		if err != nil {
			return fmt.Errorf("vector %s: %w", v.ID, err)
		}
		for name, content := range mf {
			if err := put(name, content); err != nil {
				return fmt.Errorf("vector %s: %w", v.ID, err)
			}
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var man strings.Builder
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), files[n], 0o644); err != nil {
			return err
		}
		fmt.Fprintf(&man, "%x  %s\n", sha256.Sum256(files[n]), n)
	}
	return os.WriteFile(filepath.Join(dir, "MANIFEST"), []byte(man.String()), 0o644)
}
