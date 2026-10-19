package main

// The anchored-certify suite of RB9-F5 (evidence 2.1 `links`: certify with one O(log n) Merkle link per anchored item). Each vector is a
// portable document of a synthetic chain (pkg/proof/v2/xworld, test keys, fixed seeds), either whole or with ONE member changed, and carries
// the verdict every verifier must reach: verified (with the report), or the refusal's exact text and, for a certify state, its name and
// fields. The names and their fixed details are testdata/certify1/names.json; the Go constants are hand-written and checked against it (a drift test), the TypeScript constants are generated from it and tested
// against it.
//
//	go run ./cmd/proofv2conformance -certify1 pkg/proof/v2/testdata/certify1
//
// New files under their own directory and manifest; names.json is the source of the names and is never written by this mode.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// XManifestFormatCertify1 names the anchored-certify suite.
const XManifestFormatCertify1 = "certen-certify1-conformance/1"

// Certify1Case is one manifest entry.
type Certify1Case struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// World names the document the vector edits (a world of this suite, or "conformance:<case>" for an evidence 2.0 document); Edit says in
	// one line what the edit is.
	World  string `json:"world"`
	Edit   string `json:"edit"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Expect string `json:"expect"` // "verified" or "refused"
	// State and Fields are the certify state a refusal carries (names.json), empty for a plain refusal.
	State  string   `json:"state,omitempty"`
	Fields []string `json:"fields,omitempty"`
	// Wording is the refusal's exact text (Go's Error()); Prefix the part another verifier must reproduce when the rest is a hash or a
	// codec's text (the whole text where it is the verifier's own).
	Wording string `json:"wording,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
	// SameReportAs names a verified vector whose report this one must equal exactly (the continuous and anchored forms of one chain).
	SameReportAs string `json:"sameReportAs,omitempty"`
	// Note says why a vector is what it is when that is not its description: a frozen document of an earlier suite and what moved (certify1_frozen.go).
	Note   string   `json:"note,omitempty"`
	Report *XReport `json:"report,omitempty"`
}

// Certify1Manifest lists the suite; its own hash is the content of MANIFEST.sha256, beside it.
type Certify1Manifest struct {
	Format         string         `json:"format"`
	Domain         string         `json:"domain"`
	PortableFormat string         `json:"portableFormat"`
	NamesFile      string         `json:"namesFile"`
	NamesSHA256    string         `json:"namesSha256"`
	Cases          []Certify1Case `json:"cases"`
}

type certify1Spec struct {
	Certify1Case
	// sameAsBase: the vector must be judged exactly as its unedited base (a member the 2.0 verifier must not read).
	sameAsBase bool
	apply      func(doc map[string]any, b *xworld.Built) error
}

// certify1Worlds are the chains the suite is made of. All of them share the root of the first major block and the entries of their items, so
// the continuous, anchored and mixed forms of one chain certify the same root.
func certify1Worlds() map[string]xworld.Options {
	orc := func(a bool) xworld.ChainItem { return xworld.ChainItem{Anchored: a, Update: xworld.UpdateOracle} }
	// eff is an item with an effect: a write to the globals account that the walk applies and records (the globals stay what they were). An
	// anchored item that is not the last of its sequence must have one; orc is a transaction the walk does not apply, so it has none.
	eff := func(a bool) xworld.ChainItem {
		return xworld.ChainItem{Anchored: a, Update: xworld.UpdateGenesisGlobals}
	}
	return map[string]xworld.Options{
		"chain-continuous":          {Chain: &xworld.Chain{Items: []xworld.ChainItem{eff(false), eff(false)}}},
		"chain-anchored":            {Chain: &xworld.Chain{Items: []xworld.ChainItem{eff(true), eff(true)}, Final: xworld.ChainItem{Anchored: true}}},
		"chain-mixed":               {Chain: &xworld.Chain{Items: []xworld.ChainItem{eff(true), eff(false)}, Final: xworld.ChainItem{Anchored: true}}},
		"chain-two-anchored":        {Chain: &xworld.Chain{Items: []xworld.ChainItem{eff(true)}, Final: xworld.ChainItem{Anchored: true}}},
		"chain-final-only":          {Chain: &xworld.Chain{Final: xworld.ChainItem{Anchored: true}}},
		"chain-no-effect":           {Chain: &xworld.Chain{Items: []xworld.ChainItem{{Anchored: true}, orc(false)}}},
		"chain-non-monotone":        {Chain: &xworld.Chain{Items: []xworld.ChainItem{{Anchored: true, Update: xworld.UpdateGenesisGlobals, Block: 130}, {Anchored: true, Update: xworld.UpdateGenesisGlobals, Block: 120}}, Final: xworld.ChainItem{Anchored: true}}},
		"chain-duplicated-update":   {Chain: &xworld.Chain{Items: []xworld.ChainItem{{Anchored: true, Update: xworld.UpdateGlobals, Repeat: 2}}, Final: xworld.ChainItem{Anchored: true}}},
		"chain-continuous-then-end": {Chain: &xworld.Chain{Items: []xworld.ChainItem{orc(false)}, Final: xworld.ChainItem{Anchored: true}}},
		"chain-anchored-then-end":   {Chain: &xworld.Chain{Items: []xworld.ChainItem{eff(true)}}},
		"chain-junk-update":         {Chain: &xworld.Chain{Items: []xworld.ChainItem{orc(true)}, Final: xworld.ChainItem{Anchored: true}}},
		"chain-hops-anchored":       {Chain: &xworld.Chain{Final: xworld.ChainItem{Anchored: true}, Hops: []xworld.ChainItem{eff(true), {Anchored: true}}}},
		"chain-hops-no-effect":      {Chain: &xworld.Chain{Final: xworld.ChainItem{Anchored: true}, Hops: []xworld.ChainItem{{Anchored: true}, {Anchored: true}}}},
		"chain-hops-duplicated":     {Chain: &xworld.Chain{Final: xworld.ChainItem{Anchored: true}, Hops: []xworld.ChainItem{{Anchored: true, Update: xworld.UpdateGlobals, Repeat: 2}, {Anchored: true}}}},
		// The set changes in the minor run (V-E A3): the globals are rewritten (content B, then the genesis content again: an A -> B -> A
		// sequence) and the network is rewritten to its version 2 (a fourth validator). The proven network account holds 2 entries and the
		// globals account 3; the walk applies every write, so the set check reports verified.
		"chain-accounted": {Chain: &xworld.Chain{Items: []xworld.ChainItem{
			{Anchored: true, Update: xworld.UpdateGlobalsB}, {Anchored: true, Update: xworld.UpdateGenesisGlobals}, {Anchored: true, Update: xworld.UpdateNetworkV2}},
			Final: xworld.ChainItem{Anchored: true}}},
		// The same chain as the globals part of chain-accounted, with the first write left out of the document although the chain holds it: the
		// globals end at the genesis content again, so a comparison of content cannot see the omission; only the count can.
		"chain-globals-aba-omitted": {Chain: &xworld.Chain{Items: []xworld.ChainItem{
			{Anchored: true, Update: xworld.UpdateGlobalsB}, {Anchored: true, Update: xworld.UpdateGenesisGlobals}},
			Final: xworld.ChainItem{Anchored: true}, Omit: []int{0}}},
		// A complete chain of another incarnation: it shares the pinned genesis records and the genesis set, and starts at a root of its own.
		"chain-foreign-genesis": {Chain: &xworld.Chain{Final: xworld.ChainItem{Anchored: true}, Start: xworld.ForeignGenesis()}},
		// The window of an update (V-E A2(c)): the update's root chain position, read from its receipt's shape and the signed tree size, must lie
		// in (the previous anchor's RootChainIndex, this anchor's].
		"chain-window-in": {Chain: &xworld.Chain{Items: []xworld.ChainItem{{Anchored: true, Update: xworld.UpdateGlobals}}, Final: xworld.ChainItem{Anchored: true}}},
		"chain-window-before": {Chain: &xworld.Chain{Items: []xworld.ChainItem{{Anchored: true, Update: xworld.UpdateGlobalsB},
			{Anchored: true, Update: xworld.UpdateGlobals, Leaf: xworld.LeafBefore}}, Final: xworld.ChainItem{Anchored: true}}},
		"chain-window-after": {Chain: &xworld.Chain{Items: []xworld.ChainItem{{Anchored: true, Update: xworld.UpdateGlobals, Leaf: xworld.LeafAfter}}, Final: xworld.ChainItem{Anchored: true}}},
		"chain-window-shape": {Chain: &xworld.Chain{Items: []xworld.ChainItem{{Anchored: true, Update: xworld.UpdateGlobals, Leaf: xworld.LeafShape}}, Final: xworld.ChainItem{Anchored: true}}},
	}
}

func certify1Doc(base string, worlds map[string]xworld.Options) (map[string]any, *xworld.Built, error) {
	var raw []byte
	var b *xworld.Built
	if strings.HasPrefix(base, "conformance:") {
		r, err := robustBase(base)
		if err != nil {
			return nil, nil, err
		}
		raw = r
	} else {
		o, ok := worlds[base]
		if !ok {
			return nil, nil, fmt.Errorf("no world %q", base)
		}
		var err error
		if b, err = xworld.Build(o); err != nil {
			return nil, nil, err
		}
		p, err := b.Portable()
		if err != nil {
			return nil, nil, err
		}
		if raw, err = json.Marshal(p); err != nil {
			return nil, nil, err
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, err
	}
	return doc, b, nil
}

func recordJSON(h string) (json.RawMessage, error) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	r := new(api.MinorRootRecord)
	if err := r.UnmarshalBinary(raw); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

func receiptJSONOf(h string) (json.RawMessage, error) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	r := new(merkle.Receipt)
	if err := r.UnmarshalBinary(raw); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

// asValue turns raw JSON into the generic value a document member holds.
func asValue(raw json.RawMessage, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	return v, dec.Decode(&v)
}

func certifyAt(i int) []any { return []any{"evidence", "certify", i} }

func linkAt(i int, member ...any) []any {
	return append([]any{"evidence", "links", i}, member...)
}

func certify1State(code string, fields ...string) Certify1Case {
	return Certify1Case{Expect: "refused", State: code, Fields: fields, Wording: (&proofv2.CertifyState{Code: code, Fields: fields}).Error()}
}

type edit = func(map[string]any, *xworld.Built) error

func certify1Specs() []certify1Spec {
	c := func(name, world, edit, desc string, base Certify1Case) Certify1Case {
		base.Name, base.World, base.Edit, base.Description = name, world, edit, desc
		return base
	}
	ok := Certify1Case{Expect: "verified"}
	plain := func(wording string) Certify1Case { return Certify1Case{Expect: "refused", Wording: wording} }
	flipLink := func(i int, member ...any) edit {
		return func(d map[string]any, _ *xworld.Built) error {
			p := linkAt(i, member...)
			h, okh := memberAt(d, p...).(string)
			if !okh {
				return fmt.Errorf("the base document has no hex at %v", p)
			}
			return setMember(d, p, flipFirstByte(h))
		}
	}
	flipGenesisLink := func(member ...any) edit {
		return func(d map[string]any, _ *xworld.Built) error {
			p := append([]any{"evidence", "genesisLink"}, member...)
			h, okh := memberAt(d, p...).(string)
			if !okh {
				return fmt.Errorf("the base document has no hex at %v", p)
			}
			return setMember(d, p, flipFirstByte(h))
		}
	}
	flipPending := func(i int) edit {
		return func(d map[string]any, _ *xworld.Built) error {
			p := append(certifyAt(i), "rootProof", "merkleState", "pending", 0)
			h, okh := memberAt(d, p...).(string)
			if !okh {
				return fmt.Errorf("the base document has no %v", p)
			}
			return setMember(d, p, flipFirstByte(h))
		}
	}
	setRootProof := func(i int, v any) edit {
		return func(d map[string]any, _ *xworld.Built) error {
			return setMember(d, append(certifyAt(i), "rootProof"), v)
		}
	}
	// replaceItem puts a record and its link (hex) in place of certify item i and link j.
	replaceItem := func(i, j int, rec, link string) edit {
		return func(d map[string]any, _ *xworld.Built) error {
			r, err := asValue(recordJSON(rec))
			if err != nil {
				return err
			}
			l, err := asValue(receiptJSONOf(link))
			if err != nil {
				return err
			}
			if err := setMember(d, certifyAt(i), r); err != nil {
				return err
			}
			return setMember(d, linkAt(j), l)
		}
	}
	noEdit := func(map[string]any, *xworld.Built) error { return nil }

	same := func(x Certify1Case, as string) Certify1Case {
		x.SameReportAs = as
		return x
	}
	return []certify1Spec{
		// The three forms of one chain certify the same root and report the same.
		{Certify1Case: c("continuous-chain-verified", "chain-continuous", "none", "two continuous update-bearing items and a continuous closing item: the form every earlier document has", ok), apply: noEdit},
		{Certify1Case: same(c("anchored-chain-verified", "chain-anchored", "none", "the same chain as continuous-chain-verified with every item anchored (no root proof) and three links: the same report", ok), "continuous-chain-verified"), apply: noEdit},
		{Certify1Case: same(c("mixed-chain-verified", "chain-mixed", "none", "the same chain with an anchored first item, a continuous second item and an anchored closing item, two links: the same report", ok), "continuous-chain-verified"), apply: noEdit},
		{Certify1Case: c("anchored-final-only-verified", "chain-final-only", "none", "one anchored closing item and one link: an anchored item with no update is allowed as the last of its sequence", ok), apply: noEdit},

		// The link of an anchored item.
		{Certify1Case: c("link-absent", "chain-final-only", "evidence/links removed", "the anchored item has no link", certify1State(proofv2.StateCertifyLinkMissing, "0")),
			apply: func(d map[string]any, _ *xworld.Built) error { return deleteMember(d, []any{"evidence", "links"}) }},
		{Certify1Case: c("link-start-altered", "chain-final-only", "evidence/links/0/start first byte flipped", "the link starts somewhere other than the previous verified root chain anchor", certify1State(proofv2.StateCertifyLinkStart, "0")),
			apply: flipLink(0, "start")},
		{Certify1Case: c("link-end-altered", "chain-final-only", "evidence/links/0/anchor first byte flipped", "the link ends somewhere other than the item's root chain anchor", certify1State(proofv2.StateCertifyLinkEnd, "0")),
			apply: flipLink(0, "anchor")},
		{Certify1Case: c("link-step-altered", "chain-final-only", "evidence/links/0/entries/0/hash first byte flipped", "the link starts and ends where it must but its path does not recompute: not a valid receipt", certify1State(proofv2.StateCertifyLinkInvalid, "0")),
			apply: flipLink(0, "entries", 0, "hash")},
		{Certify1Case: c("link-of-a-different-item", "chain-mixed", "evidence/links/0 and /1 exchanged", "the first anchored item takes the closing item's link, which starts at another root", certify1State(proofv2.StateCertifyLinkStart, "0")),
			apply: func(d map[string]any, _ *xworld.Built) error {
				a, b := memberAt(d, linkAt(0)...), memberAt(d, linkAt(1)...)
				if err := setMember(d, linkAt(0), b); err != nil {
					return err
				}
				return setMember(d, linkAt(1), a)
			}},
		{Certify1Case: c("link-surplus", "chain-final-only", "evidence/links/1 = a copy of links/0", "a link no anchored item takes: the same chain would have two encodings", certify1State(proofv2.StateCertifyLinkInvalid, "1")),
			apply: func(d map[string]any, _ *xworld.Built) error {
				ls, okl := memberAt(d, "evidence", "links").([]any)
				if !okl || len(ls) != 1 {
					return fmt.Errorf("the base document has no single link")
				}
				return setMember(d, []any{"evidence", "links"}, []any{ls[0], ls[0]})
			}},
		{Certify1Case: c("link-of-the-second-item-missing", "chain-anchored", "evidence/links/1 removed", "the second anchored item has no link of its own: it would take the third's, which starts elsewhere", certify1State(proofv2.StateCertifyLinkStart, "1")),
			apply: func(d map[string]any, _ *xworld.Built) error {
				ls, okl := memberAt(d, "evidence", "links").([]any)
				if !okl || len(ls) != 3 {
					return fmt.Errorf("the base document has no three links")
				}
				return setMember(d, []any{"evidence", "links"}, []any{ls[0], ls[2]})
			}},

		// The canonical form and the walk's order.
		{Certify1Case: c("anchored-item-without-update-not-last", "chain-no-effect", "none (the world's first item is anchored and carries no update, and is not the last)", "an anchored item that changes nothing is only allowed as the last of its sequence", certify1State(proofv2.StateCertifyItemWithoutEffect, "0", "110")), apply: noEdit},
		{Certify1Case: c("anchored-item-with-only-an-unapplied-update-not-last", "chain-junk-update", "none (the world's first item is anchored and carries one update, a write to acc://dn.acme/oracle with a valid receipt, which the walk does not apply; it is not the last)", "the canonical form is about effect, not about the updates member: an anchored item padded with an update that changes nothing is refused like one without updates", certify1State(proofv2.StateCertifyItemWithoutEffect, "0", "110")), apply: noEdit},
		{Certify1Case: c("non-monotone-block", "chain-non-monotone", "none (the second item's block, 120, does not pass the first's, 130)", "anchored items whose Directory minor blocks do not increase", plain("certify run 1: anchor for minor block 120 does not advance past 130")), apply: noEdit},
		{Certify1Case: c("duplicated-update", "chain-duplicated-update", "none (the anchored item carries the same globals write twice)", "an update the walk already applied: refused, so a count of the network's writes is injective", Certify1Case{Expect: "refused"}), apply: noEdit},

		// Continuity across the two forms.
		{Certify1Case: c("continuous-item-wrongly-rooted-then-anchored", "chain-continuous-then-end", "evidence/certify/0/rootProof/merkleState/pending/0 first byte flipped", "a continuous item whose proof starts at another root, then an anchored closing item", plain("certify run 0: root proof does not start at the verified root")),
			apply: flipPending(0)},
		{Certify1Case: c("anchored-then-continuous-item-wrongly-rooted", "chain-anchored-then-end", "evidence/certify/1/rootProof/merkleState/pending/0 first byte flipped", "an anchored item, then a continuous closing item whose proof starts at another root", plain("certify run 1: root proof does not start at the verified root")),
			apply: flipPending(1)},
		{Certify1Case: c("anchor-of-another-chain-genuinely-signed", "chain-final-only", "evidence/certify/0 and links/0 replaced by a record of another chain signed by the genesis set, with that chain's own link", "a genuine anchor of another chain: the signatures are intact and the link is valid in its own chain, but it does not start at the verified root", certify1State(proofv2.StateCertifyLinkStart, "0")),
			apply: func(d map[string]any, _ *xworld.Built) error {
				rec, link := xworld.ForeignItem(nil, 110, false)
				return replaceItem(0, 0, rec, link)(d, nil)
			}},
		{Certify1Case: c("anchor-re-rooted-off-the-verified-root", "chain-final-only", "evidence/certify/0, links/0 and genesisLink replaced by a record of another chain signed by the genesis set, linked from the verified root", "the link starts at the verified root and ends at the foreign anchor's root, which the genesis set signed, and the genesis link is the same receipt: the walk accepts it and the transaction's receipt, which ends at the world's own root, is refused", Certify1Case{Expect: "refused", Prefix: "receipt ends at "}),
			apply: func(d map[string]any, _ *xworld.Built) error {
				rec, link := xworld.ForeignItem(xworld.GenesisRoot(), 110, false)
				if err := replaceItem(0, 0, rec, link)(d, nil); err != nil {
					return err
				}
				l, err := asValue(receiptJSONOf(link))
				if err != nil {
					return err
				}
				return setMember(d, []any{"evidence", "genesisLink"}, l)
			}},
		{Certify1Case: c("anchor-of-another-incarnation", "chain-final-only", "evidence/certify/0 and links/0 replaced by a record signed by a validator set the genesis does not hold, linked from the verified root", "a cross-incarnation anchor: the link is valid and starts at the verified root, the signers are not in the set in force", plain("certify run 0: block 110: signer is not an active directory validator")),
			apply: func(d map[string]any, _ *xworld.Built) error {
				rec, link := xworld.ForeignItem(xworld.GenesisRoot(), 110, true)
				return replaceItem(0, 0, rec, link)(d, nil)
			}},

		// The shapes of the rootProof member of a record.
		{Certify1Case: c("root-proof-null-is-absent", "chain-final-only", "evidence/certify/0/rootProof = null", "a null rootProof is no rootProof: the item is anchored and takes its link", ok), apply: setRootProof(0, nil)},
		{Certify1Case: c("root-proof-empty-object", "chain-final-only", "evidence/certify/0/rootProof = {}", "an empty rootProof is a continuous item with an empty proof, not an anchored one", plain("certify run 0: incomplete root proof")), apply: setRootProof(0, map[string]any{})},
		{Certify1Case: c("root-proof-merkle-state-only", "chain-final-only", "evidence/certify/0/rootProof = {merkleState: the chain's}", "a rootProof without its receipt is a continuous item with an incomplete proof", plain("certify run 0: incomplete root proof")),
			apply: setRootProof(0, map[string]any{"merkleState": map[string]any{"count": json.Number("1"), "pending": []any{hex.EncodeToString(xworld.GenesisRoot())}}})},
		{Certify1Case: c("record-with-an-unknown-trailing-field", "chain-final-only", "evidence/certify/0/$epilogue = field 5", "a record carrying a field the decoder does not know (Accumulate keeps it as its epilogue): the verdict is the unmodified document's", ok),
			apply: func(d map[string]any, _ *xworld.Built) error {
				return setMember(d, append(certifyAt(0), "$epilogue"), "05010a")
			}},

		{Certify1Case: c("link-with-an-unknown-trailing-field", "chain-final-only", "evidence/links/0/$epilogue = field 5", "a link is a receipt, not a record: unlike a record, whose unknown trailing field leaves the verdict unchanged, a receipt carrying one is refused as an invalid link at its ordinal", certify1State(proofv2.StateCertifyLinkInvalid, "0")),
			apply: func(d map[string]any, _ *xworld.Built) error {
				return setMember(d, linkAt(0, "$epilogue"), "05010a")
			}},

		{Certify1Case: c("link-undecodable-before-an-earlier-items-refusal", "chain-two-anchored", "evidence/links/1/$epilogue = field 5 and evidence/certify/0/signatures = []", "every link is decoded before any item is judged: link 1 does not decode, and item 0, which comes first, has no quorum; the verdict is the link's, at its ordinal, never item 0's", certify1State(proofv2.StateCertifyLinkInvalid, "1")),
			apply: func(d map[string]any, _ *xworld.Built) error {
				if err := setMember(d, append(certifyAt(0), "signatures"), []any{}); err != nil {
					return err
				}
				return setMember(d, linkAt(1, "$epilogue"), "05010a")
			}},

		// The set check's own items (check.hops): the same rules, the links numbered on after certify's.
		{Certify1Case: c("hops-anchored-verified", "chain-hops-anchored", "none", "an anchored closing certify item and two anchored hops, three links in the order certify then hops", ok), apply: noEdit},
		{Certify1Case: c("hop-link-absent", "chain-hops-anchored", "evidence/links/2 removed", "the last hop has no link: the ordinal is counted across certify and hops", certify1State(proofv2.StateCertifyLinkMissing, "2")),
			apply: func(d map[string]any, _ *xworld.Built) error {
				ls, okl := memberAt(d, "evidence", "links").([]any)
				if !okl || len(ls) != 3 {
					return fmt.Errorf("the base document has no three links")
				}
				return setMember(d, []any{"evidence", "links"}, ls[:2])
			}},
		{Certify1Case: c("hop-link-start-altered", "chain-hops-anchored", "evidence/links/1/start first byte flipped", "the first hop's link starts somewhere other than the checkpoint's root chain anchor", certify1State(proofv2.StateCertifyLinkStart, "1")),
			apply: flipLink(1, "start")},
		{Certify1Case: c("hop-anchored-item-without-update-not-last", "chain-hops-no-effect", "none (the first hop is anchored, carries no update and is not the last)", "the canonical form holds for the set check's hops; the item is numbered across certify and hops", certify1State(proofv2.StateCertifyItemWithoutEffect, "1", "310")), apply: noEdit},
		{Certify1Case: c("hop-duplicated-update", "chain-hops-duplicated", "none (the first hop carries the same globals write twice)", "the replay refusal holds for the set check's hops", Certify1Case{Expect: "refused"}), apply: noEdit},

		// The chain identity (V-E A1b, F-VE-2): a receipt from the pinned incarnation's genesis root chain anchor to the certified root.
		{Certify1Case: c("genesis-link-absent", "chain-final-only", "evidence/genesisLink removed", "an anchored document without the chain identity", certify1State(proofv2.StateCertifyLinkMissing, "genesis")),
			apply: func(d map[string]any, _ *xworld.Built) error {
				return deleteMember(d, []any{"evidence", "genesisLink"})
			}},
		{Certify1Case: c("genesis-link-start-altered", "chain-final-only", "evidence/genesisLink/start first byte flipped", "the genesis link starts somewhere other than the pinned incarnation's genesis root chain anchor", certify1State(proofv2.StateCertifyLinkStart, "genesis")),
			apply: flipGenesisLink("start")},
		{Certify1Case: c("genesis-link-end-altered", "chain-final-only", "evidence/genesisLink/anchor first byte flipped", "the genesis link ends somewhere other than the certified root chain anchor", certify1State(proofv2.StateCertifyLinkEnd, "genesis")),
			apply: flipGenesisLink("anchor")},
		{Certify1Case: c("genesis-link-step-altered", "chain-final-only", "evidence/genesisLink/entries/0/hash first byte flipped", "the genesis link starts and ends where it must but its path does not recompute", certify1State(proofv2.StateCertifyLinkInvalid, "genesis")),
			apply: flipGenesisLink("entries", 0, "hash")},
		{Certify1Case: c("genesis-link-with-an-unknown-trailing-field", "chain-final-only", "evidence/genesisLink/$epilogue = field 5", "a genesis link is a receipt: one carrying a member the receipt does not know is refused as an invalid genesis link", certify1State(proofv2.StateCertifyLinkInvalid, "genesis")),
			apply: func(d map[string]any, _ *xworld.Built) error {
				return setMember(d, []any{"evidence", "genesisLink", "$epilogue"}, "05010a")
			}},
		{Certify1Case: c("genesis-link-of-another-incarnation", "chain-foreign-genesis", "none (the world's chain, major block and genesis link start at a root of another incarnation that shares the pinned genesis records)", "a complete chain of another incarnation, signed by the genesis set, with its own genesis link: it does not start at the pinned genesis root chain anchor", certify1State(proofv2.StateCertifyLinkStart, "genesis")), apply: noEdit},

		// The accounting (V-E A2(b), A3): every write to the network and the globals accounts, counted against their main chains.
		{Certify1Case: c("accounted-set-change-verified", "chain-accounted", "none", "updates in the minor run: the globals are rewritten (B, then the genesis content again) and the network to version 2 (a fourth validator); the proven accounts hold 3 and 2 main chain entries, the walk applied every write: the set check is verified, not asserted", ok), apply: noEdit},
		{Certify1Case: c("omitted-globals-update", "chain-globals-aba-omitted", "none (the document leaves out the first globals write of an A -> B -> A sequence; the proven globals account holds 3 main chain entries and the genesis content)", "the content of the globals the walk derives equals the proven one, so only the count of writes shows the omission", certify1State(proofv2.StateCertifyWindowUnaccounted, "globals", "300", "2", "3")), apply: noEdit},

		// The window of an update (V-E A2(c)).
		{Certify1Case: c("update-inside-its-window-verified", "chain-window-in", "none", "the update's root chain position, read from the end of its combined receipt and the signed tree size, lies between the previous anchor's RootChainIndex and this anchor's: verified", ok), apply: noEdit},
		{Certify1Case: c("update-before-its-window", "chain-window-before", "none (the second item presents a write whose root chain leaf lies in the first item's window)", "an update whose root chain leaf lies in an earlier window than the one it is presented in: its position is not above the previous anchor's RootChainIndex (the check is on the root chain position of the anchor the receipt is proven into, not on the block the main chain entry itself was recorded in)", certify1State(proofv2.StateCertifyUpdateUnproven, "acc://dn.acme/globals", "", "120")), apply: noEdit},
		{Certify1Case: c("update-after-its-window", "chain-window-after", "none (the receipt is that of a tree one leaf larger than the signed RootChainIndex + 1)", "an update whose leaf lies beyond the root chain the anchor signs: its receipt does not decompose for the signed tree size", certify1State(proofv2.StateCertifyUpdateUnproven, "acc://dn.acme/globals", "", "110")), apply: noEdit},
		{Certify1Case: c("update-receipt-shape-undecodable", "chain-window-shape", "none (the receipt's path is shorter than the root chain path of any leaf of the signed size)", "a receipt that hashes to the signed root but whose shape is the root chain path of no leaf of a tree of the signed size", certify1State(proofv2.StateCertifyUpdateUnproven, "acc://dn.acme/globals", "", "110")), apply: noEdit},

		// Evidence 2.0 is frozen.
		{Certify1Case: c("genesis-link-member-in-an-evidence-2.0-document", "conformance:network-update", "evidence/genesisLink = a string", "a genesisLink member in a document that claims 2.0 is not read: the verdict is the unmodified document's, whatever the member holds", Certify1Case{}),
			sameAsBase: true,
			apply: func(d map[string]any, _ *xworld.Built) error {
				return setMember(d, []any{"evidence", "genesisLink"}, "not a receipt at all")
			}},
		{Certify1Case: c("anchored-item-in-an-evidence-2.0-document", "conformance:network-update", "evidence/certify/0/rootProof removed", "an item without a root proof in a document that claims 2.0: refused as it always was", plain("certify run 0: incomplete minor root record")),
			apply: func(d map[string]any, _ *xworld.Built) error {
				return deleteMember(d, append(certifyAt(0), "rootProof"))
			}},
		{Certify1Case: c("links-member-in-an-evidence-2.0-document", "conformance:network-update", "evidence/links = a string", "a links member in a document that claims 2.0 is not read: the verdict is the unmodified document's, whatever the member holds", Certify1Case{}),
			sameAsBase: true,
			apply: func(d map[string]any, _ *xworld.Built) error {
				return setMember(d, []any{"evidence", "links"}, "not a list at all")
			}},
	}
}

// verdictMatches is whether the Go verifier's verdict on a document is the one the case states.
func verdictMatches(c Certify1Case, verr error) bool {
	switch c.Expect {
	case "verified":
		return verr == nil
	case "refused":
		if verr == nil || strings.HasPrefix(verr.Error(), "PANIC") {
			return false
		}
		var cs *proofv2.CertifyState
		named := errors.As(verr, &cs)
		if c.State == "" && named || c.State != "" && (!named || cs.Code != c.State || !reflect.DeepEqual(cs.Fields, c.Fields)) {
			return false
		}
		return (c.Wording == "" || verr.Error() == c.Wording) && (c.Prefix == "" || strings.HasPrefix(verr.Error(), c.Prefix))
	}
	return false
}

// judgeCertify1 checks the Go verifier's verdict on a document against the case, completes the case (the report of a verified vector, the
// wording and prefix of a refused one) and records every disagreement in problems.
func judgeCertify1(xc *Certify1Case, rep *proofv2.Report, verr error, problems *[]string, reports map[string]*XReport) error {
	switch xc.Expect {
	case "refused":
		switch {
		case verr == nil:
			*problems = append(*problems, fmt.Sprintf("%s: the Go verifier accepted a refused vector", xc.Name))
		case strings.HasPrefix(verr.Error(), "PANIC"):
			*problems = append(*problems, fmt.Sprintf("%s: %v", xc.Name, verr))
		default:
			var cs *proofv2.CertifyState
			named := errors.As(verr, &cs)
			switch {
			case xc.State == "" && named:
				*problems = append(*problems, fmt.Sprintf("%s: refused with the certify state %v, the vector names none", xc.Name, cs))
			case xc.State != "" && (!named || cs.Code != xc.State || !reflect.DeepEqual(cs.Fields, xc.Fields)):
				*problems = append(*problems, fmt.Sprintf("%s: refused with %v, the vector says %s%v", xc.Name, verr, xc.State, xc.Fields))
			}
			if xc.Wording != "" && verr.Error() != xc.Wording {
				*problems = append(*problems, fmt.Sprintf("%s: refused with %q, the vector's wording is %q", xc.Name, verr.Error(), xc.Wording))
			}
			if xc.Wording == "" {
				xc.Wording = verr.Error()
			}
			if xc.Prefix == "" {
				xc.Prefix = xc.Wording
			}
			if !strings.HasPrefix(verr.Error(), xc.Prefix) {
				*problems = append(*problems, fmt.Sprintf("%s: refused with %q, which does not begin %q", xc.Name, verr.Error(), xc.Prefix))
			}
		}
	case "verified":
		if verr != nil {
			*problems = append(*problems, fmt.Sprintf("%s: the Go verifier refused a verified vector: %v", xc.Name, verr))
			break
		}
		xc.Report = xreport(rep)
		reports[xc.Name] = xc.Report
	default:
		return fmt.Errorf("%s: expect %q", xc.Name, xc.Expect)
	}
	return nil
}

// frozenCertify1 is the case of a frozen F5-1 document: the file in out (never written here) must hash to the pin, and it is judged by the
// current verifier. Its expectation is the spec's (which the regenerated sibling is judged by) unless the verifier now refuses it with
// certify_link_missing{genesis}, the one verdict the F5-3 requirement moves; any other disagreement is a problem.
func frozenCertify1(out string, spec Certify1Case, pin string, problems *[]string, reports map[string]*XReport) (Certify1Case, error) {
	xc := spec
	xc.File, xc.SHA256, xc.SameReportAs, xc.Report = spec.Name+".json", pin, "", nil
	// What the frozen document is comes from the pinned F5-1 text, never from the spec (which describes the genesis-link-carrying sibling).
	txt, pinned := certify1FrozenTexts[spec.Name]
	if !pinned {
		*problems = append(*problems, fmt.Sprintf("%s: no pinned F5-1 text for a frozen vector", spec.Name))
		return xc, nil
	}
	xc.Description, xc.World, xc.Edit = txt.Description, txt.World, txt.Edit
	raw, err := os.ReadFile(filepath.Join(out, xc.File))
	if err != nil {
		*problems = append(*problems, fmt.Sprintf("%s: the frozen F5-1 document is not in %s: %v", spec.Name, out, err))
		return xc, nil
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != pin {
		*problems = append(*problems, fmt.Sprintf("%s: the frozen F5-1 document hashes to %x, not the pinned %s: it is never rewritten", spec.Name, sum, pin))
		return xc, nil
	}
	rep, verr := verifyGuarded(bytes.TrimSuffix(raw, []byte{0x0a}))
	xc.Note = certify1FrozenUnmovedNote
	if !verdictMatches(xc, verr) {
		// The two requirements that moved verdicts of unreleased 2.1 documents: the genesis link of an anchored document (F5-3), decided after
		// the certify runs are walked, and the update window (F5-3b), decided in the walk. Nothing else may move.
		var cs *proofv2.CertifyState
		switch {
		case errors.As(verr, &cs) && cs.Code == proofv2.StateCertifyLinkMissing && reflect.DeepEqual(cs.Fields, []string{"genesis"}):
			xc.Note = certify1FrozenMovedNote
		case errors.As(verr, &cs) && cs.Code == proofv2.StateCertifyUpdateUnproven && len(cs.Fields) == 3:
			xc.Note = certify1FrozenWindowNote
		default:
			*problems = append(*problems, fmt.Sprintf("%s: the frozen document is judged %v, which is neither the spec's verdict nor certify_link_missing{genesis} nor certify_update_unproven", spec.Name, verr))
			return xc, nil
		}
		x := certify1State(cs.Code, cs.Fields...)
		xc.Expect, xc.State, xc.Fields, xc.Wording, xc.Prefix = x.Expect, x.State, x.Fields, x.Wording, ""
	}
	if err := judgeCertify1(&xc, rep, verr, problems, reports); err != nil {
		return xc, err
	}
	// The verdict is the F5-1 one or a fixed move of certify1_frozen_text.go; a verifier that moves any other frozen document, or moves one
	// elsewhere, is a problem and not a re-baseline.
	if err := checkCertify1FrozenEntry(xc, true); err != nil {
		*problems = append(*problems, err.Error())
	}
	return xc, nil
}

// writeCertify1 writes the suite into out and refuses to write a vector the Go verifier does not judge as the suite says; every vector that
// does not is reported, not only the first. The frozen documents of the F5-1 suite (certify1_frozen.go) must already be in out and are not written.
func writeCertify1(out string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	names, err := os.ReadFile(filepath.Join(out, "names.json"))
	if err != nil {
		return fmt.Errorf("names.json is the source of the names and must exist beside the vectors: %w", err)
	}
	nsum := sha256.Sum256(names)
	m := Certify1Manifest{Format: XManifestFormatCertify1, Domain: proofv2.DomainG1V4, PortableFormat: proofv2.PortableFormat, NamesFile: "names.json", NamesSHA256: hex.EncodeToString(nsum[:])}
	worlds := certify1Worlds()
	var problems []string
	reports := map[string]*XReport{}
	renamed := map[string]string{} // frozen name -> the name of its regenerated sibling
	siblings := map[string]bool{}
	for _, s := range certify1Specs() {
		doc, built, err := certify1Doc(s.World, worlds)
		if err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
		var baseRep *proofv2.Report
		var baseErr error
		if s.sameAsBase {
			raw, err := json.Marshal(doc)
			if err != nil {
				return err
			}
			baseRep, baseErr = verifyGuarded(raw)
		}
		if err := s.apply(doc, built); err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
		edited, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		rep, verr := verifyGuarded(edited)
		xc := s.Certify1Case
		xc.File = s.Name + ".json"
		if block, unproven := map[string]string{"update-before-its-window": "120", "update-after-its-window": "110", "update-receipt-shape-undecodable": "110"}[s.Name]; unproven {
			x := certify1State(proofv2.StateCertifyUpdateUnproven, "acc://dn.acme/globals", xworld.UpdateTxHash(xworld.UpdateGlobals, built.Inputs.GlobalsRecord), block)
			xc.Expect, xc.State, xc.Fields, xc.Wording = x.Expect, x.State, x.Fields, x.Wording
		}
		if s.Name == "duplicated-update" || s.Name == "hop-duplicated-update" {
			x := certify1State(proofv2.StateCertifyUpdateReplayed, xworld.UpdateTxHash(xworld.UpdateGlobals, built.Inputs.GlobalsRecord))
			xc.Expect, xc.State, xc.Fields, xc.Wording = x.Expect, x.State, x.Fields, x.Wording
		}
		if s.sameAsBase {
			if baseErr == nil {
				xc.Expect = "verified"
			} else {
				xc.Expect, xc.Wording = "refused", baseErr.Error()
			}
			if (baseErr == nil) != (verr == nil) || (verr != nil && verr.Error() != baseErr.Error()) || (verr == nil && !reflect.DeepEqual(xreport(rep), xreport(baseRep))) {
				problems = append(problems, fmt.Sprintf("%s: judged %v, its base %v", s.Name, verr, baseErr))
			}
		}
		edited = append(edited, 0x0a)
		sum := sha256.Sum256(edited) // the hash of the file's exact bytes
		// A vector of the frozen F5-1 suite whose regenerated document is not the frozen one: the frozen document keeps the name (and moves only
		// its expectation); the regenerated one goes beside it under the sibling's name.
		if pin, frozen := certify1Frozen[s.Name]; frozen && hex.EncodeToString(sum[:]) != pin {
			fc, err := frozenCertify1(out, xc, pin, &problems, reports)
			if err != nil {
				return err
			}
			m.Cases = append(m.Cases, fc)
			xc.Name, xc.File = s.Name+certify1GenesisSuffix, s.Name+certify1GenesisSuffix+".json"
			renamed[s.Name], siblings[xc.Name] = xc.Name, true
		}
		if err := judgeCertify1(&xc, rep, verr, &problems, reports); err != nil {
			return err
		}
		xc.SHA256 = hex.EncodeToString(sum[:])
		if _, frozen := certify1Frozen[s.Name]; frozen && !renamedHere(renamed, s.Name) {
			// A frozen vector whose regenerated bytes are the frozen bytes: its entry is the F5-1 entry, with the same pinned text.
			txt, pinned := certify1FrozenTexts[s.Name]
			if !pinned {
				problems = append(problems, fmt.Sprintf("%s: no pinned F5-1 text for a frozen vector", s.Name))
			} else {
				xc.Description, xc.World, xc.Edit = txt.Description, txt.World, txt.Edit
				if err := checkCertify1FrozenEntry(xc, false); err != nil {
					problems = append(problems, err.Error())
				}
			}
		}
		if err := os.WriteFile(filepath.Join(out, xc.File), edited, 0o644); err != nil {
			return err
		}
		m.Cases = append(m.Cases, xc)
	}
	for _, name := range sortedFrozenNames() {
		if !hasCase(m.Cases, name) {
			problems = append(problems, fmt.Sprintf("%s: a frozen F5-1 vector the suite no longer has", name))
		}
	}
	for i := range m.Cases {
		c := &m.Cases[i]
		if c.SameReportAs == "" {
			continue
		}
		if siblings[c.Name] {
			if r, ok := renamed[c.SameReportAs]; ok {
				c.SameReportAs = r // a regenerated sibling is the same report as the sibling of the vector it names
			}
		}
		if want, okw := reports[c.SameReportAs]; !okw || c.Report == nil || !reflect.DeepEqual(want, c.Report) {
			problems = append(problems, fmt.Sprintf("%s: its report is not the report of %s", c.Name, c.SameReportAs))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%d vector(s) are not judged as the suite says:\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	mj = append(mj, '\n')
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), mj, 0o644); err != nil {
		return err
	}
	// The vectors are shared with the TypeScript verifier byte for byte; their hashes cover the exact bytes.
	attrs := "# The vectors are shared with the TypeScript verifier byte for byte; their hashes cover the exact bytes.\n* -text\n"
	if err := os.WriteFile(filepath.Join(out, ".gitattributes"), []byte(attrs), 0o644); err != nil {
		return err
	}
	h := sha256.Sum256(mj)
	return os.WriteFile(filepath.Join(out, "MANIFEST.sha256"), []byte(hex.EncodeToString(h[:])+"  manifest.json\n"), 0o644)
}

func renamedHere(renamed map[string]string, name string) bool {
	_, ok := renamed[name]
	return ok
}

func hasCase(cases []Certify1Case, name string) bool {
	for _, c := range cases {
		if c.Name == name {
			return true
		}
	}
	return false
}

func sortedFrozenNames() []string {
	out := make([]string, 0, len(certify1Frozen))
	for k := range certify1Frozen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
