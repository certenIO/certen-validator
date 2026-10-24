// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"
)

// The identity manifest (V2_SPEC_S8.md "Proposed evidence structure", manifest v1.1 section list) is an embedded, hash-pinned file: the
// reproducible-build identity of every contract the S8 statement relies on. Step 0 of the algorithm is implemented here:
//
//	Embedded bytes hash to ManifestSHA256 else manifest_corrupt (refuse to start);
//	chains[] has Settlement.chainId else manifest_unknown{chain};
//	an extension that redefines a primary key of v1.1 -> manifest_shadow{table,key}.
//
// The pin is the Go constant ManifestSHA256 (manifest_pin_gen.go, written by `node design/vectors/s8/lift.mjs --sync-manifest <path>`
// together with the embedded manifest and its sibling .sha256 file); TestManifestSync fails when the three disagree.

// ManifestSchema is the schema string this loader accepts.
const ManifestSchema = "certen:identity-manifest:v1.1"

//go:embed testdata/contractidentity/manifest/identity-manifest.json
var embeddedManifest []byte

//go:embed testdata/contractidentity/manifest/identity-manifest.json.sha256
var embeddedManifestSHA256File []byte

// EmbeddedManifestBytes returns a copy of the embedded manifest file.
func EmbeddedManifestBytes() []byte { return append([]byte(nil), embeddedManifest...) }

// EmbeddedManifestSHA256File returns the text of the sibling .sha256 file of the embedded manifest.
func EmbeddedManifestSHA256File() string { return string(embeddedManifestSHA256File) }

// manifestHash is the manifest hash definition of the file itself: SHA-256 over the bytes with CRLF normalised to LF.
func manifestHash(raw []byte) [32]byte {
	return sha256.Sum256(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")))
}

// ManifestHash is the SHA-256 of a manifest file as the manifest defines it (CRLF normalised to LF).
func ManifestHash(raw []byte) [32]byte { return manifestHash(raw) }

// ---- typed rows (the fields the steps read; unknown fields of a row are kept out of the types and never trusted) ----

// ChainEntry is a row of chains[].
type ChainEntry struct {
	ChainID           uint64 `json:"chainId"`
	Name              string `json:"name"`
	SnapshotBlock     uint64 `json:"snapshotBlock"`
	SnapshotBlockHash string `json:"snapshotBlockHash"`
}

// Ref is an immutable reference range in a build's runtime code.
type Ref struct {
	Start  int `json:"start"`
	Length int `json:"length"`
}

// ImmutableRule is the rule a deployed immutable value must satisfy (step 7, 10, 12).
type ImmutableRule struct {
	Kind string `json:"kind"`
	Expr string `json:"expr"`
	// Value is the constant of a `constant` rule (the EntryPoint address); empty when the row carries none, in which case the spec literal
	// applies (step 7) [r3.2:E-j].
	Value string `json:"value"`
	// Contract is the contract a `deployment` rule points at.
	Contract string `json:"contract"`
}

// Immutable is an immutable of a build: its name, type, the byte ranges of its references and its rule.
type Immutable struct {
	Name       string        `json:"name"`
	Type       string        `json:"type"`
	References []Ref         `json:"references"`
	Rule       ImmutableRule `json:"rule"`
}

// StorageRow is a storage layout row of a build (slot arithmetic is FREEZE-B's; the row is exposed as the manifest states it).
type StorageRow struct {
	Label        string `json:"label"`
	Slot         string `json:"slot"`
	ByteOffset   int    `json:"byteOffset"`
	Kind         string `json:"kind"`
	SolidityType string `json:"solidityType"`
	ByteLength   int    `json:"byteLength"`
}

// Runtime is the runtime code identity of a build: its length and the masked keccak (the maskRule of the manifest).
type Runtime struct {
	Bytes        int    `json:"bytes"`
	MaskedKeccak string `json:"maskedKeccak"`
	CBORMetadata string `json:"cborMetadata"`
}

// Creation is the creation code identity of a build.
type Creation struct {
	Bytes  int    `json:"bytes"`
	Keccak string `json:"keccak"`
}

// AuthWritersRecord is a build's writer-premise record (manifest item 10). Status is "pass" only when every condition passed.
type AuthWritersRecord struct {
	Status      string            `json:"status"`
	Conditions  map[string]string `json:"conditions"`
	EntryPoints int               `json:"entryPoints"`
	Hazards     []json.RawMessage `json:"hazards"`
	// OwnerModifier is the member-level record of the onlyOwner modifier (contract, modifier, bodyHash, predicate, shape, ownerSlot, ownerOffset,
	// file, lines); Entries are the per-entry-point records (signature, modifiers, callees, writes). Both are kept raw: the pinned body hash and
	// the writes are compared by the rule IB gate (step 22 IB3), not interpreted here.
	OwnerModifier json.RawMessage `json:"ownerModifier"`
	Entries       json.RawMessage `json:"entries"`
}

// AllowedWrites is the allowedWrites cell of an allow-list row: the string "*" (the constructor, deployment only) or a list of written paths.
type AllowedWrites struct {
	Any   bool
	Paths []string
}

// UnmarshalJSON accepts "*" or an array of strings; anything else is an error (a malformed allow-list is manifest_corrupt).
func (a *AllowedWrites) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s != "*" {
			return fmt.Errorf("allowedWrites %q is neither \"*\" nor a list", s)
		}
		*a = AllowedWrites{Any: true}
		return nil
	}
	var l []string
	if err := json.Unmarshal(b, &l); err != nil {
		return fmt.Errorf("allowedWrites: %w", err)
	}
	*a = AllowedWrites{Paths: l}
	return nil
}

// AllowRow is one allow-listed writer entry of a build (a function of the contract, the paths it may write, why that is safe).
type AllowRow struct {
	Function       string          `json:"function"`
	AllowedWrites  AllowedWrites   `json:"allowedWrites"`
	DeploymentOnly bool            `json:"deploymentOnly"`
	Why            string          `json:"why"`
	Guard          json.RawMessage `json:"guard"`
}

// AuthWriterAllowList is a build's allow-list and its pinned onlyOwner modifier record.
type AuthWriterAllowList struct {
	OwnerModifierPin json.RawMessage `json:"ownerModifierPin"`
	Rows             []AllowRow      `json:"rows"`
}

// Build is a row of builds{}: one contract at one compile variant.
type Build struct {
	Contract            string               `json:"contract"`
	Variant             string               `json:"variant"`
	SourcePath          string               `json:"sourcePath"`
	Runtime             Runtime              `json:"runtime"`
	Creation            Creation             `json:"creation"`
	Immutables          []Immutable          `json:"immutables"`
	Storage             []StorageRow         `json:"storage"`
	AuthWriters         *AuthWritersRecord   `json:"authWriters"`
	AuthWriterAllowList *AuthWriterAllowList `json:"authWriterAllowList"`
	AuthExempt          []json.RawMessage    `json:"authExempt"`
}

// Key is the primary key "<contract>/<variant>".
func (b Build) Key() string { return b.Contract + "/" + b.Variant }

// Deployment is a row of deployments[]: the primary key is (chainId, role).
type Deployment struct {
	ChainID  uint64 `json:"chainId"`
	Chain    string `json:"chain"`
	Role     string `json:"role"`
	Contract string `json:"contract"`
	Address  string `json:"address"`
	Build    string `json:"build"`
}

// Create2 is the CREATE2 record of an account row (step 8).
type Create2 struct {
	Salt            string `json:"salt"`
	InitcodeKeccak  string `json:"initcodeKeccak"`
	ComputedAddress string `json:"computedAddress"`
}

// Account is a row of accounts[].
type Account struct {
	ChainID           uint64  `json:"chainId"`
	Address           string  `json:"address"`
	ADIURL            string  `json:"adiURL"`
	GoverningBook     string  `json:"governingBook"`
	Owner             string  `json:"owner"`
	GoverningBookHash string  `json:"governingBookHash"`
	AnchorContract    string  `json:"anchorContract"`
	Factory           string  `json:"factory"`
	Build             string  `json:"build"`
	Create2           Create2 `json:"create2"`
}

// Threshold is a numerator / denominator pair.
type Threshold struct {
	Numerator   uint64 `json:"numerator"`
	Denominator uint64 `json:"denominator"`
}

// Rule is a row of policy.rules (the "Policy rules" table).
type Rule struct {
	ID        string   `json:"id"`
	AuthRows  []string `json:"authRows"`
	Predicate string   `json:"predicate"`
	At        string   `json:"at"`
	Verdict   string   `json:"verdict"`
}

// Policy holds the scalar policy rows.
type Policy struct {
	BLSThreshold             Threshold
	PubkeyBindingEnforced    bool
	BLSZKVerificationEnabled bool
	VerifierThreshold        Threshold
	MinimumGovernanceLevel   uint8
	GovernanceVerifier       string
	Rules                    []Rule
}

// OwnerRow is a row of policy.owner[chain]: who owns the anchor or the verifier from validFromBlock until validToBlock (nil: open).
type OwnerRow struct {
	Role           string  `json:"role"`
	Address        string  `json:"address"`
	ValidFromBlock uint64  `json:"validFromBlock"`
	ValidToBlock   *uint64 `json:"validToBlock"`
}

// SetRootRow is a row of policy.setRootHistory: a validator-set root with the keys and the authorized set it commits to (step 21c).
// KeysDigest, PKCCount and PKCList are nil when the row does not carry them (the Open entry registry_keys says which).
type SetRootRow struct {
	ChainID              uint64    `json:"chainId"`
	Root                 string    `json:"root"`
	ValidFromBlock       uint64    `json:"validFromBlock"`
	ValidToBlock         *uint64   `json:"validToBlock"`
	ThresholdNumerator   uint64    `json:"thresholdNumerator"`
	ThresholdDenominator uint64    `json:"thresholdDenominator"`
	KeysDigest           *string   `json:"keysDigest"`
	PKCCount             *uint64   `json:"pkcCount"`
	PKCList              *[]string `json:"pkcList"`
}

// TxEvidence is the evidence of one listed transaction type: the pinned source citation and the on-chain observation (spec shape,
// manifest item 2). A manifest that predates it has none.
type TxEvidence struct {
	Source      string          `json:"source"`
	Observation json.RawMessage `json:"observation"`
}

// TxScan is policy.txScan[chain]: the transaction types rule IB2 accepts. Evidence is nil when the manifest does not carry the spec-shape
// evidence table (it then cannot back a type, and the verifier names the type unsupported).
type TxScan struct {
	CoveredTypes []int                 `json:"coveredTypes"`
	SystemTypes  []int                 `json:"systemTypes"`
	Evidence     map[string]TxEvidence `json:"evidence"`
}

// EIP2935 is eip2935[chain]: the history contract, its code hash and the ring size.
type EIP2935 struct {
	Chain    string `json:"chain"`
	Address  string `json:"address"`
	CodeHash string `json:"codeHash"`
	Window   uint64 `json:"window"`
	SlotRule string `json:"slotRule"`
}

// Selector is a row of selectors{}.
type Selector struct {
	Role      string `json:"role"`
	Contract  string `json:"contract"`
	Function  string `json:"function"`
	Signature string `json:"signature"`
	Selector  string `json:"selector"`
	Pinned    bool   `json:"pinned"`
	Supported bool   `json:"supported"`
	Source    string `json:"source"`
}

// Topic is a row of topics{} or topics.accountEvents.events{}.
type Topic struct {
	Contract  string   `json:"contract"`
	Event     string   `json:"event"`
	Signature string   `json:"signature"`
	Topic0    string   `json:"topic0"`
	Indexed   []string `json:"indexed"`
	Source    string   `json:"source"`
}

// Generation is a row of generations[] (manifest item 5 and 12): a build that exists on a chain but is not pinned. Kind is catalogued
// or observed. The primary key is (Role, MaskedKeccak) [r3.2:E-e2]: the pair (Role, Generation) repeats (CertenAccountV7 has a catalogued and an
// observed row; several families are `unidentified`). Source is the source record of a catalogued row (null for an observed one); Evidence are
// the on-chain observations (chain, address, block, code hash) and SettlementSelector the selector of the account's settlement call when the
// row records one.
type Generation struct {
	Role               string          `json:"role"`
	Generation         string          `json:"generation"`
	Pinned             bool            `json:"pinned"`
	Kind               string          `json:"kind"`
	MaskedKeccak       string          `json:"maskedKeccak"`
	RuntimeBytes       int             `json:"runtimeBytes"`
	References         []Ref           `json:"references"`
	Source             json.RawMessage `json:"source"`
	SourceReason       string          `json:"sourceReason"`
	Evidence           []GenEvidence   `json:"evidence"`
	SettlementSelector string          `json:"settlementSelector"`
}

// GenEvidence is one on-chain observation of a generations row.
type GenEvidence struct {
	ChainID  uint64 `json:"chainId"`
	Address  string `json:"address"`
	Block    uint64 `json:"block"`
	CodeHash string `json:"codeHash"`
}

// SlotRef is the slot column of an AUTH row: a storage slot number, or the word "account" for the account-proof row C01.
type SlotRef struct {
	Text string // the cell as written ("17", "account")
	Num  uint64 // the slot number when the cell is one
	IsNo bool   // Num is meaningful
}

// UnmarshalJSON accepts a JSON number or a string.
func (s *SlotRef) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err == nil {
		v, perr := strconv.ParseUint(n.String(), 10, 64)
		if perr != nil {
			return perr
		}
		*s = SlotRef{Text: n.String(), Num: v, IsNo: true}
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	*s = SlotRef{Text: str}
	if v, err := strconv.ParseUint(str, 10, 64); err == nil {
		s.Num, s.IsNo = v, true
	}
	return nil
}

// AuthSlot is a row of authSlots[] (the AUTH slot set table in machine form). Offset and Label are nil for the account-proof row C01.
type AuthSlot struct {
	ID        string  `json:"id"`
	Contract  string  `json:"contract"`
	Slot      SlotRef `json:"slot"`
	Bytes     string  `json:"bytes"`
	Field     string  `json:"field"`
	Label     *string `json:"label"`
	Offset    *int    `json:"offset"`
	Key       string  `json:"key"`
	PreVsPost string  `json:"preVsPost"`
	AtN       string  `json:"atN"`
	JudgedBy  string  `json:"judgedBy"`
	Build     string  `json:"build"`
	Type      string  `json:"type"`
	TypeBytes int     `json:"typeBytes"`
}

// CreationArtifact is a row of creationArtifacts{}.
type CreationArtifact struct {
	File      string `json:"file"`
	Bytes     int    `json:"bytes"`
	Keccak256 string `json:"keccak256"`
	SHA256    string `json:"sha256"`
}

// ---- the manifest ----

// Manifest is a hash-checked identity manifest, possibly merged with an extension. It is immutable after Load.
type Manifest struct {
	// Source is the manifest_source of every report: embedded, override:<sha256> or extension:<sha256>.
	Source string
	// SHA256 is the hash of the primary manifest (the pinned one for the embedded manifest; the supplied one for an override).
	SHA256 [32]byte
	// ExtensionSHA256 is the hash of the extension merged into it (zero when none).
	ExtensionSHA256 [32]byte

	doc       map[string]json.RawMessage
	chains    []ChainEntry
	builds    map[string]Build
	buildKeys []string
	deploys   []Deployment
	accounts  []Account
	policy    Policy
	owners    map[uint64][]OwnerRow
	setRoots  []SetRootRow
	txScan    map[uint64]TxScan
	eip2935   map[uint64]EIP2935
	selectors map[string]Selector
	selKeys   []string
	topics    map[string]Topic
	accEvents map[string]Topic
	gens      []Generation
	hasGens   bool
	authSlots []AuthSlot
	creation  map[string]CreationArtifact
}

var (
	embeddedOnce sync.Once
	embeddedM    *Manifest
	embeddedErr  error
)

// Embedded is the embedded manifest checked against ManifestSHA256. A broken embed is manifest_corrupt: the verifier refuses to start.
func Embedded() (*Manifest, error) {
	embeddedOnce.Do(func() {
		var want [32]byte
		b, err := hex.DecodeString(ManifestSHA256)
		if err != nil || len(b) != 32 {
			embeddedErr = ManifestCorrupt()
			return
		}
		copy(want[:], b)
		embeddedM, embeddedErr = LoadManifest(embeddedManifest, want)
	})
	return embeddedM, embeddedErr
}

// LoadManifest hash-checks raw against want (manifest_corrupt on a mismatch, a malformed document or an unsupported schema) and parses
// it into the typed tables. Source is "embedded".
func LoadManifest(raw []byte, want [32]byte) (*Manifest, error) {
	got := manifestHash(raw)
	if got != want {
		return nil, ManifestCorrupt()
	}
	m, err := parseManifest(raw)
	if err != nil {
		return nil, err
	}
	m.Source = ManifestSourceEmbedded
	m.SHA256 = got
	return m, nil
}

// LoadOverride loads a manifest the caller supplies in place of the embedded one (a CLI --manifest override). It is parsed exactly as
// the embedded one but is NOT checked against the pin; the report says so through Source = override:<sha256>.
func LoadOverride(raw []byte) (*Manifest, error) {
	m, err := parseManifest(raw)
	if err != nil {
		return nil, err
	}
	m.SHA256 = manifestHash(raw)
	m.Source = "override:" + hex.EncodeToString(m.SHA256[:])
	return m, nil
}

func parseManifest(raw []byte) (*Manifest, error) {
	norm := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	if path, key, dup, err := findDuplicateKey(norm); err != nil {
		return nil, ManifestCorrupt().WithCause(err)
	} else if dup {
		return nil, ManifestCorrupt().WithCause(fmt.Errorf("manifest: duplicate key %q at %s", key, path))
	}
	doc := map[string]json.RawMessage{}
	if err := json.Unmarshal(norm, &doc); err != nil {
		return nil, ManifestCorrupt().WithCause(err)
	}
	var schema string
	if json.Unmarshal(doc["schema"], &schema) != nil || schema != ManifestSchema {
		return nil, ManifestCorrupt().WithCause(fmt.Errorf("manifest: schema %q is not %q", schema, ManifestSchema))
	}
	m := &Manifest{doc: doc}
	if err := m.decode(); err != nil {
		return nil, ManifestCorrupt().WithCause(err)
	}
	return m, nil
}

// decode fills the typed tables from m.doc. The tables every step needs must be present and well-formed; the tables that older
// manifests lack (generations, txScan evidence) stay empty and are reported as absent by their accessors.
func (m *Manifest) decode() error {
	get := func(key string, into any, required bool) error {
		b, ok := m.doc[key]
		if !ok {
			if required {
				return fmt.Errorf("manifest: table %s is absent", key)
			}
			return nil
		}
		if err := json.Unmarshal(b, into); err != nil {
			return fmt.Errorf("manifest: table %s: %w", key, err)
		}
		return nil
	}
	if err := get("chains", &m.chains, true); err != nil {
		return err
	}
	if err := get("builds", &m.builds, true); err != nil {
		return err
	}
	m.buildKeys = m.buildKeys[:0]
	for k := range m.builds {
		m.buildKeys = append(m.buildKeys, k)
	}
	sort.Strings(m.buildKeys)
	if err := get("deployments", &m.deploys, true); err != nil {
		return err
	}
	if err := get("accounts", &m.accounts, true); err != nil {
		return err
	}
	var pol struct {
		BLSThreshold             Threshold `json:"blsThreshold"`
		PubkeyBindingEnforced    bool      `json:"pubkeyBindingEnforced"`
		BLSZKVerificationEnabled bool      `json:"blsZKVerificationEnabled"`
		VerifierThreshold        Threshold `json:"verifierThreshold"`
		MinimumGovernanceLevel   struct {
			Min uint8 `json:"min"`
		} `json:"minimumGovernanceLevel"`
		GovernanceVerifier string                `json:"governanceVerifier"`
		Rules              []Rule                `json:"rules"`
		Owner              map[string][]OwnerRow `json:"owner"`
		TxScan             map[string]TxScan     `json:"txScan"`
		SetRootHistory     []SetRootRow          `json:"setRootHistory"`
	}
	if err := get("policy", &pol, true); err != nil {
		return err
	}
	m.policy = Policy{pol.BLSThreshold, pol.PubkeyBindingEnforced, pol.BLSZKVerificationEnabled, pol.VerifierThreshold, pol.MinimumGovernanceLevel.Min, pol.GovernanceVerifier, pol.Rules}
	m.owners = map[uint64][]OwnerRow{}
	for k, rows := range pol.Owner {
		chain, err := strconv.ParseUint(k, 10, 64)
		if err != nil {
			return fmt.Errorf("manifest: policy.owner key %q", k)
		}
		m.owners[chain] = rows
	}
	m.txScan = map[uint64]TxScan{}
	for k, row := range pol.TxScan {
		chain, err := strconv.ParseUint(k, 10, 64)
		if err != nil {
			return fmt.Errorf("manifest: policy.txScan key %q", k)
		}
		m.txScan[chain] = row
	}
	m.setRoots = pol.SetRootHistory
	var eip map[string]EIP2935
	if err := get("eip2935", &eip, true); err != nil {
		return err
	}
	m.eip2935 = map[uint64]EIP2935{}
	for k, row := range eip {
		chain, err := strconv.ParseUint(k, 10, 64)
		if err != nil {
			return fmt.Errorf("manifest: eip2935 key %q", k)
		}
		m.eip2935[chain] = row
	}
	if err := get("selectors", &m.selectors, true); err != nil {
		return err
	}
	m.selKeys = m.selKeys[:0]
	for k := range m.selectors {
		m.selKeys = append(m.selKeys, k)
	}
	sort.Strings(m.selKeys)
	var tp struct {
		ProofExecuted json.RawMessage `json:"ProofExecuted"`
		LeafConsumed  json.RawMessage `json:"LeafConsumed"`
		AccountEvents struct {
			Events map[string]Topic `json:"events"`
		} `json:"accountEvents"`
	}
	if err := get("topics", &tp, true); err != nil {
		return err
	}
	m.topics = map[string]Topic{}
	for name, raw := range map[string]json.RawMessage{"ProofExecuted": tp.ProofExecuted, "LeafConsumed": tp.LeafConsumed} {
		var t Topic
		if err := json.Unmarshal(raw, &t); err != nil {
			return fmt.Errorf("manifest: topics.%s: %w", name, err)
		}
		m.topics[name] = t
	}
	m.accEvents = tp.AccountEvents.Events
	if err := get("authSlots", &m.authSlots, true); err != nil {
		return err
	}
	if err := get("creationArtifacts", &m.creation, false); err != nil {
		return err
	}
	if _, ok := m.doc["generations"]; ok {
		m.hasGens = true
		if err := get("generations", &m.gens, false); err != nil {
			return err
		}
	}
	if err := m.checkRowSpans(); err != nil {
		return err
	}
	// the tables are keyed and must not repeat a primary key inside one document
	seen := map[string]bool{}
	for _, g := range m.gens {
		if err := checkGenerationKey(g.Role, g.MaskedKeccak); err != nil {
			return err
		}
		k := "generations:" + generationKey(g.Role, g.MaskedKeccak)
		if seen[k] {
			return fmt.Errorf("manifest: generations repeat (role,maskedKeccak) %s", k)
		}
		seen[k] = true
	}
	for _, d := range m.deploys {
		k := fmt.Sprintf("%d,%s", d.ChainID, d.Role)
		if seen[k] {
			return fmt.Errorf("manifest: deployments repeat (chainId,role) %s", k)
		}
		seen[k] = true
	}
	return nil
}

// findDuplicateKey reports the first object key that repeats inside one object of a JSON document (encoding/json keeps the last value
// silently, which would let a document shadow its own earlier row).
func findDuplicateKey(raw []byte) (path, key string, found bool, err error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func(path string) (string, string, bool, error)
	walk = func(path string) (string, string, bool, error) {
		tok, err := dec.Token()
		if err != nil {
			return "", "", false, err
		}
		d, isDelim := tok.(json.Delim)
		if !isDelim {
			return "", "", false, nil
		}
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return "", "", false, err
				}
				k, _ := kt.(string)
				if seen[k] {
					return path, k, true, nil
				}
				seen[k] = true
				if p, kk, f, err := walk(path + "." + k); err != nil || f {
					return p, kk, f, err
				}
			}
		case '[':
			for dec.More() {
				if p, kk, f, err := walk(path + "[]"); err != nil || f {
					return p, kk, f, err
				}
			}
		}
		if _, err := dec.Token(); err != nil {
			return "", "", false, err
		}
		return "", "", false, nil
	}
	return walk("")
}

// ---- accessors ----

// Schema is the manifest schema string.
func (m *Manifest) Schema() string { return ManifestSchema }

// Chains are the rows of chains[].
func (m *Manifest) Chains() []ChainEntry { return append([]ChainEntry(nil), m.chains...) }

// Chain is step 0's chains[] lookup: manifest_unknown{chain} when the settlement's chain is not a row.
func (m *Manifest) Chain(chain uint64) (ChainEntry, error) {
	for _, c := range m.chains {
		if c.ChainID == chain {
			return c, nil
		}
	}
	return ChainEntry{}, ManifestUnknown(chain)
}

// Build returns the build row "<contract>/<variant>".
func (m *Manifest) Build(key string) (Build, bool) { b, ok := m.builds[key]; return b, ok }

// BuildKeys are the build keys in sorted order.
func (m *Manifest) BuildKeys() []string { return append([]string(nil), m.buildKeys...) }

// Deployments are the deployments rows of a chain in manifest order.
func (m *Manifest) Deployments(chain uint64) []Deployment {
	var out []Deployment
	for _, d := range m.deploys {
		if d.ChainID == chain {
			out = append(out, d)
		}
	}
	return out
}

// Deployment is the row (chainId, role); roles are the five of Freeze item 4.
func (m *Manifest) Deployment(chain uint64, role string) (Deployment, bool) {
	for _, d := range m.deploys {
		if d.ChainID == chain && d.Role == role {
			return d, true
		}
	}
	return Deployment{}, false
}

// DeploymentAt is the deployment row of a chain whose address equals addr (case-insensitive hex).
func (m *Manifest) DeploymentAt(chain uint64, addr string) (Deployment, bool) {
	for _, d := range m.deploys {
		if d.ChainID == chain && strings.EqualFold(d.Address, addr) {
			return d, true
		}
	}
	return Deployment{}, false
}

// Accounts are the accounts rows of a chain.
func (m *Manifest) Accounts(chain uint64) []Account {
	var out []Account
	for _, a := range m.accounts {
		if a.ChainID == chain {
			out = append(out, a)
		}
	}
	return out
}

// Account is the account row of (chain, address).
func (m *Manifest) Account(chain uint64, addr string) (Account, bool) {
	for _, a := range m.accounts {
		if a.ChainID == chain && strings.EqualFold(a.Address, addr) {
			return a, true
		}
	}
	return Account{}, false
}

// Policy is the scalar policy and the rules.
func (m *Manifest) Policy() Policy {
	p := m.policy
	p.Rules = append([]Rule(nil), p.Rules...)
	return p
}

// Rule is the policy rule with the given id.
func (m *Manifest) Rule(id string) (Rule, bool) {
	for _, r := range m.policy.Rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

func effectiveEnd(from uint64, to *uint64, nextFrom *uint64) (end uint64, open bool) {
	switch {
	case to != nil && nextFrom != nil:
		e := *to
		if *nextFrom-1 < e {
			e = *nextFrom - 1
		}
		return e, false
	case to != nil:
		return *to, false
	case nextFrom != nil:
		return *nextFrom - 1, false
	}
	return 0, true
}

// OwnerRows are the owner history rows of (chain, role) in ascending validFromBlock order.
func (m *Manifest) OwnerRows(chain uint64, role string) []OwnerRow {
	var out []OwnerRow
	for _, r := range m.owners[chain] {
		if r.Role == role {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ValidFromBlock < out[j].ValidFromBlock })
	return out
}

// OwnerCovering returns the owner rows of (chain, role) whose range covers block. A row ends at its validToBlock or, when it is open or
// reaches further, one block before the next row of the same role starts: the history of a single-owner contract has one owner at a time
// (so an extension that appends a later row retires the earlier owner from that block on).
func (m *Manifest) OwnerCovering(chain uint64, role string, block uint64) []OwnerRow {
	rows := m.OwnerRows(chain, role)
	var out []OwnerRow
	for i, r := range rows {
		if block < r.ValidFromBlock {
			continue
		}
		var next *uint64
		for j := i + 1; j < len(rows); j++ {
			if rows[j].ValidFromBlock > r.ValidFromBlock {
				v := rows[j].ValidFromBlock
				next = &v
				break
			}
		}
		if end, open := effectiveEnd(r.ValidFromBlock, r.ValidToBlock, next); open || block <= end {
			out = append(out, r)
		}
	}
	return out
}

// SetRootRows are the setRootHistory rows of a chain in ascending validFromBlock order.
func (m *Manifest) SetRootRows(chain uint64) []SetRootRow {
	var out []SetRootRow
	for _, r := range m.setRoots {
		if r.ChainID == chain {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ValidFromBlock < out[j].ValidFromBlock })
	return out
}

// SetRootRowFor is the row of the chain whose range covers block and whose root equals root (step 21c), by the same retirement rule as
// OwnerCovering. ok is false when there is none.
func (m *Manifest) SetRootRowFor(chain, block uint64, root string) (SetRootRow, bool) {
	rows := m.SetRootRows(chain)
	for i, r := range rows {
		if block < r.ValidFromBlock || !strings.EqualFold(r.Root, root) {
			continue
		}
		var next *uint64
		for j := i + 1; j < len(rows); j++ {
			if rows[j].ValidFromBlock > r.ValidFromBlock {
				v := rows[j].ValidFromBlock
				next = &v
				break
			}
		}
		if end, open := effectiveEnd(r.ValidFromBlock, r.ValidToBlock, next); open || block <= end {
			return r, true
		}
	}
	return SetRootRow{}, false
}

// TxScan is policy.txScan[chain].
func (m *Manifest) TxScan(chain uint64) (TxScan, bool) { t, ok := m.txScan[chain]; return t, ok }

// EIP2935 is eip2935[chain].
func (m *Manifest) EIP2935(chain uint64) (EIP2935, bool) { e, ok := m.eip2935[chain]; return e, ok }

// Selector is the selectors row "<Contract>/<function>".
func (m *Manifest) Selector(key string) (Selector, bool) { s, ok := m.selectors[key]; return s, ok }

// Selectors are the selectors rows sorted by key.
func (m *Manifest) Selectors() []Selector {
	out := make([]Selector, 0, len(m.selKeys))
	for _, k := range m.selKeys {
		out = append(out, m.selectors[k])
	}
	return out
}

// AccountSelectors are the settlement selectors of an account generation ("V7_3"): the rows of selectors{} whose contract is
// CertenAccount<generation> and whose role is account (`[MAN].selectors.account.V7_3`).
func (m *Manifest) AccountSelectors(generation string) []Selector {
	var out []Selector
	for _, k := range m.selKeys {
		s := m.selectors[k]
		if s.Role == "account" && s.Contract == "CertenAccount"+generation {
			out = append(out, s)
		}
	}
	return out
}

// Topic is topics.ProofExecuted or topics.LeafConsumed.
func (m *Manifest) Topic(name string) (Topic, bool) { t, ok := m.topics[name]; return t, ok }

// AccountEventTopics are the events an account emits for a settlement (topics.accountEvents).
func (m *Manifest) AccountEventTopics() map[string]Topic {
	out := make(map[string]Topic, len(m.accEvents))
	for k, v := range m.accEvents {
		out[k] = v
	}
	return out
}

// Generations are the generations rows; HasGenerations is false for a manifest that predates the table.
func (m *Manifest) Generations() []Generation { return append([]Generation(nil), m.gens...) }

// HasGenerations reports whether the manifest carries the generations table at all.
func (m *Manifest) HasGenerations() bool { return m.hasGens }

// GenerationFor is the generations row with the primary key (role, maskedKeccak) [r3.2:E-e2]: the pair (role, generation) is NOT unique
// (CertenAccountV7 has a catalogued and an observed row, and several `unidentified` families exist), the masked runtime hash identifies the
// code. The hash is compared case-insensitively.
func (m *Manifest) GenerationFor(role, maskedKeccak string) (Generation, bool) {
	for _, g := range m.gens {
		if g.Role == role && strings.EqualFold(g.MaskedKeccak, maskedKeccak) {
			return g, true
		}
	}
	return Generation{}, false
}

// generationKey is the primary key of a generations row (role, maskedKeccak) as the no-shadow rule and the duplicate check use it. The hash
// is the canonical spelling itself [r3.6:H14]: it is never lower-cased here; a row that is not canonical is refused before it is keyed
// (checkGenerationKey).
func generationKey(role, maskedKeccak string) string {
	return role + "," + maskedKeccak
}

// canonicalHex32 is the one spelling of a 32-byte hex key: 0x followed by exactly 64 lower-case hexadecimal digits [r3.6:H14].
func canonicalHex32(s string) bool {
	if len(s) != 66 || s[0] != '0' || s[1] != 'x' {
		return false
	}
	for i := 2; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// checkGenerationKey refuses a generations row whose maskedKeccak is not canonical: a malformed manifest (manifest_corrupt), never repaired.
func checkGenerationKey(role, maskedKeccak string) error {
	if !canonicalHex32(maskedKeccak) {
		return fmt.Errorf("manifest: generations row %q has maskedKeccak %q, want 0x followed by exactly 64 lower-case hex digits", role, maskedKeccak)
	}
	return nil
}

// checkRowSpans refuses a policy.owner or policy.setRootHistory row that ends before it starts (validToBlock < validFromBlock) [r3.6:H13].
func (m *Manifest) checkRowSpans() error {
	chains := make([]uint64, 0, len(m.owners))
	for c := range m.owners {
		chains = append(chains, c)
	}
	sort.Slice(chains, func(i, j int) bool { return chains[i] < chains[j] })
	for _, c := range chains {
		for _, r := range m.owners[c] {
			if r.ValidToBlock != nil && *r.ValidToBlock < r.ValidFromBlock {
				return fmt.Errorf("manifest: policy.owner %d,%s row has validToBlock %d before validFromBlock %d", c, r.Role, *r.ValidToBlock, r.ValidFromBlock)
			}
		}
	}
	for _, r := range m.setRoots {
		if r.ValidToBlock != nil && *r.ValidToBlock < r.ValidFromBlock {
			return fmt.Errorf("manifest: policy.setRootHistory %d row has validToBlock %d before validFromBlock %d", r.ChainID, *r.ValidToBlock, r.ValidFromBlock)
		}
	}
	return nil
}

// AuthSlots are the rows of the AUTH slot set (authSlots[]), in table order.
func (m *Manifest) AuthSlots() []AuthSlot { return append([]AuthSlot(nil), m.authSlots...) }

// AuthSlot is the row with the given id (A01 ... V03, C01).
func (m *Manifest) AuthSlot(id string) (AuthSlot, bool) {
	for _, s := range m.authSlots {
		if s.ID == id {
			return s, true
		}
	}
	return AuthSlot{}, false
}

// AuthWritersFor is the writer-premise record of a build (nil when the build has none).
func (m *Manifest) AuthWritersFor(buildKey string) *AuthWritersRecord {
	if b, ok := m.builds[buildKey]; ok {
		return b.AuthWriters
	}
	return nil
}

// AuthAllowListFor is the allow-list of a build (nil when the build has none).
func (m *Manifest) AuthAllowListFor(buildKey string) *AuthWriterAllowList {
	if b, ok := m.builds[buildKey]; ok {
		return b.AuthWriterAllowList
	}
	return nil
}

// AuthWritersStatus is the status of a build's writer premise ("" when the build has none): rule IB is valid only for "pass".
func (m *Manifest) AuthWritersStatus(buildKey string) string {
	if b, ok := m.builds[buildKey]; ok && b.AuthWriters != nil {
		return b.AuthWriters.Status
	}
	return ""
}

// embeddedCreation holds the creation-code files the manifest's creationArtifacts rows name (identity-bytecode/<Contract>.creation.bin);
// the directory holds only its README until the manifest follow-up embeds the files [r3.2:E-j].
//
//go:embed all:testdata/contractidentity/manifest/identity-bytecode
var embeddedCreation embed.FS

// The two named errors of the creation-artifact accessors.
var (
	ErrCreationArtifactAbsent   = errors.New("contractidentity: creation artifact is not available")
	ErrCreationArtifactMismatch = errors.New("contractidentity: creation artifact differs from its manifest row")
)

// CreationArtifactBytes returns the creation code of a build from fsys (rooted at the manifest directory, so that row.File resolves), after
// checking its length, keccak256 and sha256 against the creationArtifacts row. A missing row or file is ErrCreationArtifactAbsent, a file that
// does not match its row ErrCreationArtifactMismatch; the bytes are never returned unchecked.
func (m *Manifest) CreationArtifactBytes(buildKey string, fsys fs.FS) ([]byte, error) {
	row, ok := m.creation[buildKey]
	if !ok {
		return nil, fmt.Errorf("%w: %s has no creationArtifacts row", ErrCreationArtifactAbsent, buildKey)
	}
	if !fs.ValidPath(row.File) {
		return nil, fmt.Errorf("%w: %s names the path %q", ErrCreationArtifactMismatch, buildKey, row.File)
	}
	b, err := fs.ReadFile(fsys, row.File)
	if err != nil {
		return nil, fmt.Errorf("%w: %s (%s)", ErrCreationArtifactAbsent, buildKey, row.File)
	}
	k := crypto.Keccak256Hash(b)
	s := sha256.Sum256(b)
	if len(b) != row.Bytes || !strings.EqualFold(k.Hex(), row.Keccak256) || !strings.EqualFold(hex.EncodeToString(s[:]), row.SHA256) {
		return nil, fmt.Errorf("%w: %s (%s)", ErrCreationArtifactMismatch, buildKey, row.File)
	}
	return b, nil
}

// EmbeddedCreationArtifactBytes is CreationArtifactBytes over the files embedded in this package.
func (m *Manifest) EmbeddedCreationArtifactBytes(buildKey string) ([]byte, error) {
	sub, err := fs.Sub(embeddedCreation, "testdata/contractidentity/manifest")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCreationArtifactAbsent, err)
	}
	return m.CreationArtifactBytes(buildKey, sub)
}

// CreationArtifact is the creationArtifacts row of a build key.
func (m *Manifest) CreationArtifact(buildKey string) (CreationArtifact, bool) {
	c, ok := m.creation[buildKey]
	return c, ok
}

// Section returns a top-level table of the merged document as the manifest states it (nil when absent), for tables without a typed accessor.
func (m *Manifest) Section(name string) json.RawMessage {
	if b, ok := m.doc[name]; ok {
		return append(json.RawMessage(nil), b...)
	}
	return nil
}

// ---- the extension (no shadowing) ----

// extensionMeta are the metadata keys an extension may carry; extensionRowTables are the tables it may add rows to.
var extensionMeta = map[string]bool{"schema": true, "description": true}
var extensionRowTables = map[string]bool{"builds": true, "deployments": true, "accounts": true, "eip2935": true, "policy": true, "chains": true, "generations": true}

// newChainRoles are the deployment roles a NEW chain must define; newChainOwnerRoles are its owner-history roles.
var newChainRoles = []string{RoleAnchor, RoleBlsZkVerifier, RoleGroth16Verifier, RoleAccountFactory, RoleOutcomeRegistry}
var newChainOwnerRoles = []string{"anchor", "verifier"}

// mergeMapRows adds the entries of add to base; an existing key is manifest_shadow{table,key}.
func mergeMapRows(base, add json.RawMessage, table string) (json.RawMessage, error) {
	var a, b map[string]json.RawMessage
	if err := json.Unmarshal(add, &a); err != nil {
		return nil, ManifestCorrupt().WithCause(err)
	}
	if len(base) > 0 {
		if err := json.Unmarshal(base, &b); err != nil {
			return nil, ManifestCorrupt().WithCause(err)
		}
	}
	if b == nil {
		b = map[string]json.RawMessage{}
	}
	for _, k := range sortedKeys(a) {
		if _, exists := b[k]; exists {
			return nil, ManifestShadow(table, k)
		}
		b[k] = a[k]
	}
	return mustMarshal(b), nil
}

// mergeArrayRows appends the rows of add to base; a row whose key (key(row)) is already present is manifest_shadow{table,key}.
func mergeArrayRows(base, add json.RawMessage, table string, key func(json.RawMessage) string) (json.RawMessage, error) {
	var a, b []json.RawMessage
	if err := json.Unmarshal(add, &a); err != nil {
		return nil, ManifestCorrupt().WithCause(err)
	}
	if len(base) > 0 {
		if err := json.Unmarshal(base, &b); err != nil {
			return nil, ManifestCorrupt().WithCause(err)
		}
	}
	seen := map[string]bool{}
	for _, r := range b {
		seen[key(r)] = true
	}
	for _, r := range a {
		k := key(r)
		if seen[k] {
			return nil, ManifestShadow(table, k)
		}
		seen[k] = true
		b = append(b, r)
	}
	return mustMarshal(b), nil
}

// WithExtension merges an extension into the manifest under the no-shadow rule (manifest item 7). An extension may add rows to builds,
// deployments, accounts, eip2935, chains, policy.txScan (rows of NEW keys), generations, policy.owner and policy.setRootHistory (new
// rows only, validFromBlock after the last row of that key) and nothing else; it may never redefine a primary key already present. A
// collision is manifest_shadow{table,key}. A NEW chain id needs all its dependent rows in the same extension (eip2935, txScan, both
// owner roles, the five deployment roles with an existing build), and a dependent row of a chain known neither to the base nor to the
// extension is refused: both are manifest_unknown{chain}. The merged manifest's Source is extension:<sha256 of the extension>.
func (m *Manifest) WithExtension(ext []byte) (*Manifest, error) {
	norm := bytes.ReplaceAll(ext, []byte("\r\n"), []byte("\n"))
	if p, k, dup, err := findDuplicateKey(norm); err != nil {
		return nil, ManifestCorrupt().WithCause(err)
	} else if dup {
		return nil, ManifestShadow("extension"+p, k)
	}
	var edoc map[string]json.RawMessage
	if err := json.Unmarshal(norm, &edoc); err != nil {
		return nil, ManifestCorrupt().WithCause(err)
	}
	for _, name := range sortedKeys(edoc) {
		if extensionMeta[name] || extensionRowTables[name] {
			continue
		}
		// any other table is not extendable; the key names the first entry that the extension tries to define
		key := "*"
		var obj map[string]json.RawMessage
		if json.Unmarshal(edoc[name], &obj) == nil && len(obj) > 0 {
			key = sortedKeys(obj)[0]
		}
		return nil, ManifestShadow(name, key)
	}
	if s, ok := edoc["schema"]; ok {
		var schema string
		if json.Unmarshal(s, &schema) != nil || schema != ManifestSchema {
			return nil, ManifestCorrupt()
		}
	}
	merged := map[string]json.RawMessage{}
	for k, v := range m.doc {
		merged[k] = v
	}
	var err error
	if raw, ok := edoc["builds"]; ok {
		if merged["builds"], err = mergeMapRows(merged["builds"], raw, "builds"); err != nil {
			return nil, err
		}
	}
	if raw, ok := edoc["eip2935"]; ok {
		if merged["eip2935"], err = mergeMapRows(merged["eip2935"], raw, "eip2935"); err != nil {
			return nil, err
		}
	}
	if raw, ok := edoc["deployments"]; ok {
		if merged["deployments"], err = mergeArrayRows(merged["deployments"], raw, "deployments", func(r json.RawMessage) string { return rowKey(r, "chainId", "role") }); err != nil {
			return nil, err
		}
	}
	if raw, ok := edoc["accounts"]; ok {
		if merged["accounts"], err = mergeArrayRows(merged["accounts"], raw, "accounts", func(r json.RawMessage) string { return strings.ToLower(rowKey(r, "chainId", "address")) }); err != nil {
			return nil, err
		}
	}
	if raw, ok := edoc["chains"]; ok {
		if merged["chains"], err = mergeArrayRows(merged["chains"], raw, "chains", func(r json.RawMessage) string { return strings.TrimSuffix(rowKey(r, "chainId", "_"), ",") }); err != nil {
			return nil, err
		}
	}
	if raw, ok := edoc["generations"]; ok {
		var added []Generation
		if err := json.Unmarshal(raw, &added); err != nil {
			return nil, ManifestCorrupt().WithCause(err)
		}
		for _, g := range added {
			if err := checkGenerationKey(g.Role, g.MaskedKeccak); err != nil {
				return nil, ManifestCorrupt().WithCause(err)
			}
		}
		if merged["generations"], err = mergeArrayRows(merged["generations"], raw, "generations", func(r json.RawMessage) string {
			var g struct {
				Role         string `json:"role"`
				MaskedKeccak string `json:"maskedKeccak"`
			}
			_ = json.Unmarshal(r, &g)
			return generationKey(g.Role, g.MaskedKeccak)
		}); err != nil {
			return nil, err
		}
	}
	// policy: only owner, setRootHistory and the txScan rows of new chains may be added
	if raw, ok := edoc["policy"]; ok {
		var add, base map[string]json.RawMessage
		if err := json.Unmarshal(raw, &add); err != nil {
			return nil, ManifestCorrupt().WithCause(err)
		}
		_ = json.Unmarshal(merged["policy"], &base)
		for _, k := range sortedKeys(add) {
			switch k {
			case "owner", "setRootHistory", "txScan", "description":
			case "rules":
				var rules []Rule
				_ = json.Unmarshal(add[k], &rules)
				if len(rules) > 0 {
					return nil, ManifestShadow("policy.rules", rules[0].ID)
				}
				return nil, ManifestShadow("policy.rules", "*")
			default:
				return nil, ManifestShadow("policy", k)
			}
		}
		if rawTx, ok := add["txScan"]; ok {
			if base["txScan"], err = mergeMapRows(base["txScan"], rawTx, "policy.txScan"); err != nil {
				return nil, err
			}
		}
		if rawOwner, ok := add["owner"]; ok {
			var addO, baseO map[string][]json.RawMessage
			if err := json.Unmarshal(rawOwner, &addO); err != nil {
				return nil, ManifestCorrupt().WithCause(err)
			}
			_ = json.Unmarshal(base["owner"], &baseO)
			if baseO == nil {
				baseO = map[string][]json.RawMessage{}
			}
			chainKeys := make([]string, 0, len(addO))
			for k := range addO {
				chainKeys = append(chainKeys, k)
			}
			sort.Strings(chainKeys)
			for _, chainKey := range chainKeys {
				for _, rawRow := range addO[chainKey] {
					var row OwnerRow
					if err := json.Unmarshal(rawRow, &row); err != nil {
						return nil, ManifestCorrupt().WithCause(err)
					}
					last, have := uint64(0), false
					for _, e := range baseO[chainKey] {
						var er OwnerRow
						if json.Unmarshal(e, &er) == nil && er.Role == row.Role && (!have || er.ValidFromBlock > last) {
							last, have = er.ValidFromBlock, true
						}
					}
					if have && row.ValidFromBlock <= last {
						return nil, ManifestShadow("policy.owner", chainKey+","+row.Role)
					}
					baseO[chainKey] = append(baseO[chainKey], rawRow)
				}
			}
			base["owner"] = mustMarshal(baseO)
		}
		if rawSR, ok := add["setRootHistory"]; ok {
			var addS, baseS []json.RawMessage
			if err := json.Unmarshal(rawSR, &addS); err != nil {
				return nil, ManifestCorrupt().WithCause(err)
			}
			_ = json.Unmarshal(base["setRootHistory"], &baseS)
			for _, rawRow := range addS {
				var row SetRootRow
				if err := json.Unmarshal(rawRow, &row); err != nil {
					return nil, ManifestCorrupt().WithCause(err)
				}
				last, have := uint64(0), false
				for _, e := range baseS {
					var er SetRootRow
					if json.Unmarshal(e, &er) == nil && er.ChainID == row.ChainID && (!have || er.ValidFromBlock > last) {
						last, have = er.ValidFromBlock, true
					}
				}
				if have && row.ValidFromBlock <= last {
					return nil, ManifestShadow("policy.setRootHistory", strconv.FormatUint(row.ChainID, 10))
				}
				baseS = append(baseS, rawRow)
			}
			base["setRootHistory"] = mustMarshal(baseS)
		}
		merged["policy"] = mustMarshal(base)
	}
	out := &Manifest{doc: merged, SHA256: m.SHA256}
	if err := out.decode(); err != nil {
		return nil, ManifestCorrupt().WithCause(err)
	}
	if err := out.checkChains(m); err != nil {
		return nil, err
	}
	out.ExtensionSHA256 = manifestHash(ext)
	out.Source = "extension:" + hex.EncodeToString(out.ExtensionSHA256[:])
	return out, nil
}

// checkChains enforces the chain rules of an extension: every dependent row belongs to a chain of the merged chains[], and every chain that
// the extension added has all its dependent rows. Both are manifest_unknown{chain}.
func (m *Manifest) checkChains(base *Manifest) error {
	known := map[uint64]bool{}
	for _, c := range m.chains {
		known[c.ChainID] = true
	}
	var foreign []uint64
	note := func(chain uint64) {
		if !known[chain] {
			foreign = append(foreign, chain)
		}
	}
	for _, d := range m.deploys {
		note(d.ChainID)
	}
	for _, a := range m.accounts {
		note(a.ChainID)
	}
	for c := range m.eip2935 {
		note(c)
	}
	for c := range m.txScan {
		note(c)
	}
	for c := range m.owners {
		note(c)
	}
	for _, r := range m.setRoots {
		note(r.ChainID)
	}
	if len(foreign) > 0 {
		sort.Slice(foreign, func(i, j int) bool { return foreign[i] < foreign[j] })
		return ManifestUnknown(foreign[0])
	}
	baseKnown := map[uint64]bool{}
	for _, c := range base.chains {
		baseKnown[c.ChainID] = true
	}
	var added []uint64
	for _, c := range m.chains {
		if !baseKnown[c.ChainID] {
			added = append(added, c.ChainID)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i] < added[j] })
	for _, c := range added {
		complete := true
		if _, ok := m.eip2935[c]; !ok {
			complete = false
		}
		if _, ok := m.txScan[c]; !ok {
			complete = false
		}
		for _, role := range newChainOwnerRoles {
			if len(m.OwnerRows(c, role)) == 0 {
				complete = false
			}
		}
		for _, role := range newChainRoles {
			d, ok := m.Deployment(c, role)
			if !ok {
				complete = false
				continue
			}
			if _, ok := m.builds[d.Build]; !ok {
				complete = false
			}
		}
		if !complete {
			return ManifestUnknown(c)
		}
	}
	return nil
}

func rowKey(raw json.RawMessage, a, b string) string {
	var r map[string]any
	_ = json.Unmarshal(raw, &r)
	f := func(k string) string {
		switch v := r[k].(type) {
		case float64:
			return strconv.FormatUint(uint64(v), 10)
		case string:
			return v
		}
		return ""
	}
	return f(a) + "," + f(b)
}

func sortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // marshalling values just decoded from JSON cannot fail
	}
	return b
}
