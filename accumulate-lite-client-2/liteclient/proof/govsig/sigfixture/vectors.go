// Copyright 2026 Certen Protocol

package sigfixture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The shared conformance vectors for every key-signature type (testdata/sigtypes).
//
// Go writes them; the TypeScript verifier (certen-sdk packages/verify) consumes byte-identical copies and must reach the
// same verdict on every one. A vector carries the signature in BOTH forms a consumer may hold - Accumulate's binary
// encoding (what the vote evidence stores) and the v3 JSON the network serves - and the full transaction when the type
// needs it (typedData). Nothing in a vector is a verdict the consumer is told to trust: "expect" is what Accumulate's own
// Verify produced when the vector was written, asserted again by every test that reads it.

// VectorFormat names this vector file format.
const VectorFormat = "certen:sigtypes-vectors:v1"

// Source of a vector.
const (
	SourceLocal  = "locally-generated"
	SourceKermit = "kermit-delivered"
)

// Where is where a signature was recorded.
type Where struct {
	Partition string `json:"partition"`
	Block     int64  `json:"block"`
}

// Page is the signer page's key-hash entries as of the block the signature was recorded in.
type Page struct {
	Entries []string `json:"entries"`
}

// Expect is the verdict a consumer must reach.
type Expect struct {
	Verdict    string   `json:"verdict"`
	KeyHash    string   `json:"keyHash,omitempty"`
	Form       string   `json:"form,omitempty"`
	EthRule    string   `json:"ethRule,omitempty"`
	InnerType  string   `json:"innerType,omitempty"`
	Delegators []string `json:"delegators,omitempty"`
	Vote       string   `json:"vote,omitempty"`
}

// Vector is one conformance case.
type Vector struct {
	ID            string          `json:"id"`
	Source        string          `json:"source"`
	Kind          string          `json:"kind"` // valid | adversarial
	Type          string          `json:"type"` // the innermost key type, or the type presented
	Description   string          `json:"description"`
	Transaction   string          `json:"transaction,omitempty"` // hex of Transaction.MarshalBinary
	TxHash        string          `json:"txHash"`
	Signature     string          `json:"signature"` // hex of the outermost signature's binary encoding
	SignatureJSON json.RawMessage `json:"signatureJson"`
	NetworkName   string          `json:"networkName,omitempty"`
	Where         *Where          `json:"where,omitempty"`
	Page          *Page           `json:"page,omitempty"`
	Expect        Expect          `json:"expect"`
}

// VectorFile is one file of vectors.
type VectorFile struct {
	Format      string   `json:"format"`
	Description string   `json:"description"`
	Pinned      Pinned   `json:"pinned"`
	Vectors     []Vector `json:"vectors"`
}

// Pinned is what the vectors were written against.
type Pinned struct {
	Accumulate string `json:"accumulate"`
	Commit     string `json:"commit"`
	Network    string `json:"network"`
	ChainID    string `json:"chainId"`
}

// Judge is the Go verdict on a vector: Accumulate's own Verify through govsig, then page membership.
func Judge(v Vector) (string, *govsig.Verified, error) {
	raw, err := hex.DecodeString(v.Signature)
	if err != nil {
		return "refused:undecodable", nil, err
	}
	sig, err := protocol.UnmarshalSignature(raw)
	if err != nil {
		return "refused:undecodable", nil, err
	}
	var h [32]byte
	hb, err := hex.DecodeString(v.TxHash)
	if err != nil || len(hb) != 32 {
		return "refused:undecodable", nil, fmt.Errorf("txHash is not 32 bytes of hex")
	}
	copy(h[:], hb)
	env := govsig.Env{TxHash: h, NetworkName: v.NetworkName}
	if v.Transaction != "" {
		tb, err := hex.DecodeString(v.Transaction)
		if err != nil {
			return "refused:undecodable", nil, err
		}
		txn := new(protocol.Transaction)
		if err := txn.UnmarshalBinary(tb); err != nil {
			return "refused:undecodable", nil, err
		}
		env.Transaction = txn
	}
	if v.Where != nil {
		env.Where = govsig.Where{Partition: v.Where.Partition, Block: v.Where.Block}
	}
	verified, err := govsig.Verify(sig, env)
	verdict := govsig.Verdict(err)
	if verdict == "accepted" && v.Page != nil {
		member := false
		for _, e := range v.Page.Entries {
			if strings.EqualFold(e, hex.EncodeToString(verified.KeyHash)) {
				member = true
			}
		}
		if !member {
			return "refused:key_not_on_page", verified, nil
		}
	}
	return verdict, verified, err
}

// Check requires Judge to reach exactly what the vector expects, and the JSON form to encode the binary form.
func Check(v Vector) error {
	verdict, verified, err := Judge(v)
	if verdict != v.Expect.Verdict {
		return fmt.Errorf("%s: verdict %q (%v), the vector expects %q", v.ID, verdict, err, v.Expect.Verdict)
	}
	if verdict == "accepted" {
		if got := hex.EncodeToString(verified.KeyHash); !strings.EqualFold(got, v.Expect.KeyHash) {
			return fmt.Errorf("%s: key hash %s, expected %s", v.ID, got, v.Expect.KeyHash)
		}
		if verified.Form != v.Expect.Form {
			return fmt.Errorf("%s: digest form %q, expected %q", v.ID, verified.Form, v.Expect.Form)
		}
		if verified.EthRule != v.Expect.EthRule {
			return fmt.Errorf("%s: eth rule %q, expected %q", v.ID, verified.EthRule, v.Expect.EthRule)
		}
		if verified.Inner.Type().String() != v.Type && v.Expect.InnerType == "" {
			return fmt.Errorf("%s: inner type %v, the vector says %s", v.ID, verified.Inner.Type(), v.Type)
		}
		if len(verified.Delegators) != len(v.Expect.Delegators) {
			return fmt.Errorf("%s: %d delegators, expected %d", v.ID, len(verified.Delegators), len(v.Expect.Delegators))
		}
		for i, d := range verified.Delegators {
			if d.String() != v.Expect.Delegators[i] {
				return fmt.Errorf("%s: delegator %d is %s, expected %s", v.ID, i, d, v.Expect.Delegators[i])
			}
		}
	}
	// the JSON form must decode to the same binary encoding
	if len(v.SignatureJSON) > 0 && string(v.SignatureJSON) != "null" {
		fromJSON, err := protocol.UnmarshalSignatureJSON(v.SignatureJSON)
		if err != nil {
			return fmt.Errorf("%s: signatureJson does not decode: %w", v.ID, err)
		}
		bin, err := fromJSON.MarshalBinary()
		if err != nil {
			return fmt.Errorf("%s: signatureJson does not encode: %w", v.ID, err)
		}
		if got := hex.EncodeToString(bin); got != strings.ToLower(v.Signature) {
			return fmt.Errorf("%s: signatureJson encodes to %s, not to the vector's binary %s", v.ID, got, v.Signature)
		}
	}
	return nil
}

// Manifest pins the vector files by hash.
type Manifest struct {
	Format  string         `json:"format"`
	Files   []ManifestFile `json:"files"`
	Hash    string         `json:"manifestHash"` // sha256 over "<name>:<sha256>\n" for every file in order
	Sources map[string]int `json:"sources"`      // vector counts per source
	Count   int            `json:"vectors"`
	Note    string         `json:"note"`
}

// ManifestFile is one pinned file.
type ManifestFile struct {
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Vectors int    `json:"vectors"`
}

// ManifestHash is the manifest's own hash over its files.
func ManifestHash(files []ManifestFile) string {
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%s:%s\n", f.Name, f.SHA256)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// LoadVectors reads every vector file the manifest in dir names, requiring each file to match its pinned hash and the
// manifest to match its own.
func LoadVectors(dir string) ([]Vector, *Manifest, error) {
	mb, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, nil, err
	}
	var m Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		return nil, nil, err
	}
	if m.Hash != ManifestHash(m.Files) {
		return nil, nil, fmt.Errorf("the manifest's hash %s is not the hash of its files %s", m.Hash, ManifestHash(m.Files))
	}
	var all []Vector
	names := map[string]bool{}
	for _, f := range m.Files {
		b, err := os.ReadFile(filepath.Join(dir, f.Name))
		if err != nil {
			return nil, nil, err
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			return nil, nil, fmt.Errorf("%s: sha256 %x is not the pinned %s", f.Name, sum, f.SHA256)
		}
		var vf VectorFile
		if err := json.Unmarshal(b, &vf); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		if vf.Format != VectorFormat || len(vf.Vectors) != f.Vectors {
			return nil, nil, fmt.Errorf("%s: format %q with %d vectors, the manifest pins %d", f.Name, vf.Format, len(vf.Vectors), f.Vectors)
		}
		for _, v := range vf.Vectors {
			if names[v.ID] {
				return nil, nil, fmt.Errorf("vector id %s is listed twice", v.ID)
			}
			names[v.ID] = true
		}
		all = append(all, vf.Vectors...)
	}
	return all, &m, nil
}
