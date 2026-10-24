// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// The MATERIALISED form of a vector (FORMAT.md, "Materialised vectors") [r3.2:E-i]: everything a runner needs to judge the vector, resolved
// and written down, so that a runner (Go or TypeScript) needs no world builder:
//
//	<id>.inputs.json     the resolved Inputs (this file's InputsFile)
//	<id>.expected.json   the Expected of the vector (the same document as `expected` in <id>.json)
//	<id>.inputs.container.hex   the container bytes the Verifier receives (its own name: a vector-level <id>.container.hex is a different file)
//	manifest.<sha256>.json, extension.<sha256>.json   the raw manifest / extension documents, named by the sha256 of their bytes
//
// Every file is listed in the set's MANIFEST. The encoding of a LegContext is canonical-style JSON: bytes as 0x hex, integers as decimal
// strings; the settlement is the ethproof JSON form of the proof file.

// InputsFormat is the format string of an inputs file.
const InputsFormat = "certen-contract-identity-inputs/1"

// FileRef names a file of the set and the sha256 of its bytes.
type FileRef struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// ManifestRef is a FileRef plus the pin the manifest bytes are checked against (0x hex; the embedded ManifestSHA256 for an unmodified
// manifest, the hash of the bytes for a modified but valid one, anything else for a vector about a corrupt manifest).
type ManifestRef struct {
	FileRef
	Pin string `json:"pin"`
}

// InputsFile is `<id>.inputs.json`.
type InputsFile struct {
	Format    string       `json:"format"`
	ID        string       `json:"id"`
	Container *FileRef     `json:"container"`
	Manifest  *ManifestRef `json:"manifest"`
	Extension *FileRef     `json:"extension"`
	Context   ContextFile  `json:"context"`
}

// ContextFile is the JSON form of a LegContext.
type ContextFile struct {
	Chain      string          `json:"chain"`
	Settlement json.RawMessage `json:"settlement"`
	Tx         *string         `json:"tx"`
	Receipt    *ReceiptFile    `json:"receipt"`
	ADIURL     string          `json:"adi_url"`
	S6Status   string          `json:"s6_status"`
	S6Reason   string          `json:"s6_reason"`
	S6State    string          `json:"s6_state"`
	S6         *S6File         `json:"s6"`
	Batch      BatchFile       `json:"batch"`
	Registry9  *Registry9File  `json:"registry9"`
	S7         *S7File         `json:"s7"`
}

// ReceiptFile is the JSON form of an ethproof.ReceiptLeaf.
type ReceiptFile struct {
	Type              string    `json:"type"`
	PostStateOrStatus string    `json:"post_state_or_status"`
	CumulativeGasUsed string    `json:"cumulative_gas_used"`
	Bloom             string    `json:"bloom"`
	Logs              []LogFile `json:"logs"`
}

// LogFile is one receipt log.
type LogFile struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
}

// BlockRefFile is a block named by decimal number and hash.
type BlockRefFile struct {
	Number string `json:"number"`
	Hash   string `json:"hash"`
}

// S6File is the JSON form of an S6Link.
type S6File struct {
	Contract        string       `json:"contract"`
	LeafKey         string       `json:"leaf_key"`
	SettlementBlock BlockRefFile `json:"settlement_block"`
	ProvenAt        BlockRefFile `json:"proven_at"`
	CodeHash        string       `json:"code_hash"`
}

// BatchFile is the JSON form of BatchFacts.
type BatchFile struct {
	BatchRoot   string `json:"batch_root"`
	OperationID string `json:"batch_operation_id"`
	AccSetRoot  string `json:"acc_set_root"`
	Incarnation string `json:"incarnation"`
}

// Registry9File is the JSON form of a Registry9.
type Registry9File struct {
	Members          []RegistryMemberFile `json:"members"`
	Num              string               `json:"num"`
	Den              string               `json:"den"`
	CertenSetRoot    string               `json:"certen_set_root"`
	SignerCommitment string               `json:"signer_commitment"`
}

// RegistryMemberFile is one member of a Registry9File.
type RegistryMemberFile struct {
	Address string `json:"address"`
	Power   string `json:"power"`
	BLSKey  string `json:"bls_key"`
}

// S7File is the JSON form of the members of the S7 report that S8 reads (step 24): the level statuses and the code of the state of a level
// that is not verified, the headline level, the leg's finalized block and the unsupported-chain state. The other members of an S7 state
// (its fields) are not carried; S8 reads none of them.
type S7File struct {
	Block          BlockFile          `json:"block"`
	Headline       string             `json:"headline"`
	Levels         map[string]S7Level `json:"levels"`
	Unsupported    string             `json:"unsupported"`
	FinalizedBlock *S7FinalizedBlock  `json:"finalized_block"`
}

// BlockFile is a block with its chain.
type BlockFile struct {
	Chain  string `json:"chain"`
	Number string `json:"number"`
	Hash   string `json:"hash"`
}

// S7Level is one level's status and, when it is not verified, the code of its state.
type S7Level struct {
	Status string `json:"status"`
	Code   string `json:"code"`
}

// S7FinalizedBlock is the leg block as S7 finalized it.
type S7FinalizedBlock struct {
	Number    string `json:"number"`
	Hash      string `json:"hash"`
	StateRoot string `json:"state_root"`
}

func hx(b []byte) string  { return "0x" + hex.EncodeToString(b) }
func dec(n uint64) string { return strconv.FormatUint(n, 10) }

var hexRe = regexp.MustCompile(`^0x([0-9a-f]*)$`)

func unhex(s string) ([]byte, error) {
	m := hexRe.FindStringSubmatch(s)
	if m == nil {
		return nil, fmt.Errorf("%q is not 0x-prefixed lowercase hex", s)
	}
	return hex.DecodeString(m[1])
}

func unhex32(s string) (out [32]byte, err error) {
	b, err := unhex(s)
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("%q is not 32 bytes of hex", s)
	}
	copy(out[:], b)
	return out, nil
}

func undec(s string) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("%q is not a canonical decimal string", s)
	}
	return strconv.ParseUint(s, 10, 64)
}

func blockRefFile(b BlockRef) BlockRefFile {
	return BlockRefFile{Number: dec(b.Number), Hash: hx(b.Hash[:])}
}
func (b BlockRefFile) ref() (BlockRef, error) {
	n, err := undec(b.Number)
	if err != nil {
		return BlockRef{}, err
	}
	h, err := unhex32(b.Hash)
	return BlockRef{Number: n, Hash: h}, err
}

var s7LevelNames = []finality.Level{finality.LevelIncluded, finality.LevelL1Posted, finality.LevelFinalized}

// ContextToFile renders a LegContext in its file form.
func ContextToFile(c LegContext) (ContextFile, error) {
	out := ContextFile{Chain: dec(c.Chain), ADIURL: c.ADIURL, S6Status: string(c.S6Status), S6Reason: c.S6Reason, S6State: c.S6State}
	if c.Settlement != nil {
		b, err := json.Marshal(c.Settlement)
		if err != nil {
			return out, err
		}
		out.Settlement = b
	} else {
		out.Settlement = json.RawMessage("null")
	}
	if c.Tx != nil {
		b, err := c.Tx.MarshalBinary()
		if err != nil {
			return out, err
		}
		s := hx(b)
		out.Tx = &s
	}
	if r := c.Receipt; r != nil {
		rf := &ReceiptFile{Type: dec(uint64(r.Type)), PostStateOrStatus: hx(r.PostStateOrStatus), CumulativeGasUsed: dec(r.CumulativeGasUsed), Bloom: hx(r.Bloom[:]), Logs: []LogFile{}}
		for _, l := range r.Logs {
			lf := LogFile{Address: hx(l.Address[:]), Topics: []string{}, Data: hx(l.Data)}
			for _, t := range l.Topics {
				lf.Topics = append(lf.Topics, hx(t[:]))
			}
			rf.Logs = append(rf.Logs, lf)
		}
		out.Receipt = rf
	}
	if l := c.S6; l != nil {
		out.S6 = &S6File{Contract: hx(l.Contract[:]), LeafKey: hx(l.LeafKey[:]), SettlementBlock: blockRefFile(l.SettlementBlock), ProvenAt: blockRefFile(l.ProvenAt), CodeHash: hx(l.CodeHash[:])}
	}
	out.Batch = BatchFile{hx(c.Batch.BatchRoot[:]), hx(c.Batch.OperationID[:]), hx(c.Batch.AccSetRoot[:]), hx(c.Batch.Incarnation[:])}
	if r := c.Registry9; r != nil {
		rf := &Registry9File{Members: []RegistryMemberFile{}, Num: dec(r.Num), Den: dec(r.Den), CertenSetRoot: hx(r.CertenSetRoot[:]), SignerCommitment: hx(r.SignerCommitment[:])}
		for _, m := range r.Members {
			rf.Members = append(rf.Members, RegistryMemberFile{Address: hx(m.Address[:]), Power: dec(m.Power), BLSKey: m.BLSKey})
		}
		out.Registry9 = rf
	}
	if s := c.S7; s != nil {
		sf := &S7File{Block: BlockFile{Chain: dec(s.Block.Chain), Number: dec(s.Block.Number), Hash: hx(s.Block.Hash[:])}, Headline: s.Headline.String(), Levels: map[string]S7Level{}}
		for _, l := range s7LevelNames {
			if ls, ok := s.Levels[l]; ok {
				lv := S7Level{Status: string(ls.Status)}
				if ls.State != nil {
					lv.Code = ls.State.Code
				}
				sf.Levels[l.String()] = lv
			}
		}
		if s.Unsupported != nil {
			sf.Unsupported = s.Unsupported.Code
		}
		if fb := s.FinalizedBlock; fb != nil {
			sf.FinalizedBlock = &S7FinalizedBlock{Number: dec(fb.Number), Hash: hx(fb.Hash[:]), StateRoot: hx(fb.StateRoot[:])}
		}
		out.S7 = sf
	}
	return out, nil
}

// ContextFromFile is the inverse of ContextToFile.
func ContextFromFile(f ContextFile) (LegContext, error) {
	var c LegContext
	var err error
	if c.Chain, err = undec(f.Chain); err != nil {
		return c, fmt.Errorf("context.chain: %w", err)
	}
	if len(f.Settlement) > 0 && string(f.Settlement) != "null" {
		var s ethproof.Settlement
		if err := json.Unmarshal(f.Settlement, &s); err != nil {
			return c, fmt.Errorf("context.settlement: %w", err)
		}
		c.Settlement = &s
	}
	if f.Tx != nil {
		b, err := unhex(*f.Tx)
		if err != nil {
			return c, fmt.Errorf("context.tx: %w", err)
		}
		var tx types.Transaction
		if err := tx.UnmarshalBinary(b); err != nil {
			return c, fmt.Errorf("context.tx: %w", err)
		}
		c.Tx = &tx
	}
	if r := f.Receipt; r != nil {
		t, err := undec(r.Type)
		if err != nil {
			return c, fmt.Errorf("context.receipt.type: %w", err)
		}
		leaf := &ethproof.ReceiptLeaf{Type: uint8(t)}
		if leaf.PostStateOrStatus, err = unhex(r.PostStateOrStatus); err != nil {
			return c, err
		}
		if leaf.CumulativeGasUsed, err = undec(r.CumulativeGasUsed); err != nil {
			return c, err
		}
		bl, err := unhex(r.Bloom)
		if err != nil || len(bl) != len(leaf.Bloom) {
			return c, fmt.Errorf("context.receipt.bloom: %v", err)
		}
		copy(leaf.Bloom[:], bl)
		for _, l := range r.Logs {
			lg := &types.Log{}
			a, err := unhex(l.Address)
			if err != nil || len(a) != 20 {
				return c, fmt.Errorf("context.receipt.logs.address: %v", err)
			}
			copy(lg.Address[:], a)
			for _, t := range l.Topics {
				h, err := unhex32(t)
				if err != nil {
					return c, err
				}
				lg.Topics = append(lg.Topics, common.Hash(h))
			}
			if lg.Data, err = unhex(l.Data); err != nil {
				return c, err
			}
			leaf.Logs = append(leaf.Logs, lg)
		}
		c.Receipt = leaf
	}
	c.ADIURL, c.S6Status, c.S6Reason, c.S6State = f.ADIURL, S6Status(f.S6Status), f.S6Reason, f.S6State
	if s := f.S6; s != nil {
		l := &S6Link{}
		a, err := unhex(s.Contract)
		if err != nil || len(a) != 20 {
			return c, fmt.Errorf("context.s6.contract: %v", err)
		}
		copy(l.Contract[:], a)
		if l.LeafKey, err = unhex32(s.LeafKey); err != nil {
			return c, err
		}
		if l.SettlementBlock, err = s.SettlementBlock.ref(); err != nil {
			return c, err
		}
		if l.ProvenAt, err = s.ProvenAt.ref(); err != nil {
			return c, err
		}
		if l.CodeHash, err = unhex32(s.CodeHash); err != nil {
			return c, err
		}
		c.S6 = l
	}
	for _, p := range []struct {
		s string
		d *[32]byte
	}{{f.Batch.BatchRoot, &c.Batch.BatchRoot}, {f.Batch.OperationID, &c.Batch.OperationID}, {f.Batch.AccSetRoot, &c.Batch.AccSetRoot}, {f.Batch.Incarnation, &c.Batch.Incarnation}} {
		if *p.d, err = unhex32(p.s); err != nil {
			return c, fmt.Errorf("context.batch: %w", err)
		}
	}
	if r := f.Registry9; r != nil {
		reg := &Registry9{}
		if reg.Num, err = undec(r.Num); err != nil {
			return c, err
		}
		if reg.Den, err = undec(r.Den); err != nil {
			return c, err
		}
		if reg.CertenSetRoot, err = unhex32(r.CertenSetRoot); err != nil {
			return c, err
		}
		if reg.SignerCommitment, err = unhex32(r.SignerCommitment); err != nil {
			return c, err
		}
		for _, m := range r.Members {
			a, err := unhex(m.Address)
			if err != nil || len(a) != 20 {
				return c, fmt.Errorf("context.registry9.address: %v", err)
			}
			rm := RegistryMember{BLSKey: m.BLSKey}
			copy(rm.Address[:], a)
			if rm.Power, err = undec(m.Power); err != nil {
				return c, err
			}
			reg.Members = append(reg.Members, rm)
		}
		c.Registry9 = reg
	}
	if s := f.S7; s != nil {
		rep := &finality.Report{Levels: map[finality.Level]finality.LevelStatus{}}
		if rep.Block.Chain, err = undec(s.Block.Chain); err != nil {
			return c, err
		}
		if rep.Block.Number, err = undec(s.Block.Number); err != nil {
			return c, err
		}
		if rep.Block.Hash, err = unhex32(s.Block.Hash); err != nil {
			return c, err
		}
		if s.Headline != "none" && s.Headline != "" {
			if rep.Headline, err = finality.ParseLevel(s.Headline); err != nil {
				return c, err
			}
		}
		for name, lv := range s.Levels {
			l, err := finality.ParseLevel(name)
			if err != nil {
				return c, err
			}
			ls := finality.LevelStatus{Status: finality.Status(lv.Status)}
			if lv.Code != "" {
				ls.State = finality.NewState(lv.Code)
			}
			rep.Levels[l] = ls
		}
		if s.Unsupported != "" {
			rep.Unsupported = finality.NewState(s.Unsupported)
		}
		if fb := s.FinalizedBlock; fb != nil {
			rep.FinalizedBlock = &finality.FinalizedBlock{}
			if rep.FinalizedBlock.Number, err = undec(fb.Number); err != nil {
				return c, err
			}
			if rep.FinalizedBlock.Hash, err = unhex32(fb.Hash); err != nil {
				return c, err
			}
			if rep.FinalizedBlock.StateRoot, err = unhex32(fb.StateRoot); err != nil {
				return c, err
			}
		}
		c.S7 = rep
	}
	return c, nil
}

// MaterialisedFiles are the files of one materialised vector, by file name, ready for a set directory.
type MaterialisedFiles map[string][]byte

func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// Materialise renders the resolved inputs and the expectation of one vector as the files of a materialised set. The manifest and extension
// raw documents are content-addressed (manifest.<sha256>.json), so identical documents are written once per set; the caller merges the
// maps of all vectors. pin is the hash the manifest bytes are loaded against (nil: the embedded pin).
func Materialise(id string, in Inputs, expected Expected) (MaterialisedFiles, error) {
	if in.ManifestRaw == nil {
		return nil, fmt.Errorf("vector %s: a materialised vector needs the raw manifest document (Inputs.ManifestRaw)", id)
	}
	files := MaterialisedFiles{}
	ctx, err := ContextToFile(in.Ctx)
	if err != nil {
		return nil, err
	}
	f := InputsFile{Format: InputsFormat, ID: id, Context: ctx}
	if in.Container != nil {
		name := id + ".inputs.container.hex"
		files[name] = []byte(hex.EncodeToString(in.Container) + "\n")
		f.Container = &FileRef{File: name, SHA256: sha256Hex(files[name])}
	}
	pin := embeddedPin()
	if in.ManifestPin != nil {
		pin = *in.ManifestPin
	}
	mname := "manifest." + sha256Hex(in.ManifestRaw) + ".json"
	files[mname] = in.ManifestRaw
	f.Manifest = &ManifestRef{FileRef: FileRef{File: mname, SHA256: sha256Hex(in.ManifestRaw)}, Pin: hx(pin[:])}
	if in.ExtensionRaw != nil {
		ename := "extension." + sha256Hex(in.ExtensionRaw) + ".json"
		files[ename] = in.ExtensionRaw
		f.Extension = &FileRef{File: ename, SHA256: sha256Hex(in.ExtensionRaw)}
	}
	ib, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return nil, err
	}
	files[id+".inputs.json"] = append(ib, '\n')
	eb, err := json.MarshalIndent(expected, "", " ")
	if err != nil {
		return nil, err
	}
	files[id+".expected.json"] = append(eb, '\n')
	return files, nil
}

func embeddedPin() [32]byte {
	var pin [32]byte
	b, _ := hex.DecodeString(ManifestSHA256)
	copy(pin[:], b)
	return pin
}

// LoadMaterialised reads one vector's inputs file against the other files of its set (name -> bytes), checking every referenced file's sha256.
func LoadMaterialised(inputsJSON []byte, files map[string][]byte) (Inputs, error) {
	var in Inputs
	d := json.NewDecoder(bytes.NewReader(inputsJSON))
	d.DisallowUnknownFields()
	var f InputsFile
	if err := d.Decode(&f); err != nil {
		return in, fmt.Errorf("inputs file: %w", err)
	}
	if f.Format != InputsFormat {
		return in, fmt.Errorf("inputs file %s: format %q", f.ID, f.Format)
	}
	ref := func(r *FileRef) ([]byte, error) {
		b, ok := files[r.File]
		if !ok {
			return nil, fmt.Errorf("inputs file %s: referenced file %s is not in the set", f.ID, r.File)
		}
		if sha256Hex(b) != r.SHA256 {
			return nil, fmt.Errorf("inputs file %s: file %s does not hash to %s", f.ID, r.File, r.SHA256)
		}
		return b, nil
	}
	var err error
	if f.Container != nil {
		b, err := ref(f.Container)
		if err != nil {
			return in, err
		}
		if in.Container, err = hex.DecodeString(strings.TrimSpace(string(b))); err != nil {
			return in, fmt.Errorf("inputs file %s: container: %w", f.ID, err)
		}
	}
	if f.Manifest == nil {
		return in, fmt.Errorf("inputs file %s: no manifest reference", f.ID)
	}
	if in.ManifestRaw, err = ref(&f.Manifest.FileRef); err != nil {
		return in, err
	}
	pin, err := unhex32(f.Manifest.Pin)
	if err != nil {
		return in, fmt.Errorf("inputs file %s: manifest pin: %w", f.ID, err)
	}
	in.ManifestPin = &pin
	if f.Extension != nil {
		if in.ExtensionRaw, err = ref(f.Extension); err != nil {
			return in, err
		}
	}
	if in.Ctx, err = ContextFromFile(f.Context); err != nil {
		return in, fmt.Errorf("inputs file %s: %w", f.ID, err)
	}
	return in, nil
}
