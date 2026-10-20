package main

// vectors: turn captures/ into the shared conformance vectors kermit2.json + manifest2.json.
//
// A vector here is a signature Kermit DELIVERED for a CERTEN intent, exactly as the network served it (JSON) with the
// binary encoding Accumulate's own marshaller makes of it. "expect" is what Accumulate's own Verify produced through
// govsig.Judge when the vector was written; it is asserted again by every test that reads the file, in Go and in TS. The
// file is written once: evidence is never regenerated in place, and manifest.json (hash 032b15bd...) is not touched.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

const (
	manifestV2Name  = "manifest2.json"
	manifestV2Fmt   = "certen:sigtypes-manifest:v2"
	kermitV2Name    = "kermit2.json"
	kermitV2Comment = "signatures Kermit delivered for CERTEN intents written by cmd/sigtypelive (RB8 phase D): one per accepted key-signature type and one delegated ecdsaSha256, as the network served them"
)

// signatureBlock returns the local block of the signer's partition in which the network recorded the signature message
// (the "received" field of the signature-chain entry, as the northfield-inspection vector's block was read).
func (k *kermit) signatureBlock(ctx context.Context, signerPage string, txHash []byte, sigBin []byte) (int64, error) {
	raw, err := k.rawQuery(ctx, map[string]any{
		"scope": signerPage,
		"query": map[string]any{"queryType": "chain", "name": "signature", "range": map[string]any{"fromEnd": true, "count": 200, "expand": true}},
	})
	if err != nil {
		return 0, err
	}
	var rng struct {
		Records []struct {
			Value struct {
				Received int64 `json:"received"`
				Message  struct {
					Type      string          `json:"type"`
					Signature json.RawMessage `json:"signature"`
				} `json:"message"`
			} `json:"value"`
		} `json:"records"`
	}
	if err := json.Unmarshal(raw, &rng); err != nil {
		return 0, err
	}
	for _, r := range rng.Records {
		if r.Value.Message.Type != "signature" {
			continue
		}
		s, err := protocol.UnmarshalSignatureJSON(r.Value.Message.Signature)
		if err != nil {
			continue
		}
		if th := s.GetTransactionHash(); string(th[:]) != string(txHash) {
			continue
		}
		if b, err := s.MarshalBinary(); err == nil && string(b) == string(sigBin) {
			if r.Value.Received == 0 {
				return 0, fmt.Errorf("the signature-chain entry on %s carries no received block", signerPage)
			}
			return r.Value.Received, nil
		}
	}
	return 0, fmt.Errorf("no signature-chain entry on %s matches tx %x", signerPage, txHash[:6])
}

func (k *kermit) networkStatusBody(ctx context.Context) ([]byte, error) {
	raw, err := k.rawQuery2(ctx, "network-status", map[string]any{"partition": "Directory"})
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]json.RawMessage{"result": raw})
}

// innerSigner returns the key signature at the bottom of a (possibly delegated) signature.
func innerKey(sig protocol.Signature) protocol.KeySignature {
	return sigfixture.Inner(sig).(protocol.KeySignature)
}

func (a *app) vectors(ctx context.Context, l liveConfig, outDir, vectorDir string) error {
	if _, err := os.Stat(filepath.Join(outDir, kermitV2Name)); err == nil {
		return fmt.Errorf("%s already exists: vectors are evidence and are never regenerated in place", filepath.Join(outDir, kermitV2Name))
	}
	nsBody, err := a.k.networkStatusBody(ctx)
	if err != nil {
		return err
	}
	net, err := govsig.ParseNetworkStatus(nsBody)
	if err != nil {
		return err
	}
	cases, err := l.selected()
	if err != nil {
		return err
	}
	var vs []sigfixture.Vector
	for _, c := range cases {
		capb, err := os.ReadFile(filepath.Join(l.Out, c.Tag, "capture.json"))
		if err != nil {
			return fmt.Errorf("%s: no capture (run submit): %w", c.Name, err)
		}
		var cp capture
		if err := json.Unmarshal(capb, &cp); err != nil {
			return err
		}
		if cp.Status != "delivered" || cp.Signature == "" {
			return fmt.Errorf("%s: the capture is %q, not a delivered signature", c.Name, cp.Status)
		}
		bin, _ := hex.DecodeString(cp.Signature)
		sig, err := protocol.UnmarshalSignature(bin)
		if err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
		js, err := os.ReadFile(filepath.Join(l.Out, c.Tag, "signature.json"))
		if err != nil {
			return err
		}
		txb, err := os.ReadFile(filepath.Join(l.Out, c.Tag, "transaction.bin"))
		if err != nil {
			return err
		}
		ik := innerKey(sig)
		signerPage := ik.GetSigner().String()
		block, err := a.k.signatureBlock(ctx, signerPage, mustHex(cp.TxHash), bin)
		if err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
		part, err := net.Partition(signerPage)
		if err != nil {
			return err
		}
		kp, err := a.k.page(ctx, signerPage)
		if err != nil || kp == nil {
			return fmt.Errorf("%s: signer page %s: %v", c.Name, signerPage, err)
		}
		var entries []string
		for _, e := range kp.Keys {
			if len(e.PublicKeyHash) > 0 {
				entries = append(entries, hex.EncodeToString(e.PublicKeyHash))
			}
		}
		id := c.Name + "/kermit2/live"
		desc := fmt.Sprintf("%s signature Kermit delivered for a CERTEN intent (tx %s, signer %s v%d, recorded in %s local block %d, written by cmd/sigtypelive for %s)",
			c.Name, cp.TxHash[:8]+"..."+cp.TxHash[56:], signerPage, ik.GetSignerVersion(), part, block, a.adi)
		if c.Delegated {
			id = "delegated-ecdsaSha256/kermit2/live"
			desc = "a delegated ecdsaSha256 signature (delegating page " + strings.Join(cp.Delegators, ",") + ") " + desc[len(c.Name)+1:]
		}
		base := sigfixture.Vector{
			ID: id, Source: sigfixture.SourceKermit, Kind: "valid", Type: ik.Type().String(), Description: desc,
			Transaction: hex.EncodeToString(txb), TxHash: cp.TxHash, Signature: cp.Signature, SignatureJSON: js,
			NetworkName: net.Name, Where: &sigfixture.Where{Partition: part, Block: block}, Page: &sigfixture.Page{Entries: entries},
		}
		for _, v := range []struct {
			v    sigfixture.Vector
			want string
		}{
			{base, "accepted"},
			{variant(base, "wrong-page", "the same Kermit-delivered signature judged against a page that does not hold its key", func(v *sigfixture.Vector) {
				v.Page = &sigfixture.Page{Entries: []string{strings.Repeat("00", 32)}}
			}), "refused:key_not_on_page"},
		} {
			vec := v.v
			verdict, verified, jerr := sigfixture.Judge(vec)
			if verdict != v.want {
				return fmt.Errorf("%s: Accumulate's Verify gives %q (%v); the vector was written to be %q", vec.ID, verdict, jerr, v.want)
			}
			vec.Expect = sigfixture.Expect{Verdict: verdict}
			if verdict == "accepted" {
				vec.Expect.KeyHash = hex.EncodeToString(verified.KeyHash)
				vec.Expect.Form = verified.Form
				vec.Expect.EthRule = verified.EthRule
				for _, d := range verified.Delegators {
					vec.Expect.Delegators = append(vec.Expect.Delegators, d.String())
				}
			} else {
				vec.Kind = "adversarial"
			}
			vs = append(vs, vec)
		}
		// the executor-version gate: the same signature recorded before its partition's proven activation
		if act, ok := govsig.KermitActivations()[govsig.NormalizePartition(part)]; ok && ik.Type() != protocol.SignatureTypeED25519 {
			gate := variant(base, "before-activation", "the same signature presented as recorded before its partition's proven executor activation: the version is unproven", func(v *sigfixture.Vector) {
				v.Where = &sigfixture.Where{Partition: part, Block: act.Block - 1}
			})
			verdict, _, _ := sigfixture.Judge(gate)
			if strings.HasPrefix(verdict, "named:") {
				gate.Kind = "adversarial"
				gate.Expect = sigfixture.Expect{Verdict: verdict}
				vs = append(vs, gate)
			} // a type the gate does not govern is accepted before the activation too: no gate vector for it
		}
	}
	for _, v := range vs {
		if err := sigfixture.Check(v); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	// pin: the three earlier files by the hashes manifest.json already pins, then kermit2.json.
	if _, _, err := sigfixture.LoadVectorsFrom(vectorDir, "manifest.json"); err != nil {
		return err
	}
	prev, err := readManifest(filepath.Join(vectorDir, "manifest.json"))
	if err != nil {
		return err
	}
	vf := sigfixture.VectorFile{
		Format: sigfixture.VectorFormat, Description: kermitV2Comment,
		Pinned: pinnedKermit(), Vectors: vs,
	}
	b, err := json.MarshalIndent(vf, "", " ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.WriteFile(filepath.Join(outDir, kermitV2Name), b, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	files := append(append([]sigfixture.ManifestFile{}, prev.Files...), sigfixture.ManifestFile{Name: kermitV2Name, SHA256: hex.EncodeToString(sum[:]), Vectors: len(vs)})
	m := sigfixture.Manifest{Format: manifestV2Fmt, Files: files, Hash: sigfixture.ManifestHash(files), Sources: map[string]int{}}
	for k, n := range prev.Sources {
		m.Sources[k] = n
	}
	m.Sources[sigfixture.SourceKermit] += len(vs)
	m.Count = prev.Count + len(vs)
	m.Note = "manifest2: manifest.json's three files, byte for byte (manifest.json and its hash " + prev.Hash + " are unchanged and still pinned by the earlier suites), plus kermit2.json: signatures Kermit delivered for live CERTEN intents written by cmd/sigtypelive, one per accepted key-signature type and one delegated ecdsaSha256. 'expect' is what Accumulate's own Verify produced through govsig.Judge; the TypeScript verifier must reach the same verdict, key hash and digest form on every vector."
	mb, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, manifestV2Name), append(mb, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %d vectors to %s, manifest2 hash %s (%d vectors in all)\n", len(vs), filepath.Join(outDir, kermitV2Name), m.Hash, m.Count)
	return nil
}

func variant(base sigfixture.Vector, suffix, desc string, f func(*sigfixture.Vector)) sigfixture.Vector {
	v := base
	v.ID = strings.Replace(base.ID, "/live", "/"+suffix, 1)
	v.Description = desc
	v.Kind = "adversarial"
	f(&v)
	return v
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fatal("bad hex %q", s)
	}
	return b
}

func readManifest(path string) (*sigfixture.Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m sigfixture.Manifest
	return &m, json.Unmarshal(b, &m)
}

func pinnedKermit() sigfixture.Pinned {
	return sigfixture.Pinned{
		Accumulate: "gitlab.com/accumulatenetwork/accumulate v1.4.7-0.20260926030013-e1d1db9ebb7c",
		Commit:     "e1d1db9ebb7c75318b6652293d5c7008da76ecf4", Network: "DevNet", ChainID: "317849881",
	}
}
