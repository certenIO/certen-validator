package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"gitlab.com/accumulatenetwork/accumulate/pkg/client/signing"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// sigVector is one Directory anchor with a key signature on it, as Go builds and verifies it.
// The TypeScript verifier must reach the same verdict (Valid) with the same message hash.
type sigVector struct {
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	Message     json.RawMessage `json:"message"`     // the SequencedMessage, as Go renders it
	MessageHash string          `json:"messageHash"` // msg.Hash(), hex
	Signature   json.RawMessage `json:"signature"`   // the signature, as Go renders it
	Valid       bool            `json:"valid"`       // sig.Verify(nil, msg), computed by Go
}

func anchorMessage(minor uint64) *messaging.SequencedMessage {
	root := [32]byte{1, 2, 3, byte(minor)}
	state := [32]byte{9, 8, 7, byte(minor)}
	return &messaging.SequencedMessage{
		Message: &messaging.TransactionMessage{Transaction: &protocol.Transaction{
			Header: protocol.TransactionHeader{Principal: url.MustParse("acc://dn.acme/anchors")},
			Body: &protocol.DirectoryAnchor{
				PartitionAnchor: protocol.PartitionAnchor{Source: url.MustParse("acc://dn.acme"), MinorBlockIndex: minor, RootChainIndex: minor, RootChainAnchor: root, StateTreeAnchor: state},
			},
		}},
		Source:      url.MustParse("acc://dn.acme"),
		Destination: url.MustParse("acc://dn.acme"),
		Number:      minor,
	}
}

func writeSignatureVectors(path string) error {
	_, priv, err := ed25519.GenerateKey(deterministic{})
	if err != nil {
		return err
	}
	var out []sigVector
	add := func(name string, typ protocol.SignatureType, msg *messaging.SequencedMessage, mutate func(protocol.Signature)) error {
		b := new(signing.Builder).SetType(typ).SetUrl(url.MustParse("acc://dn.acme/network")).SetVersion(1).SetTimestamp(1700000000000).SetPrivateKey(priv)
		h := msg.Hash()
		sig, err := b.Sign(h[:])
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if mutate != nil {
			mutate(sig)
		}
		ks, ok := sig.(protocol.KeySignature)
		if !ok {
			return fmt.Errorf("%s: not a key signature", name)
		}
		sj, err := json.Marshal(sig)
		if err != nil {
			return err
		}
		mj, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		out = append(out, sigVector{Name: name, Type: typ.String(), Message: mj, MessageHash: hex.EncodeToString(h[:]), Signature: sj, Valid: ks.Verify(nil, msg)})
		return nil
	}
	flip := func(s protocol.Signature) {
		switch k := s.(type) {
		case *protocol.ED25519Signature:
			k.Signature[0] ^= 1
		case *protocol.RCD1Signature:
			k.Signature[0] ^= 1
		case *protocol.LegacyED25519Signature:
			k.Signature[0] ^= 1
		}
	}
	later := func(s protocol.Signature) {
		switch k := s.(type) {
		case *protocol.ED25519Signature:
			k.Timestamp++
		case *protocol.RCD1Signature:
			k.Timestamp++
		case *protocol.LegacyED25519Signature:
			k.Timestamp++
		}
	}
	for _, t := range []protocol.SignatureType{protocol.SignatureTypeED25519, protocol.SignatureTypeRCD1, protocol.SignatureTypeLegacyED25519} {
		if err := add(t.String()+"-valid", t, anchorMessage(10), nil); err != nil {
			return err
		}
		if err := add(t.String()+"-flipped-signature", t, anchorMessage(10), flip); err != nil {
			return err
		}
		if err := add(t.String()+"-metadata-changed-after-signing", t, anchorMessage(10), later); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(map[string]any{"generator": "certen-validator cmd/netrecordvectors", "vectors": out}, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// deterministic is a fixed byte stream, so the vectors are reproducible.
type deterministic struct{}

func (deterministic) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i*31 + 7)
	}
	return len(p), nil
}
