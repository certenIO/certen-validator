package proof

import (
	"encoding/hex"
	"strings"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB8-E. The first live run of every accepted key-signature type (Kermit, 2026-10-18, validators at RB8-B) was refused at
// the recording of the governance decision for the four types whose key-page entry hash is 20 bytes, with
// `page .../book-btc/1 counts "key:57bedd15a79b1c23f0fba46cf7958c04cea3e2ce", which is not a key hash`. The recorder
// accepted only 64 hex characters, the width of a SHA-256 hash, but Accumulate's PublicKeyHash is the type's own rule:
// 32 bytes for ed25519, legacyED25519, rcd1, rsaSha256 and ecdsaSha256, 20 bytes for btc, btclegacy, eth and typedData.
// The entry is hashed into the decision as the string it is, so the width is the only thing the recorder may check.

// The public keys are the ones Kermit delivered in the RB8-D live run (evidence/rb8-d-live.md).
var liveKeyHashSamples = map[protocol.SignatureType]string{
	protocol.SignatureTypeBTC:       "024b82d682663f04acc44303bdafb37d86d71d83c68431513c35d22812e902b0d3",
	protocol.SignatureTypeBTCLegacy: "04cd30c1ebcaef7264ffc7f2b2c3c68c4cfa37dfd053a7a19e3d3c6f77b4d813cc792002ed233e0fb97c8abe77468702ce61421525d9e8e6510a0082d9dfcaf316",
	protocol.SignatureTypeETH:       "040736bba0257c4b336193abebd5b501f47729f14f491d655eb2b6f71d1727d84d11e9574863dbd37ce9f080642a0e5957b16cfa1bb87163a5002573c3c8d3ccc1",
	protocol.SignatureTypeTypedData: "040b70846a2849a7fbb14555416d02352d567842076c99ee624145cf83b881b39cead2131cf1b6dbb4f2e8d3e7a925196b2f44993afda9358da1121fd046894354",
	protocol.SignatureTypeRCD1:      "186a3e9d73c5f9f2b3ec4d2ceae8c672529826555430cc620065f8935a805953",
	protocol.SignatureTypeED25519:   "d24d7de852c58ae24b3a6d5740f18eaf66034df753b33978fa651d596990e77d",
}

func TestGovernanceDecision_CountsTheKeyHashOfEveryAcceptedKeyType(t *testing.T) {
	short := 0
	for ty, pubHex := range liveKeyHashSamples {
		pub, err := hex.DecodeString(pubHex)
		if err != nil {
			t.Fatal(err)
		}
		h, err := protocol.PublicKeyHash(pub, ty)
		if err != nil {
			t.Fatalf("%v: %v", ty, err)
		}
		if len(h) == 20 {
			short++
		}
		rec, g0 := decisionOf(t, "gdr_g1_delegated_case_c.json")
		inner := &rec.Authorities[0].Vote.Pages[0].Delegates[0].Pages[0]
		inner.Counted[0].Entry = "key:" + hex.EncodeToString(h)
		if _, err := GovernanceDecisionRecord(g0, rec); err != nil {
			t.Errorf("%v: a decision counting the type's own %d-byte key hash is refused: %v", ty, len(h), err)
		}
	}
	if short == 0 {
		t.Fatal("the samples must include 20-byte key hashes, the case that was refused")
	}
}

// Only a key-page entry hash is a key: 40 or 64 hexadecimal characters, nothing else.
func TestGovernanceDecision_RefusesWhatIsNotAKeyHash(t *testing.T) {
	for name, entry := range map[string]string{
		"empty":            "key:",
		"39 hex":           "key:" + strings.Repeat("a", 39),
		"41 hex":           "key:" + strings.Repeat("a", 41),
		"63 hex":           "key:" + strings.Repeat("a", 63),
		"65 hex":           "key:" + strings.Repeat("a", 65),
		"40 non-hex":       "key:" + strings.Repeat("z", 40),
		"64 non-hex":       "key:" + strings.Repeat("g", 64),
		"neither key/dele": "page:" + strings.Repeat("a", 40),
	} {
		rec, g0 := decisionOf(t, "gdr_g1_delegated_case_c.json")
		rec.Authorities[0].Vote.Pages[0].Delegates[0].Pages[0].Counted[0].Entry = entry
		if _, err := GovernanceDecisionRecord(g0, rec); err == nil {
			t.Errorf("%s: %q was encoded instead of refused", name, entry)
		}
	}
}

// A 20-byte hash and a 32-byte hash are different facts and commit differently.
func TestGovernanceDecision_AKeyHashWidthChangesTheCommitment(t *testing.T) {
	commit := func(entry string) [32]byte {
		rec, g0 := decisionOf(t, "gdr_g1_delegated_case_c.json")
		rec.Authorities[0].Vote.Pages[0].Delegates[0].Pages[0].Counted[0].Entry = entry
		gdr, err := GovernanceDecisionRecord(g0, rec)
		if err != nil {
			t.Fatalf("%q: %v", entry, err)
		}
		return GovernanceCommitment(gdr)
	}
	a, b := commit("key:"+strings.Repeat("ab", 20)), commit("key:"+strings.Repeat("ab", 32))
	if a == b {
		t.Fatal("a 20-byte and a 32-byte key hash committed identically")
	}
}
