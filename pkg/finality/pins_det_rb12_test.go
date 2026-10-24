// Copyright 2026 Certen Protocol

package finality

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// RB12-OPS-A1 item 1 (ledger F4/N1): the pins loader is a function of the bytes of the file. Two spellings of one name, which the
// decoders of the chain sections do not tell apart (hex digits and field names match without regard to letter case), used to be merged
// in the order a Go map is visited in; they are now the named finality_pins_corrupt{duplicate_key} wherever they stand.

// The digest of the shipped file is part of the contract of the channel (certen-contracts evm/deployments/finality-pins.json, the SDK copy
// and this file all hash to it): a change to the loader must not move it, and a change to the file must be a deliberate new constant.
func TestThePinsDigestOfTheShippedFileIsTheOneTheChannelPublishes(t *testing.T) {
	const published = "fdba733e7fc4206d96d73c87352834c51801ee8fe0af76d60654cb461fbd5440"
	sum := sha256.Sum256(EmbeddedPinsBytes())
	if got := hex.EncodeToString(sum[:]); got != published {
		t.Fatalf("the shipped pins file hashes to %s, the published digest is %s", got, published)
	}
	if PinsSHA256 != published {
		t.Fatalf("PinsSHA256 = %s, the published digest is %s", PinsSHA256, published)
	}
	for i := 0; i < 3; i++ { // the load of the shipped file answers the same every time, and with the same identity
		p, err := EmbeddedPins()
		if err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
		if h, src := p.Identity(); h != published || src != PinsSourceEmbedded {
			t.Fatalf("load %d: identity %s %s", i, h, src)
		}
	}
}

func permutations(items []string) [][]string {
	if len(items) <= 1 {
		return [][]string{append([]string(nil), items...)}
	}
	var out [][]string
	for i := range items {
		rest := append(append([]string(nil), items[:i]...), items[i+1:]...)
		for _, p := range permutations(rest) {
			out = append(out, append([]string{items[i]}, p...))
		}
	}
	return out
}

// pinsWithLogicPins is the smallest pins file that reaches the key walk with the given logic_pins keys in the given order (the raw
// sections of the chain packages are not validated by the framework loader).
func pinsWithLogicPins(keys []string) []byte {
	var b strings.Builder
	b.WriteString("{\n  \"arb_sepolia\": {\n    \"logic_pins\": {\n")
	for i, k := range keys {
		sep := ","
		if i == len(keys)-1 {
			sep = ""
		}
		fmt.Fprintf(&b, "      %q: \"validator_wallet_proxy\"%s\n", k, sep)
	}
	b.WriteString("    }\n  },\n  \"format\": \"certen-finality-pins/1\",\n  \"published_utc\": \"2026-10-23T00:00:00Z\"\n}\n")
	return []byte(b.String())
}

func loadAnswer(raw []byte) string {
	sum := sha256.Sum256(raw)
	p, err := LoadPins(raw, sum)
	if err != nil {
		return err.Error()
	}
	h, _ := p.Identity()
	return "ok " + h
}

// Four spellings of one code hash in every order the document can list them: each of the 24 documents is loaded 1,000 times and every
// load answers duplicate_key naming the SECOND key of the document (the first one that repeats an earlier name), whether or not the
// order of the document is also unsorted.
func TestCaseVariantDuplicateKeysAreDuplicateKeyForEveryOrderOfTheSet(t *testing.T) {
	hash := "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"
	spellings := []string{"0x" + hash, "0x" + strings.ToUpper(hash), "0x" + strings.ToUpper(hash[:32]) + hash[32:], "0x" + hash[:32] + strings.ToUpper(hash[32:])}
	perms := permutations(spellings)
	if len(perms) != 24 {
		t.Fatalf("%d permutations of 4 spellings", len(perms))
	}
	for _, perm := range perms {
		raw := pinsWithLogicPins(perm)
		want := PinsCorrupt(PinsDuplicateKey, "key", perm[1]).Error()
		for i := 0; i < 1000; i++ {
			if got := loadAnswer(raw); got != want {
				t.Fatalf("order %q, load %d: got %s, want %s", perm, i, got, want)
			}
		}
	}
}

// What did not change: the same spellings in objects of their own are accepted, distinct names in order are accepted, distinct names out of
// order are keys_unsorted, an exact repeat next to itself is duplicate_key, and the objects the loader has a schema for still refuse a
// wrong-case name as unknown_key (the published finality_chain2 vectors pin those).
func TestTheCaseVariantRuleTouchesOnlyCaseVariantsInOneObject(t *testing.T) {
	hash := "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"
	lower, upper := "0x"+hash, "0x"+strings.ToUpper(hash)
	other := "0x" + strings.Repeat("11", 32)
	cases := []struct {
		name string
		keys []string
		want string
	}{
		{"distinct names in order", []string{other, upper}, "ok"},
		{"exact repeat", []string{lower, lower}, PinsCorrupt(PinsDuplicateKey, "key", lower).Error()},
		{"distinct names out of order", []string{lower, other}, PinsCorrupt(PinsKeysUnsorted, "key", other).Error()},
		{"case variant after an unrelated key", []string{other, lower, upper}, PinsCorrupt(PinsDuplicateKey, "key", upper).Error()},
	}
	for _, c := range cases {
		got := loadAnswer(pinsWithLogicPins(c.keys))
		if c.want == "ok" {
			if !strings.HasPrefix(got, "ok ") {
				t.Errorf("%s: %s", c.name, got)
			}
		} else if got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
	// the spellings in two different objects are two different names
	two := []byte("{\n  \"arb_sepolia\": {\n    \"logic_pins\": {\n      \"" + upper + "\": \"a\"\n    },\n    \"other_pins\": {\n      \"" + lower + "\": \"b\"\n    }\n  },\n  \"format\": \"certen-finality-pins/1\",\n  \"published_utc\": \"2026-10-23T00:00:00Z\"\n}\n")
	if got := loadAnswer(two); !strings.HasPrefix(got, "ok ") {
		t.Errorf("two objects: %s", got)
	}
	// a wrong-case name in an object with a schema is unknown_key, as before (not duplicate_key)
	typed := []byte("{\n  \"Format\": \"certen-finality-pins/1\",\n  \"format\": \"certen-finality-pins/1\",\n  \"published_utc\": \"2026-10-23T00:00:00Z\"\n}\n")
	if got, want := loadAnswer(typed), PinsCorrupt(PinsUnknownKey, "key", "Format").Error(); got != want {
		t.Errorf("typed object: got %s, want %s", got, want)
	}
}

// foldKey is the equivalence encoding/json matches names with: the orbit of a rune under simple case folding.
func TestFoldKeyIsTheEqualFoldEquivalence(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"0xAB", "0xab", true}, {"logic_pins", "Logic_Pins", true}, {"k", "K", true}, {"s", "ſ", true}, {"a", "b", false}, {"0xab", "0xac", false}, {"", "", true},
	} {
		if (foldKey(c.a) == foldKey(c.b)) != c.same || strings.EqualFold(c.a, c.b) != c.same {
			t.Errorf("%q vs %q: foldKey equal %v, EqualFold %v, want %v", c.a, c.b, foldKey(c.a) == foldKey(c.b), strings.EqualFold(c.a, c.b), c.same)
		}
	}
}
