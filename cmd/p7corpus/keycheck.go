package main

// Key derivation cross-check.
//
// The corpus keys were minted by a Python SDK, and PHASE7_CORPUS_MANIFEST.md
// §4 records that two builds of that SDK derive DIFFERENT keypairs from the
// SAME seed - a discrepancy that orphaned one ADI already. Before this program
// signs anything, it proves the Go derivation agrees with what is ON THE PAGE,
// by hashing the derived public key and looking for that hash among the page's
// entries. A seed that does not round-trip that way is not usable and must be
// reported, never worked around.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// keyFor derives the ed25519 private key for a named corpus seed.
func keyFor(seeds map[string]string, name string) (ed25519.PrivateKey, error) {
	hexSeed, ok := seeds[name]
	if !ok {
		return nil, fmt.Errorf("no seed named %q in keys.json", name)
	}
	raw, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, fmt.Errorf("seed %q is not hex: %w", name, err)
	}
	if len(raw) < ed25519.SeedSize {
		return nil, fmt.Errorf("seed %q is %d bytes, need %d", name, len(raw), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize]), nil
}

func pubKeyHash(priv ed25519.PrivateKey) string {
	h := sha256.Sum256(priv.Public().(ed25519.PublicKey))
	return hex.EncodeToString(h[:])
}

// pageKeyHashes returns the key hashes recorded on a key page, as the network
// reports them.
func pageKeyHashes(ctx context.Context, c *client, page string) (map[string]bool, uint64, uint64, error) {
	u, err := url.Parse(page)
	if err != nil {
		return nil, 0, 0, err
	}
	rec, err := c.Query(ctx, u, &api.DefaultQuery{})
	if err != nil {
		return nil, 0, 0, fmt.Errorf("query %s: %w", page, err)
	}
	acct, ok := rec.(*api.AccountRecord)
	if !ok {
		return nil, 0, 0, fmt.Errorf("query %s: not an account record (%T)", page, rec)
	}
	kp, ok := acct.Account.(*protocol.KeyPage)
	if !ok {
		return nil, 0, 0, fmt.Errorf("%s is a %v, not a key page", page, acct.Account.Type())
	}
	out := make(map[string]bool, len(kp.Keys))
	for _, k := range kp.Keys {
		out[hex.EncodeToString(k.PublicKeyHash)] = true
	}
	return out, kp.Version, kp.AcceptThreshold, nil
}

// checkKeys proves every named seed derives a key that the named page actually
// carries. Reports every failure rather than stopping at the first.
func checkKeys(ctx context.Context, c *client, seeds map[string]string, want map[string]string) error {
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)

	var bad int
	for _, name := range names {
		page := want[name]
		priv, err := keyFor(seeds, name)
		if err != nil {
			fmt.Printf("  %-5s FAIL  %v\n", name, err)
			bad++
			continue
		}
		hashes, version, threshold, err := pageKeyHashes(ctx, c, page)
		if err != nil {
			fmt.Printf("  %-5s FAIL  %v\n", name, err)
			bad++
			continue
		}
		kh := pubKeyHash(priv)
		if !hashes[kh] {
			fmt.Printf("  %-5s FAIL  derived key hash %s is NOT on %s (page has %d keys)\n",
				name, kh[:16], page, len(hashes))
			bad++
			continue
		}
		fmt.Printf("  %-5s ok    %s on %s (v%d, %d-of-%d)\n",
			name, kh[:16], page, version, threshold, len(hashes))
	}
	if bad > 0 {
		return fmt.Errorf("%d of %d corpus keys do not match the chain", bad, len(names))
	}
	return nil
}
