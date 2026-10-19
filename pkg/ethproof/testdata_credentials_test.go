// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// publicProviderURLs are the public RPC endpoints the programme's live captures used (cmd/s6livecapture's chain table):
// hosts that need no key, and the one public path some of them carry. Nothing else may appear as a URL in a published
// fixture.
var publicProviderURLs = []string{
	"https://ethereum-sepolia-rpc.publicnode.com",
	"https://sepolia.gateway.tenderly.co",
	"https://sepolia.base.org",
	"https://base-sepolia-rpc.publicnode.com",
	"https://sepolia-rollup.arbitrum.io/rpc",
	"https://arbitrum-sepolia-rpc.publicnode.com",
	"https://rpc.telcoin.network",
	"https://node1.telcoin.network",
	"https://node2.telcoin.network",
}

// keyedProviderHosts are providers whose URL path is the API key: no fixture may name one at all.
var keyedProviderHosts = regexp.MustCompile(`(?i)alchemy\.com|alchemyapi\.io|infura\.io|quiknode\.pro|quicknode\.com|blastapi\.io|chainstack\.com|ankr\.com|getblock\.io|nodereal\.io|drpc\.org|moralis\.io`)

// scanWindow and scanOverlap: how a fixture is read through the bounded redactor.
const (
	scanWindow  = 32 << 10
	scanOverlap = 4 << 10
)

// RB10-B11: the published fixtures (the recorded live worlds with their evidence and verdicts, the s6replay vectors and
// their mutations) hold no provider credential: only a public provider URL, with no path beyond the public one.
func TestPublishedS6FixturesHoldNoProviderCredential(t *testing.T) {
	var scanned, bytesScanned int
	for _, dir := range []string{"s6live1", "s6replay1", "s6replay2", "s6replay3", "s6replay4"} {
		root := filepath.Join("testdata", dir)
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.HasSuffix(path, ".gz") {
				zr, err := gzip.NewReader(bytes.NewReader(raw))
				if err != nil {
					t.Errorf("%s: %v", path, err)
					return nil
				}
				if raw, err = io.ReadAll(zr); err != nil {
					t.Errorf("%s: %v", path, err)
					return nil
				}
			}
			scanned++
			bytesScanned += len(raw)
			text := string(raw)
			if m := keyedProviderHosts.FindString(text); m != "" {
				t.Errorf("%s names a provider whose URL carries its API key (%q)", path, m)
			}
			// What is left once the public URLs are taken out must hold no URL, no userinfo, no host path and no key query.
			rest := text
			for _, u := range publicProviderURLs {
				rest = strings.ReplaceAll(rest, u, "PUBLIC")
			}
			if strings.Contains(rest, "://") {
				i := strings.Index(rest, "://")
				t.Errorf("%s holds a URL that is not a public provider's: %q", path, rest[max(0, i-20):min(len(rest), i+60)])
			}
			// The redactor reads at most 64 KiB of a text (RB10-B15), so a fixture is read in overlapping windows of 32 KiB: a URL or a key
			// in it, 4 KiB or shorter, lies whole in one window.
			for off := 0; off < len(rest); off += scanWindow - scanOverlap {
				w := rest[off:min(len(rest), off+scanWindow)]
				if red := ethproof.RedactEndpoints(w); red != w {
					i := 0
					for i < len(red) && i < len(w) && red[i] == w[i] {
						i++
					}
					t.Errorf("%s holds a host with a path or a key in it: %q", path, w[max(0, i-30):min(len(w), i+60)])
					break
				}
				if off+scanWindow >= len(rest) {
					break
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned < 50 {
		t.Fatalf("only %d fixture files scanned", scanned)
	}
	t.Logf("%d fixture files, %d bytes scanned: only public provider URLs", scanned, bytesScanned)
}
