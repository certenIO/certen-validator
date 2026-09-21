// Copyright 2026 Certen Protocol
//
// Which key page actually signed, established from the transaction itself.
//
// WHY THIS EXISTS.
//
// G1 is built against one named key page: the page's genesis is replayed to the
// execution block, and its threshold is the threshold the proof reports. The
// validator used to choose that page by GUESSING. The governance blob's
// required_key_page is written by the intent builder, and for multi-leg intents
// that builder writes the template "<adi>/book/page" - a URL that resolves to
// nothing, because Accumulate names pages by index. The validator detected the
// invalid form and repaired it to "<book>/1" by string rule, and the discovery
// path did the same unconditionally.
//
// Page 1 is frequently the wrong answer. The Business Transaction Controls books
// put humans on page 1 and the machine key on page 2, and an automated payment is
// signed by page 2. G1 still passed - it resolves the principal's whole authority
// set, so the page-2 signature satisfied the book - but the proof NAMED page 1 and
// took page 1's threshold as its required threshold. The page a proof names and
// the page that authorised the transaction were different pages, and nothing said
// so.
//
// WHAT IT DOES INSTEAD.
//
// It reads the transaction's signature sets from the network. Every key page that
// signed carries its own set, with the signature (public key, signer, signer
// version) and the page's current state (version, key hashes). A page of the
// required key book is a candidate when it carries a key signature over THIS
// transaction from a key that is on the page. The page chosen is:
//
//   - the declared page, when it is a well-formed page URL and it signed;
//   - otherwise the only page of the book that signed;
//   - otherwise, when several pages of the book signed, the lowest-index one - the
//     priority page, and a choice every validator makes identically from the same
//     transaction.
//
// When no page of the book signed, there is nothing to name and the caller gets an
// error. It must fail the proof: a governance proof that names a page that did not
// authorise the transaction is a claim, not evidence.
package proof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// signingKeyPageQuery is the subset of a transaction query the resolver reads.
//
// Decoded from raw JSON for the same reason signerDiscovery is: the pinned
// protocol package cannot decode every Kermit response, and a narrow decode cannot
// be broken by a field it never reads.
type signingKeyPageQuery struct {
	Result struct {
		Signatures struct {
			Records []signingKeyPageSet `json:"records"`
		} `json:"signatures"`
	} `json:"result"`
}

type signingKeyPageSet struct {
	Account struct {
		Type    string `json:"type"`
		URL     string `json:"url"`
		Version uint64 `json:"version"`
		Keys    []struct {
			PublicKeyHash string `json:"publicKeyHash"`
		} `json:"keys"`
	} `json:"account"`
	Signatures struct {
		Records []struct {
			Message struct {
				Type      string `json:"type"`
				TxID      string `json:"txID"`
				Signature struct {
					Type          string `json:"type"`
					PublicKey     string `json:"publicKey"`
					Signer        string `json:"signer"`
					SignerVersion uint64 `json:"signerVersion"`
				} `json:"signature"`
			} `json:"message"`
		} `json:"records"`
	} `json:"signatures"`
}

// ChainKeyPageResolver resolves the signing key page against an Accumulate v3
// endpoint.
type ChainKeyPageResolver struct {
	endpoint string
	logf     func(string, ...interface{})
}

// NewChainKeyPageResolver builds a resolver for a v3 endpoint. The endpoint is
// normalised to end in /v3, the same way the governance CLI adapter does, so both
// read the same network through the same path.
func NewChainKeyPageResolver(endpoint string, logf func(string, ...interface{})) (*ChainKeyPageResolver, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("key page resolver requires an Accumulate endpoint")
	}
	if !strings.HasSuffix(endpoint, "/v3") {
		endpoint = strings.TrimSuffix(endpoint, "/") + "/v3"
	}
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	return &ChainKeyPageResolver{endpoint: endpoint, logf: logf}, nil
}

// ResolveSigningKeyPage returns the page of keyBook that signed the transaction
// txHash executed against principal.
//
// keyBook may be empty, in which case it is taken as the parent of declaredPage -
// structurally, a page's book is the URL it sits under, whether or not the last
// segment is a valid index. With both empty there is no book to look in and the
// call fails.
func (r *ChainKeyPageResolver) ResolveSigningKeyPage(
	ctx context.Context,
	principal, txHash, keyBook, declaredPage string,
) (string, error) {
	book, err := keyBookFor(keyBook, declaredPage)
	if err != nil {
		return "", err
	}
	scope := signerTxScope(principal, txHash)
	var resp signingKeyPageQuery
	if err := queryRawJSON(ctx, r.endpoint, "query", map[string]any{"scope": scope}, &resp); err != nil {
		return "", fmt.Errorf("resolve signing key page of %s: query %s: %w", book, scope, err)
	}
	page, notes, err := selectSigningKeyPage(book, declaredPage, hashOfTxID(txHash), resp.Result.Signatures.Records)
	for _, n := range notes {
		r.logf("[KEYPAGE-RESOLVE] tx %s: %s", scope, n)
	}
	if err != nil {
		return "", fmt.Errorf("resolve signing key page of %s for %s: %w", book, scope, err)
	}
	return page, nil
}

// keyBookFor returns the key book to search, normalised.
func keyBookFor(keyBook, declaredPage string) (string, error) {
	if b := normalizeAccountURL(keyBook); b != "" {
		return b, nil
	}
	p := normalizeAccountURL(declaredPage)
	if i := strings.LastIndex(p, "/"); i > len("acc://") {
		return p[:i], nil
	}
	return "", fmt.Errorf("neither a key book nor a key page was declared; there is no book to " +
		"resolve the signing page in")
}

// selectSigningKeyPage is the decision, separated from the network read so it can
// be tested against recorded responses.
//
// notes are the observations a reader of the log needs - chiefly that the declared
// page is not the page that signed, which is otherwise invisible.
func selectSigningKeyPage(
	book, declaredPage, txHash string,
	sets []signingKeyPageSet,
) (string, []string, error) {
	var notes []string
	type candidate struct {
		url   string
		index uint64
	}
	var candidates []candidate
	seen := map[string]bool{}

	for _, set := range sets {
		if !strings.EqualFold(set.Account.Type, "keyPage") {
			continue
		}
		page := normalizeAccountURL(set.Account.URL)
		idx, inBook := pageIndexInBook(page, book)
		if !inBook || seen[page] {
			continue
		}
		keyHashes := map[string]bool{}
		for _, k := range set.Account.Keys {
			keyHashes[strings.ToLower(strings.TrimPrefix(k.PublicKeyHash, "0x"))] = true
		}
		signed := false
		for _, rec := range set.Signatures.Records {
			sig := rec.Message.Signature
			if txHash != "" && hashOfTxID(rec.Message.TxID) != txHash {
				continue // a signature for some other transaction says nothing about this one
			}
			keyHash, ok := keyHashOfSignature(sig.Type, sig.PublicKey)
			if !ok {
				continue // not a key signature: requests, payments, authority records
			}
			if signer := normalizeAccountURL(sig.Signer); signer != "" && signer != page {
				continue // filed under this page but signed as another: not this page's vote
			}
			switch {
			case keyHashes[keyHash]:
				signed = true
			case set.Account.Version > sig.SignerVersion:
				// The page has been updated since it signed, so its CURRENT keys cannot
				// confirm membership. The network accepted the signature at the signer
				// version it records, and G1 replays the page to the execution block and
				// checks membership there - that replay is authoritative, not this read.
				notes = append(notes, fmt.Sprintf("%s signed at version %d and is now at "+
					"version %d; membership is left to G1's replay at the execution block",
					page, sig.SignerVersion, set.Account.Version))
				signed = true
			default:
				notes = append(notes, fmt.Sprintf("%s carries a %s signature from a key that is "+
					"not on the page at the version it signed with; not counted", page, sig.Type))
			}
		}
		if signed {
			seen[page] = true
			candidates = append(candidates, candidate{url: page, index: idx})
		}
	}

	if len(candidates) == 0 {
		return "", notes, fmt.Errorf("no page of key book %s carries a key signature over this "+
			"transaction; the governance proof has no signing page to name", book)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].index < candidates[j].index })

	declared := normalizeAccountURL(declaredPage)
	_, declaredWellFormed := pageIndexInBook(declared, book)
	if declaredWellFormed {
		for _, c := range candidates {
			if c.url == declared {
				return c.url, notes, nil
			}
		}
	}

	chosen := candidates[0].url
	switch {
	case declared == "":
		notes = append(notes, fmt.Sprintf("no key page declared; %s signed", chosen))
	case !declaredWellFormed:
		notes = append(notes, fmt.Sprintf("declared key page %q is not a page of %s; the page "+
			"that signed is %s", declaredPage, book, chosen))
	default:
		notes = append(notes, fmt.Sprintf("declared key page %s did not sign this transaction; "+
			"the page that signed is %s", declared, chosen))
	}
	if len(candidates) > 1 {
		all := make([]string, 0, len(candidates))
		for _, c := range candidates {
			all = append(all, c.url)
		}
		notes = append(notes, fmt.Sprintf("%d pages of %s signed (%s); naming the priority page %s",
			len(candidates), book, strings.Join(all, ", "), chosen))
	}
	return chosen, notes, nil
}

// pageIndexInBook reports whether page is <book>/<N> with N a positive integer.
func pageIndexInBook(page, book string) (uint64, bool) {
	if page == "" || book == "" || !strings.HasPrefix(page, book+"/") {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(page, book+"/"), 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return n, true
}

// keyHashOfSignature returns the key-page entry hash of a signature's public key.
//
// Only ED25519 keys are recognised, because only their entry hash is a plain
// SHA-256 of the public key; guessing the hash of another key type would compare
// against the wrong value and count or reject a signature on a coincidence. A
// signature of another type is reported as not a key signature, so a page that
// only carries one is not a candidate and the resolver fails rather than guess.
func keyHashOfSignature(sigType, publicKey string) (string, bool) {
	switch strings.ToLower(sigType) {
	case "ed25519", "legacyed25519":
	default:
		return "", false
	}
	pk, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(publicKey), "0x"))
	if err != nil || len(pk) == 0 {
		return "", false
	}
	sum := sha256.Sum256(pk)
	return hex.EncodeToString(sum[:]), true
}

// normalizeAccountURL lower-cases an acc:// URL and strips a trailing slash, so
// the same account spelled two ways compares equal.
func normalizeAccountURL(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	if u == "" {
		return ""
	}
	if !strings.HasPrefix(u, "acc://") {
		u = "acc://" + u
	}
	return strings.TrimSuffix(u, "/")
}
