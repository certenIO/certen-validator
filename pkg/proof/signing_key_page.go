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
// required key book is a candidate when it carries a vote over THIS transaction:
// an ED25519 signature from a key that is on the page, or a delegated or
// non-ED25519 signature the network accepted as the page's (whose key G1 verifies
// cryptographically). The page is named as the network spells it, because the URL
// is hashed into the govRoot. The page chosen is:
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
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
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

// signingKeySig is the part of a signature record this layer reads. A delegated signature carries the delegating page in
// `delegator` and its inner signature under `signature` (an object, where a key signature carries its signature bytes there
// as a string); an `authority` record carries `delegator` as a list.
type signingKeySig struct {
	Type          string            `json:"type"`
	PublicKey     string            `json:"publicKey"`
	Signer        string            `json:"signer"`
	SignerVersion uint64            `json:"signerVersion"`
	Delegator     signingDelegators `json:"delegator"`
	Inner         json.RawMessage   `json:"signature"`
}

// signingDelegators is a `delegator` field: one URL, or a list of them.
type signingDelegators []string

// UnmarshalJSON reads the two shapes the network writes, a URL and a list of URLs. Any other shape is NO delegator - never
// an error: this field is one of many in a response this layer reads narrowly, and a shape it does not know must not fail the
// decode of the whole response (RB8-G). A delegator that is not understood names no page, so it can never make one the signer.
func (d *signingDelegators) UnmarshalJSON(b []byte) error {
	*d = nil
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		if one != "" {
			*d = signingDelegators{one}
		}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return nil // an unknown shape: no delegator
	}
	*d = many
	return nil
}

// delegatingPages returns the pages a delegated signature was cast through, outermost first: its own delegator and, when its
// inner signature is itself delegated, that one's, down to Accumulate's delegation depth. A signature that is not delegated
// delegates through nothing.
func (s signingKeySig) delegatingPages() []string {
	if c := classOf(s.Type); c != govsig.ClassDelegated {
		return nil
	}
	var out []string
	cur := s
	for depth := 0; depth <= maxDecisionDepth; depth++ {
		for _, d := range cur.Delegator {
			if p := normalizeAccountURL(d); p != "" {
				out = append(out, p)
			}
		}
		inner := bytes.TrimSpace(cur.Inner)
		if len(inner) == 0 || inner[0] != '{' {
			break
		}
		var next signingKeySig
		if json.Unmarshal(inner, &next) != nil || classOf(next.Type) != govsig.ClassDelegated {
			break
		}
		cur = next
	}
	return out
}

func classOf(sigType string) govsig.Class {
	_, c := govsig.Classify(sigType)
	return c
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
				Type      string        `json:"type"`
				TxID      string        `json:"txID"`
				Signature signingKeySig `json:"signature"`
			} `json:"message"`
		} `json:"records"`
	} `json:"signatures"`
}

// holdsAuthorityRecord reports whether this page's OWN signature set holds the chain-created evidence that the page counted
// a delegated vote: a record of type `authority`, over txHash (every transaction when txHash is empty), whose delegator list
// contains the page. The network files such a record under the delegating page when - and only when - a delegate's vote was
// cast through it (testdata/kermit_delegated_ecdsa_signing_sets.json); a delegated vote that merely names a page as its
// delegator does not make that page the signer (RB8-G).
func (s signingKeyPageSet) holdsAuthorityRecord(page, txHash string) bool {
	for _, rec := range s.Signatures.Records {
		if txHash != "" && hashOfTxID(rec.Message.TxID) != txHash {
			continue
		}
		sig := rec.Message.Signature
		if !strings.EqualFold(strings.TrimSpace(sig.Type), "authority") {
			continue
		}
		for _, d := range sig.Delegator {
			if normalizeAccountURL(d) == page {
				return true
			}
		}
	}
	return false
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
// ErrNoSigningKeyPage is an intent whose signing key page cannot be established from what it declared and how it
// was signed: it declared no key book or page, or no signature on its transaction is from a page of the declared
// book. A fact about the intent, not an outage (RB4-F13).
var ErrNoSigningKeyPage = errors.New("no signing key page")

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
		return "", fmt.Errorf("resolve signing key page of %s for %s: %w: %w", book, scope, ErrNoSigningKeyPage, err)
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
	return "", fmt.Errorf("%w: neither a key book nor a key page was declared; there is no book to "+
		"resolve the signing page in", ErrNoSigningKeyPage)
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
		url   string // normalised, for comparison
		named string // as the network spells it, which is what is hashed into the govRoot
		index uint64
	}
	var candidates, viaDelegation []candidate
	seen := map[string]bool{}

	// A delegated vote is filed by the network under the DELEGATE's page (type "delegated", the delegating page in `delegator`),
	// and only an `authority` record lands under the delegating page. The page that counted the vote for the principal's authority
	// is the delegating one, so every page named as a delegator of a delegated signature over THIS transaction, at any
	// depth, is a page that signed by delegation (RB8-E). Which key stands behind it is G1's to verify.
	delegating := map[string]string{}
	for _, set := range sets {
		for _, rec := range set.Signatures.Records {
			if txHash != "" && hashOfTxID(rec.Message.TxID) != txHash {
				continue
			}
			for _, p := range rec.Message.Signature.delegatingPages() {
				if _, ok := delegating[p]; !ok {
					delegating[p] = normalizeAccountURL(set.Account.URL)
				}
			}
		}
	}

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
			if !isVoteSignature(sig.Type) {
				continue // not a vote: requests, payments, authority and system records
			}
			if signer := normalizeAccountURL(sig.Signer); signer != "" && signer != page {
				continue // filed under this page but signed as another: not this page's vote
			}
			keyHash, hashable := keyHashOfSignature(sig.Type, sig.PublicKey)
			switch {
			case !hashable:
				// A delegated signature (the key lives in a delegate's book) or a key type whose
				// entry hash is not a plain SHA-256 of the key. The network accepted it as this
				// page's vote; G1 verifies it cryptographically and resolves the delegation. This
				// read has nothing further to check, and refusing it would fail every intent a
				// delegate or a non-ED25519 key signs - which G1 itself accepts.
				notes = append(notes, fmt.Sprintf("%s carries a %s vote; its key is verified by G1, "+
					"not by this read", page, sig.Type))
				signed = true
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
			candidates = append(candidates, candidate{url: page, named: strings.TrimSuffix(strings.TrimSpace(set.Account.URL), "/"), index: idx})
		} else if from, ok := delegating[page]; ok {
			// A delegated vote that names this page is not enough: the page's own signature set must hold the authority
			// record the network created when the page counted it (RB8-G).
			if !set.holdsAuthorityRecord(page, txHash) {
				notes = append(notes, fmt.Sprintf("%s is named as the delegator of a delegated vote cast from %s, but its own "+
					"signature set holds no authority record over this transaction naming it; not counted", page, from))
				continue
			}
			// Only when no page of the book filed a vote of its own (below): a delegating page never displaces a page that
			// resolved before this was read.
			viaDelegation = append(viaDelegation, candidate{url: page, named: strings.TrimSuffix(strings.TrimSpace(set.Account.URL), "/"), index: idx})
			notes = append(notes, fmt.Sprintf("%s carries a delegated vote cast from %s; its delegate's key is verified by G1, "+
				"not by this read", page, from))
		}
	}

	if len(candidates) == 0 {
		for _, c := range viaDelegation {
			seen[c.url] = true
		}
		candidates = viaDelegation
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
				return c.named, notes, nil
			}
		}
	}

	chosen := candidates[0].named
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

// isVoteSignature reports whether a signature type is a vote by a key page: a key
// signature of any algorithm, or a delegated one. Signature requests, credit
// payments, authority, partition, receipt and internal records are not votes.
//
// The set is govsig's (Accumulate's own: the nine key-signature types and the delegation wrapper), the one rule the
// online G1 proof, the offline vote evidence and this layer share.
func isVoteSignature(sigType string) bool {
	_, class := govsig.Classify(sigType)
	return class == govsig.ClassKey || class == govsig.ClassDelegated
}

// keyHashOfSignature returns the key-page entry hash of a signature's public key by the TYPE'S OWN rule
// (protocol.PublicKeyHash): sha256(key) for ed25519, legacyED25519, rsaSha256 and ecdsaSha256, and the other hash
// for rcd1, btc, btclegacy, eth and typedData. A delegated signature carries no key of its own at this level, and a key
// that does not parse has no hash: neither is guessed, and for either the caller defers key membership to G1.
func keyHashOfSignature(sigType, publicKey string) (string, bool) {
	t, class := govsig.Classify(sigType)
	if class != govsig.ClassKey {
		return "", false
	}
	pk, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(publicKey), "0x"))
	if err != nil || len(pk) == 0 {
		return "", false
	}
	h, err := protocol.PublicKeyHash(pk, t)
	if err != nil || len(h) == 0 {
		return "", false
	}
	return hex.EncodeToString(h), true
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
