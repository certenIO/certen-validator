// Copyright 2026 Certen Protocol
//
// THE GOVERNANCE DECISION RECORD (RB4-F66).
//
// On the live batch path CERTEN anchored nothing of an intent's governance: createBatchAnchor stores a zero
// governanceRoot, the batch leaf carries (chainId, adiURLHash, executionCommitment, operationID), and the quorum's
// BLS message covers (bundleId, batchRoot, batchOperationID, validatorSetRoot). The A+++ govRoot existed only inside
// each validator's own, unaggregated pre-exec signature.
//
// The decision record is what makes the quorum commit to governance. It is WHO decided the transaction, as G1
// established it and as Accumulate records it: for each authority the account required, the page that cast the
// book's vote (the network's record of it, cross-checked by the replay - consolidated_governance-proof g1_votes.go),
// that page's version and thresholds, the block it decided in, the entries it counted and the message behind each,
// and for every delegate entry the same, recursively, down to the keys. It is fixed by the chain at execution, so
// every validator derives it identically from its own proof; what depends on when or where the record was read -
// receipts, messages excluded for a reason, signatures that reached no required authority - is evidence, not part of
// the decision, and is not in it.
//
// Its commitment is carried by each batch member and aggregated into the batch operation id the quorum signs and the
// anchor stores (batch_tree.go, DeriveBatchOperationIDV2). A validator whose own G1 reached a different decision
// derives a different id and does not sign.
package proof

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// AuthorizationRecord is the governance proof CLI's vote record (consolidated_governance-proof AccountVote): each
// required authority and how it voted. It travels on the GovernanceProof wrapper, which no hash reaches; G1Result must
// not carry it (it is inside the ValidatorBlock's BundleID - an old binary would drop the field and recompute a
// different one).
type AuthorizationRecord struct {
	Account     string                   `json:"account"`
	Authorities []AuthorizationAuthority `json:"authorities"`
	Satisfied   bool                     `json:"satisfied"`
	Unused      []AuthorizationExclusion `json:"unused,omitempty"`
}

// AuthorizationAuthority is one required authority and its book's vote.
type AuthorizationAuthority struct {
	Authority string            `json:"authority"`
	Disabled  bool              `json:"disabled,omitempty"`
	Extra     bool              `json:"extra,omitempty"`
	Vote      AuthorizationBook `json:"vote"`
}

// AuthorizationBook is a book's vote: By is the page that cast it.
type AuthorizationBook struct {
	Book  string              `json:"book"`
	Voted bool                `json:"voted"`
	Vote  string              `json:"vote,omitempty"`
	By    string              `json:"by,omitempty"`
	Pages []AuthorizationPage `json:"pages,omitempty"`
}

// AuthorizationPage is one page's vote on one delegation path.
type AuthorizationPage struct {
	Page              string                   `json:"page"`
	Path              []string                 `json:"path,omitempty"`
	Voted             bool                     `json:"voted"`
	Vote              string                   `json:"vote,omitempty"`
	Version           uint64                   `json:"version,omitempty"`
	Threshold         uint64                   `json:"threshold,omitempty"`
	RejectThreshold   uint64                   `json:"rejectThreshold,omitempty"`
	ResponseThreshold uint64                   `json:"responseThreshold,omitempty"`
	DecidedAt         int64                    `json:"decidedAt,omitempty"`
	Counted           []AuthorizationEntry     `json:"counted,omitempty"`
	Excluded          []AuthorizationExclusion `json:"excluded,omitempty"`
	Delegates         []AuthorizationBook      `json:"delegates,omitempty"`
}

// AuthorizationEntry is one page entry - a key or a delegate book - and the vote it cast, by which message, where.
type AuthorizationEntry struct {
	Entry string `json:"entry"`
	Vote  string `json:"vote"`
	By    string `json:"by"`
	Block int64  `json:"block"`
}

// AuthorizationExclusion is a message that did not count, and why.
type AuthorizationExclusion struct {
	By     string `json:"by"`
	Reason string `json:"reason"`
}

// AuthorizationRecordFromRaw reads the vote record out of a G1 or G2 CLI output. An output with no record returns
// nil (a govproof build predating it); a record that is present but does not parse is an error, never an absence.
func AuthorizationRecordFromRaw(raw json.RawMessage) (*AuthorizationRecord, error) {
	var env struct {
		Authorization json.RawMessage `json:"authorization"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("read the vote record: %w", err)
	}
	if len(env.Authorization) == 0 || string(env.Authorization) == "null" {
		return nil, nil
	}
	var rec AuthorizationRecord
	dec := json.NewDecoder(bytes.NewReader(env.Authorization))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return nil, fmt.Errorf("the vote record is malformed: %w", err)
	}
	return &rec, nil
}

// GovernanceDecisionDomain opens every decision record; GovernanceCommitmentDomain tags its commitment.
const (
	GovernanceDecisionDomain   = "certen:gdr:v1"
	GovernanceCommitmentDomain = "certen:govdecision:v1"
)

// GovernanceCommitment is keccak256(GovernanceCommitmentDomain || gdr).
func GovernanceCommitment(gdr []byte) [32]byte {
	var out [32]byte
	copy(out[:], crypto.Keccak256([]byte(GovernanceCommitmentDomain), gdr))
	return out
}

// GovernanceDecisionRecord encodes who decided the transaction g0 proved executed, from rec. Every field is length-
// or width-delimited, lists are sorted, and a record that cannot support a decision is refused by name.
func GovernanceDecisionRecord(g0 *G0Result, rec *AuthorizationRecord) ([]byte, error) {
	if g0 == nil {
		return nil, fmt.Errorf("no G0 result: which transaction executed is not established")
	}
	if rec == nil {
		return nil, fmt.Errorf("the governance proof carries no vote record, so who decided the transaction is not " +
			"established")
	}
	txHash := strings.ToLower(strings.TrimPrefix(g0.TxHash, "0x"))
	if len(txHash) != 64 {
		return nil, fmt.Errorf("G0 names transaction %q, not a 32-byte hash", g0.TxHash)
	}
	if g0.ExecMBI <= 0 {
		return nil, fmt.Errorf("G0 names no execution block")
	}
	account := strings.ToLower(strings.TrimSpace(rec.Account))
	if identityOfAccount(account) != strings.ToLower(strings.TrimPrefix(strings.TrimSpace(g0.Principal), "acc://")) {
		return nil, fmt.Errorf("the vote record is for %s, but G0 proved a transaction of %s", rec.Account, g0.Principal)
	}
	if !rec.Satisfied {
		return nil, fmt.Errorf("the vote record says %s's authorities did not all accept", rec.Account)
	}
	if len(rec.Authorities) == 0 {
		return nil, fmt.Errorf("the vote record names no authority of %s", rec.Account)
	}

	w := &gdrWriter{}
	w.str(GovernanceDecisionDomain)
	w.str(account)
	w.str(txHash)
	w.uint(uint64(g0.ExecMBI))

	auths := append([]AuthorizationAuthority(nil), rec.Authorities...)
	sort.Slice(auths, func(i, j int) bool { return auths[i].Authority < auths[j].Authority })
	w.uint(uint64(len(auths)))
	for i, a := range auths {
		if i > 0 && a.Authority == auths[i-1].Authority {
			return nil, fmt.Errorf("the vote record lists authority %s twice", a.Authority)
		}
		w.str(a.Authority)
		w.bool(a.Disabled)
		w.bool(a.Extra)
		if a.Vote.Book != a.Authority {
			return nil, fmt.Errorf("authority %s is recorded with the vote of %s", a.Authority, a.Vote.Book)
		}
		if a.Vote.Vote != "accept" {
			return nil, fmt.Errorf("authority %s did not vote to accept (%q)", a.Authority, a.Vote.Vote)
		}
		if err := w.book(a.Vote, 0); err != nil {
			return nil, fmt.Errorf("authority %s: %w", a.Authority, err)
		}
	}
	return w.buf.Bytes(), nil
}

// maxDecisionDepth bounds delegation in a record as Accumulate bounds it (protocol.DelegationDepthLimit).
const maxDecisionDepth = 20

type gdrWriter struct{ buf bytes.Buffer }

func (w *gdrWriter) uint(v uint64) {
	var b [binary.MaxVarintLen64]byte
	w.buf.Write(b[:binary.PutUvarint(b[:], v)])
}

func (w *gdrWriter) str(s string) {
	w.uint(uint64(len(s)))
	w.buf.WriteString(s)
}

func (w *gdrWriter) bool(v bool) {
	if v {
		w.buf.WriteByte(1)
	} else {
		w.buf.WriteByte(0)
	}
}

// book writes a book's decision: the page that cast it, and that page's decision.
func (w *gdrWriter) book(b AuthorizationBook, depth int) error {
	if depth > maxDecisionDepth {
		return fmt.Errorf("delegation deeper than Accumulate's limit of %d", maxDecisionDepth)
	}
	if !b.Voted || b.Vote == "" || b.By == "" {
		return fmt.Errorf("book %s did not vote", b.Book)
	}
	var deciding *AuthorizationPage
	for i := range b.Pages {
		if b.Pages[i].Page == b.By {
			if deciding != nil {
				return fmt.Errorf("book %s records page %s twice", b.Book, b.By)
			}
			deciding = &b.Pages[i]
		}
	}
	if deciding == nil {
		return fmt.Errorf("book %s's vote is cast by %s, which the record does not carry", b.Book, b.By)
	}
	if !deciding.Voted || deciding.Vote != b.Vote {
		return fmt.Errorf("book %s's vote (%s) is not the vote of the page that cast it (%s)", b.Book, b.Vote, deciding.Vote)
	}
	w.str(b.Book)
	w.str(b.Vote)
	return w.page(*deciding, depth)
}

// page writes a deciding page: where it decided, on what, and the delegates behind its delegate entries.
func (w *gdrWriter) page(p AuthorizationPage, depth int) error {
	if p.DecidedAt <= 0 {
		return fmt.Errorf("page %s records no block it decided in", p.Page)
	}
	if p.Version == 0 || p.Threshold == 0 {
		return fmt.Errorf("page %s records no version or threshold", p.Page)
	}
	if len(p.Counted) == 0 {
		return fmt.Errorf("page %s decided on nothing it counted", p.Page)
	}
	w.str(p.Page)
	w.uint(uint64(len(p.Path)))
	for _, s := range p.Path {
		w.str(s)
	}
	w.str(p.Vote)
	w.uint(p.Version)
	w.uint(p.Threshold)
	w.uint(p.RejectThreshold)
	w.uint(p.ResponseThreshold)
	w.uint(uint64(p.DecidedAt))

	counted := append([]AuthorizationEntry(nil), p.Counted...)
	sort.Slice(counted, func(i, j int) bool { return counted[i].Entry < counted[j].Entry })
	delegates := map[string]AuthorizationBook{}
	for _, d := range p.Delegates {
		if _, dup := delegates[d.Book]; dup {
			return fmt.Errorf("page %s records delegate %s twice", p.Page, d.Book)
		}
		delegates[d.Book] = d
	}
	w.uint(uint64(len(counted)))
	used := 0
	for i, c := range counted {
		if i > 0 && c.Entry == counted[i-1].Entry {
			return fmt.Errorf("page %s counts entry %s twice", p.Page, c.Entry)
		}
		if c.By == "" || c.Block <= 0 || c.Block > p.DecidedAt {
			return fmt.Errorf("page %s counts %s without the message and block that cast it before its decision",
				p.Page, c.Entry)
		}
		w.str(c.Entry)
		w.str(c.Vote)
		w.str(c.By)
		w.uint(uint64(c.Block))
		switch {
		case strings.HasPrefix(c.Entry, "key:"):
			if len(c.Entry) != len("key:")+64 {
				return fmt.Errorf("page %s counts %q, which is not a key hash", p.Page, c.Entry)
			}
		case strings.HasPrefix(c.Entry, "delegate:"):
			d, ok := delegates[strings.TrimPrefix(c.Entry, "delegate:")]
			if !ok {
				return fmt.Errorf("page %s counts %s without that delegate's own decision", p.Page, c.Entry)
			}
			used++
			if err := w.book(d, depth+1); err != nil {
				return fmt.Errorf("%s: %w", c.Entry, err)
			}
		default:
			return fmt.Errorf("page %s counts %q, which is neither a key nor a delegate", p.Page, c.Entry)
		}
	}
	if used != len(delegates) {
		return fmt.Errorf("page %s records %d delegate decision(s) and counts %d", p.Page, len(delegates), used)
	}
	return nil
}

// identityOfAccount is the ADI of an account URL: acc://x.acme/data -> x.acme.
func identityOfAccount(account string) string {
	s := strings.TrimPrefix(account, "acc://")
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	return s
}
