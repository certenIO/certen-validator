// Copyright 2026 Certen Protocol
//
// The canonical HASHED form of G0/G1/G2 for govRoot v2 (RB5-F19, owner decision D3 2026-09-29).
//
// Seven validators build G0/G1/G2 independently for the same execution, at slightly different times. For a quorum to
// certify one govRoot per intent, the hashed form must contain only facts fixed by the execution. Measured on
// production (RUNLOG_RB5 2026-09-29 22:40Z): 457 of 468 operations agreed, and every disagreement came from a read
// made at BUILD time rather than a fact of the execution:
//
//   - receipt.majorBlock: Accumulate assigns an entry's major block hours after the fact, so an early builder reads
//     null and a later one reads the number (G2 of 0x43372539: null vs 464). The receipt's terminus (start, anchor,
//     localBlock, end) is fixed at execution; only majorBlock is not. Cleared on every receipt.
//   - authority_snapshot.validation.totalEntries: the key page's main-chain length at the moment of the build
//     ("entries examined"), not at execution (G1 of 0x34b9c023: 5 vs 6). The execution-fixed facts - the genesis, the
//     mutations up to the execution block, the state in force - stay committed. Cleared.
//   - validated_signatures: their ORDER and the spelling of messageID depend on which signature route answered (a
//     transient primary-route failure yields the secondary route's evidence). The SET is the fact. Sorted by
//     (messageHash, publicKey), and messageID rewritten to the one canonical form acc://<messageHash>@<signer page>,
//     both lower case.
//   - outcome_leaf.payloadBinding.goVerifierOutput: the txhash tool's raw stdout, which depends on the binary. The
//     verified hash itself (computedTxHash) stays committed. Cleared.
//
// The stored results are NOT modified: these functions hash a canonical COPY. govRoot v1 (and its golden tests) is
// untouched; v2 is a new, separately tagged value.
package proof

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CanonicalG0JSONV2 returns the canonical hashed form of a G0 result.
func CanonicalG0JSONV2(g *G0Result) ([]byte, error) {
	if g == nil {
		return nil, fmt.Errorf("govRoot v2: no G0 result")
	}
	var c G0Result
	if err := deepCopyJSON(g, &c); err != nil {
		return nil, fmt.Errorf("govRoot v2: G0: %w", err)
	}
	canonicalizeG0(&c)
	return json.Marshal(&c)
}

// CanonicalG1JSONV2 returns the canonical hashed form of a G1 result.
func CanonicalG1JSONV2(g *G1Result) ([]byte, error) {
	if g == nil {
		return nil, fmt.Errorf("govRoot v2: no G1 result")
	}
	var c G1Result
	if err := deepCopyJSON(g, &c); err != nil {
		return nil, fmt.Errorf("govRoot v2: G1: %w", err)
	}
	if err := canonicalizeG1(&c); err != nil {
		return nil, err
	}
	return json.Marshal(&c)
}

// CanonicalG2JSONV2 returns the canonical hashed form of a G2 result.
func CanonicalG2JSONV2(g *G2Result) ([]byte, error) {
	if g == nil {
		return nil, fmt.Errorf("govRoot v2: no G2 result")
	}
	var c G2Result
	if err := deepCopyJSON(g, &c); err != nil {
		return nil, fmt.Errorf("govRoot v2: G2: %w", err)
	}
	if err := canonicalizeG1(&c.G1Result); err != nil {
		return nil, err
	}
	c.OutcomeLeaf.PayloadBinding.GoVerifierOutput = ""
	return json.Marshal(&c)
}

func canonicalizeG0(g *G0Result) {
	g.Receipt.MajorBlock = nil
}

func canonicalizeG1(g *G1Result) error {
	canonicalizeG0(&g.G0Result)
	snap := &g.AuthoritySnapshot
	snap.Validation.TotalEntries = 0
	snap.Genesis.Receipt.MajorBlock = nil
	for i := range snap.Mutations {
		snap.Mutations[i].Receipt.MajorBlock = nil
	}
	for i := range g.ValidatedSignatures {
		s := &g.ValidatedSignatures[i]
		s.Receipt.MajorBlock = nil
		hash := strings.ToLower(strings.TrimSpace(s.MessageHash))
		page := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s.Signature.Signer), "acc://"))
		if hash == "" || page == "" {
			return fmt.Errorf("govRoot v2: validated signature %d has no message hash or signer page", i)
		}
		s.MessageHash = hash
		s.MessageID = "acc://" + hash + "@" + page
	}
	sort.SliceStable(g.ValidatedSignatures, func(i, j int) bool {
		a, b := g.ValidatedSignatures[i], g.ValidatedSignatures[j]
		if a.MessageHash != b.MessageHash {
			return a.MessageHash < b.MessageHash
		}
		return strings.ToLower(a.Signature.PublicKey) < strings.ToLower(b.Signature.PublicKey)
	})
	for i := 1; i < len(g.ValidatedSignatures); i++ {
		a, b := g.ValidatedSignatures[i-1], g.ValidatedSignatures[i]
		if a.MessageHash == b.MessageHash && strings.EqualFold(a.Signature.PublicKey, b.Signature.PublicKey) {
			return fmt.Errorf("govRoot v2: the same signature (%s by %s) is listed twice", a.MessageHash, a.Signature.PublicKey)
		}
	}
	return nil
}

func deepCopyJSON(in, out interface{}) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
