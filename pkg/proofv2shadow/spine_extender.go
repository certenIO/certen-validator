package proofv2shadow

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/ledger"
)

// The spine extender keeps CERTEN's consensus-held Accumulate spine (execution rules v13) current: once the admin
// quorum has committed the genesis of the registry's incarnation, it submits the next major blocks this node has
// walked whenever the chain is behind. Every validator runs it. Each node builds the same
// transaction from the same committed state and the same Accumulate records, so concurrent submissions are identical
// bytes the mempool already holds; a submission the chain has moved past is refused by FinalizeBlock and changes
// nothing. The chain verifies every record itself: what a node submits is never trusted, only proposed.

// SpineChain is the committed state the extender reads.
type SpineChain interface {
	IntentCertificateContext() (string, *ledger.BLSRegistryRecord, error)
	CommittedAccumulateSpine() (*ledger.AccumulateSpineLog, error)
}

// Broadcast submits a transaction to CERTEN's chain.
type Broadcast func(ctx context.Context, tx []byte) error

const (
	spineExtendEvery = time.Minute
	// spineChunkRecords and spineChunkBytes keep one extension inside consensus.AccumulateSpineExtendTx's bounds
	// (100 records, 448 KiB decoded).
	spineChunkRecords = 100
	spineChunkBytes   = 400 << 10
)

// ExtendSpine runs until ctx ends.
func (l *Lazy) ExtendSpine(ctx context.Context, chain SpineChain, send Broadcast) {
	t := time.NewTicker(spineExtendEvery)
	defer t.Stop()
	last := ""
	for {
		if s := l.p.Load(); s != nil {
			msg, err := s.extendOnce(ctx, chain, send)
			switch {
			case err != nil:
				msg = "[PROOF-V2-SPINE] " + err.Error()
			case msg != "":
				msg = "[PROOF-V2-SPINE] " + msg
			}
			// Milestones only: a state is logged when it changes, not every minute.
			if msg != "" && msg != last {
				l.logf("%s", msg)
			}
			last = msg
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// extendOnce submits at most one transaction and says what it did, "" when the chain is current.
func (s *Shadow) extendOnce(ctx context.Context, chain SpineChain, send Broadcast) (string, error) {
	chainID, reg, err := chain.IntentCertificateContext()
	if err != nil {
		return "", err
	}
	if reg == nil {
		return "no BLS registry is in force, so no incarnation to hold a spine for", nil
	}
	if !strings.EqualFold(strings.TrimPrefix(reg.AccumulateIncarnation, "0x"), hex.EncodeToString(s.pin[:])) {
		return "", fmt.Errorf("the registry's incarnation %s is not this node's pinned %x: not proposing a spine", reg.AccumulateIncarnation, s.pin)
	}
	spine, err := chain.CommittedAccumulateSpine()
	if err != nil {
		return "", err
	}
	// The genesis is the admin quorum's act (validator-rotate spine-genesis): it switches the chain to v3 intent
	// certificates, so when it happens is governed, never a node's initiative. Until it is committed, nothing to extend.
	if spine.Genesis == nil || !strings.EqualFold(strings.TrimPrefix(spine.Genesis.Incarnation, "0x"), hex.EncodeToString(s.pin[:])) {
		return fmt.Sprintf("awaiting the admin-signed spine genesis of incarnation %x (validator-rotate spine-genesis)", s.pin), nil
	}
	if err := s.b.Refresh(ctx); err != nil {
		return "", fmt.Errorf("walk new major blocks: %w", err)
	}
	majors := s.b.Archive().Majors
	have := len(spine.Checkpoints)
	if have >= len(majors) {
		return "", nil
	}
	var recs []string
	size := 0
	for _, r := range majors[have:] {
		b, err := r.MarshalBinary()
		if err != nil {
			return "", err
		}
		if len(recs) == spineChunkRecords || (len(recs) > 0 && size+len(b) > spineChunkBytes) {
			break
		}
		recs, size = append(recs, hex.EncodeToString(b)), size+len(b)
	}
	tx := consensus.AccumulateSpineExtendTx{Kind: consensus.AccumulateSpineExtendKind, ChainID: chainID, First: uint64(have) + 1, Records: recs}
	what := fmt.Sprintf("proposed major blocks %d-%d (the chain has verified %d, this node has walked %d)", have+1, have+len(recs), have, len(majors))
	b, err := json.Marshal(tx)
	if err != nil {
		return "", err
	}
	if err := send(ctx, b); err != nil && !strings.Contains(err.Error(), "already exists in cache") {
		return "", fmt.Errorf("submit: %w", err)
	}
	return what, nil
}
