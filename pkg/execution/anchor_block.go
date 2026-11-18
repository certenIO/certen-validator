// Copyright 2025 Certen Protocol
//
// The anchor block of a layer 5: the block the anchor-create transaction is in, its hash and its time, as the chain
// reports them for THAT transaction (AGT-F11).
//
// Since 2026-09-27 every anchor reference was written without the anchor block's hash and with no time, and every proof
// bundle stated anchored_at 0001-01-01: the anchor read-back went through the settlement observer, which proves a
// settlement in its block and does not answer for an anchor-create transaction, and when it did not answer the layer
// was written anyway, looking finished. A stranger's verifier rightly refuses such a reference ("anchor reference is
// well-formed"). The block is now read from the anchor transaction's own receipt (receipt block hash, header time by
// that hash), checked against the block the canonical row recorded, and a layer whose block was not read is a NAMED
// state, never a reference with the fields missing.

package execution

import (
	"errors"
	"fmt"
	"strings"
	"time"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
)

// AnchorBlockUnread is the state of a layer 5 whose anchor block has not been read off its chain. Such a layer is
// written with this state; no anchor reference and no bundle anchor component is produced from it.
const AnchorBlockUnread = "anchor_block_unread"

var (
	// ErrAnchorBlockUnread: the anchor transaction's receipt block (number, hash and time) was not read.
	ErrAnchorBlockUnread = errors.New(AnchorBlockUnread)
	// ErrAnchorBlockMismatch: the anchor transaction's receipt is in a different block than the one recorded for it.
	// Refused by name: neither block is picked silently.
	ErrAnchorBlockMismatch = errors.New("anchor_block_mismatch")
)

// completeAnchorBlock states l5's anchor block from anchorObs, the anchor transaction's own receipt as read from its
// chain. recordedBlock is the block the canonical row recorded for the anchor (0 when unknown). It never takes a value
// from the settlement observation: only anchorObs, and only when it is the anchor transaction's.
//
// On ErrAnchorBlockUnread the layer is marked with AnchorBlockUnread and keeps no block hash or time. On
// ErrAnchorBlockMismatch the caller refuses the layer.
func completeAnchorBlock(l5 *Layer5, recordedBlock int64, anchorObs *chain.ObservationResult) error {
	if l5 == nil {
		return nil
	}
	unread := func(why string) error {
		l5.BlockHash, l5.BlockTime, l5.Confirmations = "", time.Time{}, 0
		l5.AnchorBlock = AnchorBlockUnread
		return fmt.Errorf("%w{anchor=%s}: %s", ErrAnchorBlockUnread, l5.AnchorTx, why)
	}
	if anchorObs == nil || anchorObs.BlockNumber == 0 {
		return unread("the anchor transaction's receipt was not read")
	}
	if !strings.EqualFold(anchorObs.TxHash, l5.AnchorTx) {
		return unread(fmt.Sprintf("the reading is of transaction %s, not the anchor", anchorObs.TxHash))
	}
	if recordedBlock > 0 && uint64(recordedBlock) != anchorObs.BlockNumber {
		return fmt.Errorf("%w{anchor=%s,recorded=%d,receipt=%d}", ErrAnchorBlockMismatch, l5.AnchorTx, recordedBlock, anchorObs.BlockNumber)
	}
	if l5.BlockNumber != 0 && l5.BlockNumber != anchorObs.BlockNumber {
		return fmt.Errorf("%w{anchor=%s,layer=%d,receipt=%d}", ErrAnchorBlockMismatch, l5.AnchorTx, l5.BlockNumber, anchorObs.BlockNumber)
	}
	if !IsTransactionHash(anchorObs.BlockHash) { // a block hash has the same shape: 0x + 64 hex
		return unread(fmt.Sprintf("the receipt names no block hash (%q)", anchorObs.BlockHash))
	}
	if anchorObs.BlockTimestamp.IsZero() || anchorObs.BlockTimestamp.Unix() <= 0 {
		return unread("the anchor block's header time was not read")
	}
	l5.BlockNumber = anchorObs.BlockNumber
	l5.BlockHash = anchorObs.BlockHash
	l5.BlockTime = anchorObs.BlockTimestamp.UTC()
	l5.Confirmations = anchorObs.Confirmations
	l5.AnchorBlock = ""
	return nil
}

// anchorBlockComplete is nil only when l5 states its anchor block in full: number, hash and time. Every anchor reference
// and every bundle anchor component is gated on it.
func anchorBlockComplete(l5 *Layer5) error {
	switch {
	case l5 == nil:
		return fmt.Errorf("%w: no layer 5", ErrAnchorBlockUnread)
	case l5.AnchorBlock != "":
		return fmt.Errorf("%w{anchor=%s}: layer state %s", ErrAnchorBlockUnread, l5.AnchorTx, l5.AnchorBlock)
	case l5.BlockNumber == 0 || !IsTransactionHash(l5.BlockHash) || l5.BlockTime.IsZero() || l5.BlockTime.Unix() <= 0:
		return fmt.Errorf("%w{anchor=%s}: block %d, hash %q, time %s", ErrAnchorBlockUnread, l5.AnchorTx, l5.BlockNumber, l5.BlockHash, l5.BlockTime)
	}
	return nil
}
