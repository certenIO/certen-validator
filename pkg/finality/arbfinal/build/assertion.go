// Copyright 2026 Certen Protocol

package build

import (
	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality/arbfinal"
)

// TopicAssertionCreated is the topic0 of the Rollup's AssertionCreated event (annex A2).
var TopicAssertionCreated = common.HexToHash("0x901c3aee23cf4478825462caaab375c606ab83516060388344f0650340753630")

// createdDataWords is the number of 32-byte words of the AssertionCreated data (annex A2): AssertionInputs = beforeStateData
// (7 words: prevPrevAssertionHash, sequencerBatchAcc, ConfigData x5) + beforeState (6) + afterState (6), then
// afterInboxBatchAcc, inboxMaxCount, wasmModuleRoot, requiredStake, challengeManager, confirmPeriodBlocks.
const createdDataWords = 25

// Assertion is a decoded AssertionCreated event.
type Assertion struct {
	Hash      [32]byte
	Parent    [32]byte
	After     arbfinal.AfterState
	SeqAcc    [32]byte // afterInboxBatchAcc: the sequencerBatchAcc of the assertion hash preimage
	ParentCfg arbfinal.ParentConfig
	L1Block   uint64
	L1Hash    [32]byte
	// EndBlock is the L2 block number of After.BlockHash (read from the L2 header; 0 until looked up).
	EndBlock uint64
}

func wordU64(w []byte) (uint64, bool) {
	for _, b := range w[:24] {
		if b != 0 {
			return 0, false
		}
	}
	return binary.BigEndian.Uint64(w[24:]), true
}

// DecodeCreated decodes an AssertionCreated log and recomputes the assertion hash from its preimage: the recomputed value must
// equal the indexed topic, so a misdecoded field can never pass as a different assertion.
func DecodeCreated(l Log) (*Assertion, error) {
	if len(l.Topics) != 3 || l.Topics[0] != TopicAssertionCreated {
		return nil, fmt.Errorf("log is not an AssertionCreated event")
	}
	if len(l.Data) != createdDataWords*32 {
		return nil, fmt.Errorf("AssertionCreated data has %d bytes, want %d", len(l.Data), createdDataWords*32)
	}
	w := func(i int) []byte { return l.Data[32*i : 32*i+32] }
	u := func(i int) (uint64, error) {
		v, ok := wordU64(w(i))
		if !ok {
			return 0, fmt.Errorf("AssertionCreated word %d does not fit a uint64", i)
		}
		return v, nil
	}
	a := &Assertion{Hash: l.Topics[1], Parent: l.Topics[2], L1Block: l.Block, L1Hash: l.BlockHash}
	copy(a.ParentCfg.WasmModuleRoot[:], w(2))
	copy(a.ParentCfg.RequiredStake[:], w(3))
	if !allZero(w(4)[:12]) {
		return nil, fmt.Errorf("AssertionCreated challengeManager word has dirty high bytes")
	}
	copy(a.ParentCfg.ChallengeManager[:], w(4)[12:])
	var err error
	if a.ParentCfg.ConfirmPeriodBlocks, err = u(5); err != nil {
		return nil, err
	}
	if a.ParentCfg.NextInboxPosition, err = u(6); err != nil {
		return nil, err
	}
	copy(a.After.BlockHash[:], w(13))
	copy(a.After.SendRoot[:], w(14))
	if a.After.InboxPosition, err = u(15); err != nil {
		return nil, err
	}
	if a.After.PositionInMessage, err = u(16); err != nil {
		return nil, err
	}
	ms, err := u(17)
	if err != nil || ms > 0xff {
		return nil, fmt.Errorf("AssertionCreated machineStatus word is not a uint8")
	}
	a.After.MachineStatus = uint8(ms)
	copy(a.After.EndHistoryRoot[:], w(18))
	copy(a.SeqAcc[:], w(19))
	if got := arbfinal.AssertionHash(a.Parent, a.After, a.SeqAcc); got != a.Hash {
		return nil, fmt.Errorf("AssertionCreated preimage hashes to %x, the event's topic is %x", got[:4], a.Hash[:4])
	}
	return a, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// l1ReferenceOf is the L1 block number an Arbitrum header's mixHash states (nitro HeaderInfo: mixHash = sendCount(8) ||
// l1BlockNumber(8) || arbosVersion(8) || flags). It is a scan hint for the builder (where to start looking for events), never
// evidence.
func l1ReferenceOf(mixHash common.Hash) uint64 { return binary.BigEndian.Uint64(mixHash[8:16]) }
