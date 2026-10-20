// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// Kind is the verifier of arb-sepolia/l1_posted/v1 (spec 5.6). It is pure: no I/O, no clock, no randomness.
type Kind struct{}

// New returns the verifier.
func New() *Kind { return &Kind{} }

func (*Kind) Name() string          { return KindName }
func (*Kind) Chain() uint64         { return finality.ChainArbitrumSepolia }
func (*Kind) Level() finality.Level { return finality.LevelL1Posted }
func (k *Kind) String() string      { return KindName }

func boundsFor(p ethl1.Pins, a *arbPins) Bounds {
	lim := finality.DefaultLimits()
	lim.MaxBlobsArbitrum = a.MaxBlobs
	lim.MaxSegments = a.MaxSegments
	lim.MaxUncompressedBatch = a.MaxUncompressedBatch
	return Bounds{Limits: lim, MaxLinks: p.MaxLinks, MaxSpineHeaders: p.MaxSpineHeaders, MaxBlobs: a.MaxBlobs}
}

// EIP-1967 implementation slot.
var eip1967ImplSlot = common.HexToHash("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")

// The Arbitrum transaction types a block can hold (nitro arbos/types): signed standard types 0-4; the internal start-block
// 0x6a and the execution-derived retry 0x68 are tolerated; 0x64/0x65/0x66/0x69 originate from the delayed inbox.
const (
	txRetry    = 0x68
	txInternal = 0x6a
)

func isDelayedOriginType(t uint8) bool {
	return t == 0x64 || t == 0x65 || t == 0x66 || t == 0x69
}

func w32(v uint64) common.Hash {
	var h common.Hash
	binary.BigEndian.PutUint64(h[24:], v)
	return h
}

// arrayElementSlot is the storage slot of element n of the dynamic array declared at slot base: keccak256(w(base)) + n.
func arrayElementSlot(base uint64, n uint64) common.Hash {
	b := new(big.Int).SetBytes(crypto.Keccak256(w32(base).Bytes()))
	b.Add(b, new(big.Int).SetUint64(n))
	return common.BigToHash(b)
}

func header40(h [5]uint64) []byte {
	out := make([]byte, 0, 40)
	for _, v := range h {
		out = binary.BigEndian.AppendUint64(out, v)
	}
	return out
}

// DataHash is the SequencerInbox dataHash of a batch: keccak256(header40 || 0x50 || versionedHashes...) for blobs,
// keccak256(header40 || data) for calldata (annex A6.2).
func DataHash(e Evidence) [32]byte {
	var buf []byte
	buf = append(buf, header40(e.Header40)...)
	if e.DataKind == DataBlobs {
		buf = append(buf, 0x50)
		for _, h := range e.VersionedHashes {
			buf = append(buf, h[:]...)
		}
	} else {
		buf = append(buf, e.Calldata...)
	}
	return crypto.Keccak256Hash(buf)
}

// Accumulator is Bridge.sequencerInboxAccs[N] for a batch: keccak256(beforeAcc || dataHash || delayedAcc).
func Accumulator(beforeAcc, dataHash, delayedAcc [32]byte) [32]byte {
	return crypto.Keccak256Hash(beforeAcc[:], dataHash[:], delayedAcc[:])
}

// DelayedMessageHash is Messages.messageHash (annex A6.5): keccak256(kind u8, sender, blockNumber u64, timestamp u64,
// inboxSeqNum u256 = k, baseFeeL1 u256, keccak256(data)).
func DelayedMessageHash(d Delayed) [32]byte {
	var b []byte
	b = append(b, d.MsgKind)
	b = append(b, d.Sender[:]...)
	b = binary.BigEndian.AppendUint64(b, d.MsgBlockNumber)
	b = binary.BigEndian.AppendUint64(b, d.MsgTimestamp)
	b = append(b, w32(d.K).Bytes()...)
	b = append(b, d.BaseFeeL1[:]...)
	b = append(b, crypto.Keccak256(d.Data)...)
	return crypto.Keccak256Hash(b)
}

// Verify judges the whole CFE1 container of one leg block (spec 5.6). The order of the checks is the order of annex A6.3
// (the first failing check names the state): pins and pre-BoLD, block transactions root, L1 finality, Bridge identity, the
// accumulator, the blobs, the payload decode and the match.
func (k *Kind) Verify(p *finality.Pins, b finality.BlockRef, evidence []byte) (finality.Verdict, error) {
	c, err := finality.DecodeContainer(evidence, finality.DefaultLimits())
	if err != nil {
		return finality.Verdict{}, err
	}
	if c.Header.Kind != KindName || c.Header.Chain != finality.ChainArbitrumSepolia || c.Header.Level != finality.LevelL1Posted {
		return finality.Verdict{}, finality.EvidenceUnrecognised(c.Header.Kind, "")
	}
	arb, err := loadArbPins(p)
	if err != nil {
		return finality.Verdict{}, err
	}
	l1p, kzgPin, err := ethl1Pins(p)
	if err != nil {
		return finality.Verdict{}, err
	}
	if kzgPin != UsedKZGSetupSHA256 {
		return finality.Verdict{}, PinMismatch(pinKZG)
	}
	e, err := Decode(c.Body, boundsFor(l1p, arb))
	if err != nil {
		return finality.Verdict{}, err
	}
	hdr, err := finality.ReadHeader(b.HeaderRLP)
	if err != nil {
		return finality.Verdict{}, err
	}
	if hdr.Number <= arb.BoldGenesisL2Block {
		return finality.Verdict{}, finality.NewState(CodePreBold, "n", hdr.Number, "bold_genesis_l2_block", arb.BoldGenesisL2Block)
	}
	return k.verifyBody(arb, l1p, b, hdr, e)
}

func (k *Kind) verifyBody(arb *arbPins, l1p ethl1.Pins, b finality.BlockRef, hdr finality.HeaderFields, e Evidence) (finality.Verdict, error) {
	// annex step 1: the carried transaction list is the block's.
	if ethproof.TrieRoot(e.BlockTxs) != common.Hash(hdr.TransactionRoot) {
		return finality.Verdict{}, contentNotFound(ContentBlockTxsRootMismatch, "batch", e.BatchSeq)
	}
	if e.DataKind == DataNone {
		return finality.Verdict{}, contentNotFound(ContentNoDataBatch, "batch", e.BatchSeq)
	}
	// annex step 2 / 5.2: the L1 finalized head, and the state block on its covered spine.
	head, err := ethl1.VerifyFinalizedHead(l1p, e.LC)
	if err != nil {
		return finality.Verdict{}, l1FinalityUnproven(L1FinalityLCRefused, innerCode(err))
	}
	covered, err := head.Covers(e.L1Spine, l1p.MaxSpineHeaders)
	if err != nil {
		return finality.Verdict{}, l1FinalityUnproven(L1FinalitySpineRefused, innerCode(err))
	}
	s, err := ethl1.BlockAt(covered, e.StateBlock)
	if err != nil {
		return finality.Verdict{}, asState(err)
	}
	return k.verifyState(arb, s, b, hdr, e)
}

// verifyState is the part of the judgement that runs under the state root of the covered L1 block S: the Bridge identity, the
// accumulator, the blobs, the payload decode and the match. It is separate so that tests can give it a state built in memory.
func (k *Kind) verifyState(arb *arbPins, s ethl1.L1Block, b finality.BlockRef, hdr finality.HeaderFields, e Evidence) (finality.Verdict, error) {
	root := common.Hash(s.StateRoot)

	// 5.6 O2: the Bridge account under stateRoot_S, its EIP-1967 implementation, the pinned implementation code hash.
	bridge, err := ethproof.VerifyAccount(root, arb.bridge, e.Nodes)
	if err != nil {
		return finality.Verdict{}, stateProofInvalid("account")
	}
	if !bridge.Exists {
		return finality.Verdict{}, contractIdentity(bridgeImplRole, arb.bridge[:], make([]byte, 32), s.Number)
	}
	implWord, err := ethproof.VerifySlot(bridge.StorageRoot, eip1967ImplSlot, e.Nodes)
	if err != nil {
		return finality.Verdict{}, stateProofInvalid("slot")
	}
	impl := common.BytesToAddress(implWord[12:])
	implAcct, err := ethproof.VerifyAccount(root, impl, e.Nodes)
	if err != nil {
		return finality.Verdict{}, stateProofInvalid("account")
	}
	if !bytes.Equal(implWord[:12], make([]byte, 12)) || !implAcct.Exists || !arb.pinnedBridgeImpl(implAcct.CodeHash) {
		return finality.Verdict{}, contractIdentity(bridgeImplRole, impl[:], implAcct.CodeHash[:], s.Number)
	}

	// 5.6 O3: acc_N and the recomputed accumulator.
	accWord, err := ethproof.VerifySlot(bridge.StorageRoot, arrayElementSlot(arb.Layout.AccArraySlot, e.BatchSeq), e.Nodes)
	if err != nil {
		return finality.Verdict{}, stateProofInvalid("slot")
	}
	if e.DataKind == DataCalldata {
		if len(e.Calldata) == 0 {
			return finality.Verdict{}, finality.NewState(CodeBatchHeaderUnknown, "batch", e.BatchSeq)
		}
		switch e.Calldata[0] {
		case headerBrotli, headerZeroheavy, headerDAS, headerDASTree:
		default:
			return finality.Verdict{}, finality.NewState(CodeBatchHeaderUnknown, "batch", e.BatchSeq, "byte", e.Calldata[0])
		}
	}
	if Accumulator(e.BeforeAcc, DataHash(e), e.DelayedAcc) != [32]byte(accWord) {
		return finality.Verdict{}, contentNotFound(ContentAccumulatorMismatch, "batch", e.BatchSeq)
	}

	// 5.6 O4: blobs.
	var payload []byte
	if e.DataKind == DataBlobs {
		if len(e.Blobs) != len(e.VersionedHashes) {
			return finality.Verdict{}, blobMismatch()
		}
		raws := make([][]byte, len(e.Blobs))
		for j := range e.Blobs {
			if err := verifyBlob(e.Blobs[j], e.VersionedHashes[j]); err != nil {
				return finality.Verdict{}, err
			}
			raws[j] = e.Blobs[j].Raw
		}
		payload, err = decodeBlobs(raws)
		if err != nil {
			return finality.Verdict{}, contentNotFound(ContentPayloadUndecodable, "batch", e.BatchSeq)
		}
	} else {
		payload = e.Calldata
	}
	res := decodePayload(payload, arb.MaxUncompressedBatch, arb.MaxSegments)
	switch res.status {
	case payloadOffL1:
		return finality.Verdict{}, finality.NewState(CodeBatchDataOffL1, "batch", e.BatchSeq, "header_byte", res.headerByte)
	case payloadUnknownHeader:
		return finality.Verdict{}, finality.NewState(CodeBatchHeaderUnknown, "batch", e.BatchSeq, "byte", res.headerByte)
	case payloadUndecodable:
		return finality.Verdict{}, contentNotFound(ContentPayloadUndecodable, "batch", e.BatchSeq)
	case payloadTooLarge:
		if res.exceededUncompressed {
			return finality.Verdict{}, finality.EvidenceTooLarge("uncompressed_batch", uint64(arb.MaxUncompressedBatch)+1, uint64(arb.MaxUncompressedBatch))
		}
		return finality.Verdict{}, finality.EvidenceTooLarge("segments", uint64(arb.MaxSegments)+1, uint64(arb.MaxSegments))
	}

	// annex steps 7-8: classify the block's transactions and match one message.
	var std [][]byte
	var types []uint64
	delayedOrigin := false
	for _, tx := range e.BlockTxs {
		t := ethproof.TxType(tx)
		types = append(types, uint64(t))
		switch {
		case t <= 4:
			std = append(std, tx)
		case t == txInternal || t == txRetry:
		case isDelayedOriginType(t):
			delayedOrigin = true
		default:
			return finality.Verdict{}, contentNotFound(ContentUnsupportedTxType, "batch", e.BatchSeq, "tx_type", uint64(t))
		}
	}
	var delayedK *uint64
	if delayedOrigin {
		nonce, _ := headerNonce(b.HeaderRLP)
		kk, err := verifyDelayed(arb, root, bridge, e, res, types, nonce)
		if err != nil {
			return finality.Verdict{}, err
		}
		delayedK = &kk
	}
	if len(std) == 0 && !delayedOrigin {
		return finality.Verdict{}, contentNotFound(ContentNoStandardTransactions, "batch", e.BatchSeq)
	}
	ordinal := -1
	if len(std) > 0 {
		for _, m := range res.messages {
			if sameTxs(std, m.txs) {
				ordinal = m.ordinal
				break
			}
		}
		if ordinal < 0 {
			return finality.Verdict{}, contentNotFound(ContentNoMatchingMessage, "batch", e.BatchSeq, "messages_scanned", uint64(len(res.messages)), "segments", uint64(res.segments))
		}
	}
	fields := map[string]any{
		"batch_sequence_number": e.BatchSeq,
		"blobs":                 uint64(len(e.Blobs)),
		"l1_state_block":        s.Number,
		"l1_state_block_hash":   s.Hash,
		"messages":              uint64(len(res.messages)),
		"statement":             Statement,
	}
	if ordinal >= 0 {
		fields["message_ordinal"] = uint64(ordinal)
	}
	if delayedK != nil {
		fields["delayed_message_index"] = *delayedK
	}
	return finality.Verdict{Level: finality.LevelL1Posted, Kind: KindName, Fields: fields}, nil
}

func innerCode(err error) string {
	if f, ok := err.(*ethl1.Fault); ok {
		return f.Code
	}
	if s, ok := finality.AsNamed(err); ok {
		return s.Code
	}
	return "unknown"
}

func asState(err error) error {
	if f, ok := err.(*ethl1.Fault); ok {
		return FaultState(f)
	}
	return err
}

func sameTxs(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// verifyBlob checks one blob against its versioned hash: the commitment hashes to the versioned hash, and the blob proof
// verifies under the pinned setup (the Go backend's embedded setup, UsedKZGSetupSHA256).
func verifyBlob(bl Blob, want [32]byte) error {
	var kb kzg4844.Blob
	copy(kb[:], bl.Raw)
	commit := kzg4844.Commitment(bl.Commitment)
	if kzg4844.CalcBlobHashV1(sha256.New(), &commit) != want {
		return blobMismatch()
	}
	if err := kzg4844.VerifyBlobProof(&kb, commit, kzg4844.Proof(bl.Proof)); err != nil {
		return blobMismatch()
	}
	return nil
}
