// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"errors"
	"math/big"
	"math/rand"
	"runtime"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// The expected encoding comes from go-ethereum's accounts/abi (an independent implementation); the decoder under test is abi.go.

type tGov struct {
	KeyBookURL         string
	KeyBookRoot        [32]byte
	KeyPageProofs      [][32]byte
	AuthorityAddress   common.Address
	AuthorityLevel     uint8
	Nonce              *big.Int
	RequiredSignatures *big.Int
	ProvidedSignatures *big.Int
	ThresholdMet       bool
}
type tBLS struct {
	AggregateSignature []byte
	ValidatorAddresses []common.Address
	VotingPowers       []*big.Int
	TotalVotingPower   *big.Int
	SignedVotingPower  *big.Int
	ThresholdMet       bool
	MessageHash        [32]byte
}
type tCommit struct {
	OperationCommitment  [32]byte
	CrossChainCommitment [32]byte
	GovernanceRoot       [32]byte
	ExecutionCommitment  [32]byte
	SourceChain          string
	SourceBlockHeight    *big.Int
	SourceTxHash         [32]byte
	TargetChain          string
	TargetAddress        common.Address
}
type tProof struct {
	TransactionHash [32]byte
	MerkleRoot      [32]byte
	ProofHashes     [][32]byte
	LeafHash        [32]byte
	GovernanceProof tGov
	BlsProof        tBLS
	Commitments     tCommit
	ExpirationTime  *big.Int
	Metadata        []byte
}
type tADI struct {
	AdiURL              string
	AnchorId            [32]byte
	MerkleProof         [][32]byte
	OperationID         [32]byte
	KeyBookProof        []byte
	RoleProof           []byte
	ThresholdProof      []byte
	Timestamp           *big.Int
	ExpiresAt           *big.Int
	ValidatorSignatures []byte
	Nonce               *big.Int
	AuthorityBook       [32]byte
	AuthorityPage       uint64
	NotBefore           uint64
	NotAfter            uint64
}

func am(name, typ string, comps ...abi.ArgumentMarshaling) abi.ArgumentMarshaling {
	return abi.ArgumentMarshaling{Name: name, Type: typ, Components: comps}
}

func mustType(t *testing.T, typ string, comps ...abi.ArgumentMarshaling) abi.Type {
	t.Helper()
	ty, err := abi.NewType(typ, "", comps)
	if err != nil {
		t.Fatal(err)
	}
	return ty
}

func proofTypeT(t *testing.T) abi.Type {
	return mustType(t, "tuple",
		am("transactionHash", "bytes32"), am("merkleRoot", "bytes32"), am("proofHashes", "bytes32[]"), am("leafHash", "bytes32"),
		am("governanceProof", "tuple", am("keyBookURL", "string"), am("keyBookRoot", "bytes32"), am("keyPageProofs", "bytes32[]"), am("authorityAddress", "address"),
			am("authorityLevel", "uint8"), am("nonce", "uint256"), am("requiredSignatures", "uint256"), am("providedSignatures", "uint256"), am("thresholdMet", "bool")),
		am("blsProof", "tuple", am("aggregateSignature", "bytes"), am("validatorAddresses", "address[]"), am("votingPowers", "uint256[]"),
			am("totalVotingPower", "uint256"), am("signedVotingPower", "uint256"), am("thresholdMet", "bool"), am("messageHash", "bytes32")),
		am("commitments", "tuple", am("operationCommitment", "bytes32"), am("crossChainCommitment", "bytes32"), am("governanceRoot", "bytes32"), am("executionCommitment", "bytes32"),
			am("sourceChain", "string"), am("sourceBlockHeight", "uint256"), am("sourceTxHash", "bytes32"), am("targetChain", "string"), am("targetAddress", "address")),
		am("expirationTime", "uint256"), am("metadata", "bytes"))
}

func adiTypeT(t *testing.T) abi.Type {
	return mustType(t, "tuple", am("adiURL", "string"), am("anchorId", "bytes32"), am("merkleProof", "bytes32[]"), am("operationID", "bytes32"),
		am("keyBookProof", "bytes"), am("roleProof", "bytes"), am("thresholdProof", "bytes"), am("timestamp", "uint256"), am("expiresAt", "uint256"),
		am("validatorSignatures", "bytes"), am("nonce", "uint256"), am("authorityBook", "bytes32"), am("authorityPage", "uint64"), am("notBefore", "uint64"), am("notAfter", "uint64"))
}

func b32(n byte) [32]byte { return [32]byte(bytes.Repeat([]byte{n}, 32)) }

func honestProof(nVals int) tProof {
	p := tProof{
		TransactionHash: b32(1), MerkleRoot: b32(2), ProofHashes: [][32]byte{b32(3), b32(4), b32(5)}, LeafHash: b32(6),
		GovernanceProof: tGov{KeyBookURL: "acc://rb7.acme/book", KeyBookRoot: b32(7), KeyPageProofs: [][32]byte{b32(8)}, AuthorityAddress: common.HexToAddress("0x91C798AA0Ad11d2670029b3B0572d154bd42c059"),
			AuthorityLevel: 3, Nonce: big.NewInt(9), RequiredSignatures: big.NewInt(2), ProvidedSignatures: big.NewInt(3), ThresholdMet: true},
		BlsProof: tBLS{AggregateSignature: zkBlobBytes(), TotalVotingPower: big.NewInt(int64(nVals)), SignedVotingPower: big.NewInt(int64(nVals)), ThresholdMet: true, MessageHash: b32(12)},
		Commitments: tCommit{OperationCommitment: b32(13), CrossChainCommitment: b32(14), GovernanceRoot: b32(15), ExecutionCommitment: b32(16), SourceChain: "accumulate", SourceBlockHeight: big.NewInt(1234),
			SourceTxHash: b32(17), TargetChain: "ethereum-sepolia", TargetAddress: common.HexToAddress("0xb4Ea0cDA7b4755751293cb6d9b8D6027E05077BA")},
		ExpirationTime: big.NewInt(1999999999), Metadata: []byte("meta"),
	}
	for i := 0; i < nVals; i++ {
		p.BlsProof.ValidatorAddresses = append(p.BlsProof.ValidatorAddresses, common.BigToAddress(big.NewInt(int64(i+1))))
		p.BlsProof.VotingPowers = append(p.BlsProof.VotingPowers, big.NewInt(1))
	}
	return p
}

func zkBlobBytes() []byte {
	blob := make([]byte, 0, 18*32)
	for i := 0; i < 18; i++ {
		w := b32(byte(0x40 + i))
		if i >= 14 { // numbers
			w = [32]byte{}
			w[31] = byte(i)
		}
		blob = append(blob, w[:]...)
	}
	return blob
}

func packProofCall(t *testing.T, anchorID [32]byte, p tProof) []byte {
	t.Helper()
	b32t := mustType(t, "bytes32")
	args := abi.Arguments{{Type: b32t}, {Type: proofTypeT(t)}}
	enc, err := args.Pack(anchorID, p)
	if err != nil {
		t.Fatal(err)
	}
	sel := Selector4(SigExecuteComprehensiveProof)
	return append(sel[:], enc...)
}

func proofOfCall(c *ComprehensiveProofCall) tProof {
	return tProof{
		TransactionHash: c.TransactionHash, MerkleRoot: c.MerkleRoot, ProofHashes: c.ProofHashes, LeafHash: c.LeafHash,
		GovernanceProof: tGov{KeyBookURL: c.Governance.KeyBookURL, KeyBookRoot: c.Governance.KeyBookRoot, KeyPageProofs: c.Governance.KeyPageProofs,
			AuthorityAddress: c.Governance.AuthorityAddress, AuthorityLevel: c.Governance.AuthorityLevel, Nonce: c.Governance.Nonce,
			RequiredSignatures: c.Governance.RequiredSignatures, ProvidedSignatures: c.Governance.ProvidedSignatures, ThresholdMet: c.Governance.ThresholdMet},
		BlsProof: tBLS{AggregateSignature: c.BLS.AggregateSignature, ValidatorAddresses: c.BLS.ValidatorAddresses, VotingPowers: c.BLS.VotingPowers,
			TotalVotingPower: c.BLS.TotalVotingPower, SignedVotingPower: c.BLS.SignedVotingPower, ThresholdMet: c.BLS.ThresholdMet, MessageHash: c.BLS.MessageHash},
		Commitments: tCommit{OperationCommitment: c.Commitments.OperationCommitment, CrossChainCommitment: c.Commitments.CrossChainCommitment, GovernanceRoot: c.Commitments.GovernanceRoot,
			ExecutionCommitment: c.Commitments.ExecutionCommitment, SourceChain: c.Commitments.SourceChain, SourceBlockHeight: c.Commitments.SourceBlockHeight,
			SourceTxHash: c.Commitments.SourceTxHash, TargetChain: c.Commitments.TargetChain, TargetAddress: c.Commitments.TargetAddress},
		ExpirationTime: c.ExpirationTime, Metadata: c.Metadata,
	}
}

func wantABI(t *testing.T, err error, kind ABIKind) *ABIError {
	t.Helper()
	var ae *ABIError
	if !errors.As(err, &ae) || ae.Kind != kind {
		t.Fatalf("want abi %s, got %v", kind, err)
	}
	return ae
}

func TestABISelectorsAndTopicsEqualManifest(t *testing.T) {
	m, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	rows := m.Selectors()
	if len(rows) < 9 {
		t.Fatalf("%d selector rows", len(rows))
	}
	for _, s := range rows { // every manifest row: the literal equals keccak256(signature)[:4]
		got := Selector4(s.Signature)
		if "0x"+common.Bytes2Hex(got[:]) != s.Selector {
			t.Fatalf("%s/%s: %s derives 0x%x, manifest %s", s.Contract, s.Function, s.Signature, got, s.Selector)
		}
	}
	// the literals of the specification, by signature constant
	for sig, want := range map[string]string{
		SigExecuteComprehensiveProof: "0x4ca9d0c8", SigExecuteGovernanceDirect: "0x606f2c8d", SigBatchGovernanceDirect: "0x329fe012",
	} {
		got := Selector4(sig)
		if "0x"+common.Bytes2Hex(got[:]) != want {
			t.Fatalf("%s derives 0x%x, want %s", sig, got, want)
		}
		found := false
		for _, s := range rows {
			found = found || (s.Signature == sig && s.Selector == want)
		}
		if !found {
			t.Fatalf("%s is no manifest selector row", sig)
		}
	}
	// the older generations the decoder must NOT decode: the V7 selectors of the spec (0x5b1264bc, 0xb9408c5b) and V7_2
	for _, lit := range []string{"0x5b1264bc", "0xb9408c5b", "0x57f8567d", "0xb7daa901"} {
		found := false
		for _, s := range rows {
			if s.Selector == lit {
				found = true
				if s.Pinned {
					t.Fatalf("%s is pinned", lit)
				}
				if _, err := DecodeSettlementCall(append(common.FromHex(lit), make([]byte, 32)...), DefaultABILimits()); err == nil {
					t.Fatalf("%s decoded", lit)
				} else {
					wantABI(t, err, ABISelector)
				}
			}
		}
		if !found {
			t.Fatalf("%s is no manifest row", lit)
		}
	}
	// topics: the manifest rows and the account events
	topics := map[string]string{
		SigProofExecuted:       "0xaafab89926d77fbd622e61cfa62ca5de53bbde4f6686f2c46842b4e3a41f767d",
		SigLeafConsumed:        "0xf65d46899882fe56bab13370dcd464db22e179625c161992c07d962286f7ea73",
		SigGovernanceOperation: "0x74b66e509fa5263d4932860a2e1f6d187381ae68dee216710283b8677703ff12",
		SigGovernanceBatch:     "0xcbcdc100c8089d25ab823b5044f746670e86a90b18c729bc7d27b7ce78733c56",
	}
	for sig, want := range topics {
		if got := TopicOf(sig); got.Hex() != want {
			t.Fatalf("%s derives %s, want %s", sig, got.Hex(), want)
		}
	}
	for name, sig := range map[string]string{"ProofExecuted": SigProofExecuted, "LeafConsumed": SigLeafConsumed} {
		tp, ok := m.Topic(name)
		if !ok || tp.Signature != sig || tp.Topic0 != TopicOf(sig).Hex() {
			t.Fatalf("manifest topic %s: %+v", name, tp)
		}
	}
	ev := m.AccountEventTopics()
	for name, sig := range map[string]string{"GovernanceOperationExecuted": SigGovernanceOperation, "GovernanceBatchExecuted": SigGovernanceBatch, "LeafConsumed": SigLeafConsumed} {
		if ev[name].Signature != sig || ev[name].Topic0 != TopicOf(sig).Hex() {
			t.Fatalf("manifest account event %s: %+v", name, ev[name])
		}
	}
}

func TestComprehensiveProofCallRoundTrip(t *testing.T) {
	anchor := b32(0xaa)
	p := honestProof(7)
	cd := packProofCall(t, anchor, p)
	c, err := DecodeComprehensiveProofCall(cd, DefaultABILimits())
	if err != nil {
		t.Fatal(err)
	}
	if c.AnchorID != anchor || c.BLS.MessageHash != b32(12) || c.Commitments.OperationCommitment != b32(13) || c.Governance.AuthorityLevel != 3 ||
		len(c.BLS.ValidatorAddresses) != 7 || c.BLS.TotalVotingPower.Int64() != 7 || c.BLS.SignedVotingPower.Int64() != 7 || len(c.ProofHashes) != 3 ||
		c.Governance.KeyBookURL != "acc://rb7.acme/book" || c.Commitments.TargetChain != "ethereum-sepolia" || string(c.Metadata) != "meta" {
		t.Fatalf("decoded %+v", c)
	}
	// the blob layout words 12-15 of step 17
	z, err := DecodeZKBlob(c.BLS.AggregateSignature)
	if err != nil {
		t.Fatal(err)
	}
	if z.MessageHash != b32(0x40+12) || z.PubkeyCommitment != b32(0x40+13) || z.SignedVotingPower.Int64() != 14 || z.TotalVotingPower.Int64() != 15 ||
		z.ThresholdNumerator.Int64() != 16 || z.ThresholdDenominator.Int64() != 17 || z.Length != 576 {
		t.Fatalf("blob %+v", z)
	}
	// re-encoding the decoded value gives the input bytes
	if re := packProofCall(t, c.AnchorID, proofOfCall(c)); !bytes.Equal(re, cd) {
		t.Fatal("encode(decode(x)) != x")
	}
}

func TestComprehensiveProofEveryTruncationAndTrailingByteIsRefused(t *testing.T) {
	cd := packProofCall(t, b32(0xaa), honestProof(3))
	for n := 0; n < len(cd); n++ {
		if _, err := DecodeComprehensiveProofCall(cd[:n], DefaultABILimits()); err == nil {
			t.Fatalf("a truncation to %d of %d bytes decoded", n, len(cd))
		}
	}
	for _, extra := range [][]byte{{0}, {1}, make([]byte, 32), make([]byte, 33)} {
		_, err := DecodeComprehensiveProofCall(append(append([]byte{}, cd...), extra...), DefaultABILimits())
		wantABI(t, err, ABITrailing)
	}
	// wrong selector
	bad := append([]byte{}, cd...)
	bad[0] ^= 1
	wantABI(t, func() error { _, e := DecodeComprehensiveProofCall(bad, DefaultABILimits()); return e }(), ABISelector)
}

// canonicalProperty mutates every byte of cd three ways and requires: no panic, and whatever still decodes re-encodes to exactly the
// mutated input (so no malleable encoding is accepted).
func canonicalProperty(t *testing.T, cd []byte, decodeRepack func([]byte) ([]byte, error)) (accepted, refused int) {
	t.Helper()
	for i := range cd {
		for _, v := range []byte{cd[i] ^ 0x01, 0x00, 0xff} {
			if v == cd[i] {
				continue
			}
			mut := append([]byte{}, cd...)
			mut[i] = v
			re, err := decodeRepack(mut)
			if err != nil {
				refused++
				continue
			}
			accepted++
			if !bytes.Equal(re, mut) {
				t.Fatalf("byte %d := %#x decoded to a value that re-encodes differently (malleable encoding accepted)", i, v)
			}
		}
	}
	return
}

func TestComprehensiveProofCanonicalProperty(t *testing.T) {
	cd := packProofCall(t, b32(0xaa), honestProof(3))
	acc, ref := canonicalProperty(t, cd, func(in []byte) ([]byte, error) {
		c, err := DecodeComprehensiveProofCall(in, DefaultABILimits())
		if err != nil {
			return nil, err
		}
		return packProofCall(t, c.AnchorID, proofOfCall(c)), nil
	})
	if acc == 0 || ref == 0 {
		t.Fatalf("accepted %d refused %d", acc, ref)
	}
	t.Logf("every single-byte mutation of a %d byte calldata: %d decode (and re-encode identically), %d refused", len(cd), acc, ref)
}

func offsetWordPositions() []int {
	// executeComprehensiveProof args: word 1 = offset of the proof tuple (0x40); inside the tuple (head 9 words at 0x40): offsets of
	// proofHashes (idx 2), governanceProof (4), blsProof (5), commitments (6), metadata (8)
	pos := []int{4 + 32}
	for _, idx := range []int{2, 4, 5, 6, 8} {
		pos = append(pos, 4+0x40+32*idx)
	}
	return pos
}

func TestComprehensiveProofOffsetsMustBeCanonical(t *testing.T) {
	cd := packProofCall(t, b32(0xaa), honestProof(3))
	for _, p := range offsetWordPositions() {
		orig := new(big.Int).SetBytes(cd[p : p+32])
		for _, delta := range []int64{32, -32, 1, 31, 64} { // a gap, an overlap with the previous tail, misaligned
			mut := append([]byte{}, cd...)
			new(big.Int).Add(orig, big.NewInt(delta)).FillBytes(mut[p : p+32])
			_, err := DecodeComprehensiveProofCall(mut, DefaultABILimits())
			wantABI(t, err, ABIOffset)
		}
		for _, huge := range []*big.Int{new(big.Int).Lsh(big.NewInt(1), 64), new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(int64(len(cd))), big.NewInt(0)} {
			mut := append([]byte{}, cd...)
			huge.FillBytes(mut[p : p+32])
			_, err := DecodeComprehensiveProofCall(mut, DefaultABILimits())
			wantABI(t, err, ABIOffset)
		}
	}
	// two fields pointing at the same tail (overlapping): governanceProof and blsProof offsets equal
	g, b := 4+0x40+32*4, 4+0x40+32*5
	mut := append([]byte{}, cd...)
	copy(mut[b:b+32], mut[g:g+32])
	_, err := DecodeComprehensiveProofCall(mut, DefaultABILimits())
	wantABI(t, err, ABIOffset)
	// out of order: swap the governanceProof and blsProof offsets
	mut = append([]byte{}, cd...)
	copy(mut[g:g+32], cd[b:b+32])
	copy(mut[b:b+32], cd[g:g+32])
	_, err = DecodeComprehensiveProofCall(mut, DefaultABILimits())
	wantABI(t, err, ABIOffset)
}

func TestComprehensiveProofPaddingAndWords(t *testing.T) {
	p := honestProof(3)
	p.Metadata = []byte("abc") // 3 bytes: 29 bytes of padding
	cd := packProofCall(t, b32(0xaa), p)
	// the metadata tail is last: length word then one padded word
	last := len(cd) - 32
	mut := append([]byte{}, cd...)
	mut[last+31] = 1
	_, err := DecodeComprehensiveProofCall(mut, DefaultABILimits())
	wantABI(t, err, ABIPadding)
	mut = append([]byte{}, cd...)
	mut[last+2] = 1 // inside the data bytes: changes the value, still valid
	if _, err := DecodeComprehensiveProofCall(mut, DefaultABILimits()); err != nil {
		t.Fatal(err)
	}
	// authorityLevel is a uint8: a bit above 8 is refused; authorityAddress (idx 3) with a high byte; thresholdMet (idx 8) = 2
	govStart := func() int { // absolute position of the governanceProof tuple
		off := new(big.Int).SetBytes(cd[4+0x40+32*4 : 4+0x40+32*5]).Int64()
		return 4 + 0x40 + int(off)
	}()
	for _, c := range []struct {
		name string
		pos  int
		val  byte
	}{{"uint8 level 256", govStart + 32*4 + 30, 1}, {"address high byte", govStart + 32*3, 1}, {"bool 2", govStart + 32*8 + 31, 2}} {
		mut := append([]byte{}, cd...)
		mut[c.pos] = c.val
		_, err := DecodeComprehensiveProofCall(mut, DefaultABILimits())
		if ae := wantABI(t, err, ABIWord); !strings.Contains(ae.Field, "governanceProof") {
			t.Fatalf("%s: field %q", c.name, ae.Field)
		}
	}
}

func TestComprehensiveProofValidatorCapIsExact(t *testing.T) {
	lim := DefaultABILimits()
	if _, err := DecodeComprehensiveProofCall(packProofCall(t, b32(0xaa), honestProof(lim.MaxValidators)), lim); err != nil {
		t.Fatalf("%d validators: %v", lim.MaxValidators, err)
	}
	ae := wantABI(t, func() error {
		_, e := DecodeComprehensiveProofCall(packProofCall(t, b32(0xaa), honestProof(lim.MaxValidators+1)), lim)
		return e
	}(), ABICap)
	if ae.Got != 65 || ae.Limit != 64 || !strings.Contains(ae.Field, "validatorAddresses") {
		t.Fatalf("%+v", ae)
	}
	// different lengths of the two arrays
	p := honestProof(3)
	p.BlsProof.VotingPowers = p.BlsProof.VotingPowers[:2]
	_, err := DecodeComprehensiveProofCall(packProofCall(t, b32(0xaa), p), lim)
	wantABI(t, err, ABIShape)
}

func TestZKBlobBoundaries(t *testing.T) {
	blob := zkBlobBytes()
	if z, err := DecodeZKBlob(blob); err != nil || z.Length != 576 {
		t.Fatalf("576: %v", err)
	}
	if z, err := DecodeZKBlob(append(append([]byte{}, blob...), 1, 2, 3)); err != nil || z.Length != 579 {
		t.Fatalf("579 (the anchor's abi.decode ignores trailing bytes): %v", err)
	}
	for _, n := range []int{0, 1, 31, 32, 575} {
		_, err := DecodeZKBlob(blob[:n])
		wantABI(t, err, ABITruncated)
	}
}

func packSettlement(t *testing.T, sig string, proof tADI, vals ...any) []byte {
	t.Helper()
	var args abi.Arguments
	switch sig {
	case SigExecuteGovernanceDirect:
		args = abi.Arguments{{Type: mustType(t, "address")}, {Type: mustType(t, "uint256")}, {Type: mustType(t, "bytes")}, {Type: adiTypeT(t)}}
	case SigBatchGovernanceDirect:
		args = abi.Arguments{{Type: mustType(t, "address[]")}, {Type: mustType(t, "uint256[]")}, {Type: mustType(t, "bytes[]")}, {Type: adiTypeT(t)}}
	}
	enc, err := args.Pack(append(vals, proof)...)
	if err != nil {
		t.Fatal(err)
	}
	sel := Selector4(sig)
	return append(sel[:], enc...)
}

func honestADI() tADI {
	return tADI{AdiURL: "acc://rb7.acme", AnchorId: b32(1), MerkleProof: [][32]byte{b32(2), b32(3)}, OperationID: b32(4), KeyBookProof: []byte("kb"), RoleProof: []byte{},
		ThresholdProof: bytes.Repeat([]byte{9}, 40), Timestamp: big.NewInt(5), ExpiresAt: big.NewInt(6), ValidatorSignatures: bytes.Repeat([]byte{7}, 65), Nonce: big.NewInt(8),
		AuthorityBook: b32(0xb0), AuthorityPage: 2, NotBefore: 10, NotAfter: 20}
}

func batchVals(n int) (targets []common.Address, values []*big.Int, datas [][]byte) {
	for i := 0; i < n; i++ {
		targets = append(targets, common.BigToAddress(big.NewInt(int64(100+i))))
		values = append(values, new(big.Int).Mul(big.NewInt(int64(i)), big.NewInt(250000000000000000)))
		d := []byte{0xa9, 0x05, 0x9c, 0xbb, byte(i)} // transfer(...) selector then data
		if i%3 == 2 {
			d = []byte{1, 2} // shorter than a selector
		}
		datas = append(datas, d)
	}
	return
}

func TestSettlementCallsRoundTrip(t *testing.T) {
	lim := DefaultABILimits()
	one := packSettlement(t, SigExecuteGovernanceDirect, honestADI(), common.HexToAddress("0xdead"), big.NewInt(1e18), []byte{0xa9, 0x05, 0x9c, 0xbb, 1})
	c, err := DecodeSettlementCall(one, lim)
	if err != nil {
		t.Fatal(err)
	}
	if c.Batch || len(c.Legs) != 1 || c.Legs[0].Target != common.HexToAddress("0xdead") || c.Legs[0].Value.Cmp(big.NewInt(1e18)) != 0 ||
		c.Legs[0].Selector != [4]byte{0xa9, 0x05, 0x9c, 0xbb} || c.Proof.AuthorityBook != b32(0xb0) || c.Proof.AuthorityPage != 2 ||
		c.Proof.ADIURL != "acc://rb7.acme" || len(c.Proof.MerkleProof) != 2 || c.Proof.NotAfter != 20 {
		t.Fatalf("%+v", c)
	}
	tg, vs, ds := batchVals(5)
	many := packSettlement(t, SigBatchGovernanceDirect, honestADI(), tg, vs, ds)
	c, err = DecodeSettlementCall(many, lim)
	if err != nil || !c.Batch || len(c.Legs) != 5 {
		t.Fatalf("%v %+v", err, c)
	}
	for i, l := range c.Legs {
		if l.Target != tg[i] || l.Value.Cmp(vs[i]) != 0 || !bytes.Equal(l.Data, ds[i]) {
			t.Fatalf("leg %d: %+v", i, l)
		}
		wantSel := [4]byte{}
		if len(ds[i]) >= 4 {
			copy(wantSel[:], ds[i][:4])
		}
		if l.Selector != wantSel { // bytes4(0) for data shorter than a selector (step 14)
			t.Fatalf("leg %d selector %x", i, l.Selector)
		}
	}
	// every truncation and a trailing byte; the canonical property over every single-byte mutation of both calls
	for _, cd := range [][]byte{one, many} {
		for n := 0; n < len(cd); n++ {
			if _, err := DecodeSettlementCall(cd[:n], lim); err == nil {
				t.Fatalf("a truncation to %d of %d bytes decoded", n, len(cd))
			}
		}
		_, err := DecodeSettlementCall(append(append([]byte{}, cd...), 0), lim)
		wantABI(t, err, ABITrailing)
	}
	repack := func(in []byte) ([]byte, error) {
		c, err := DecodeSettlementCall(in, lim)
		if err != nil {
			return nil, err
		}
		a := tADI{AdiURL: c.Proof.ADIURL, AnchorId: c.Proof.AnchorID, MerkleProof: c.Proof.MerkleProof, OperationID: c.Proof.OperationID, KeyBookProof: c.Proof.KeyBookProof,
			RoleProof: c.Proof.RoleProof, ThresholdProof: c.Proof.ThresholdProof, Timestamp: c.Proof.Timestamp, ExpiresAt: c.Proof.ExpiresAt,
			ValidatorSignatures: c.Proof.ValidatorSignatures, Nonce: c.Proof.Nonce, AuthorityBook: c.Proof.AuthorityBook, AuthorityPage: c.Proof.AuthorityPage,
			NotBefore: c.Proof.NotBefore, NotAfter: c.Proof.NotAfter}
		if !c.Batch {
			return packSettlement(t, SigExecuteGovernanceDirect, a, c.Legs[0].Target, c.Legs[0].Value, c.Legs[0].Data), nil
		}
		var tg []common.Address
		var vs []*big.Int
		var ds [][]byte
		for _, l := range c.Legs {
			tg, vs, ds = append(tg, l.Target), append(vs, l.Value), append(ds, l.Data)
		}
		return packSettlement(t, SigBatchGovernanceDirect, a, tg, vs, ds), nil
	}
	for name, cd := range map[string][]byte{"single": one, "batch": many} {
		acc, ref := canonicalProperty(t, cd, repack)
		if acc == 0 || ref == 0 {
			t.Fatalf("%s: accepted %d refused %d", name, acc, ref)
		}
	}
}

func TestSettlementBatchLegBoundaryIsExact(t *testing.T) {
	lim := DefaultABILimits()
	for _, c := range []struct {
		n    int
		want ABIKind
	}{{64, ""}, {65, ABICap}, {1, ""}} {
		tg, vs, ds := batchVals(c.n)
		cd := packSettlement(t, SigBatchGovernanceDirect, honestADI(), tg, vs, ds)
		got, err := DecodeSettlementCall(cd, lim)
		if c.want == "" {
			if err != nil || len(got.Legs) != c.n {
				t.Fatalf("%d legs: %v", c.n, err)
			}
			continue
		}
		ae := wantABI(t, err, c.want)
		if ae.Got != 65 || ae.Limit != 64 || ae.Field != "targets" {
			t.Fatalf("%+v", ae)
		}
	}
	// the cap applies to each of the three arrays: 65 values/datas with 64 targets is also refused by the cap on its own array
	tg, vs, ds := batchVals(65)
	cd := packSettlement(t, SigBatchGovernanceDirect, honestADI(), tg[:64], vs, ds)
	ae := wantABI(t, func() error { _, e := DecodeSettlementCall(cd, lim); return e }(), ABICap)
	if ae.Field != "values" {
		t.Fatalf("field %q", ae.Field)
	}
	// empty batch and length mismatch are shape refusals
	cd = packSettlement(t, SigBatchGovernanceDirect, honestADI(), []common.Address{}, []*big.Int{}, [][]byte{})
	_, err := DecodeSettlementCall(cd, lim)
	wantABI(t, err, ABIShape)
	tg, vs, ds = batchVals(3)
	cd = packSettlement(t, SigBatchGovernanceDirect, honestADI(), tg, vs[:2], ds)
	_, err = DecodeSettlementCall(cd, lim)
	wantABI(t, err, ABIShape)
	// more values (or datas) than targets is the same refusal
	tg4, vs4, ds4 := batchVals(4)
	_, err = DecodeSettlementCall(packSettlement(t, SigBatchGovernanceDirect, honestADI(), tg4[:3], vs4, ds4[:3]), lim)
	wantABI(t, err, ABIShape)
	_, err = DecodeSettlementCall(packSettlement(t, SigBatchGovernanceDirect, honestADI(), tg4[:3], vs4[:3], ds4), lim)
	wantABI(t, err, ABIShape)
}

func TestSettlementAuthorityPageIsUint64(t *testing.T) {
	one := packSettlement(t, SigExecuteGovernanceDirect, honestADI(), common.HexToAddress("0xdead"), big.NewInt(0), []byte{})
	// find the authorityPage word: the proof tuple is the last dynamic head item; its word 12
	off := new(big.Int).SetBytes(one[4+32*3 : 4+32*4]).Int64()
	page := 4 + int(off) + 32*12
	if new(big.Int).SetBytes(one[page:page+32]).Int64() != 2 {
		t.Fatal("test layout: authorityPage not at word 12")
	}
	for _, hi := range []int{page, page + 23} { // bit 255 and bit 64 (byte 23 = bits 64..71)
		mut := append([]byte{}, one...)
		mut[hi] = 0x80
		_, err := DecodeSettlementCall(mut, DefaultABILimits())
		if ae := wantABI(t, err, ABIWord); !strings.Contains(ae.Field, "authorityPage") {
			t.Fatalf("field %q", ae.Field)
		}
	}
	mut := append([]byte{}, one...)
	mut[page+24] = 0x80 // the top bit of the uint64: legal
	if c, err := DecodeSettlementCall(mut, DefaultABILimits()); err != nil || c.Proof.AuthorityPage != 1<<63|2 {
		t.Fatalf("uint64 high bit: %v", err)
	}
}

func TestLogDataDecoders(t *testing.T) {
	u256 := mustType(t, "uint256")
	b32t := mustType(t, "bytes32")
	boolt := mustType(t, "bool")
	bytest := mustType(t, "bytes")
	u8 := mustType(t, "uint8")
	// ProofExecuted
	data, _ := abi.Arguments{{Type: b32t}, {Type: boolt}, {Type: boolt}, {Type: boolt}, {Type: u256}}.Pack(b32(5), true, true, false, big.NewInt(77))
	pe, err := DecodeProofExecutedData(data)
	if err != nil || pe.TransactionHash != b32(5) || !pe.MerkleVerified || !pe.BLSVerified || pe.GovernanceVerified || pe.Timestamp.Int64() != 77 {
		t.Fatalf("%v %+v", err, pe)
	}
	bad := append([]byte{}, data...)
	bad[32+31] = 2
	_, err = DecodeProofExecutedData(bad)
	wantABI(t, err, ABIWord)
	_, err = DecodeProofExecutedData(data[:len(data)-1])
	wantABI(t, err, ABITruncated)
	_, err = DecodeProofExecutedData(append(append([]byte{}, data...), 0))
	wantABI(t, err, ABITrailing)
	// LeafConsumed
	v9 := b32(9)
	if op, err := DecodeLeafConsumedData(v9[:]); err != nil || op != v9 {
		t.Fatal(err)
	}
	_, err = DecodeLeafConsumedData(make([]byte, 31))
	wantABI(t, err, ABITruncated)
	_, err = DecodeLeafConsumedData(make([]byte, 33))
	wantABI(t, err, ABITrailing)
	// GovernanceOperationExecuted: head word 2 is the level
	data, _ = abi.Arguments{{Type: u256}, {Type: bytest}, {Type: u8}}.Pack(big.NewInt(1e18), []byte{0xa9, 0x05, 0x9c, 0xbb}, uint8(3))
	op, err := DecodeGovernanceOperationData(data)
	if err != nil || op.Level != 3 || op.Value.Cmp(big.NewInt(1e18)) != 0 || !bytes.Equal(op.Data, []byte{0xa9, 0x05, 0x9c, 0xbb}) {
		t.Fatalf("%v %+v", err, op)
	}
	if new(big.Int).SetBytes(data[64:96]).Int64() != 3 {
		t.Fatal("level is not head word 2")
	}
	for _, lv := range []uint8{0, 4} {
		d, _ := abi.Arguments{{Type: u256}, {Type: bytest}, {Type: u8}}.Pack(big.NewInt(0), []byte{}, lv)
		if o, err := DecodeGovernanceOperationData(d); err != nil || o.Level != lv {
			t.Fatalf("level %d: %v", lv, err)
		}
	}
	d5, _ := abi.Arguments{{Type: u256}, {Type: bytest}, {Type: u8}}.Pack(big.NewInt(0), []byte{}, uint8(5))
	_, err = DecodeGovernanceOperationData(d5)
	wantABI(t, err, ABIWord)
	for n := 0; n < len(data); n++ {
		if _, err := DecodeGovernanceOperationData(data[:n]); err == nil {
			t.Fatalf("truncation to %d decoded", n)
		}
	}
	// GovernanceBatchExecuted: head word 1 is the level
	data, _ = abi.Arguments{{Type: u256}, {Type: u8}}.Pack(big.NewInt(4), uint8(2))
	gb, err := DecodeGovernanceBatchData(data)
	if err != nil || gb.Level != 2 || gb.CallCount.Int64() != 4 {
		t.Fatalf("%v %+v", err, gb)
	}
	data[63] = 5
	_, err = DecodeGovernanceBatchData(data)
	wantABI(t, err, ABIWord)
}

func TestABIDecodersNeverPanicOnGarbageAndAllocateLittle(t *testing.T) {
	lim := DefaultABILimits()
	rng := rand.New(rand.NewSource(0x4142492d))
	for i := 0; i < 3000; i++ {
		n := rng.Intn(600)
		in := make([]byte, n)
		rng.Read(in)
		if n >= 4 && i%2 == 0 { // a valid selector in front of garbage
			var sel [4]byte
			switch i % 3 {
			case 0:
				sel = Selector4(SigExecuteComprehensiveProof)
			case 1:
				sel = Selector4(SigExecuteGovernanceDirect)
			default:
				sel = Selector4(SigBatchGovernanceDirect)
			}
			copy(in, sel[:])
		}
		_, _ = DecodeComprehensiveProofCall(in, lim)
		_, _ = DecodeSettlementCall(in, lim)
		_, _ = DecodeProofExecutedData(in)
		_, _ = DecodeGovernanceOperationData(in)
		_, _ = DecodeGovernanceBatchData(in)
	}
	// lengths that claim gigabytes against a few hundred input bytes allocate nothing like the claim
	cd := packProofCall(t, b32(0xaa), honestProof(2))
	hdr := 4 + 0x40
	mut := append([]byte{}, cd...)
	// the proofHashes length word (first word of its tail) := 2^40
	off := int(new(big.Int).SetBytes(mut[hdr+64 : hdr+96]).Int64())
	new(big.Int).Lsh(big.NewInt(1), 40).FillBytes(mut[hdr+off : hdr+off+32])
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	_, err := DecodeComprehensiveProofCall(mut, lim)
	runtime.ReadMemStats(&m1)
	wantABI(t, err, ABILength)
	if used := m1.TotalAlloc - m0.TotalAlloc; used > uint64(64*1024+2*len(cd)) {
		t.Fatalf("a hostile length allocated %d bytes for %d input bytes", used, len(cd))
	}
}
