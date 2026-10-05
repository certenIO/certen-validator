package intentcert

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// G1HistoricalUnavailable names the one G1 refusal of govRoot v3: no pages were captured as of the transaction's
// block, so a G1 slot would claim what was not proven (docs/proof/GOVROOT_V3.md).
const G1HistoricalUnavailable = "g1_historical_unavailable"

// GovRootV3Inputs are the per-intent facts govRoot v3 commits. Report is what proofv2.Verify established; Evidence is
// the evidence it verified, read only for the page states' bytes.
type GovRootV3Inputs struct {
	Report      *proofv2.Report
	Evidence    *proofv2.Evidence
	G0          *proof.G0Result
	G1          *proof.G1Result
	G2          *proof.G2Result
	KeyPageURL  string
	KeyBookURL  string
	OperationID [32]byte
}

// GovRootV3HashInputs are GovRootV3Inputs with each governance level reduced to sha256 of its canonical v2 JSON, the
// form the slots commit and the conformance fixture carries.
type GovRootV3HashInputs struct {
	Report      *proofv2.Report
	Evidence    *proofv2.Evidence
	G0Hash      [32]byte
	G1Hash      [32]byte
	G2Hash      [32]byte
	KeyPageURL  string
	KeyBookURL  string
	OperationID [32]byte
}

// GovRootV3 returns govRoot v3 and its slots. Every input is required; nothing is left silently zero.
func GovRootV3(in GovRootV3Inputs) ([32]byte, contracts.AccumulateGovRootInputs, error) {
	h := GovRootV3HashInputs{Report: in.Report, Evidence: in.Evidence, KeyPageURL: in.KeyPageURL, KeyBookURL: in.KeyBookURL, OperationID: in.OperationID}
	var err error
	if h.G0Hash, h.G1Hash, h.G2Hash, err = governanceHashesV3(in); err != nil {
		return [32]byte{}, contracts.AccumulateGovRootInputs{}, err
	}
	return GovRootV3FromHashes(h)
}

// governanceHashesV3 is sha256 of each level's canonical v2 JSON, the first field of the G0-G2 slot payloads.
func governanceHashesV3(in GovRootV3Inputs) (g0, g1, g2 [32]byte, err error) {
	j0, err := proof.CanonicalG0JSONV2(in.G0)
	if err != nil {
		return
	}
	j1, err := proof.CanonicalG1JSONV2(in.G1)
	if err != nil {
		return
	}
	j2, err := proof.CanonicalG2JSONV2(in.G2)
	if err != nil {
		return
	}
	return sha256.Sum256(j0), sha256.Sum256(j1), sha256.Sum256(j2), nil
}

// PortableGovRootV3Inputs reduces in to the portable form's govRootV3Inputs block: the governance results to sha256
// of their canonical v2 JSON, the operation id to hex.
func PortableGovRootV3Inputs(in GovRootV3Inputs) (*proofv2.PortableGovRootV3Inputs, error) {
	h0, h1, h2, err := governanceHashesV3(in)
	if err != nil {
		return nil, err
	}
	return &proofv2.PortableGovRootV3Inputs{
		G0Hash: hex.EncodeToString(h0[:]), G1Hash: hex.EncodeToString(h1[:]), G2Hash: hex.EncodeToString(h2[:]),
		KeyPageURL: in.KeyPageURL, KeyBookURL: in.KeyBookURL, OperationID: hex.EncodeToString(in.OperationID[:]),
	}, nil
}

// GovRootV3FromPortable is GovRootV3FromHashes with the governance hashes, key page, key book and operation id read
// from a portable proof's govRootV3Inputs block, as the conformance suite carries them.
func GovRootV3FromPortable(rep *proofv2.Report, ev *proofv2.Evidence, p *proofv2.PortableGovRootV3Inputs) ([32]byte, contracts.AccumulateGovRootInputs, error) {
	if p == nil {
		return [32]byte{}, contracts.AccumulateGovRootInputs{}, fmt.Errorf("govRoot v3: the portable proof carries no govRootV3Inputs")
	}
	h := GovRootV3HashInputs{Report: rep, Evidence: ev, KeyPageURL: p.KeyPageURL, KeyBookURL: p.KeyBookURL}
	for _, f := range []struct {
		name string
		s    string
		out  *[32]byte
	}{{"g0Hash", p.G0Hash, &h.G0Hash}, {"g1Hash", p.G1Hash, &h.G1Hash}, {"g2Hash", p.G2Hash, &h.G2Hash}, {"operationId", p.OperationID, &h.OperationID}} {
		b, err := hex.DecodeString(f.s)
		if err != nil || len(b) != 32 {
			return [32]byte{}, contracts.AccumulateGovRootInputs{}, fmt.Errorf("govRoot v3: govRootV3Inputs.%s is not 32 bytes of hex", f.name)
		}
		copy(f.out[:], b)
	}
	return GovRootV3FromHashes(h)
}

// GovRootV3FromHashes builds every slot from the verified report (docs/proof/GOVROOT_V3.md) and returns the root.
func GovRootV3FromHashes(in GovRootV3HashInputs) ([32]byte, contracts.AccumulateGovRootInputs, error) {
	var slots contracts.AccumulateGovRootInputs
	var zero [32]byte
	rep := in.Report
	if rep == nil {
		return zero, slots, fmt.Errorf("govRoot v3: no verified proof v2 report")
	}
	// Verify sets every one of these; a zero one is a report Verify did not produce.
	for _, f := range []struct {
		name string
		v    [32]byte
	}{
		{"transaction hash", rep.TxHash}, {"partition anchor transaction hash", rep.AnchorTxHash},
		{"partition state tree anchor", rep.AnchorStateRoot}, {"certified root chain anchor", rep.CertifiedRoot},
		{"accumulate set root", rep.AccumulateSetRoot}, {"incarnation", rep.Incarnation},
		{"G0 hash", in.G0Hash}, {"G1 hash", in.G1Hash}, {"G2 hash", in.G2Hash},
	} {
		if f.v == zero {
			return zero, slots, fmt.Errorf("govRoot v3: the %s is required", f.name)
		}
	}
	if rep.AnchorBlock == 0 || rep.CertifiedBlock == 0 {
		return zero, slots, fmt.Errorf("govRoot v3: the report names no anchor block or certified block")
	}
	// The L4 slot states the set was proven; any weaker verdict is a set check that failed, which fails closed.
	if rep.SetVerdict != proof.VerdictVerified {
		return zero, slots, fmt.Errorf("govRoot v3: the validator set check is %s, not verified", rep.SetVerdict)
	}
	pagesRoot, err := PagesRootV3(rep, in.Evidence)
	if err != nil {
		return zero, slots, err
	}

	slots.L1AccountHash = contracts.GovRootV3L1(rep.TxHash, rep.AnchorTxHash, rep.AnchorBlock)
	slots.L2BPTRoot = contracts.GovRootV3L2(rep.CertifiedRoot, rep.CertifiedBlock)
	slots.L3BlockHash = contracts.GovRootV3L3(rep.AnchorStateRoot, rep.AnchorBlock)
	slots.L4ConsensusProofH = contracts.GovRootV3L4(rep.AccumulateSetRoot, rep.Incarnation, rep.CertifiedBlock)
	slots.G0CanonicalHash = contracts.GovRootV3G0(in.G0Hash, rep.TxHash, rep.CertifiedRoot)
	slots.G1CanonicalHash = contracts.GovRootV3G1(in.G1Hash, pagesRoot)
	slots.G2CanonicalHash = contracts.GovRootV3G2(in.G2Hash, slots.G1CanonicalHash)
	// As v2: in canonical spelling, since Accumulate URLs are case-insensitive and two validators naming one page two
	// ways must commit one govRoot.
	slots.KeypageURLHash = contracts.HashURLString(govvote.CanonicalAccSpelling(in.KeyPageURL))
	slots.KeybookURLHash = contracts.HashURLString(govvote.CanonicalAccSpelling(in.KeyBookURL))
	slots.OperationID = in.OperationID
	root, err := contracts.ComputeAccumulateGovRootV3(slots)
	return root, slots, err
}

// PagesRootV3 commits the proven pages: sorted by canonical URL, each record is sha256(canonicalURL) ‖ sha256(state) ‖
// bound (1 byte) ‖ uint64(mainHeight), with bound 0 and mainHeight 0 for a page whose chains are unbound, and the
// root is the merkle hash (merkle.Hasher) of the sha256 of each record. The URL and chain facts are the report's; the
// state bytes are the evidence's, and must be exactly the encoding of the account the report proved.
func PagesRootV3(rep *proofv2.Report, ev *proofv2.Evidence) ([32]byte, error) {
	var zero [32]byte
	if rep == nil || ev == nil {
		return zero, fmt.Errorf("govRoot v3: the pages root needs the verified report and its evidence")
	}
	if len(rep.Pages) == 0 {
		return zero, fmt.Errorf("govRoot v3: %s: no pages were captured as of the transaction's block", G1HistoricalUnavailable)
	}
	if len(rep.PageChains) != len(rep.Pages) || len(ev.Pages) != len(rep.Pages) {
		return zero, fmt.Errorf("govRoot v3: the report proves %d pages with %d chain results, the evidence carries %d",
			len(rep.Pages), len(rep.PageChains), len(ev.Pages))
	}
	type record struct {
		url  string
		leaf [32]byte
	}
	recs := make([]record, len(rep.Pages))
	for i, acct := range rep.Pages {
		if acct == nil || acct.GetUrl() == nil {
			return zero, fmt.Errorf("govRoot v3: page %d of the report has no account", i)
		}
		u := govvote.CanonicalAccSpelling(acct.GetUrl().String())
		if govvote.CanonicalAccSpelling(rep.PageChains[i].URL) != u || govvote.CanonicalAccSpelling(ev.Pages[i].URL) != u {
			return zero, fmt.Errorf("govRoot v3: page %d is %s in the report, but its chains are %s and its evidence %s",
				i, u, rep.PageChains[i].URL, ev.Pages[i].URL)
		}
		state, err := hex.DecodeString(ev.Pages[i].State)
		if err != nil {
			return zero, fmt.Errorf("govRoot v3: %s: state: %w", u, err)
		}
		proven, err := acct.MarshalBinary()
		if err != nil {
			return zero, fmt.Errorf("govRoot v3: %s: %w", u, err)
		}
		if !bytes.Equal(state, proven) {
			return zero, fmt.Errorf("govRoot v3: %s: the evidence's state is not the account the report proved", u)
		}
		var bound byte
		var height uint64
		if rep.PageChains[i].Bound {
			bound, height = 1, rep.PageChains[i].MainHeight
		}
		urlHash, stateHash := sha256.Sum256([]byte(u)), sha256.Sum256(state)
		rec := make([]byte, 0, 32+32+1+8)
		rec = append(rec, urlHash[:]...)
		rec = append(rec, stateHash[:]...)
		rec = append(rec, bound)
		rec = binary.BigEndian.AppendUint64(rec, height)
		recs[i] = record{url: u, leaf: sha256.Sum256(rec)}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].url < recs[j].url })
	// Two pages under one canonical URL would make the order, and so the root, depend on capture order.
	for i := 1; i < len(recs); i++ {
		if recs[i].url == recs[i-1].url {
			return zero, fmt.Errorf("govRoot v3: page %s is captured twice", recs[i].url)
		}
	}
	var h merkle.Hasher
	for _, r := range recs {
		h.AddHash2(r.leaf)
	}
	var out [32]byte
	copy(out[:], h.MerkleHash())
	return out, nil
}
