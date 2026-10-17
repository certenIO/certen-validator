package intentcert

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// govRoot v4 (docs/proof/G1_CROSS_PARTITION.md D4/D7, rules v15; conventions of docs/proof/GOVROOT_V3.md): the per-intent
// commitment over a proof v2 of evidence 2.1. It is govRoot v3 with the G1 slot widened to commit what 2.1 proves beyond 2.0:
// every page with the partition and block it is proven at and the roles that put it in the governing set (design D1, D4), and the
// authority votes copied from the principal's proven signature chain (D3). The other slots commit the same facts in the same
// bytes as v3 - the transaction's anchor, the certified Directory root, the validator set, G0, and G2 over the G1 slot - so they
// are v3's slot functions; the root's domain, certen:govroot:v4, is what separates the two roots.

// GovRootV4Inputs are the per-intent facts govRoot v4 commits: those of v3, over a 2.1 report.
type GovRootV4Inputs = GovRootV3Inputs

// GovRootV4HashInputs are GovRootV4Inputs with each governance level reduced to sha256 of its canonical v2 JSON.
type GovRootV4HashInputs = GovRootV3HashInputs

// GovRootV4 returns govRoot v4 and its slots. Every input is required; nothing is left silently zero.
func GovRootV4(in GovRootV4Inputs) ([32]byte, contracts.AccumulateGovRootInputs, error) {
	h := GovRootV4HashInputs{Report: in.Report, Evidence: in.Evidence, KeyPageURL: in.KeyPageURL, KeyBookURL: in.KeyBookURL, OperationID: in.OperationID}
	var err error
	if h.G0Hash, h.G1Hash, h.G2Hash, err = governanceHashesV3(in); err != nil {
		return [32]byte{}, contracts.AccumulateGovRootInputs{}, err
	}
	return GovRootV4FromHashes(h)
}

// PortableGovRootV4Inputs reduces in to the portable form's govRoot inputs block (the same fields as v3's: the governance
// results' hashes, the key page, key book and operation id). The block is named govRootV3Inputs in the portable document; the
// version of the root computed from it is the evidence's.
func PortableGovRootV4Inputs(in GovRootV4Inputs) (*proofv2.PortableGovRootV3Inputs, error) {
	return PortableGovRootV3Inputs(in)
}

// GovRootV4FromPortable is GovRootV4FromHashes with the governance hashes, key page, key book and operation id read from a
// portable proof's govRootV3Inputs block.
func GovRootV4FromPortable(rep *proofv2.Report, ev *proofv2.Evidence, p *proofv2.PortableGovRootV3Inputs) ([32]byte, contracts.AccumulateGovRootInputs, error) {
	if p == nil {
		return [32]byte{}, contracts.AccumulateGovRootInputs{}, fmt.Errorf("govRoot v4: the portable proof carries no govRootV3Inputs")
	}
	h := GovRootV4HashInputs{Report: rep, Evidence: ev, KeyPageURL: p.KeyPageURL, KeyBookURL: p.KeyBookURL}
	for _, f := range []struct {
		name string
		s    string
		out  *[32]byte
	}{{"g0Hash", p.G0Hash, &h.G0Hash}, {"g1Hash", p.G1Hash, &h.G1Hash}, {"g2Hash", p.G2Hash, &h.G2Hash}, {"operationId", p.OperationID, &h.OperationID}} {
		b, err := hex.DecodeString(f.s)
		if err != nil || len(b) != 32 {
			return [32]byte{}, contracts.AccumulateGovRootInputs{}, fmt.Errorf("govRoot v4: govRootV3Inputs.%s is not 32 bytes of hex", f.name)
		}
		copy(f.out[:], b)
	}
	return GovRootV4FromHashes(h)
}

// GovRootV4FromHashes builds every slot from the verified 2.1 report and returns the root.
func GovRootV4FromHashes(in GovRootV4HashInputs) ([32]byte, contracts.AccumulateGovRootInputs, error) {
	var slots contracts.AccumulateGovRootInputs
	var zero [32]byte
	rep := in.Report
	if rep == nil {
		return zero, slots, fmt.Errorf("govRoot v4: no verified proof v2 report")
	}
	if in.Evidence == nil || in.Evidence.Version != proofv2.Version21 {
		return zero, slots, fmt.Errorf("govRoot v4: the evidence is not version %s", proofv2.Version21)
	}
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
			return zero, slots, fmt.Errorf("govRoot v4: the %s is required", f.name)
		}
	}
	if rep.AnchorBlock == 0 || rep.CertifiedBlock == 0 {
		return zero, slots, fmt.Errorf("govRoot v4: the report names no anchor block or certified block")
	}
	if rep.SetVerdict != proof.VerdictVerified {
		return zero, slots, fmt.Errorf("govRoot v4: the validator set check is %s, not verified", rep.SetVerdict)
	}
	pagesRoot, err := PagesRootV4(rep, in.Evidence)
	if err != nil {
		return zero, slots, err
	}
	votesRoot, err := VotesRootV4(in.Evidence.Votes)
	if err != nil {
		return zero, slots, err
	}

	slots.L1AccountHash = contracts.GovRootV3L1(rep.TxHash, rep.AnchorTxHash, rep.AnchorBlock)
	slots.L2BPTRoot = contracts.GovRootV3L2(rep.CertifiedRoot, rep.CertifiedBlock)
	slots.L3BlockHash = contracts.GovRootV3L3(rep.AnchorStateRoot, rep.AnchorBlock)
	slots.L4ConsensusProofH = contracts.GovRootV3L4(rep.AccumulateSetRoot, rep.Incarnation, rep.CertifiedBlock)
	slots.G0CanonicalHash = contracts.GovRootV3G0(in.G0Hash, rep.TxHash, rep.CertifiedRoot)
	slots.G1CanonicalHash = contracts.GovRootV4G1(in.G1Hash, pagesRoot, votesRoot)
	slots.G2CanonicalHash = contracts.GovRootV3G2(in.G2Hash, slots.G1CanonicalHash)
	slots.KeypageURLHash = contracts.HashURLString(govvote.CanonicalAccSpelling(in.KeyPageURL))
	slots.KeybookURLHash = contracts.HashURLString(govvote.CanonicalAccSpelling(in.KeyBookURL))
	slots.OperationID = in.OperationID
	root, err := contracts.ComputeAccumulateGovRootV4(slots)
	return root, slots, err
}

// PagesRootV4 commits the proven pages: sorted by canonical URL, each record is
//
//	sha256(canonicalURL) ‖ sha256(state) ‖ bound (1 byte) ‖ uint64(mainHeight) ‖ sha256(canonicalPartition) ‖ uint64(block) ‖ sha256(roles)
//
// with bound 0 and mainHeight 0 for a page whose chains are unbound (as v3), canonicalPartition the partition's lower-case
// spelling, and roles the page's roles in proofv2.CanonicalRoles order joined with ",". The root is the merkle hash
// (merkle.Hasher) of the sha256 of each record. The report lists the partition, block and roles of every page (Report.Proven,
// in the order of Report.Pages), the evidence carries the same and the state bytes; any disagreement between the two, a page
// with no partition, block or role, or a page proven twice is refused by name.
func PagesRootV4(rep *proofv2.Report, ev *proofv2.Evidence) ([32]byte, error) {
	var zero [32]byte
	if rep == nil || ev == nil {
		return zero, fmt.Errorf("govRoot v4: the pages root needs the verified report and its evidence")
	}
	if len(rep.Pages) == 0 {
		return zero, fmt.Errorf("govRoot v4: %s: no pages were captured as of the transaction's block", G1HistoricalUnavailable)
	}
	if len(rep.PageChains) != len(rep.Pages) || len(ev.Pages) != len(rep.Pages) || len(rep.Proven) != len(rep.Pages) {
		return zero, fmt.Errorf("govRoot v4: the report proves %d pages with %d chain results and %d (partition, block, roles) records, the evidence carries %d",
			len(rep.Pages), len(rep.PageChains), len(rep.Proven), len(ev.Pages))
	}
	type record struct {
		url  string
		leaf [32]byte
	}
	recs := make([]record, len(rep.Pages))
	for i, acct := range rep.Pages {
		if acct == nil || acct.GetUrl() == nil {
			return zero, fmt.Errorf("govRoot v4: page %d of the report has no account", i)
		}
		u := govvote.CanonicalAccSpelling(acct.GetUrl().String())
		pp := rep.Proven[i]
		if govvote.CanonicalAccSpelling(rep.PageChains[i].URL) != u || govvote.CanonicalAccSpelling(ev.Pages[i].URL) != u || govvote.CanonicalAccSpelling(pp.URL) != u {
			return zero, fmt.Errorf("govRoot v4: page %d is %s in the report, but its chains are %s, its evidence %s and its proven record %s",
				i, u, rep.PageChains[i].URL, ev.Pages[i].URL, pp.URL)
		}
		partition := govvote.CanonicalAccSpelling(pp.Partition)
		if partition == "" {
			return zero, fmt.Errorf("govRoot v4: %s: %s: the page is proven with no partition", u, proofv2.StateForeignPartitionMismatch)
		}
		if pp.Block == 0 {
			return zero, fmt.Errorf("govRoot v4: %s: %s: the page is proven with no block", u, proofv2.StatePageBlockMismatch)
		}
		roles, err := proofv2.CanonicalRoles(pp.Roles)
		if err != nil {
			return zero, fmt.Errorf("govRoot v4: %s: %w", u, err)
		}
		if len(roles) == 0 {
			return zero, fmt.Errorf("govRoot v4: %s: the page is proven with no role, so nothing says why it is in the governing set", u)
		}
		if govvote.CanonicalAccSpelling(ev.Pages[i].Partition) != partition {
			return zero, fmt.Errorf("govRoot v4: %s: the report proves it on %s, the evidence claims %s", u, pp.Partition, ev.Pages[i].Partition)
		}
		evRoles, err := proofv2.CanonicalRoles(ev.Pages[i].Roles)
		if err != nil || !rolesEqual(evRoles, roles) {
			return zero, fmt.Errorf("govRoot v4: %s: the report records roles %v, the evidence %v", u, roles, ev.Pages[i].Roles)
		}
		state, err := hex.DecodeString(ev.Pages[i].State)
		if err != nil {
			return zero, fmt.Errorf("govRoot v4: %s: state: %w", u, err)
		}
		proven, err := acct.MarshalBinary()
		if err != nil {
			return zero, fmt.Errorf("govRoot v4: %s: %w", u, err)
		}
		if string(state) != string(proven) {
			return zero, fmt.Errorf("govRoot v4: %s: the evidence's state is not the account the report proved", u)
		}
		var bound byte
		var height uint64
		if rep.PageChains[i].Bound {
			bound, height = 1, rep.PageChains[i].MainHeight
		}
		urlHash, stateHash := sha256.Sum256([]byte(u)), sha256.Sum256(state)
		partHash := sha256.Sum256([]byte(partition))
		roleStrs := make([]string, len(roles))
		for j, r := range roles {
			roleStrs[j] = string(r)
		}
		rolesHash := sha256.Sum256([]byte(strings.Join(roleStrs, ",")))
		rec := make([]byte, 0, 32+32+1+8+32+8+32)
		rec = append(rec, urlHash[:]...)
		rec = append(rec, stateHash[:]...)
		rec = append(rec, bound)
		rec = binary.BigEndian.AppendUint64(rec, height)
		rec = append(rec, partHash[:]...)
		rec = binary.BigEndian.AppendUint64(rec, pp.Block)
		rec = append(rec, rolesHash[:]...)
		recs[i] = record{url: u, leaf: sha256.Sum256(rec)}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].url < recs[j].url })
	for i := 1; i < len(recs); i++ {
		if recs[i].url == recs[i-1].url {
			return zero, fmt.Errorf("govRoot v4: page %s is captured twice", recs[i].url)
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

func rolesEqual(a, b []proofv2.PageRole) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// VotesRootV4 commits the authority votes copied from the principal's proven signature chain (design D3): the merkle hash
// (merkle.Hasher) of the sha256 of each vote's encoding/json form (the struct's field order is fixed, so the bytes are), the
// votes sorted by (authority, origin, message) in canonical spelling. An intent with no recorded vote was authorized by
// nothing, and is refused by name; so is one vote recorded twice.
func VotesRootV4(votes []proofv2.Vote) ([32]byte, error) {
	var zero [32]byte
	if len(votes) == 0 {
		return zero, fmt.Errorf("govRoot v4: the evidence records no authority vote, so nothing authorized the intent")
	}
	type leaf struct {
		authority, origin, message string
		h                          [32]byte
	}
	leaves := make([]leaf, len(votes))
	for i, v := range votes {
		b, err := json.Marshal(v)
		if err != nil {
			return zero, fmt.Errorf("govRoot v4: vote %d: %w", i, err)
		}
		leaves[i] = leaf{govvote.CanonicalAccSpelling(v.Authority), govvote.CanonicalAccSpelling(v.Origin), strings.ToLower(v.Message), sha256.Sum256(b)}
	}
	sort.SliceStable(leaves, func(i, j int) bool {
		a, b := leaves[i], leaves[j]
		if a.authority != b.authority {
			return a.authority < b.authority
		}
		if a.origin != b.origin {
			return a.origin < b.origin
		}
		return a.message < b.message
	})
	for i := 1; i < len(leaves); i++ {
		if leaves[i].h == leaves[i-1].h {
			return zero, fmt.Errorf("govRoot v4: the vote of %s by %s is recorded twice", leaves[i].authority, leaves[i].origin)
		}
	}
	var h merkle.Hasher
	for _, l := range leaves {
		h.AddHash2(l.h)
	}
	var out [32]byte
	copy(out[:], h.MerkleHash())
	return out, nil
}
