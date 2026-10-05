package intentcert

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// BindProofV2 requires the governance levels and the certified key page to be about exactly what the proof v2 report
// proved, the v3 counterpart of proof.BindG0ToChainedProof. govRoot v3 commits the report's facts and the levels'
// hashes side by side; without this, a block could pair a verified proof of one transaction with G0-G2 of another.
//
//   - G0's execution entry is the transaction the report's receipt starts at, and G0's receipt starts there;
//   - G0's execution witness is the root chain anchor of the partition anchor the receipt passes through, and its
//     execution block that anchor's block - which also pins AnchorBlock as the execution block, which the report
//     alone does not prove (proofv2.Report.AnchorBlock);
//   - the key page G1 validated against is the certified key page, and it is one of the pages the report proved.
func BindProofV2(rep *proofv2.Report, g0 *proof.G0Result, g1 *proof.G1Result, keyPageURL string) error {
	if rep == nil || g0 == nil || g1 == nil {
		return fmt.Errorf("proof v2 binding: the report, G0 and G1 are all required")
	}
	entry, err := hashOf(g0.EntryHashExec, "G0 entry_hash_exec")
	if err != nil {
		return err
	}
	start, err := hashOf(g0.Receipt.Start, "G0 receipt.start")
	if err != nil {
		return err
	}
	witness, err := hashOf(g0.ExecWitness, "G0 exec_witness")
	if err != nil {
		return err
	}
	switch {
	case entry != rep.TxHash:
		return fmt.Errorf("proof v2 binding: G0 proves entry %x, the report transaction %x", entry, rep.TxHash)
	case start != entry:
		return fmt.Errorf("proof v2 binding: G0's receipt starts at %x, not at its entry %x", start, entry)
	case witness != rep.AnchorRootChainAnchor:
		return fmt.Errorf("proof v2 binding: G0's witness %x is not the root %x of the partition anchor the report's receipt passes through",
			witness, rep.AnchorRootChainAnchor)
	case g0.ExecMBI <= 0 || uint64(g0.ExecMBI) != rep.AnchorBlock:
		return fmt.Errorf("proof v2 binding: G0's execution block %d is not the partition anchor's block %d", g0.ExecMBI, rep.AnchorBlock)
	}
	page := govvote.CanonicalAccSpelling(keyPageURL)
	if page == "" || page != govvote.CanonicalAccSpelling(g1.AuthoritySnapshot.Page) {
		return fmt.Errorf("proof v2 binding: the certified key page %q is not the page G1 validated against (%q)", keyPageURL, g1.AuthoritySnapshot.Page)
	}
	for _, a := range rep.Pages {
		if a != nil && a.GetUrl() != nil && govvote.CanonicalAccSpelling(a.GetUrl().String()) == page {
			return nil
		}
	}
	return fmt.Errorf("proof v2 binding: the certified key page %s is not among the pages the report proved", page)
}

func hashOf(s, what string) ([32]byte, error) {
	var h [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if err != nil || len(b) != 32 {
		return h, fmt.Errorf("proof v2 binding: %s is not 32 bytes of hex", what)
	}
	copy(h[:], b)
	return h, nil
}
