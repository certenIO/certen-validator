package main

import (
	"fmt"
	"reflect"
	"strings"
)

// The pinned F5-1 text and the fixed moves of the frozen documents (V-M V-M1 and notes 4, 5).
//
// A manifest entry of a frozen document says what that document is. Its description, world and edit are the F5-1 words (validator 3fdd056,
// testdata/certify1_f5_1_manifest.json, a verbatim copy of that commit's manifest): never the words of today's genesis-link-carrying spec, which
// describe the regenerated "-g" sibling. The world names are the F5-1 ones too: a frozen document was built from the chain of that name
// before the genesis link existed, while today's world of the same name carries one (and builds the regenerated "-g" sibling).

// certify1FrozenText is the F5-1 text of a frozen entry.
type certify1FrozenText struct{ Description, World, Edit string }

// certify1FrozenMove is the fixed expectation of a frozen document whose verdict the verifier moved (always refused; the text is the verifier's
// wording of State and Fields, fixed by certify1FrozenMoveWording). A frozen document that is not in certify1FrozenMoves keeps every other key of
// its F5-1 entry, whatever the verifier does; a verifier change that moves a further document, or moves one of these elsewhere, fails the
// generator and TestCertify1FrozenEntriesAreTheF5_1Ones instead of being re-baselined.
type certify1FrozenMove struct {
	State  string
	Fields []string
	Note   string
}

// certify1FrozenTexts holds the F5-1 text of the 33 frozen entries (git show 3fdd056:pkg/proof/v2/testdata/certify1/manifest.json).
var certify1FrozenTexts = map[string]certify1FrozenText{
	"continuous-chain-verified":                            {Description: "two continuous update-bearing items and a continuous closing item: the form every earlier document has", World: "chain-continuous", Edit: "none"},
	"anchored-chain-verified":                              {Description: "the same chain as continuous-chain-verified with every item anchored (no root proof) and three links: the same report", World: "chain-anchored", Edit: "none"},
	"mixed-chain-verified":                                 {Description: "the same chain with an anchored first item, a continuous second item and an anchored closing item, two links: the same report", World: "chain-mixed", Edit: "none"},
	"anchored-final-only-verified":                         {Description: "one anchored closing item and one link: an anchored item with no update is allowed as the last of its sequence", World: "chain-final-only", Edit: "none"},
	"link-absent":                                          {Description: "the anchored item has no link", World: "chain-final-only", Edit: "evidence/links removed"},
	"link-start-altered":                                   {Description: "the link starts somewhere other than the previous verified root chain anchor", World: "chain-final-only", Edit: "evidence/links/0/start first byte flipped"},
	"link-end-altered":                                     {Description: "the link ends somewhere other than the item's root chain anchor", World: "chain-final-only", Edit: "evidence/links/0/anchor first byte flipped"},
	"link-step-altered":                                    {Description: "the link starts and ends where it must but its path does not recompute: not a valid receipt", World: "chain-final-only", Edit: "evidence/links/0/entries/0/hash first byte flipped"},
	"link-of-a-different-item":                             {Description: "the first anchored item takes the closing item's link, which starts at another root", World: "chain-mixed", Edit: "evidence/links/0 and /1 exchanged"},
	"link-surplus":                                         {Description: "a link no anchored item takes: the same chain would have two encodings", World: "chain-final-only", Edit: "evidence/links/1 = a copy of links/0"},
	"link-of-the-second-item-missing":                      {Description: "the second anchored item has no link of its own: it would take the third's, which starts elsewhere", World: "chain-anchored", Edit: "evidence/links/1 removed"},
	"anchored-item-without-update-not-last":                {Description: "an anchored item that changes nothing is only allowed as the last of its sequence", World: "chain-no-effect", Edit: "none (the world's first item is anchored and carries no update, and is not the last)"},
	"anchored-item-with-only-an-unapplied-update-not-last": {Description: "the canonical form is about effect, not about the updates member: an anchored item padded with an update that changes nothing is refused like one without updates", World: "chain-junk-update", Edit: "none (the world's first item is anchored and carries one update, a write to acc://dn.acme/oracle with a valid receipt, which the walk does not apply; it is not the last)"},
	"non-monotone-block":                                   {Description: "anchored items whose Directory minor blocks do not increase", World: "chain-non-monotone", Edit: "none (the second item's block, 120, does not pass the first's, 130)"},
	"duplicated-update":                                    {Description: "an update the walk already applied: refused, so a count of the network's writes is injective", World: "chain-duplicated-update", Edit: "none (the anchored item carries the same globals write twice)"},
	"continuous-item-wrongly-rooted-then-anchored":         {Description: "a continuous item whose proof starts at another root, then an anchored closing item", World: "chain-continuous-then-end", Edit: "evidence/certify/0/rootProof/merkleState/pending/0 first byte flipped"},
	"anchored-then-continuous-item-wrongly-rooted":         {Description: "an anchored item, then a continuous closing item whose proof starts at another root", World: "chain-anchored-then-end", Edit: "evidence/certify/1/rootProof/merkleState/pending/0 first byte flipped"},
	"anchor-of-another-chain-genuinely-signed":             {Description: "a genuine anchor of another chain: the signatures are intact and the link is valid in its own chain, but it does not start at the verified root", World: "chain-final-only", Edit: "evidence/certify/0 and links/0 replaced by a record of another chain signed by the genesis set, with that chain's own link"},
	"anchor-re-rooted-off-the-verified-root":               {Description: "the link starts at the verified root and ends at the foreign anchor's root, which the genesis set signed: the walk accepts it and the transaction's receipt, which ends at the world's own root, is refused", World: "chain-final-only", Edit: "evidence/certify/0 and links/0 replaced by a record of another chain signed by the genesis set, linked from the verified root"},
	"anchor-of-another-incarnation":                        {Description: "a cross-incarnation anchor: the link is valid and starts at the verified root, the signers are not in the set in force", World: "chain-final-only", Edit: "evidence/certify/0 and links/0 replaced by a record signed by a validator set the genesis does not hold, linked from the verified root"},
	"root-proof-null-is-absent":                            {Description: "a null rootProof is no rootProof: the item is anchored and takes its link", World: "chain-final-only", Edit: "evidence/certify/0/rootProof = null"},
	"root-proof-empty-object":                              {Description: "an empty rootProof is a continuous item with an empty proof, not an anchored one", World: "chain-final-only", Edit: "evidence/certify/0/rootProof = {}"},
	"root-proof-merkle-state-only":                         {Description: "a rootProof without its receipt is a continuous item with an incomplete proof", World: "chain-final-only", Edit: "evidence/certify/0/rootProof = {merkleState: the chain's}"},
	"record-with-an-unknown-trailing-field":                {Description: "a record carrying a field the decoder does not know (Accumulate keeps it as its epilogue): the verdict is the unmodified document's", World: "chain-final-only", Edit: "evidence/certify/0/$epilogue = field 5"},
	"link-with-an-unknown-trailing-field":                  {Description: "a link is a receipt, not a record: unlike a record, whose unknown trailing field leaves the verdict unchanged, a receipt carrying one is refused as an invalid link at its ordinal", World: "chain-final-only", Edit: "evidence/links/0/$epilogue = field 5"},
	"link-undecodable-before-an-earlier-items-refusal":     {Description: "every link is decoded before any item is judged: link 1 does not decode, and item 0, which comes first, has no quorum; the verdict is the link's, at its ordinal, never item 0's", World: "chain-two-anchored", Edit: "evidence/links/1/$epilogue = field 5 and evidence/certify/0/signatures = []"},
	"hops-anchored-verified":                               {Description: "an anchored closing certify item and two anchored hops, three links in the order certify then hops", World: "chain-hops-anchored", Edit: "none"},
	"hop-link-absent":                                      {Description: "the last hop has no link: the ordinal is counted across certify and hops", World: "chain-hops-anchored", Edit: "evidence/links/2 removed"},
	"hop-link-start-altered":                               {Description: "the first hop's link starts somewhere other than the checkpoint's root chain anchor", World: "chain-hops-anchored", Edit: "evidence/links/1/start first byte flipped"},
	"hop-anchored-item-without-update-not-last":            {Description: "the canonical form holds for the set check's hops; the item is numbered across certify and hops", World: "chain-hops-no-effect", Edit: "none (the first hop is anchored, carries no update and is not the last)"},
	"hop-duplicated-update":                                {Description: "the replay refusal holds for the set check's hops", World: "chain-hops-duplicated", Edit: "none (the first hop carries the same globals write twice)"},
	"anchored-item-in-an-evidence-2.0-document":            {Description: "an item without a root proof in a document that claims 2.0: refused as it always was", World: "conformance:network-update", Edit: "evidence/certify/0/rootProof removed"},
	"links-member-in-an-evidence-2.0-document":             {Description: "a links member in a document that claims 2.0 is not read: the verdict is the unmodified document's, whatever the member holds", World: "conformance:network-update", Edit: "evidence/links = a string"},
}

// certify1FrozenMoves holds the 18 frozen documents whose verdict moved (the other 15 keep their F5-1 verdict).
var certify1FrozenMoves = map[string]certify1FrozenMove{
	"continuous-chain-verified":                            {State: "certify_update_unproven", Fields: []string{"acc://dn.acme/globals", "28ae41e0a0d8e5aeb3e4dd8559c4e384534a247d10db100c07db37ad89cf6eea", "110"}, Note: certify1FrozenWindowNote},
	"anchored-chain-verified":                              {State: "certify_update_unproven", Fields: []string{"acc://dn.acme/globals", "28ae41e0a0d8e5aeb3e4dd8559c4e384534a247d10db100c07db37ad89cf6eea", "110"}, Note: certify1FrozenWindowNote},
	"mixed-chain-verified":                                 {State: "certify_update_unproven", Fields: []string{"acc://dn.acme/globals", "28ae41e0a0d8e5aeb3e4dd8559c4e384534a247d10db100c07db37ad89cf6eea", "110"}, Note: certify1FrozenWindowNote},
	"anchored-final-only-verified":                         {State: "certify_link_missing", Fields: []string{"genesis"}, Note: certify1FrozenMovedNote},
	"link-surplus":                                         {State: "certify_link_missing", Fields: []string{"genesis"}, Note: certify1FrozenMovedNote},
	"link-of-the-second-item-missing":                      {State: "certify_update_unproven", Fields: []string{"acc://dn.acme/globals", "28ae41e0a0d8e5aeb3e4dd8559c4e384534a247d10db100c07db37ad89cf6eea", "110"}, Note: certify1FrozenWindowNote},
	"anchored-item-with-only-an-unapplied-update-not-last": {State: "certify_update_unproven", Fields: []string{"acc://dn.acme/oracle", "f78037c5e762bd659cb58220ef5b42d2a7de24c554e92894776b7c9f71c612f1", "110"}, Note: certify1FrozenWindowNote},
	"non-monotone-block":                                   {State: "certify_update_unproven", Fields: []string{"acc://dn.acme/globals", "28ae41e0a0d8e5aeb3e4dd8559c4e384534a247d10db100c07db37ad89cf6eea", "130"}, Note: certify1FrozenWindowNote},
	"duplicated-update":                                    {State: "certify_update_unproven", Fields: []string{"acc://dn.acme/globals", "57b7ace2b33e5851a709a3c29b3d3642fb137669e9ecf8a9cfec95ba31278a42", "110"}, Note: certify1FrozenWindowNote},
	"anchored-then-continuous-item-wrongly-rooted":         {State: "certify_update_unproven", Fields: []string{"acc://dn.acme/globals", "28ae41e0a0d8e5aeb3e4dd8559c4e384534a247d10db100c07db37ad89cf6eea", "110"}, Note: certify1FrozenWindowNote},
	"anchor-re-rooted-off-the-verified-root":               {State: "certify_link_missing", Fields: []string{"genesis"}, Note: certify1FrozenMovedNote},
	"root-proof-null-is-absent":                            {State: "certify_link_missing", Fields: []string{"genesis"}, Note: certify1FrozenMovedNote},
	"record-with-an-unknown-trailing-field":                {State: "certify_link_missing", Fields: []string{"genesis"}, Note: certify1FrozenMovedNote},
	"hops-anchored-verified":                               {State: "certify_link_missing", Fields: []string{"genesis"}, Note: certify1FrozenMovedNote},
	"hop-link-absent":                                      {State: "certify_link_missing", Fields: []string{"genesis"}, Note: certify1FrozenMovedNote},
	"hop-link-start-altered":                               {State: "certify_link_missing", Fields: []string{"genesis"}, Note: certify1FrozenMovedNote},
	"hop-anchored-item-without-update-not-last":            {State: "certify_link_missing", Fields: []string{"genesis"}, Note: certify1FrozenMovedNote},
	"hop-duplicated-update":                                {State: "certify_link_missing", Fields: []string{"genesis"}, Note: certify1FrozenMovedNote},
}

// certify1FrozenMoveWording is the verifier's exact text of a fixed move, written out here and not taken from the verifier ("" for a state no
// move has).
func certify1FrozenMoveWording(m certify1FrozenMove) string {
	switch m.State {
	case "certify_link_missing":
		return "certify_link_missing{" + strings.Join(m.Fields, ",") + "}: an anchored item has no link"
	case "certify_update_unproven":
		return "certify_update_unproven{" + strings.Join(m.Fields, ",") + "}: the update's root chain position does not lie between the previous and this anchor's root chain index"
	}
	return ""
}

// checkCertify1FrozenEntry is the rule every frozen entry of the generated manifest obeys: the F5-1 text, and either the fixed move or the
// spec's F5-1 verdict (the unmoved note where a regenerated sibling exists).
func checkCertify1FrozenEntry(c Certify1Case, hasSibling bool) error {
	txt, ok := certify1FrozenTexts[c.Name]
	if !ok {
		return fmt.Errorf("%s: no pinned F5-1 text", c.Name)
	}
	if c.Description != txt.Description || c.World != txt.World || c.Edit != txt.Edit {
		return fmt.Errorf("%s: description, world and edit are not the pinned F5-1 text", c.Name)
	}
	if mv, moved := certify1FrozenMoves[c.Name]; moved {
		if c.Expect != "refused" || c.State != mv.State || !reflect.DeepEqual(c.Fields, mv.Fields) || c.Note != mv.Note ||
			c.Wording != certify1FrozenMoveWording(mv) || c.Prefix != c.Wording || c.Report != nil || c.SameReportAs != "" {
			return fmt.Errorf("%s: the frozen document is judged %s %s%v (%q), not the fixed move %s%v", c.Name, c.Expect, c.State, c.Fields, c.Note, mv.State, mv.Fields)
		}
		return nil
	}
	if hasSibling && c.Note != certify1FrozenUnmovedNote || !hasSibling && c.Note != "" {
		return fmt.Errorf("%s: note %q on an unmoved frozen document", c.Name, c.Note)
	}
	return nil
}
