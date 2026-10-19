// Copyright 2026 Certen Protocol

package xworld

import proofv2 "github.com/certen/independant-validator/pkg/proof/v2"

// RB9-F6, F-VE-2 option (b) (owner decision 2026-10-19): the offline walk requires the genesis link of every evidence 2.1 document, the
// continuous form included. A document of the earlier suites that VERIFIED has no such link, so its verdict moves: the suites keep its
// bytes (a frozen document) and say so, and beside it sits the document of the same case that carries the link, under the suffix `-g`.
// A document that was REFUSED was refused for another reason, which the offline walk still judges first: its verdict does not move.

// GenesisMovedNote is the manifest note of a frozen document whose verdict moved.
const GenesisMovedNote = "frozen document; verdict moved by F-VE-2 (b) (2.1 unreleased)"

// GenesisSiblingSuffix is the suffix of the sibling that carries the genesis link.
const GenesisSiblingSuffix = "-g"

// Linked is the case as the offline walk requires its document to be: the same world and the same edit, with the genesis link
// (Options.GenesisLinked). Its verdict is the case's own.
func (c Case) Linked() Case {
	c.Opts.GenesisLinked = true
	return c
}

// GenesisRequired applies F-VE-2 (b) to a suite: every case that verified keeps its name, its document and its description, and is now
// refused certify_link_missing{genesis} (State, Fields, Note); its sibling, named with GenesisSiblingSuffix, carries the link and is judged
// as the case was. The siblings follow the suite's earlier cases, in their order. A refused case is unchanged.
func GenesisRequired(cases []Case) []Case {
	out := make([]Case, 0, len(cases)*2)
	var siblings []Case
	for _, c := range cases {
		if c.Expect != verified {
			out = append(out, c)
			continue
		}
		frozen := c
		frozen.Expect, frozen.State, frozen.Fields, frozen.Note = refused, proofv2.StateCertifyLinkMissing, []string{"genesis"}, GenesisMovedNote
		frozen.Partition, frozen.Block, frozen.Unproven, frozen.Disclosures = "", 0, nil, nil
		out = append(out, frozen)
		s := c.Linked()
		s.Name = c.Name + GenesisSiblingSuffix
		s.Description = c.Description + " (the sibling of the frozen document " + c.Name + " that carries the genesis link: F-VE-2 (b))"
		siblings = append(siblings, s)
	}
	return append(out, siblings...)
}
