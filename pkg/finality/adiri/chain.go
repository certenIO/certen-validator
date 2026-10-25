// Copyright 2026 Certen Protocol

package adiri

import (
	"io"

	"github.com/certen/independant-validator/pkg/finality"
)

// ChainResult is what the committee chain established.
type ChainResult struct {
	Epoch          uint64 // E = the last record
	Digests        [][32]byte
	Shrunk         []*finality.StateError // committee_shrunk attributes, ascending epoch
	Signers        int                    // signers of record E
	CommitteeSize  int                    // size of committee(E)
	Final          NumHash                // record(E).final_state
	FinalConsensus NumHash
}

func quorum(n int) int { return 2*n/3 + 1 }

func keySet(keys [][]byte) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[string(k)] = true
	}
	return m
}

// VerifyCommitteeChain judges records 0..E of c against the pins par: O1 (record 0 against the pinned genesis), O2 (every
// record's compatibility, size and quorum), O3 (every signature). The structural checks of ALL records run before any
// signature is verified, so that the verdict does not depend on the mode; mode only chooses how signatures are verified.
// rnd supplies the batch scalars (nil = crypto/rand).
func VerifyCommitteeChain(par *Params, c *CFA1, mode Mode, rnd io.Reader) (*ChainResult, error) {
	if par.Codec != Codec {
		return nil, CodecUnsupported(0, par.Codec, Codec)
	}
	if len(c.Records) == 0 {
		return nil, finality.Malformed("cfa1.n_records", finality.ReasonCFA1NoRecords, 0, 1)
	}
	// This function is exported and judges any CFA1, not only one DecodeCFA1 returned: the table and signer rules DecodeCFA1 applies
	// are applied again, for every record, before RecordDigests indexes the tables and before a signer list indexes a committee.
	for i, rec := range c.Records {
		if err := checkRecordTables(i, rec, len(c.Tables)); err != nil {
			return nil, err
		}
		if err := checkRecordSigners(i, rec.Signers, len(c.Tables[rec.CommitteeIdx])); err != nil {
			return nil, err
		}
	}
	keys := newKeyCache()
	digests, err := c.RecordDigests()
	if err != nil {
		return nil, err
	}
	res := &ChainResult{Epoch: uint64(len(c.Records) - 1), Digests: digests}

	// O1: committee(0) as a SET equals the pinned genesis committee; record(0).final_state equals the pinned one.
	c0 := c.Committee(0)
	if dup := firstDuplicate(c0); dup >= 0 {
		return nil, ChainBroken(0, CheckDuplicateKey, "index", uint64(dup))
	}
	if !sameSet(c0, par.GenesisCommittee) {
		return nil, PinMismatch("genesis_committee", uint64(len(par.GenesisCommittee)), uint64(len(c0)))
	}
	if c.Records[0].FinalState != par.Epoch0FinalState {
		return nil, IncarnationMismatch(par.Epoch0FinalState, c.Records[0].FinalState)
	}

	items := make([]sigItem, 0, len(c.Records))
	for i := range c.Records {
		ep := uint64(i)
		rec := c.Records[i]
		committee := c.Committee(i)
		entries := make([]*keyEntry, len(committee))
		for j, k := range committee {
			if entries[j] = keys.get(k); entries[j] == nil {
				return nil, ChainBroken(ep, CheckPublicKeyInvalid, "index", uint64(j))
			}
		}
		if dup := firstDuplicate(committee); dup >= 0 {
			return nil, ChainBroken(ep, CheckDuplicateKey, "index", uint64(dup))
		}
		if i > 0 {
			expected := keySet(c.Next(i - 1))
			size := len(committee)
			switch {
			case size > len(expected):
				return nil, incompatible(ep, ReasonLargerThanExpected, size, len(expected), par.MinCommittee)
			case size == len(expected):
				for _, k := range committee {
					if !expected[string(k)] {
						return nil, incompatible(ep, ReasonSetMismatch, size, len(expected), par.MinCommittee)
					}
				}
			default:
				for _, k := range committee {
					if !expected[string(k)] {
						return nil, incompatible(ep, ReasonNotSubset, size, len(expected), par.MinCommittee)
					}
				}
				if 3*size < 2*len(expected) {
					return nil, incompatible(ep, ReasonBelowTwoThirds, size, len(expected), par.MinCommittee)
				}
				if size < par.MinCommittee {
					return nil, incompatible(ep, ReasonBelowMinCommitteeSize, size, len(expected), par.MinCommittee)
				}
				res.Shrunk = append(res.Shrunk, Shrunk(ep, size, len(expected)))
			}
		}
		if len(committee) < par.MinCommittee {
			return nil, incompatible(ep, ReasonBelowMinCommitteeSize, len(committee), len(committee), par.MinCommittee)
		}
		need := quorum(len(committee))
		if len(rec.Signers) < need {
			return nil, ChainBroken(ep, CheckBelowQuorum, "got", uint64(len(rec.Signers)), "need", uint64(need))
		}
		signers := make([]*keyEntry, len(rec.Signers))
		for j, s := range rec.Signers {
			signers[j] = entries[s]
		}
		items = append(items, sigItem{epoch: i, sig: rec.Signature[:], signer: signers, msg: SignedMessage(digests[i])})
	}

	idx, reason, err := firstFailure(items, mode, rnd)
	if err != nil {
		// firstFailure fails only when the batch scalars cannot be read: a fact about the process, not a verdict of the verifier (RB12 OPS-A2 item 12)
		return nil, finality.NewState(finality.CodeRandomnessUnavailable, "chain", par.ChainID, "kind", Name, "cause", err.Error())
	}
	if idx >= 0 {
		return nil, ChainBroken(uint64(items[idx].epoch), CheckSignatureInvalid, "reason", reason)
	}
	last := c.Records[len(c.Records)-1]
	res.Signers = len(last.Signers)
	res.CommitteeSize = len(c.Committee(len(c.Records) - 1))
	res.Final = last.FinalState
	res.FinalConsensus = last.FinalConsensus
	return res, nil
}

func incompatible(epoch uint64, reason IncompatibleReason, size, expected, min int) *finality.StateError {
	return ChainBroken(epoch, CheckCommitteeIncompatible, "reason", reason, "size", uint64(size), "expected", uint64(expected), "min_committee_size", uint64(min))
}

func firstDuplicate(keys [][]byte) int {
	seen := make(map[string]bool, len(keys))
	for i, k := range keys {
		if seen[string(k)] {
			return i
		}
		seen[string(k)] = true
	}
	return -1
}

// sameSet reports set equality (duplicates collapse).
func sameSet(a, b [][]byte) bool {
	sa, sb := keySet(a), keySet(b)
	if len(sa) != len(sb) {
		return false
	}
	for k := range sa {
		if !sb[k] {
			return false
		}
	}
	return true
}
