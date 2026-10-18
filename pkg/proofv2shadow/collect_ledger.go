// Copyright 2026 Certen Protocol
//
// The system ledger of every partition a capture reads pages from, as of the same block (RB9 Phase C1b-2; pkg/proof/v2 xexecutor.go).
// SystemLedger.ExecutorVersion is the executor version in force at the block; a document that proves the ledger proves the version the
// re-evaluation's rules (Baikonur and later) are for.

package proofv2shadow

import (
	"context"
	"fmt"
	"sort"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// ledgerURL is a partition's system ledger.
func ledgerURL(partition string) *url.URL {
	if isDirectory(partition) {
		return protocol.DnUrl().JoinPath(protocol.Ledger)
	}
	return protocol.PartitionUrl(partition).JoinPath(protocol.Ledger)
}

// captureLedgers reads each bound partition's system ledger at the partition's block, binds it like the partition's other pages, adds it to
// the closure with the role system-ledger, and returns g1_executor_version_unsupported{partition, block} for a version before Baikonur.
// A ledger that cannot be read becomes the note g1_executor_version_unproven{partition, block}, carried in the capture.
func (c *Collector) captureLedgers(ctx context.Context, st *runState, cl *Closure, _ AccountReader) error {
	names := make([]string, 0, len(st.bindings))
	for p := range st.bindings {
		names = append(names, p)
	}
	sort.Strings(names)
	var first error
	for _, p := range names {
		bd := st.bindings[p]
		lu := ledgerURL(p)
		ps, err := c.Page(ctx, lu.String(), p, bd.block)
		if err == nil && bd.pb != nil {
			ps, err = proofv2.BindToAnchor(ps, p, bd.block, bd.stateRoot)
		}
		var led *protocol.SystemLedger
		if err == nil {
			var acct protocol.Account
			if acct, err = decodeAccount(ps, lu); err == nil {
				var ok bool
				if led, ok = acct.(*protocol.SystemLedger); !ok {
					err = fmt.Errorf("%v is %T, not a system ledger", lu, acct)
				}
			}
		}
		if err != nil {
			cl.Notes = append(cl.Notes, &proofv2.NamedState{Code: proofv2.StateExecutorVersionUnproven, Partition: p, Block: bd.block,
				Detail: fmt.Sprintf("the system ledger %v could not be read at the block: %v", lu, err)})
			continue
		}
		ps.Partition = protocol.PartitionUrl(p).String()
		if isDirectory(p) {
			ps.Partition = protocol.DnUrl().String()
		}
		st.cache[key(lu)] = &captured{page: ps, block: bd.block}
		cl.Pages = append(cl.Pages, GovPage{URL: lu.String(), Roles: []proofv2.PageRole{proofv2.RoleSystemLedger}})
		if !led.ExecutorVersion.V2BaikonurEnabled() && first == nil {
			first = &proofv2.NamedState{Code: proofv2.StateExecutorVersionUnsupported, Partition: p, Block: bd.block,
				Detail: fmt.Sprintf("%v holds executor version %d, before Baikonur (%d)", lu, led.ExecutorVersion, protocol.ExecutorVersionV2Baikonur)}
		}
	}
	return first
}
