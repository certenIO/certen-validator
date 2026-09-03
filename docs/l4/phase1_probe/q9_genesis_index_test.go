// Q9 probe (Phase 1). Read-only research against origin/main, extracted with
// `git archive` so accumulate-core itself is never touched.
//
// Phase 0 measured: on the live networks the genesis chain entry of
// acc://dn.acme/network cannot be found by HASH (no ElementIndex) but is fully
// receipt-provable by INDEX. Q9 asks whether that missing hash->index map is
// GUARANTEED by how genesis is built, or INCIDENTAL to how these particular
// nodes were provisioned. This builds a genesis from scratch and asks again.
package q9probe

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/accumulatenetwork/accumulate/internal/database"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
	. "gitlab.com/accumulatenetwork/accumulate/test/harness"
	. "gitlab.com/accumulatenetwork/accumulate/test/helpers"
	"gitlab.com/accumulatenetwork/accumulate/test/simulator"
)

func TestQ9_GenesisElementIndexOnAFreshChain(t *testing.T) {
	sim := NewSim(t,
		simulator.SimpleNetwork(t.Name(), 3, 3),
		simulator.Genesis(GenesisTime),
	)
	sim.StepN(10)

	for _, path := range []string{protocol.Network, protocol.Globals} {
		u := protocol.DnUrl().JoinPath(path)
		View(t, sim.Database(protocol.Directory), func(batch *database.Batch) {
			mc, err := batch.Account(u).ChainByName("main")
			require.NoError(t, err)
			head, err := mc.Head().Get()
			require.NoError(t, err)
			t.Logf("--- %v : main chain height %d ---", u, head.Count)
			require.NotZero(t, head.Count, "genesis must have written this account")

			hash, err := mc.Entry(0)
			require.NoError(t, err)
			t.Logf("    entry[0]        = %x", hash)

			idx, err := mc.Inner().IndexOf(hash)
			if err != nil {
				t.Logf("    IndexOf(entry0) -> ERROR: %v", err)
				t.Logf("    VERDICT: hash->index map ABSENT on a freshly built genesis")
			} else {
				t.Logf("    IndexOf(entry0) -> %d", idx)
				t.Logf("    VERDICT: hash->index map PRESENT on a freshly built genesis;")
				t.Logf("             its absence on the live nodes is INCIDENTAL to provisioning")
			}
		})
	}
}
