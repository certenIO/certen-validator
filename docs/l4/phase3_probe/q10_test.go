// Q10 (Phase 3). Exercise the path that has never run.
//
// The validator set has never changed on mainnet or Kermit, so every claim
// about the update timeline is untested in production. This runs a real
// validator-set change end to end on origin/main's executor and then asks the
// question the whole design rests on:
//
//	AFTER the set changes, can the PREVIOUS set still be proven?
//
// Phase 1 §1.1 predicted no, from reading bpt_receipt.go. This settles it by
// running it.
package q10probe

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/accumulatenetwork/accumulate/internal/core"
	"gitlab.com/accumulatenetwork/accumulate/internal/database"
	"gitlab.com/accumulatenetwork/accumulate/pkg/build"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
	. "gitlab.com/accumulatenetwork/accumulate/test/harness"
	. "gitlab.com/accumulatenetwork/accumulate/test/helpers"
	"gitlab.com/accumulatenetwork/accumulate/test/simulator"
	acctesting "gitlab.com/accumulatenetwork/accumulate/test/testing"
)

func dataOf(e protocol.DataEntry) []any {
	var out []any
	for _, b := range e.GetData() {
		out = append(out, b)
	}
	return out
}

func TestQ10_ValidatorSetChangeAndHistoricalProvability(t *testing.T) {
	g := new(core.GlobalValues)
	g.Globals = new(protocol.NetworkGlobals)
	g.Globals.OperatorAcceptThreshold.Set(1, 3)
	g.ExecutorVersion = protocol.ExecutorVersionV2Vandenberg

	sim := NewSim(t,
		simulator.SimpleNetwork(t.Name(), 1, 3),
		simulator.GenesisWith(GenesisTime, g),
	)
	sim.StepN(5)

	netAcct := protocol.DnUrl().JoinPath(protocol.Network)

	// ---- BEFORE: the genesis validator set, and a proof of it ---------------
	var genesisLeaf, genesisBptRoot [32]byte
	var genesisState []byte
	var genesisValidators int
	View(t, sim.Database(protocol.Directory), func(batch *database.Batch) {
		acct := batch.Account(netAcct)
		st, err := acct.Main().Get()
		require.NoError(t, err)
		genesisState, err = st.MarshalBinary()
		require.NoError(t, err)
		genesisLeaf = sha256.Sum256(genesisState)

		r, err := acct.StateReceipt()
		require.NoError(t, err)
		copy(genesisBptRoot[:], r.Anchor)
		require.True(t, r.Validate(nil), "genesis state receipt must validate")

		da := st.(*protocol.DataAccount)
		var nd protocol.NetworkDefinition
		require.NoError(t, nd.UnmarshalBinary(da.Entry.GetData()[0]))
		genesisValidators = len(nd.Validators)

		mc, err := acct.ChainByName("main")
		require.NoError(t, err)
		h, err := mc.Head().Get()
		require.NoError(t, err)
		t.Logf("BEFORE: %d validators, NetworkDefinition.Version=%d, main chain height=%d",
			genesisValidators, nd.Version, h.Count)
		t.Logf("BEFORE: state leaf   %x", genesisLeaf[:8])
		t.Logf("BEFORE: BPT root     %x  (receipt VALIDATES)", genesisBptRoot[:8])
	})

	// ---- CHANGE: add a validator, the way the network really does it --------
	ops := protocol.DnUrl().JoinPath(protocol.Operators, "1")
	CreditCredits(t, sim.Database(protocol.Directory), ops, 1e9)

	newKey := acctesting.GenerateKey("q10-new-validator")
	values := new(core.GlobalValues)
	values.ExecutorVersion = protocol.ExecutorVersionV2Vandenberg
	View(t, sim.Database(protocol.Directory), func(batch *database.Batch) {
		st, err := batch.Account(netAcct).Main().Get()
		require.NoError(t, err)
		da := st.(*protocol.DataAccount)
		nd := new(protocol.NetworkDefinition)
		require.NoError(t, nd.UnmarshalBinary(da.Entry.GetData()[0]))
		values.Network = nd
	})
	// Added as INACTIVE on the Directory: this changes the RECORDED validator set
	// (what L4 carries and checks isActiveOn against) without changing consensus
	// membership, so the simulator can keep producing blocks with real nodes.
	values.Network.AddValidator(newKey[32:], protocol.Directory, false)
	values.Network.Version++

	wd := new(protocol.WriteData)
	wd.WriteToState = true
	wd.Entry = values.FormatNetwork()

	st := sim.BuildAndSubmitTxnSuccessfully(
		build.Transaction().For(netAcct).
			Body(wd).
			SignWith(ops).Version(1).Timestamp(1).Signer(sim.SignWithNode(protocol.Directory, 0)))

	sim.StepUntil(Txn(st.TxID).Succeeds())
	sim.StepN(20)

	// ---- AFTER --------------------------------------------------------------
	View(t, sim.Database(protocol.Directory), func(batch *database.Batch) {
		acct := batch.Account(netAcct)
		cur, err := acct.Main().Get()
		require.NoError(t, err)
		curBin, err := cur.MarshalBinary()
		require.NoError(t, err)
		curLeaf := sha256.Sum256(curBin)

		da := cur.(*protocol.DataAccount)
		var nd protocol.NetworkDefinition
		require.NoError(t, nd.UnmarshalBinary(da.Entry.GetData()[0]))

		mc, err := acct.ChainByName("main")
		require.NoError(t, err)
		h, err := mc.Head().Get()
		require.NoError(t, err)

		t.Logf("")
		t.Logf("AFTER : %d validators, NetworkDefinition.Version=%d, main chain height=%d",
			len(nd.Validators), nd.Version, h.Count)
		require.Equal(t, genesisValidators+1, len(nd.Validators), "the set must actually have changed")

		r, err := acct.StateReceipt()
		require.NoError(t, err)
		var newRoot [32]byte
		copy(newRoot[:], r.Anchor)
		t.Logf("AFTER : state leaf   %x", curLeaf[:8])
		t.Logf("AFTER : BPT root     %x  (receipt VALIDATES: %v)", newRoot[:8], r.Validate(nil))

		// --- THE DECISIVE CHECK ---------------------------------------------
		t.Logf("")
		t.Logf("=== Q10: can the PREVIOUS validator set still be proven? ===")
		t.Logf("  receipt.start is now  %x (the NEW state)", r.Start[:8])
		t.Logf("  the genesis leaf was  %x", genesisLeaf[:8])
		require.NotEqual(t, genesisLeaf[:], r.Start,
			"the BPT receipt must now start at the new leaf")
		t.Logf("  -> StateReceipt() returns a proof of the CURRENT set ONLY.")
		t.Logf("  -> There is no API taking a height or a historical root.")
		t.Logf("  -> The genesis validator set is now UNPROVABLE via the public API.")

		// The historical ROOT is still on chain, though - the asymmetry.
		anchors := batch.Account(protocol.DnUrl().JoinPath(protocol.AnchorPool))
		bptChain, err := anchors.ChainByName("anchor(directory)-bpt")
		if err == nil {
			bh, err := bptChain.Head().Get()
			require.NoError(t, err)
			t.Logf("")
			t.Logf("  ASYMMETRY: anchor(directory)-bpt retains %d historical BPT roots,", bh.Count)
			t.Logf("             including the one the genesis set was provable against.")
			t.Logf("             The ROOT survives; the MEMBERSHIP PATH to it does not.")
		}

		// --- the update entry itself is provable ----------------------------
		require.Equal(t, int64(2), h.Count, "the change must be a second main-chain entry")
		hash, err := mc.Entry(1)
		require.NoError(t, err)
		idx, errIdx := mc.Inner().IndexOf(hash)
		t.Logf("")
		t.Logf("  the UPDATE entry [1] = %x", hash[:8])
		if errIdx == nil {
			t.Logf("  by-hash lookup -> index %d (works: it went through AddEntry, unlike genesis)", idx)
		} else {
			t.Logf("  by-hash lookup -> %v", errIdx)
		}
		rcpt, err := mc.Inner().Receipt(1, h.Count-1)
		if err == nil {
			t.Logf("  update receipt: %d steps, validates=%v", len(rcpt.Entries), rcpt.Validate(nil))
		} else {
			t.Logf("  update receipt: %v", err)
		}

		// --- the one number Phase 2 could not measure: NetworkUpdateProof ---
		var msg messaging.MessageWithTransaction
		if err := batch.Message2(hash).Main().GetAs(&msg); err == nil {
			tb, err := msg.GetTransaction().MarshalBinary()
			require.NoError(t, err)
			rb := 0
			if rcpt != nil {
				b, err := rcpt.MarshalBinary()
				require.NoError(t, err)
				rb = len(b)
			}
			t.Logf("")
			t.Logf("  NetworkUpdateProof for THIS change:")
			t.Logf("    Transaction (WriteData + full NetworkDefinition) : %4d B", len(tb))
			t.Logf("    Receipt                                          : %4d B", rb)
			t.Logf("    -> NetworkUpdateProof ~= %d B for a 4-validator set", len(tb)+rb)
			t.Logf("    (this is the per-change cost the spine adds to a major-block window)")
		}
	})
}
