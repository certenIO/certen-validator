package consensus

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// The rules v11 admin re-seal REHEARSED on a real CometBFT network of four in-process validators running this
// ValidatorApp - the production path the fleet will take. Sealed at genesis with an admin set this test treats as the
// lost one, the network:
//
//  1. commits the re-seal; every node records it at the same height;
//  2. refuses, from the next height, a BLS registry signed by the lost admins, and accepts one signed by the new ones;
//  3. refuses a second re-seal;
//  4. restarted as a whole fleet (a deploy), comes back on one chain with its state stamped v11.
func TestAdminResealRehearsalOnALiveNetwork(t *testing.T) {
	f := newRegistryFixture(t)
	from, to, newAdmins := resealSets(f.rotationFixture)
	lost, installed := lostAdminSet, resealedAdminSet
	lostAdminSet, resealedAdminSet = from, to
	defer func() { lostAdminSet, resealedAdminSet = lost, installed }()

	var adminEnv []string
	for _, id := range []string{"ops-1", "ops-2", "ops-3"} {
		adminEnv = append(adminEnv, id+":"+f.policy.AdminKeys[id])
	}
	t.Setenv("CERTEN_ENTITLEMENT_MODE", "off")
	t.Setenv("CERTEN_ENTITLEMENT_ADMIN_KEYS", strings.Join(adminEnv, ","))
	t.Setenv("CERTEN_ENTITLEMENT_ADMIN_THRESHOLD", "2")
	t.Setenv("CERTEN_BLOCK_RETENTION", "0")

	const size = 4
	nodes, genesis, _, tick := startRehearsalNetwork(t, f.rotationFixture, size)

	submit := func(via *rehearsalNode, tx []byte) (uint32, string, int64) {
		t.Helper()
		res, err := via.client.BroadcastTxCommit(context.Background(), cmttypes.Tx(tx))
		if err != nil {
			t.Fatalf("broadcast: %v", err)
		}
		if res.CheckTx.Code != 0 {
			return res.CheckTx.Code, res.CheckTx.Log, 0
		}
		return res.TxResult.Code, res.TxResult.Log, res.Height
	}
	everyNode := func(what string, h int64) {
		t.Helper()
		waitNetwork(t, what, 90*time.Second, func() bool {
			for _, n := range nodes {
				if n.height() < h {
					return false
				}
			}
			return true
		})
	}
	signedByNew := func(version uint64) []byte {
		tx := f.registry(version)
		tx.Signatures = nil
		for _, id := range []string{"admin-b", "admin-c"} {
			tx.Signatures = append(tx.Signatures, PolicySignature{KeyID: id,
				Signature: hex.EncodeToString(ed25519.Sign(newAdmins[id], tx.SigningBytes()))})
		}
		return rotJSON(t, tx)
	}

	// 1. The re-seal.
	code, logText, h := submit(nodes[0], rotJSON(t, resealFor(to, rotChain)))
	if code != 0 {
		t.Fatalf("the re-seal was refused: %d %s", code, logText)
	}
	tick(nodes[0], 2)
	everyNode("every node to commit past the re-seal", h+2)
	for _, n := range nodes {
		st, err := ledger.NewLedgerStore(n.kv).LoadEntitlementPolicy()
		if err != nil || len(st.AdminReseals) != 1 || st.AdminReseals[0].Height != h {
			t.Fatalf("%s's re-seal record: (%+v, %v)", n.name, st, err)
		}
		if keys, th := AdminSetAt(st, h+1); !sameAdminSet(keys, th, to) {
			t.Fatalf("%s: the admin set in force after the re-seal is not the installed one", n.name)
		}
	}

	// 2. The lost admins no longer authorise; the new ones do.
	if code, logText, _ := submit(nodes[1], rotJSON(t, f.registry(1, "ops-1", "ops-2"))); code != codeBLSRegistryRefused {
		t.Fatalf("a registry signed by the lost admins after the re-seal: %d %s", code, logText)
	}
	code, logText, hr := submit(nodes[2], signedByNew(1))
	if code != 0 {
		t.Fatalf("a registry signed by the new admins was refused: %d %s", code, logText)
	}
	tick(nodes[0], 2)
	everyNode("every node to commit past the registry", hr+2)
	for _, n := range nodes {
		l, err := ledger.NewLedgerStore(n.kv).LoadBLSRegistry()
		if err != nil || len(l.Versions) != 1 || l.Versions[0].Height != hr {
			t.Fatalf("%s's registry log: (%+v, %v)", n.name, l, err)
		}
	}

	// 3. No second re-seal. The identical bytes are refused by CometBFT's own cache before the rule sees them; the same
	// re-seal in other bytes (a trailing space - it decodes identically) reaches the rule, which refuses it.
	if res, err := nodes[3].client.BroadcastTxCommit(context.Background(), cmttypes.Tx(rotJSON(t, resealFor(to, rotChain)))); err == nil &&
		res.CheckTx.Code == 0 && res.TxResult.Code == 0 {
		t.Fatal("the identical re-seal was committed again")
	}
	if code, logText, _ := submit(nodes[3], append(rotJSON(t, resealFor(to, rotChain)), ' ')); code != codeAdminResealRefused ||
		!strings.Contains(logText, "already re-sealed") {
		t.Fatalf("a second re-seal: code %d %s", code, logText)
	}

	// Every node's whole committed chain passes the record check v12 runs at start: the re-seal and the registry
	// accepted, each found in its record.
	for _, n := range nodes {
		if got := checkLiveHistory(t, n); got != 2 {
			t.Fatalf("%s: %d accepted re-seals and registries found in their records, want 2", n.name, got)
		}
	}

	// 4. The whole fleet restarts and carries on, its state v11's.
	for _, n := range nodes {
		n.stop(t)
	}
	for _, n := range nodes {
		n.start(t, genesis)
	}
	restartedAt := nodes[0].height()
	waitNetwork(t, "the restarted fleet to connect", 90*time.Second, func() bool {
		for _, n := range nodes {
			if n.node.Switch().Peers().Size() < size-1 {
				return false
			}
		}
		return true
	})
	tick(nodes[0], 3)
	everyNode("the restarted fleet to commit", restartedAt+3)
	for _, n := range nodes {
		st, err := ledger.NewLedgerStore(n.kv).LoadABCIState()
		if err != nil || st.ExecutionRulesVersion != executionRulesV11 {
			t.Fatalf("%s: state after the re-seal is stamped (%+v, %v); want v11", n.name, st, err)
		}
	}
	// One chain: every node reports the same app hash at the same height.
	waitNetwork(t, "every node at one height", 30*time.Second, func() bool {
		top := nodes[0].height()
		for _, n := range nodes {
			if n.height() != top {
				return false
			}
		}
		return true
	})
	var first string
	for i, n := range nodes {
		info, err := n.client.ABCIInfo(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		got := hex.EncodeToString(info.Response.LastBlockAppHash)
		if i == 0 {
			first = got
		} else if got != first {
			t.Fatalf("%s's app hash %s is not %s's %s", n.name, got, nodes[0].name, first)
		}
	}
}
