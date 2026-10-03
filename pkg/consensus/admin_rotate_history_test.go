package consensus

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
)

// preV12Chain executes, through FinalizeBlock and Commit, a chain holding every transaction kind rules v11 knows - a
// ValidatorBlock, a policy update, a tick, a validator rotation, a BLS registry, a refused and an accepted admin re-seal,
// a registry signed by the re-sealed admins - and returns each block's result codes and app hash. It uses only what the
// v11 test suite already had, so the same function runs unchanged against the v11 binary (origin/main 96522ff); its
// output there is pinned below.
func preV12Chain(t *testing.T) []string {
	lines, _, _, _ := runPreV12Chain(t)
	return lines
}

// runPreV12Chain is preV12Chain, also returning the app (its ledger is the chain's committed state) and every block's
// transactions and result codes.
func runPreV12Chain(t *testing.T) ([]string, *ValidatorApp, [][][]byte, [][]uint32) {
	t.Helper()
	f := newRegistryFixture(t)
	from, to, newAdmins := resealSets(f.rotationFixture)
	lost, installed := lostAdminSet, resealedAdminSet
	lostAdminSet, resealedAdminSet = from, to
	defer func() { lostAdminSet, resealedAdminSet = lost, installed }()

	app, _ := rotationApp(t, f.rotationFixture)
	policy := &PolicyUpdateTx{Kind: PolicyUpdateKind, ChainID: rotChain, Mode: string(EntitlementOff),
		ActivationUnix: 1_800_000_001 + MinActivationDelay + 60, Version: 1}
	for _, id := range []string{"ops-1", "ops-2"} {
		policy.Signatures = append(policy.Signatures, PolicySignature{KeyID: id,
			Signature: hex.EncodeToString(ed25519.Sign(f.admins[id], policy.SigningBytes()))})
	}
	byNew := f.registry(2)
	for _, id := range []string{"admin-a", "admin-c"} {
		byNew.Signatures = append(byNew.Signatures, PolicySignature{KeyID: id,
			Signature: hex.EncodeToString(ed25519.Sign(newAdmins[id], byNew.SigningBytes()))})
	}
	blocks := [][][]byte{
		{persistTestBlockJSON(t, "op-pre12-1", "G2", "validator-1"), rotJSON(t, policy),
			rotJSON(t, ChainTickTx{Kind: ChainTickKind, Nonce: "00112233445566778899aabbccddeeff"})},
		{rotJSON(t, f.rotation(1, f.validators[5], seededKey(0x91), "ops-1", "ops-3"))},
		{rotJSON(t, f.registry(1, "ops-2", "ops-3")), rotJSON(t, &AdminResealTx{Kind: AdminResealKind, ChainID: rotChain})},
		{rotJSON(t, resealFor(to, rotChain))},
		{rotJSON(t, f.registry(2, "ops-1", "ops-2")), rotJSON(t, byNew)},
	}
	var out []string
	var allCodes [][]uint32
	for i, txs := range blocks {
		h := int64(i + 1)
		resp, err := app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{
			Height: h, Time: time.Unix(1_800_000_000+h, 0), Hash: make([]byte, 32), Txs: txs})
		if err != nil {
			t.Fatal(err)
		}
		codes := make([]uint32, len(resp.TxResults))
		for j, r := range resp.TxResults {
			codes[j] = r.Code
		}
		if _, err := app.Commit(context.Background(), &abcitypes.RequestCommit{}); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("h=%d codes=%v apphash=%x stamp=v%d", h, codes, resp.AppHash, app.committedRulesVersion()))
		allCodes = append(allCodes, codes)
	}
	return out, app, blocks, allCodes
}

// v11PreV12Chain is preV12Chain's output under the v11 binary (origin/main 96522ff, captured 2026-10-03).
var v11PreV12Chain = []string{
	"h=1 codes=[0 0 0] apphash=c5e8b0b23d4b6ab4614fb6c65eb810702f7e676dbe25bbc0ecdd0edde98c4569 stamp=v8",
	"h=2 codes=[0] apphash=babd492d0f2240964cf3e9ea5075b24aea44b9db6080793d5b23499821b5b4bc stamp=v8",
	"h=3 codes=[0 11] apphash=24badee4162c7afa50972631afe70d940c7ebf0e68e03b9b120abbf2759a7721 stamp=v11",
	"h=4 codes=[0] apphash=ef1f873d0a5ad1cfa84892c5e35b0323dd1342ab2b3467c26c6e1c2b32ff9171 stamp=v11",
	"h=5 codes=[9 0] apphash=56a6d4b6dff05456d82fecb3a56fb6dadf1eccc05d84d8d2cfc9d90400aa3272 stamp=v11",
}

// Pre-v12 history replays identically: every block of a chain using every kind v11 knows is decided by v12 with the
// same result codes and the same app hash the v11 binary produced, and the state stays stamped with the version v11
// stamped it with.
func TestPreV12HistoryReplaysIdenticallyUnderV12(t *testing.T) {
	got := preV12Chain(t)
	for _, line := range got {
		t.Log(line)
	}
	if len(got) != len(v11PreV12Chain) {
		t.Fatalf("%d blocks, the v11 binary decided %d", len(got), len(v11PreV12Chain))
	}
	for i := range got {
		if got[i] != v11PreV12Chain[i] {
			t.Fatalf("block %d under v12:\n  %s\nunder v11:\n  %s", i+1, got[i], v11PreV12Chain[i])
		}
	}
}

// The stricter history check refuses no legitimately committed history: every block of the pre-v12 chain - a
// registry accepted, a re-seal refused and one accepted, a registry refused and one accepted by the re-sealed admins -
// passes it against the chain's own committed records, both as each node runs it at start and as the tool runs it.
func TestThePreV12ChainPassesTheRecordCheck(t *testing.T) {
	_, app, blocks, codes := runPreV12Chain(t)
	records, err := app.committedRecords()
	if err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for i := range blocks {
		h := int64(i + 1)
		v, u, err := CommittedBlockViolations(h, blocks[i], codes[i], records)
		if err != nil || len(v) != 0 || len(u) != 0 {
			t.Fatalf("block %d: %v %v %v", h, v, u, err)
		}
		for j, tx := range blocks[i] {
			_, isKind, err := app.kindViolation(h, j, tx, codes[i][j])
			if err != nil {
				t.Fatal(err)
			}
			if isKind && codes[i][j] == 0 {
				accepted++
			}
		}
		if _, found, err := app.historicalOperations(h, time.Unix(1_800_000_000+h, 0), blocks[i], codes[i]); err != nil || len(found) != 0 {
			t.Fatalf("block %d at start: %v %v", h, found, err)
		}
	}
	// Two registries and one re-seal accepted (and one policy update): each found in its record.
	if accepted != 4 {
		t.Fatalf("%d accepted transactions of the checked kinds, want 4", accepted)
	}
}
