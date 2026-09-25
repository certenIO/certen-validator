// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The replay against real Kermit key pages, one per way a page is born, each
// ending in the check that the replay reaches the page the network holds.
//
// certen-kermit-12.acme/book/1 is the page whose v1 -> v2 update on
// 2026-08-26 produced a false governance rejection: the updateKeyPage at block
// 10245670 added a delegate entry. One block before it the page is v1 with its
// single key; at that block it is v2 with the delegate as well.
func TestReplay_LiveKermitPages(t *testing.T) {
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}
	const endpoint = "https://kermit.accumulatenetwork.io/v3"
	const kermit12Key = "4d07443e23bf3d244facb56f7fd4614d29b21f5530361ca1f77c40ac17f16192"

	cases := []struct {
		name        string
		page        string
		execMBI     int64
		wantVersion uint64
		wantEntries []KeyPageEntry
		wantMuts    int
	}{
		{
			name:        "kermit-12 before its update",
			page:        "acc://certen-kermit-12.acme/book/1",
			execMBI:     10245669,
			wantVersion: 1,
			wantEntries: []KeyPageEntry{{KeyHash: kermit12Key}},
		},
		{
			name:        "kermit-12 at its update",
			page:        "acc://certen-kermit-12.acme/book/1",
			execMBI:     10245670,
			wantVersion: 2,
			wantEntries: []KeyPageEntry{
				{Delegate: "acc://certen-p7f-omega.acme/book"},
				{KeyHash: kermit12Key},
			},
			wantMuts: 1,
		},
		{
			name:        "p8m page 2, born by createKeyPage",
			page:        "acc://certen-p8m.acme/book/2",
			execMBI:     1 << 40,
			wantVersion: 1,
		},
		{
			name:        "p7f-alpha, updated once",
			page:        "acc://certen-p7f-alpha.acme/book/1",
			execMBI:     1 << 40,
			wantVersion: 2,
			wantMuts:    1,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			am, err := NewArtifactManager(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			client := NewCachedRPCClient(NewRPCClient(RPCConfig{Endpoint: endpoint, UseHTTP: true}))
			ab := NewAuthorityBuilder(client, am)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			snap, err := ab.BuildAuthoritySnapshot(ctx, c.page, c.execMBI, "")
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			st := snap.StateExec
			t.Logf("%s @%d: v%d threshold %d entries %v, %d mutation(s)", c.page, c.execMBI,
				st.Version, st.Threshold, st.EntrySet(), len(snap.Mutations))

			if st.Version != c.wantVersion {
				t.Fatalf("version at exec = %d, want %d", st.Version, c.wantVersion)
			}
			if c.wantEntries != nil && !entriesEqual(st.EntrySet(), c.wantEntries) {
				t.Fatalf("entries at exec = %v, want %v", st.EntrySet(), c.wantEntries)
			}
			if len(snap.Mutations) != c.wantMuts {
				t.Fatalf("mutations = %d, want %d", len(snap.Mutations), c.wantMuts)
			}
			for _, m := range snap.Mutations {
				if m.NewState.Version != m.PreviousState.Version+1 && !strings.EqualFold(m.TxType, "updateKey") {
					t.Fatalf("mutation %s moved the version %d -> %d", m.TxType, m.PreviousState.Version, m.NewState.Version)
				}
				if len(m.Receipt.Entries) == 0 && m.Receipt.Start != m.Receipt.Anchor {
					t.Fatalf("mutation %s carries no merkle path", m.EntryHash)
				}
			}
		})
	}
}
