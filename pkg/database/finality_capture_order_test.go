// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// PutBlock inserts in key order (chain, block, hash, item) whatever order the caller lists the rows in: every validator captures the
// same blocks into this one database, and two writers that take their row locks in the same order queue on the first key they share
// instead of each holding what the other waits for (RB11-DBFIX D7). The order is observable through the locks: a transaction that
// holds the middle key stops PutBlock there, and the keys PutBlock has already taken are exactly the ones that sort before it.
func TestPutBlockTakesItsRowLocksInKeyOrderWhateverOrderTheRowsAreListedIn(t *testing.T) {
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	blk := uint64(2_100_000_000 + time.Now().UnixNano()%900_000_000)
	hdr, tx1, nodes := key(11, blk, 0x51, "hdr"), key(11, blk, 0x51, "tx/1"), key(11, blk, 0x51, "txnodes/1")
	insert := func(tx *sql.Tx, k finality.CaptureKey) error {
		_, err := tx.Exec(`INSERT INTO proof_finality_capture (chain, l1_block, l1_hash, item, bytes) VALUES ($1, $2, $3, $4, $5)`,
			int64(k.Chain), int64(k.L1Block), k.L1Hash[:], k.Item, []byte("p"))
		return err
	}
	holder, err := testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if err := insert(holder, tx1); err != nil { // holds the middle key
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		// listed neither in key order nor in the reverse of it
		done <- store.PutBlock(ctx, []finality.CaptureRow{{CaptureKey: tx1, Bytes: []byte("a")}, {CaptureKey: nodes, Bytes: []byte("b")}, {CaptureKey: hdr, Bytes: []byte("c")}})
	}()
	time.Sleep(400 * time.Millisecond) // PutBlock has taken what it can and waits for the holder

	probe := func(k finality.CaptureKey) error {
		p, err := testDB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer p.Rollback()
		if _, err := p.Exec(`SET LOCAL lock_timeout = '150ms'`); err != nil {
			t.Fatal(err)
		}
		return insert(p, k)
	}
	// hdr sorts before the held key: PutBlock took it first
	if err := probe(hdr); err == nil || !strings.Contains(err.Error(), "lock timeout") {
		t.Errorf("hdr sorts first, so PutBlock must already hold it: %v", err)
	}
	// txnodes/1 sorts after the held key: PutBlock has not reached it
	if err := probe(nodes); err != nil {
		t.Errorf("txnodes/1 sorts after the held key, so PutBlock must not hold it yet: %v", err)
	}
	holder.Rollback()
	if err := <-done; err != nil {
		t.Fatalf("PutBlock once the holder is gone: %v", err)
	}
	if got := heldItems(t, store, 11, blk); len(got) != 3 {
		t.Fatalf("%v", got)
	}
}
