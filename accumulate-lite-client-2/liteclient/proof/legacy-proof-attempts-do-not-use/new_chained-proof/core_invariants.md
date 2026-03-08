Below is a proof-grade, **non-negotiable** set of invariants (assertions) and a practical unit/integration test shape that will lock `getRootReceiptWithQuerier` down as a deterministic, verifiable primitive.

---

## A. Core invariants (must hold for every “successful” receipt)

Define:

* `local := localRootChain.Receipt(from, to)` (the BVN-local root chain receipt you already compute)
* `dir := PartitionAnchorReceipt` found in `AnchorPool` (DN→BVN receipt)
* `stitched := local.Combine(dir.RootChainReceipt)`

### A1) Partition semantics

**DN partition**

* Must return `local` directly.
* Invariants:

  * `bytes.Equal(r.Start, local.Start)`
  * `bytes.Equal(r.Anchor, local.Anchor)`
  * (Optional but strong) `reflect.DeepEqual(r, local)` if the struct is stable.

**BVN partition**

* Must return **stitched**, not local.
* Invariants:

  * `bytes.Equal(dir.RootChainReceipt.Start, local.Anchor)`
    (hard boundary: DN receipt must start at exactly what BVN proved as its root-chain anchor)
  * `bytes.Equal(r.Start, local.Start)`
    (combining must not change the start)
  * `bytes.Equal(r.Anchor, dir.RootChainReceipt.Anchor)`
    (combined anchor must end at the DN-provided anchor)
  * `validate(r) == nil` **and** `validate(local) == nil` **and** `validate(dir.RootChainReceipt) == nil`
    (each receipt must be internally self-consistent)

> `validate` here means whichever method your `merkle.Receipt` type provides (commonly `Validate()` or a function like `merkle.VerifyReceipt(...)`). Use the actual name in your tree.

### A2) Deterministic block mapping (root index chain correctness)

If you map `to` (root-chain entry index) → `block`, using your helper:

* Let `ie := first root index entry where ie.Source >= to`
* Invariants:

  * `ie.Source >= to`
  * If there is a previous index entry `prev`, then `prev.Source < to`
  * The code uses `ie.BlockIndex` as the canonical minor block index for directory receipt search.

### A3) Deterministic directory receipt selection

When searching the BVN’s `AnchorPool` chain:

* Returned `dir` must satisfy:

  * `dir.Anchor.Source.Equal(partition.URL)`
  * `dir.Anchor.MinorBlockIndex >= block` (never accept older)
  * `dir.RootChainReceipt != nil`
  * `bytes.Equal(dir.RootChainReceipt.Start, local.Anchor)` (mandatory)

If multiple candidates exist, your function should choose deterministically. Your current “scan forward from the first index entry at/after block and return the first match” is deterministic given stable chain ordering. If you want an even stronger canonical selection rule, pick the match with **smallest** `dir.Anchor.MinorBlockIndex` (tie-break by earliest chain position). Either rule is fine; the test should assert the rule you choose.

---

## B. Failure invariants (must fail loudly, never partial)

For correctness-sensitive callers (Certen), these are required behaviors:

### B1) Missing DN receipt must fail (NotFound)

If no directory receipt is present in the BVN’s anchor pool chain that satisfies the constraints above:

* `getRootReceiptWithQuerier(...)` must return `err != nil`
* `errors.Is(err, errors.NotFound)` must be true (or your equivalent)
* Returned receipt must be `nil`

### B2) Wrong-start receipts must be rejected

If there is a directory receipt for the block, but `dir.RootChainReceipt.Start != local.Anchor`:

* It must not be accepted.
* If no other matching receipt exists, return `NotFound` (not a partial local receipt, not a mismatch warning).

### B3) Index-chain holes / unmappable `to` must fail

If the root index chain cannot map `to` to a block boundary:

* Return `NotFound` (or a precise error) and `nil` receipt.

---

## C. Concrete test cases you should implement

### 1) Unit test: DN behavior is identity

**Test name:** `TestGetRootReceipt_Strict_DN_ReturnsLocal`

Assertions:

* Call strict `getRootReceiptWithQuerier(DN, ...)`
* Verify `r` equals `local` (Start/Anchor equality + optional DeepEqual)

### 2) Unit test: BVN fails when DN receipt is not present

**Test name:** `TestGetRootReceipt_Strict_BVN_NoDirectoryReceipt_Fails`

Setup:

* Ensure BVN root chain and root index chain contain entries so `local` can be built
* Ensure anchor pool chain has **no** matching DirectoryAnchor receipts

Assertions:

* Error is NotFound
* Receipt is nil

### 3) Unit test: BVN rejects wrong-start receipt

**Test name:** `TestGetRootReceipt_Strict_BVN_WrongStartReceipt_Fails`

Setup:

* Insert a DirectoryAnchor into anchor pool that includes a PartitionAnchorReceipt for this BVN and block,
  but with `RootChainReceipt.Start != local.Anchor`

Assertions:

* Error NotFound
* Receipt nil

### 4) Unit test: BVN stitches correctly when receipt exists

**Test name:** `TestGetRootReceipt_Strict_BVN_Stitches`

Setup:

* Same as above, but DirectoryAnchor includes a PartitionAnchorReceipt where:

  * `RootChainReceipt.Start == local.Anchor`
  * `RootChainReceipt` validates

Assertions (all from section A):

* `dir.RootChainReceipt.Start == local.Anchor`
* `r.Start == local.Start`
* `r.Anchor == dir.RootChainReceipt.Anchor`
* `validate(local)`, `validate(dir.RootChainReceipt)`, `validate(r)` all succeed

### 5) Integration test (recommended): end-to-end anchoring via simulator

**Test name:** `TestGetRootReceipt_Strict_BVN_EndToEnd`

Goal: Prove this works against **real** produced receipts and chain contents (not synthetic test-constructed ones).

High-level steps (adapt to your simulator harness):

1. Start a simulator with DN + at least one BVN.
2. Submit a transaction that causes BVN state change (so the root chain advances).
3. Execute a block where the BVN commits that change.
4. Execute enough blocks for the DN to produce a DirectoryAnchor and the BVN to receive/store the `PartitionAnchorReceipt` in its anchor pool chain.
5. Open a view batch on the BVN DB and call strict `getRootReceiptWithQuerier` for the relevant `from/to`.
6. Assert the same invariants as the unit “Stitches” test, but now with real receipts.

If your simulator can step partitions independently, you can also add:

* **Integration failure case:** call strict receipt builder *after BVN commit but before DN receipt delivery* → must return NotFound.

---

## D. Skeleton assertion helpers (drop-in)

These helpers are stable and should work regardless of your harness.

```go
func requireReceiptValid(t *testing.T, r *merkle.Receipt) {
    t.Helper()
    if r == nil {
        t.Fatal("receipt is nil")
    }

    // Use the actual validation primitive available in your merkle package.
    // Common patterns are: r.Validate() or merkle.VerifyReceipt(r)
    if err := r.Validate(); err != nil { // adjust if needed
        t.Fatalf("receipt failed validation: %v", err)
    }
}

func requireNotFound(t *testing.T, err error) {
    t.Helper()
    if err == nil {
        t.Fatal("expected error, got nil")
    }
    if !errors.Is(err, errors.NotFound) { // uses accumulate/pkg/errors semantics
        t.Fatalf("expected NotFound, got %T: %v", err, err)
    }
}
```

And the BVN stitching invariant block:

```go
func assertBVNStitchedReceiptInvariants(t *testing.T, local, dirRoot, stitched *merkle.Receipt) {
    t.Helper()

    if !bytes.Equal(dirRoot.Start, local.Anchor) {
        t.Fatalf("dir receipt start != local anchor: got %X want %X", dirRoot.Start[:4], local.Anchor[:4])
    }
    if !bytes.Equal(stitched.Start, local.Start) {
        t.Fatalf("stitched start != local start: got %X want %X", stitched.Start[:4], local.Start[:4])
    }
    if !bytes.Equal(stitched.Anchor, dirRoot.Anchor) {
        t.Fatalf("stitched anchor != dir anchor: got %X want %X", stitched.Anchor[:4], dirRoot.Anchor[:4])
    }

    requireReceiptValid(t, local)
    requireReceiptValid(t, dirRoot)
    requireReceiptValid(t, stitched)
}
```

---

## E. One critical note for the tests to be meaningful

Make sure your strict `getRootReceiptWithQuerier` **never** returns `local` for BVNs. Your tests should assert BVN success returns a receipt whose `Anchor` differs from `local.Anchor` (it should end at DN’s anchor).

