# G1(b): why the captured authority set is complete

RB6 §4 asks for G1(b) as a written argument, implemented only if it is sound. This is the argument. It is sound for
the authorities the shadow captures and verifies today, and it names exactly where it is not yet sound.

## The claim

For an intent transaction T on principal P, executed at or before block B on partition X, the v2 proof contains the
state as of B of every account that decides who may sign for P, and nothing it omits could change that decision.

## What decides who may sign

Accumulate resolves an account's authority set with `GetAccountAuthoritySet` (internal/core/block/shared), which the
executor calls through `getAccountAuthoritySet` (internal/api/v3/load.go):

1. A full account that lists any authority entry uses its own list. Disabled entries stay in the list; a disabled
   authority's signatures are not required.
2. A full account that lists none inherits from its parent identity (`Url.Identity()`), recursively. A root identity
   that lists none resolves to its own, empty, set.
3. Each authority is a key book. Its signers are its pages, `book/1` … `book/N`, where N is the book's `PageCount`.
4. A page's keys, threshold and version are its main state.

Nothing else is read: no other account, and no off-chain data.

## Why the capture is complete

The shadow's `governing` (pkg/proofv2shadow) follows rules 1 and 2 step by step. It captures:
- P;
- every account on the inheritance chain, whose proven state shows it lists no authority, which is why the walk
  continues;
- the first account with a list;
- every enabled key book in that list, whose proven state includes `PageCount`;
- every page `1 … PageCount`.

Each captured state is proven as of B: its receipt ends at the state root that the partition anchor for B carries,
proven into the certified Directory root.

So:
- **No authority is omitted.** The list is the proven state of the account that holds it, and that account is the one
  rule 2 reaches, because each account skipped on the way is proven to list none.
- **No page is omitted.** The page count is the proven state of the book, and every page up to it is captured.
- **No captured state is stale.** Each is the state as of B, bound to B's partition anchor. RB6-F14 qualifies this:
  B is the block whose anchor the transaction's receipt passes through, so "as of B" means as of that block, at or
  after execution. The shadow cross-check against v1's replay catches any difference.

## Where it is not yet sound (named, not hidden)

1. **Authorities of another identity.** A book outside P's root identity may live on another partition, whose blocks
   differ from X's. These are recorded as `g1_cross_identity_pending` and not captured. Completing them needs that
   partition's anchor for the matching block, which the same mechanism provides.
2. **Delegation.** A page entry can delegate to another book. The pages that a delegated vote reaches are governed
   the same way, but the capture does not follow delegation yet. v1's vote model does, and the cross-check compares
   only the pages both captured.
3. **Signature arrival time.** v1 judges each signature against the page's states during its own arrival block. G1(b)
   establishes the complete set as of B. The certified timeline (PROOF_V2.md §5.2, refined 2026-10-05) is what extends
   the guarantee back to each arrival.

Until 1 and 2 are captured, G1(b) is sound for intents whose authorities lie in the principal's identity and whose
pages do not delegate, which is every intent in the shadow run to date. The verifier reports any other case by name.
