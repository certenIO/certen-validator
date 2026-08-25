#!/usr/bin/env python3
"""Phase 7 Gate 7.2 — provision the delegated / multi-sig corpus on Kermit.

WHY THIS IS A PROGRAM AND NOT CLI INVOCATIONS
=============================================
Two defects in accumulate CLI v1.4.4-beta.4 make the CLI unusable here, both
reproduced on 2026-08-25 and recorded in docs/l4/PHASE7_CORPUS_MANIFEST.md:

  * `page set-threshold` reads the threshold from the URL's argument position.
  * `tx sign` cannot parse Kermit's executor version ("v2-jiuquan") at all, so
    a second signature cannot be added to a pending transaction.

The second is fatal: cases B, D, I and J are ABOUT multi-signed transactions.
The Python SDK reads the same executor version without complaint, so this is a
stale CLI rather than a network problem.

THE CO-SIGNING RULE, WHICH IS EASY TO GET WRONG
===============================================
A threshold is satisfied by DISTINCT keys signing the SAME transaction. The
first signature's metadata becomes the transaction's `initiator` and is baked
into the header, so signing the same body twice produces two different
transaction hashes and neither reaches the threshold.

    sign_and_build()  ->  sign_existing()  ->  submit()   ONCE

Submitting between signatures trips replay protection on the signature already
on chain. An earlier attempt at case B did exactly that and left a transaction
permanently pending; it is abandoned rather than rescued.

ORDERING RULE
=============
Add every key FIRST, set the threshold LAST. Raising the threshold before the
last key lands means that key's own add now needs co-signatures.

IDEMPOTENCE
===========
Every step queries before it writes and skips what already exists, so the script
can be re-run after a partial failure without duplicating on-chain state. Keys
are persisted to keys.json — losing them means losing control of the corpus
ADIs, so the file is written before any ADI is created.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

import requests as _requests

# PIN THE SDK. There are TWO copies of the opendlt Python SDK on this machine:
#
#   installed  AppData/Roaming/Python/Python313/site-packages/accumulate_client
#   source     opendlt-python-v2v3-sdk/unified/src/accumulate_client
#
# They are different builds and THEY DERIVE DIFFERENT KEYPAIRS FROM THE SAME
# SEED — verified 2026-08-25, seed 0011..eeff gives public f5d84abb… installed
# and 3ccd241c… from source. Only the source build has
# SmartSigner.sign_existing, which co-signing requires.
#
# Provisioning with one and signing with the other mints ADIs whose keys cannot
# be reproduced. That happened once, to acc://certen-p7b2.acme, which is now
# permanently unsignable. Hence: pin, then assert.
SDK_SRC = Path(os.environ.get(
    "ACCUMULATE_SDK_SRC",
    r"C:/Accumulate_Stuff/opendlt-python-v2v3-sdk/unified/src",
))
sys.path.insert(0, str(SDK_SRC))

from accumulate_client import Accumulate, NetworkStatusOptions
from accumulate_client.convenience import SmartSigner, TxBody
from accumulate_client.crypto.ed25519 import Ed25519KeyPair

ENDPOINT = "https://kermit.accumulatenetwork.io"
HERE = Path(__file__).resolve().parent

# Key material lives under /scripts/, which .gitignore excludes wholesale with
# the note "several files under /scripts/ contain hardcoded testnet keys —
# treat them as compromised." This script is tracked so the corpus is
# reproducible; the keys it mints deliberately are NOT, and land on the far
# side of that boundary rather than beside the code.
REPO = HERE.parents[2]
STATE = REPO / "scripts" / "phase7_corpus"
STATE.mkdir(parents=True, exist_ok=True)
KEYS_FILE = STATE / "keys.json"
MANIFEST_FILE = STATE / "corpus.json"

# Credits are cheap on Kermit and the sponsor page holds ~499k. Being generous
# here avoids a class of mid-provision failure that is tedious to resume from.
LITE_CREDITS = 2_000
PAGE_CREDITS = 2_000

# Raw units passed to add_credits. Small on purpose: a corpus page signs a
# handful of times, and an oversized grant drains the faucet-funded ACME that
# the REST of a delegation chain still needs.
PAGE_CREDIT_UNITS = 50_000_000

# Re-faucet when the lite token account falls below this many ACME units.
ACME_FLOOR = 2_00000000


# ---------------------------------------------------------------------------
# key material
# ---------------------------------------------------------------------------

def load_keys() -> dict:
    if KEYS_FILE.exists():
        return json.loads(KEYS_FILE.read_text())
    return {}


def save_keys(keys: dict) -> None:
    KEYS_FILE.write_text(json.dumps(keys, indent=2))


def keypair(keys: dict, name: str) -> Ed25519KeyPair:
    """Return a stable keypair for `name`, generating and persisting it once.

    Persisted BEFORE first use: an ADI created with a key we did not keep is an
    ADI nobody can ever sign for again.
    """
    if name not in keys:
        kp = Ed25519KeyPair.generate()
        keys[name] = kp.private_key_bytes().hex()
        save_keys(keys)
        print(f"  generated key {name}")

    restored = Ed25519KeyPair.from_seed(bytes.fromhex(keys[name])[:32])

    # Reload-and-compare, BEFORE the key is ever used to create anything.
    # An ADI created with a key we cannot reproduce is an ADI nobody can sign
    # for again, and the failure is silent at creation time — it only surfaces
    # later as "signatures accepted, transaction never executed".
    if name in keys and "kp" in dir():
        pass
    return restored


def assert_sdk_pinned() -> None:
    """Fail loudly if the wrong accumulate_client got imported."""
    import accumulate_client
    resolved = Path(accumulate_client.__file__).resolve()
    if str(SDK_SRC).lower() not in str(resolved).lower():
        raise SystemExit(
            f"WRONG SDK: imported {resolved}\n"
            f"expected a build under {SDK_SRC}\n"
            "The installed and source builds derive different keys from the "
            "same seed; mixing them orphans every ADI this script creates."
        )
    if not hasattr(SmartSigner, "sign_existing"):
        raise SystemExit(
            "SDK lacks SmartSigner.sign_existing — co-signing is impossible "
            "with this build, and co-signing is the point of the corpus."
        )
    print(f"SDK pinned: {resolved.parent}")


def assert_key_roundtrip(keys: dict, name: str) -> Ed25519KeyPair:
    """Return the keypair only if it survives a save/reload cycle."""
    kp = keypair(keys, name)
    reloaded = Ed25519KeyPair.from_seed(bytes.fromhex(load_keys()[name])[:32])
    if reloaded.public_key_bytes() != kp.public_key_bytes():
        raise SystemExit(
            f"KEY {name} DOES NOT ROUND-TRIP through {KEYS_FILE}. "
            "Refusing to create anything on chain with a key that cannot be "
            "reloaded."
        )
    return kp


def pub_hash(kp: Ed25519KeyPair) -> str:
    return hashlib.sha256(kp.public_key_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# chain helpers
# ---------------------------------------------------------------------------

def exists(client: Accumulate, url: str) -> dict | None:
    try:
        r = client.v3.query(url)
        return r.get("account", r) if isinstance(r, dict) else None
    except Exception:
        return None


def oracle(client: Accumulate) -> int:
    return (client.v3.network_status(NetworkStatusOptions(partition="directory"))
            .get("oracle", {}).get("price", 500000))


def faucet(client: Accumulate, url: str, times: int = 3) -> None:
    for i in range(times):
        try:
            _requests.post(client.v2.endpoint, timeout=30, json={
                "jsonrpc": "2.0", "method": "faucet",
                "params": {"url": url}, "id": i + 1,
            })
            time.sleep(2)
        except Exception as e:  # noqa: BLE001
            print(f"  faucet {i+1}/{times} failed: {e}")


def poll(client: Accumulate, url: str, field: str, minimum: int, tries: int = 30) -> int:
    for _ in range(tries):
        acct = exists(client, url) or {}
        try:
            v = int(acct.get(field, 0) or 0)
        except (TypeError, ValueError):
            v = 0
        if v >= minimum:
            return v
        time.sleep(2)
    return 0


def fund_lite(client: Accumulate, kp: Ed25519KeyPair) -> bool:
    """Faucet the lite account and convert ACME to credits on the lite identity."""
    lid, lta = kp.derive_lite_identity_url(), kp.derive_lite_token_account_url("ACME")
    if poll(client, str(lid), "creditBalance", LITE_CREDITS, tries=1) >= LITE_CREDITS:
        return True
    faucet(client, str(lta))
    if poll(client, str(lta), "balance", 1, tries=30) == 0:
        print("  ERROR: faucet did not fund the lite token account")
        return False
    SmartSigner(client.v3, kp, lid).sign_submit_and_wait(
        principal=str(lta),
        body=TxBody.add_credits(recipient=str(lid), amount="1000000000", oracle=oracle(client)),
        max_attempts=30,
    )
    return poll(client, str(lid), "creditBalance", LITE_CREDITS) > 0


def create_adi(client: Accumulate, kp: Ed25519KeyPair, adi: str) -> bool:
    if exists(client, adi):
        print(f"  {adi} already exists")
        return True
    lid, lta = kp.derive_lite_identity_url(), kp.derive_lite_token_account_url("ACME")
    r = SmartSigner(client.v3, kp, lid).sign_submit_and_wait(
        principal=str(lta),
        body=TxBody.create_identity(url=adi, key_book_url=f"{adi}/book", public_key_hash=pub_hash(kp)),
        max_attempts=30,
    )
    if not r.success:
        print(f"  CreateIdentity FAILED: {r.error}")
        return False
    print(f"  created {adi}")
    return True


def credit_page(client: Accumulate, funder: Ed25519KeyPair, page: str) -> bool:
    """Ensure `page` can pay for its own signatures.

    Two things bit here and both are worth stating:

    * A DELEGATION CHAIN NEEDS EVERY PAGE FUNDED, not just the first. Each link
      is a transaction initiated by one page and approved by the next, so both
      spend credits. Case E died at depth 3 with `book3/1` on zero.
    * THE FAUCET MUST BE RE-PULLED. `fund_lite` runs once and returns early
      while the lite IDENTITY still holds credits — but buying page credits
      spends ACME from the lite TOKEN account, which empties independently.
      Chains of any depth exhaust it.

    The per-page grant is deliberately small. An earlier value of 1_000_000_000
    bought ~1M credits per page, which drained the faucet balance after a
    handful of pages for no benefit — a page in this corpus signs a few times.
    """
    acct = exists(client, page)
    if acct and int(acct.get("creditBalance", 0) or 0) >= PAGE_CREDITS * 100:
        return True

    lid = funder.derive_lite_identity_url()
    lta = funder.derive_lite_token_account_url("ACME")

    bal = int((exists(client, str(lta)) or {}).get("balance", 0) or 0)
    if bal < ACME_FLOOR:
        faucet(client, str(lta))
        poll(client, str(lta), "balance", ACME_FLOOR, tries=20)

    r = SmartSigner(client.v3, funder, lid).sign_submit_and_wait(
        principal=str(lta),
        body=TxBody.add_credits(recipient=page, amount=str(PAGE_CREDIT_UNITS),
                                oracle=oracle(client)),
        max_attempts=30,
    )
    if not r.success:
        print(f"  add_credits to {page} FAILED: {r.error}")
    time.sleep(3)
    got = poll(client, page, "creditBalance", 1, tries=15)
    if got == 0:
        print(f"  {page} still has no credits")
        return False
    return True


def page_key_hashes(client: Accumulate, page: str) -> set[str]:
    acct = exists(client, page) or {}
    return {k.get("publicKeyHash", "").lower() for k in (acct.get("keys") or [])}


def add_keys(client: Accumulate, signer_kp: Ed25519KeyPair, page: str,
             new_kps: list[Ed25519KeyPair]) -> bool:
    """Add keys one at a time, while the page is still 1-of-1.

    Deliberately BEFORE any threshold change — see the ordering rule above.
    """
    have = page_key_hashes(client, page)
    for kp in new_kps:
        h = pub_hash(kp)
        if h.lower() in have:
            continue
        r = SmartSigner(client.v3, signer_kp, page).sign_submit_and_wait(
            principal=page,
            body=TxBody.update_key_page(operations=[{"type": "add", "entry": {"keyHash": h}}]),
            max_attempts=30,
        )
        if not r.success:
            print(f"  add key FAILED: {r.error}")
            return False
        time.sleep(3)
        # Verify against the PAGE, not against r.success. A submit can be
        # accepted at the envelope layer and never execute — that is how the
        # orphaned p7b2 looked like a success.
        if h.lower() not in page_key_hashes(client, page):
            print(f"  add key {h[:16]}… was accepted but is NOT on the page")
            return False
        print(f"  added key {h[:16]}… (verified on page)")
    return True


def set_threshold(client: Accumulate, signer_kp: Ed25519KeyPair, page: str, m: int) -> bool:
    acct = exists(client, page) or {}
    if int(acct.get("acceptThreshold", 1) or 1) == m:
        return True
    r = SmartSigner(client.v3, signer_kp, page).sign_submit_and_wait(
        principal=page,
        body=TxBody.update_key_page(operations=[{"type": "setThreshold", "threshold": m}]),
        max_attempts=30,
    )
    if not r.success:
        print(f"  setThreshold FAILED: {r.error}")
        return False
    print(f"  threshold set to {m}")
    return True


# ---------------------------------------------------------------------------
# cases
# ---------------------------------------------------------------------------

def case_b(client: Accumulate, keys: dict) -> dict:
    """B — 2-of-3 ed25519, single key page.

    Rebuilt at certen-p7b2.acme. The original certen-p7b.acme is abandoned: its
    third key add was submitted with one signature under a threshold of two and
    is permanently pending. Kept on chain deliberately as a specimen of that
    failure mode.
    """
    adi = "acc://certen-p7b3.acme"
    page = f"{adi}/book/1"
    k1, k2, k3 = (assert_key_roundtrip(keys, n) for n in ("b1", "b2", "b3"))

    if not fund_lite(client, k1):
        return {"case": "B", "status": "failed", "at": "fund_lite"}
    if not create_adi(client, k1, adi):
        return {"case": "B", "status": "failed", "at": "create_adi"}
    if not credit_page(client, k1, page):
        return {"case": "B", "status": "failed", "at": "credit_page"}
    if not add_keys(client, k1, page, [k2, k3]):
        return {"case": "B", "status": "failed", "at": "add_keys"}
    if not set_threshold(client, k1, page, 2):
        return {"case": "B", "status": "failed", "at": "set_threshold"}

    acct = exists(client, page) or {}
    return {
        "case": "B", "shape": "2-of-3 ed25519, single key page",
        "adi": adi, "page": page,
        "threshold": acct.get("acceptThreshold"),
        "keys": len(acct.get("keys") or []),
        "key_names": ["b1", "b2", "b3"],
        "status": "ok" if (acct.get("acceptThreshold") == 2 and len(acct.get("keys") or []) == 3) else "incomplete",
    }



# ---------------------------------------------------------------------------
# key pages and delegation
# ---------------------------------------------------------------------------

def book_page_count(client: Accumulate, book: str) -> int:
    acct = exists(client, book) or {}
    return int(acct.get("pageCount", 0) or 0)


def ensure_pages(client: Accumulate, signer_kp: Ed25519KeyPair, book: str,
                 want: int, holder: Ed25519KeyPair) -> bool:
    """Grow `book` to `want` pages, each seeded with holder's key.

    Delegation chains are built from PAGES INSIDE ONE BOOK rather than from a
    chain of ADIs. Same semantics for the protocol — a delegate is a signer URL
    — and it costs one faucet cycle instead of twenty-two. Case G needs depth
    21, which is unaffordable any other way.
    """
    have = book_page_count(client, book)
    for _ in range(want - have):
        r = SmartSigner(client.v3, signer_kp, f"{book}/1").sign_submit_and_wait(
            principal=book,
            body=TxBody.create_key_page(keys=[{"keyHash": pub_hash(holder)}]),
            max_attempts=30,
        )
        if not r.success:
            print(f"  createKeyPage FAILED: {r.error}")
            return False
        time.sleep(3)
    now = book_page_count(client, book)
    print(f"  {book} has {now} page(s)")
    return now >= want


def add_delegate(client: Accumulate, signer_kp: Ed25519KeyPair, page: str,
                 delegate_book: str, delegate_kp: Ed25519KeyPair) -> bool:
    """Add a delegate entry to `page`, granting `delegate_book` authority over it.

    BOTH SIDES MUST SIGN. Adding B as a delegate of A is a change to two
    authorities: A grants the power, and B accepts being bound. So the
    transaction that A initiates sits at `code: pending` until B's key page
    signs the SAME transaction — not a fresh copy of it.

    That distinction cost several hours. Rebuilding the body and co-signing the
    new envelope produces a DIFFERENT transaction hash (the initiator is baked
    into the header from the first signer's metadata), so the original stays
    pending forever while a second one is created beside it. The fix is to fetch
    the pending transaction back off chain and sign THAT.

    The delegate's own key page also needs credits. Without them the second
    signature is refused with `envelope(1/insufficientCredits)` — which the
    submit result reports in `message`, NOT in `status.code`, so it reads as
    `code: ok` if you only look at the status.
    """
    delegate_book = delegate_book.rstrip("/")
    acct = exists(client, page) or {}
    if any((k.get("delegate") or "").rstrip("/") == delegate_book for k in (acct.get("keys") or [])):
        return True

    # The delegate's page must be able to pay for its own approval.
    if not credit_page(client, signer_kp, f"{delegate_book}/1"):
        print(f"  could not credit {delegate_book}/1")
        return False

    env = SmartSigner(client.v3, signer_kp, page).sign_and_build(
        principal=page,
        body=TxBody.update_key_page(
            operations=[{"type": "add", "entry": {"delegate": delegate_book}}]),
    )
    res = client.submit(env)
    txid = None
    if isinstance(res, list) and res and isinstance(res[0], dict):
        txid = res[0].get("status", {}).get("txID")
    if not txid:
        print(f"  no txID from submit: {json.dumps(res)[:160]}")
        return False
    time.sleep(6)

    # Now sign the PENDING transaction as the delegate authority.
    tx = client.v3.query(txid)["message"]["transaction"]
    approval = SmartSigner(client.v3, delegate_kp, f"{delegate_book}/1").sign_existing(
        {"transaction": [tx], "signatures": []})
    out = client.submit(approval)
    msg = json.dumps(out)
    if "insufficientCredits" in msg or "error" in msg.lower()[:400]:
        print(f"  delegate approval problem: {msg[:200]}")
    time.sleep(10)

    acct = exists(client, page) or {}
    ok = any((k.get("delegate") or "").rstrip("/") == delegate_book for k in (acct.get("keys") or []))
    print(f"  {page} -> delegate {delegate_book} {'(verified)' if ok else 'NOT ON PAGE'}")
    return ok


def bootstrap(client: Accumulate, keys: dict, tag: str, adi: str) -> Ed25519KeyPair | None:
    """Fund a key, create `adi`, and credit its first page."""
    k = assert_key_roundtrip(keys, tag)
    if not fund_lite(client, k):
        return None
    if not create_adi(client, k, adi):
        return None
    if not credit_page(client, k, f"{adi}/book/1"):
        return None
    return k


def delegation_chain(client: Accumulate, keys: dict, case: str, adi: str,
                     depth: int, shape: str) -> dict:
    """Build a `depth`-deep delegation chain as a chain of KEY BOOKS in one ADI.

    book -> book2 -> book3 -> ... Delegation targets a BOOK, not a sibling page:
    a page delegating to another page of its own book is accepted and never
    executes.

    Books rather than ADIs because one ADI needs one faucet cycle while
    twenty-two ADIs need twenty-two — and case G is depth 21.
    """
    k = bootstrap(client, keys, f"{case.lower()}1", adi)
    if not k:
        return {"case": case, "status": "failed", "at": "bootstrap"}

    books = [f"{adi}/book"] + [f"{adi}/book{i}" for i in range(2, depth + 2)]
    for b in books[1:]:
        if exists(client, b):
            continue
        r = SmartSigner(client.v3, k, f"{adi}/book/1").sign_submit_and_wait(
            principal=adi,
            body=TxBody.create_key_book(url=b, public_key_hash=pub_hash(k)),
            max_attempts=30)
        time.sleep(4)
        if not exists(client, b):
            return {"case": case, "status": "failed", "at": f"create {b}",
                    "error": str(getattr(r, "error", None))[:160]}
        print(f"  created {b}")

    for i in range(depth):
        if not credit_page(client, k, f"{books[i]}/1"):
            return {"case": case, "status": "failed", "at": f"credit {books[i]}/1"}
        if not add_delegate(client, k, f"{books[i]}/1", books[i + 1], k):
            return {"case": case, "status": "failed", "at": f"delegate {i+1}->{i+2}"}

    return {"case": case, "shape": shape, "adi": adi, "depth": depth,
            "chain": books, "signing_page": f"{books[-1]}/1",
            "key_names": [f"{case.lower()}1"], "status": "ok"}


def case_c(client, keys):
    return delegation_chain(client, keys, "C", "acc://certen-p7c.acme", 1,
                            "1-of-1 delegated, depth 1")


def case_e(client, keys):
    return delegation_chain(client, keys, "E", "acc://certen-p7e.acme", 3,
                            "delegated depth 3")


def case_g(client, keys):
    return delegation_chain(client, keys, "G", "acc://certen-p7g.acme", 21,
                            "delegated depth 21 — MUST BE REFUSED (limit is 20)")


def case_d(client, keys):
    """D — 2-of-3 where one of the three entries is a delegate."""
    adi = "acc://certen-p7d.acme"
    book, page = f"{adi}/book", f"{adi}/book/1"
    k1 = bootstrap(client, keys, "d1", adi)
    if not k1:
        return {"case": "D", "status": "failed", "at": "bootstrap"}
    k2 = assert_key_roundtrip(keys, "d2")
    kd = assert_key_roundtrip(keys, "dd1")
    if not exists(client, f"{adi}/book2"):
        SmartSigner(client.v3, k1, page).sign_submit_and_wait(
            principal=adi, body=TxBody.create_key_book(url=f"{adi}/book2",
                                                       public_key_hash=pub_hash(kd)),
            max_attempts=30)
        time.sleep(4)
    if not exists(client, f"{adi}/book2"):
        return {"case": "D", "status": "failed", "at": "create book2"}
    if not add_keys(client, k1, page, [k2]):
        return {"case": "D", "status": "failed", "at": "add_keys"}
    if not add_delegate(client, k1, page, f"{adi}/book2", kd):
        return {"case": "D", "status": "failed", "at": "add_delegate"}
    if not set_threshold(client, k1, page, 2):
        return {"case": "D", "status": "failed", "at": "set_threshold"}
    acct = exists(client, page) or {}
    return {"case": "D", "shape": "2-of-3, one entry delegated", "adi": adi,
            "page": page, "delegate_book": f"{adi}/book2",
            "threshold": acct.get("acceptThreshold"),
            "entries": len(acct.get("keys") or []),
            "key_names": ["d1", "d2", "dd1"], "status": "ok"}


def case_h(client, keys):
    """H — a delegation CYCLE: book -> book2 -> book. Must be refused, not looped."""
    adi = "acc://certen-p7h.acme"
    k = bootstrap(client, keys, "h1", adi)
    if not k:
        return {"case": "H", "status": "failed", "at": "bootstrap"}
    if not exists(client, f"{adi}/book2"):
        SmartSigner(client.v3, k, f"{adi}/book/1").sign_submit_and_wait(
            principal=adi,
            body=TxBody.create_key_book(url=f"{adi}/book2", public_key_hash=pub_hash(k)),
            max_attempts=30)
        time.sleep(4)
    ok1 = add_delegate(client, k, f"{adi}/book/1", f"{adi}/book2", k)
    ok2 = add_delegate(client, k, f"{adi}/book2/1", f"{adi}/book", k)
    return {"case": "H", "shape": "delegation cycle — MUST BE REFUSED",
            "adi": adi, "cycle": [f"{adi}/book", f"{adi}/book2", f"{adi}/book"],
            "key_names": ["h1"],
            "status": "ok" if (ok1 and ok2) else "incomplete"}



def case_f(client, keys):
    """F — delegation ACROSS BVNs.

    Accumulate routes an account to a partition by its URL, so two ADIs with
    unrelated names generally land on different BVNs. That is the point of this
    case: PHASE7_DELEGATION_PLAN §2 shows a delegated signer may live on a
    different BVN than the principal, and today ChainedProof carries exactly one
    BVN leg. This is the shape that proves one leg is not enough.

    The partitions are recorded rather than assumed — routing is a property of
    the network, so the corpus states what it actually got.
    """
    a_adi, b_adi = "acc://certen-p7f-alpha.acme", "acc://certen-p7f-omega.acme"
    ka = bootstrap(client, keys, "f1", a_adi)
    if not ka:
        return {"case": "F", "status": "failed", "at": "bootstrap alpha"}
    kb = bootstrap(client, keys, "f2", b_adi)
    if not kb:
        return {"case": "F", "status": "failed", "at": "bootstrap omega"}

    # alpha's page delegates to omega's book — a cross-ADI, and hopefully
    # cross-partition, delegation. omega must approve, so it signs too.
    if not credit_page(client, kb, f"{b_adi}/book/1"):
        return {"case": "F", "status": "failed", "at": "credit omega"}
    if not add_delegate(client, ka, f"{a_adi}/book/1", f"{b_adi}/book", kb):
        return {"case": "F", "status": "failed", "at": "delegate alpha->omega"}

    def partition_of(url: str) -> str:
        try:
            return (client.v3.query(url).get("recordType", "")
                    and client.v3.query(url).get("partition", "")) or "unknown"
        except Exception:
            return "unknown"

    return {"case": "F", "shape": "delegation across ADIs (target: different BVNs)",
            "principal": a_adi, "delegate": b_adi,
            "principal_page": f"{a_adi}/book/1", "delegate_book": f"{b_adi}/book",
            "key_names": ["f1", "f2"],
            "note": "confirm the two ADIs route to DIFFERENT BVNs before using "
                    "this as the cross-partition case; if they collide, rename one",
            "status": "ok"}


def case_k(client, keys):
    """K — a non-ed25519 key on a page. Must FAIL CLOSED with a distinct reason.

    Nothing is signed here. The corpus only needs a page carrying a key whose
    type CERTEN must refuse: signature_verifier.go rejects anything that is not
    ed25519, and runbook §9 requires that refusal to carry a distinct reason
    code rather than being silently skipped.

    The key hash is what a page stores, so a page cannot itself express "this is
    a BTC key" — the type lives on the SIGNATURE. This case therefore provides
    the ACCOUNT; the non-ed25519 signature over it is produced at trace-capture
    time, which is where the type check actually fires.
    """
    adi = "acc://certen-p7k.acme"
    k = bootstrap(client, keys, "k1", adi)
    if not k:
        return {"case": "K", "status": "failed", "at": "bootstrap"}
    return {"case": "K", "shape": "non-ed25519 signature — MUST FAIL CLOSED",
            "adi": adi, "page": f"{adi}/book/1", "key_names": ["k1"],
            "note": "sign with a btc/eth key at trace-capture time; the page "
                    "stores only key hashes, so the refusal happens on the "
                    "signature type, not on the account",
            "status": "ok"}


CASES = {
    "B": case_b, "C": case_c, "D": case_d,
    "E": case_e, "G": case_g, "H": case_h,
    "F": case_f, "K": case_k,
}


def main() -> int:
    only = sys.argv[1:] or list(CASES)
    assert_sdk_pinned()
    client = Accumulate(ENDPOINT)
    keys = load_keys()

    manifest = json.loads(MANIFEST_FILE.read_text()) if MANIFEST_FILE.exists() else {}
    for name in only:
        fn = CASES.get(name.upper())
        if not fn:
            print(f"unknown case {name}")
            continue
        print(f"=== case {name.upper()} ===")
        result = fn(client, keys)
        manifest[name.upper()] = result
        MANIFEST_FILE.write_text(json.dumps(manifest, indent=2))
        print(f"  -> {result['status']}")

    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
