# CARP × CERTEN — Live Demo Run Book

**Rehearsed end to end 2026-07-28.** Every command below was run for real; the
evidence in §7 is from that run.

---

## 0. The 60-second pre-flight — DO NOT SKIP

One check has failed twice and it fails **silently**: every container reports
healthy while identity provisioning hangs forever.

```bash
# 1. Onboarding sponsor — the demo dies at step one without this
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'docker logs --tail 200 api-bridge 2>&1 | grep -i "Sponsor status check" | tail -1'
```

**Want `"sponsorHealthy":true`.** If false, fix it and wait ~60s:

```bash
SP=acc://4d07443e23bf3d244facb56f7fd4614d29b21f553c25eef5/ACME
for i in $(seq 1 120); do curl -s -X POST https://kermit.accumulatenetwork.io/v3 \
  -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"faucet\",\"params\":{\"account\":\"$SP\"}}" >/dev/null; done
```

```bash
# 2. Validator fleet — want 7
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'docker ps --format "{{.Names}} {{.Status}}" | grep -c "certen-validator.*healthy"'

# 3. Entitlement gate — want mode=observe (cannot refuse mid-demo)
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'docker logs certen-validator-1 2>&1 | grep -oE "rule at height [0-9]+: mode=[a-z]+" | tail -1'

# 4. Gateway + epoch publisher — want publishing:true
curl -s https://gateway.kompendium.co/v1/entitlement/health

# 5. Funder balance — want > 0.05 ETH (a run costs 0.0015)
cast balance 0x32422604b797f0a135d8F28B84Ce72EefA185FC8 \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com --ether
```

| Check | Want | If wrong |
|---|---|---|
| `sponsorHealthy` | `true` | Faucet, wait 60s, re-check |
| Validators | `7` | Do not start. Investigate. |
| Gate mode | `observe` | Enforce risks refusing a new identity live |
| Publisher | `publishing:true` | Restart `certen-gateway` |
| Funder | > 0.05 ETH | Top up |

---

## 1. Terminal setup

Two terminals, side by side, large font.

**Terminal A — the demo:**
```bash
cd C:/Accumulate_Stuff/certen/certen-carp-starter/examples
export SEPOLIA_PRIVATE_KEY=$(grep -oE "^EVM_SPONSOR_PRIVATE_KEY=.*" \
  "C:/Accumulate_Stuff/certen/api-bridge/.env" | cut -d= -f2- | tr -d '"'"'"' \r')
cp -a two-agent-escrow.state.json "state.bak.$(date +%s)" 2>/dev/null
rm -f two-agent-escrow.state.json      # fresh identities for the audience
```

**Terminal B — the fleet (proof that it is real):**
```bash
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'docker logs -f certen-validator-1 2>&1 | grep --line-buffered -E "DISCOVERED|PROOF-CLASS|BLS-SIG|ELECTED|EVM-EXEC|executed successfully|ENTITLEMENT"'
```

Browser tabs, pre-opened:
- `https://sepolia.etherscan.io/address/0x9F452b98e33fF3F973a12ee9333B33082D824816`
- The Accumulate explorer
- The deck: `docs/demo/carp-demo-deck.html`

---

## 2. Stage-by-stage: what to run, what to say

Timings are from the rehearsal. **Every proof-gated stage takes 60–120s** —
that dead air is your friend, use it to narrate Terminal B.

### Stage 1 — `agents` (~90s)

```bash
node two-agent-escrow.mjs agents
```

> "I'm creating two AI agents from nothing. Each one gets an identity on
> Accumulate — a name, a key book, its own governance — and a smart account on
> Ethereum. Watch: neither of them is being handed a wallet."

Output gives you two ADIs and two Sepolia addresses. **Read them out.** These
are new, they did not exist a minute ago.

### Stage 2 — `handshake` (~5s)

```bash
node two-agent-escrow.mjs handshake
```

> "Now they introduce themselves to each other — no broker, no registry. The
> seller proves it holds the key behind its DID, they derive a shared secret,
> and everything after this is encrypted end to end. Notice the DID carries the
> agent's Accumulate identity: that binding is what makes the later proofs
> mean something."

### Stage 3 — `submit` (~90s)

```bash
node two-agent-escrow.mjs submit
```

> "The seller lists an order. It does **not** sign an Ethereum transaction — it
> signs an *intent* on Accumulate. Watch the validators pick it up."

**Switch to Terminal B.** Point at: `DISCOVERED` → `BLS-SIG` → `ELECTED
EXECUTOR` → `EVM-EXEC` → `executed successfully`.

> "Seven independent validators just agreed this was authorised, signed it as a
> group, elected one of themselves to execute, and the contract checked their
> proof before doing anything."

### Stage 4 — `buy` (~120s) — **the money moves**

```bash
node two-agent-escrow.mjs buy
```

> "Now real value. We fund the buyer's smart account with 0.0015 ETH, and the
> buyer pays into escrow — again by intent, never by signing a transaction.
> The order goes to status 2: PAID."

**Switch to Etherscan.** Show the order status change.

### Stage 5 — `ship` (~90s)

```bash
node two-agent-escrow.mjs ship
```

> "Seller ships. Status 4."

### Stage 6 — `confirm` (~90s)

```bash
node two-agent-escrow.mjs confirm
```

> "Buyer confirms, and the contract settles: seller gets the price, buyer gets
> the bond back. Status 5 — COMPLETE."

Output prints the settlement amounts. **Read them out.**

### Stage 7 — `receipts` (~10s)

```bash
node two-agent-escrow.mjs receipts
```

> "Finally the agents swap proof receipts over their encrypted channel — and
> each one *re-checks the other's maths* rather than taking its word. That is
> the whole thesis: verify, don't trust."

---

## 3. The close

> "Two AI agents just ran a real financial transaction on a public blockchain.
> Neither of them could have stolen the money if it tried — because neither ever
> held the authority to move it. The authority was a proof, the contract checked
> it, and every one of you can re-check it right now on Etherscan."

Then hand them the order id and let them look.

---

## 4. If something breaks

| Symptom | Cause | Do this |
|---|---|---|
| `no Sepolia account`, stuck `creating` | **Sponsor ACME below 1000** | §0 faucet. Most likely failure. |
| Stage hangs > 3 min | Proof cycle slow / intent not discovered | Terminal B: is it `DISCOVERED`? Re-run the stage — stages are idempotent |
| `ENTITLEMENT] REJECTED` | Gate in enforce, identity too new | Should not happen in observe. Say "that's the fee layer refusing unpaid work" and move on |
| Etherscan lagging | RPC | Use `cast call` from Terminal A instead |
| Everything is broken | — | Fall back to the deck + §7 evidence from the rehearsal |

**Recovery is cheap:** every stage is idempotent and reads its state file. Re-run
the failed stage; you do not have to start over.

**The safest single mitigation:** run `agents` + `handshake` *before* the
audience arrives, and demo from `submit` onward. You lose the "created from
nothing" moment but remove the slowest and most fragile stage.

---

## 5. What to have ready but not say

- **Cost:** 0.0015 ETH per run (0.001 price + 0.0005 bond). Funder holds ~1.09 ETH.
- **Gas:** CERTEN fronts native gas on all four legs. The customer pays one
  price — that is the fee layer, and it is live and charging.
- **Chains:** the same cycle runs on 14. Sepolia is what we're showing.
- **The gate:** entitlement is in `observe` for the demo — it evaluates and logs
  every verdict but cannot refuse. In production it enforces.

---

## 6. Questions and honest answers

**"Could a validator steal the funds?"**
No. Execution needs a ≥2/3 BLS quorum verified on-chain. One validator cannot
act alone.

**"Could the agent be tricked into overpaying?"**
The proof binds chain, target, value and calldata. An approval for 0.001 to this
order cannot become 1.0 to somewhere else.

**"What if CERTEN goes away?"**
Receipts are self-contained. Re-verify offline, forever.

**"Is this production-ready?"**
It runs on testnets today, on 14 chains, with the fee layer live. Be
straightforward about that — it is a strong position and overclaiming invites
the one question you don't want.

**"Has anything gone wrong?"**
Yes, and say so if asked. Enforcement was rolled out, broke on an edge case
around block-time lag, was diagnosed and fixed, and the mechanism to change that
rule safely — quorum-signed, activating at an agreed time, no restart — is
itself part of what shipped. That story is more convincing than claiming a clean
run.

---

## 7. Rehearsal evidence — 2026-07-28

A complete run, verified independently on-chain (not from the demo's own
output).

**Identities created live:**
```
seller-bot  acc://carp-seller-26661.acme  →  0xAaCda17a39745325eDC56A1fE69Ef6f44dd454f5
buyer-bot   acc://carp-buyer-26577.acme   →  0x8a68fB07Fb01D0C365c55011F290341505Bd74D3
```

**Escrobot order:** `0x50b75e7b19c721f6b4728420178d28a822f68f54dfaa2c42115d6327e89f04fa`
Contract `0x9F452b98e33fF3F973a12ee9333B33082D824816` · statuses 1 → 2 → 4 → 5

**Accumulate receipt:** `5c96ba818afccbb725ec48fba2d18dd7678a6a5a434066a646eda52642a19878`
principal `acc://carp-buyer-26577.acme/data` · `anchored: true`

**Settlement, read from the contract:**
```
status(order)                 = 5   (COMPLETED)
pendingWithdrawals(seller)    = 1000000000000000   (0.001 ETH — the price)
pendingWithdrawals(buyer)     =  500000000000000   (0.0005 ETH — bond returned)
balance(buyer smart account)  = 0.000000000000000  (escrow took it)
```

Verify any of it yourself:
```bash
cast call 0x9F452b98e33fF3F973a12ee9333B33082D824816 "status(bytes32)(uint8)" \
  0x50b75e7b19c721f6b4728420178d28a822f68f54dfaa2c42115d6327e89f04fa \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
```
