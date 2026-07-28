# escrobot × CERTEN — Panel Demo Run Book

**Audience:** Bryan (boardy.ai) and anyone evaluating whether escrobot's Admin
function is trustworthy.

**The one thing this demo proves:** the lone Admin key is gone, and the thing
that replaced it is automatable right up to a single human click.

Act 1 was rehearsed end to end on 2026-07-28 and every hash in §6 is from that
run. Acts 2 and 3 are marked with their rehearsal status — **do not present an
unrehearsed act as proven**.

---

## 0. Pre-flight — 90 seconds, do not skip

```bash
cd C:/Accumulate_Stuff/certen/certen-carp-starter/examples

# The funded Sepolia key plays deployer/seller and funds the buyer.
export SEPOLIA_PRIVATE_KEY=$(node -e '
  const fs=require("fs");
  const m=fs.readFileSync("C:/Accumulate_Stuff/certen/api-bridge/.env","utf8")
    .match(/^EVM_SPONSOR_PRIVATE_KEY=(.*)$/m);
  process.stdout.write(m[1].trim().replace(/^["\x27]|["\x27]$/g,""));')

node panel-admin.mjs panel-status
```

| Check | Want | If wrong |
|---|---|---|
| Key page | `2-of-2 {bryan, agent}` | `node panel-admin.mjs restore-panel-v1` |
| `escrobot admin` | `0x895b2871…F9f3` | Stop. The panel is not the admin. |
| Gateway commit | `0b0ef45` or later | Redeploy — see §5 |
| Validators | 7 healthy | Stop and investigate |
| Funder balance | > 0.05 ETH | Top up |

```bash
# gateway must carry the signer fix, or the agent cannot open an intent
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'cd /root/api-gateway && git log --oneline -1'

ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'docker ps --format "{{.Names}} {{.Status}}" | grep -c "certen-validator.*healthy"'
```

**The failure that has bitten twice:** an API key that does not own the panel
identity. Every call 404s with "Identity not found". The driver now defaults to
the correct one; if you override `CK`, use the key from `certen-carp-KEYS.txt`.

---

## 1. Terminals

**A — the demo:** the `examples/` directory, large font.

**B — the fleet:**
```bash
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'docker logs -f certen-validator-1 2>&1 | grep --line-buffered -E "DISCOVERED|ELECTED|EVM-EXEC|executed successfully"'
```

Pre-open: Etherscan on `0x9F452b98e33fF3F973a12ee9333B33082D824816`, and the deck
`docs/demo/carp-panel-deck.html`.

---

## 2. Act 1 — the disputed order  *(REHEARSED, ~4 min)*

### 2.1 Show the panel is the admin

```bash
node panel-admin.mjs panel-status
```

> "Your contract is untouched. `forceResolve` is exactly as you wrote it, and
> `isAdmin` is exactly as you wrote it. The only thing that moved is the address
> in `admin` — and it is now a two-seat panel: you, and your agent."

### 2.2 Seed a real order  (~60s)

```bash
node panel-admin.mjs seed-dispute
```

Order goes LISTED → PAID → SHIPPED. **Read the order id out.**

> "escrobot only allows arbitration on a SHIPPED order. That's your rule, not ours."

### 2.3 The parties fall out — on chain  (~20s)

```bash
node panel-admin.mjs raise-dispute
```

> "The buyer says it never arrived. The seller says tracking shows delivered.
> Both are now `Noted` events on Ethereum, signed by their own addresses. The
> panel is about to rule on a public record, not on a story I'm telling you."

### 2.4 The panel resolves it  (~3 min)

```bash
node panel-admin.mjs force-resolve
```

Watch the output: the **agent** opens the intent, then it sits.

> "That's the agent proposing a resolution. One signature of two. Right now
> nothing can happen — and this pause is the product. Your escrow cannot be
> resolved by your agent alone."

Then Bryan's signature lands and the fleet executes. **Switch to Terminal B** and
point at `DISCOVERED → ELECTED → EVM-EXEC → executed successfully`.

> "Seven independent validators agreed the panel authorised this, signed it as a
> group, elected one of themselves to execute, and the contract checked their
> proof before moving a single wei."

### 2.5 Prove it

```bash
node panel-admin.mjs evidence
```

Then hand them the order id and let them run it themselves:

```bash
cast call 0x9F452b98e33fF3F973a12ee9333B33082D824816 "status(bytes32)(uint8)" \
  <ORDER_ID> --rpc-url https://ethereum-sepolia-rpc.publicnode.com
```

> "Status 5. Seller got the price, buyer got the bond back, and the reason the
> panel gave is written into your contract's own `note()` — permanently."

---

## 3. Act 2 — automating Admin  *(ALL THREE SCENES REHEARSED — see §6.2)*

The panel is already 3-of-3 `{agent, policy, Bryan}`. If it is not:

```bash
node panel-admin.mjs add-policy-seat
```

Two more terminals — **the config path is positional, not `--config`**:

```bash
# C — Bryan's rules, on Bryan's machine
cd C:/Accumulate_Stuff/certen/certen-carp-starter/examples
node escrow-policy-engine.mjs

# D — the signer holding the third seat
cd C:/Accumulate_Stuff/certen/certen-carp-starter/examples
node ../../certen-headless-offchain-policy-engine-signer/dist/signer.cjs ./panel-policy-signer.yaml
```

**Check terminal D's boot line before starting.** It must read:

```
intent decoder chain (first claim wins)  decoders=["escrobot-force-resolve", …]
SR6 self-check OK: pubkey matches page
```

If `escrobot-force-resolve` is missing, **stop**: the engine will be gating on the
leg value (`0`) instead of the payout, and will approve a forfeiture. That is not
hypothetical — see §6.3.

### Scene 1 — routine (engine approves)  ~4 min

```bash
node panel-admin.mjs seed-dispute
node panel-admin.mjs force-resolve
```

Terminal C prints `APPROVE`; terminal D prints `vote submitted vote=approve`.

> "The agent proposed it, your rules checked it automatically, and you finished
> it with one signature. That's the every-day-or-two model, running."

### Scene 2 — out of policy (engine denies)  ~2 min

```bash
node panel-admin.mjs seed-dispute
node panel-admin.mjs force-resolve-forfeit
```

Terminal C prints `DENY … exceeds the … ceiling; escalate to manual review`;
terminal D prints `vote=reject`. **The order stays at status 4.**

> "Conservation balances — escrobot would happily execute this. Your ceiling rule
> is what refuses it: awarding one party the other's bond is a human decision.
> And notice what happens now. Both of us signed. It still doesn't happen."

### Scene 3 — the engine is down  ← **the one that wins the room**  ~4 min

Ctrl-C terminal C, then:

```bash
node panel-admin.mjs seed-dispute
node panel-admin.mjs force-resolve      # a PERFECTLY VALID resolution
```

Terminal D repeats `policy decision failed | connect ECONNREFUSED` and **casts no
vote at all** — note it withholds rather than rejecting.

> "Nothing happens. Not a default-allow, not a timeout that waves it through.
> The signer's own documentation puts it best: *an outage can never become an
> approval — that is a property of the code, not a setting*."

Now restart terminal C. The same resolution completes on its own.

> "It wasn't lost. It was waiting."

---

## 4. Act 3 — making it official  *(REHEARSED, ~3 min)*

```bash
node panel-admin.mjs add-regulator
```

Ends at `3-of-4 {policy, bryan, agent, regulator}`, printed from the live page.

> "Adding a regulator is a panel decision, made by the existing panel. No
> redeployment. No downtime. Your contract never notices — and the regulator can
> refuse, but cannot redirect a single wei, because the split is sealed in the
> proof and conservation is enforced by your own `require`."

**Then make the threshold point explicitly, because it is the whole control.**

A page threshold counts how many signatures, not which. At 3-of-3, `updateKeyPage`
requires every current entry to sign — that is the enforcement, not an obstacle.
Want two seats to be able to change membership? Set 2-of-3, and accept that two
seats can settle disputes as well. One number governs both.

Note aloud that adding the regulator moved the panel to 3-of-4 and **stopped
requiring Bryan** — `{agent, policy, regulator}` could now resolve without him.
Adding a seat is also a decision about who is necessary.

Then the judgement call in §6.4:

> "Our first version had the policy seat auto-approve membership changes, because
> they move no money. That was wrong. At 3-of-3 it hands any two other seats the
> third signature for free — governance quietly becomes 2-of-3 while resolution
> stays 3-of-3. So it withholds instead, and a human releases it."

---

## 5. If something breaks

| Symptom | Cause | Do this |
|---|---|---|
| `Identity not found` (404) | Wrong API key | Use the key from `certen-carp-KEYS.txt` |
| Agent's intent rejected 400 | Gateway predates `0b0ef45` | Redeploy (below) |
| api-bridge 500 on submit | Same — half-deployed fix | Redeploy |
| Cloudflare 502 | Transient | Retry; the driver already retries |
| Intent stuck `anchoring` | **Status lag, not failure** | Check the CONTRACT: `status(order)` |
| Resolution never executes | Threshold not met | `panel-status`; check signature count |

```bash
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'cd /root/api-gateway && git fetch && git reset --hard origin/main && \
   docker compose up -d --build --force-recreate certen-gateway'
```

**Do not trust intent status.** It lagged the whole way through the rehearsal
while the resolution had already executed on Sepolia. Verify effect on the
contract, never in the dashboard.

Every stage is idempotent and reads its state file — re-run the failed stage
rather than starting over.

---

## 6. Rehearsal evidence

### 6.0 Full three-act rerun on the updated fleet — 2026-07-28

Every act, back to back, verified on-chain rather than from the demo's output.

| Act | Order | Expected | Actual |
|---|---|---|---|
| 1 — panel resolves | `0xcad6e943…` | 5 | **5** |
| 2 scene 1 — approve | `0x1a8f71a8…` | 5 | **5** |
| 2 scene 2 — deny | `0xfe8f613b…` | **4 (refused)** | **4** |
| 2 scene 3 — outage | `0x9edc8447…` | 5 after recovery | **5** |

**Act 1.** Dispute recorded on-chain (`0x7f961765…` buyer, `0x338c0396…` seller),
then resolution `72ad64f8…` delivered with two signatures — agent `bfec7219…`
opened it, Bryan `d7a0d860…` finalized it.

**Act 2 scene 2** — the engine read the decoded call and refused:
```
DENY  "…1500000000000000 wei to seller, 0 wei to buyer" — exceeds the
      1000000000000000 wei auto-approval ceiling; escalate to manual review
signer: vote=reject          order: still 4, with both humans signed
```

**Act 2 scene 3** — with the engine stopped: `policy decision failed |
ECONNREFUSED` on every poll and **no vote cast**. On restart, `vote=approve` and
the order completed. Withheld, not lost.

**Act 3** — the corrected governance path. The membership change was **not**
auto-signed:
```
PENDING "updateKeyPage on …/book/1" — awaiting operator release
signer:  "policy engine has not decided yet; withholding signature and will retry"
page:    unchanged at 3-of-3
```
After `POST /release {"txHash":"c97b6084…","by":"bryan"}`:
```
APPROVE — released by an operator
page:   3-of-4 {policy, bryan, agent, regulator}
```

**Resetting afterwards needs releases too — budget for it.** `restore-panel-v1`
runs governance operations, so while the policy seat is still on the page each
one waits for a release. In this run: removing the regulator went through on
three human/agent signatures (no release needed), lowering the threshold needed
one release, and removing the policy seat needed none once the threshold was 2.
Watch the engine log for `PENDING` and release each `txHash` as it appears.

Panel returned to `2-of-2 {bryan, agent}`, so the whole sequence is repeatable.

### 6.1 Earlier Act 1 evidence — 2026-07-28

Verified independently on-chain, not from the demo's own output.

```
order            0x77b8b764f4e4c0c5ce72c6b551b445bef8c3d2804365150dec5ff9b1bc66c8e3
buyer complaint  0x68a70bae4d4a64d982925b942fb6f2c5843cad70e2aafdfdcbff5155d04b6ccc  block 11367729
seller rebuttal  0x5ecbdca77d3ad14c53a7d453bcb8418db93426ad333f827ca44c9142b2cf5620  block 11367730
RESOLUTION       0xe0e1233f5195c37962436624a6ad3bbee18b57860dd9fdd902eeb13c51ba69da  block 11367750
```

That last transaction contains, in order:
- `Noted` — *"panel arbitration: carrier tracking confirms delivery; buyer
  non-response past the deadline. Seller paid in full, buyer bond returned."*
  with `noter = 0x895b2871…` (the panel)
- two withdrawal-queued events carrying escrobot's own force-resolve reason codes
  (5 = seller, 6 = buyer)
- `Completed(order, 0x895b28715FA81F6F4d6994cDda4e5323cC07F9f3)` — **the panel**

On Accumulate:
```
WriteData   dafa54f7805ba9a5253e496308e8b5dbf2e6e79d83d90e4b13b63780ef8a9b61
status      delivered, anchored
signatures  2  —  agent bfec7219… opened it, Bryan d7a0d860… finalized it
executor    validator-6 elected; all 7 validators agreed
settlement  seller 0.001 ETH (price) · buyer 0.0005 ETH (bond returned)
```

### 6.2 Act 2 evidence — 2026-07-28

Panel took the policy seat and moved to **3-of-3 `{agent, policy, Bryan}`**. The
signer's own SR6 self-check confirmed its key is genuinely on the page, which
also proves the seed chain: one 32-byte seed → registered seat hash → the key the
signer signs with.

**Scene 1 — approve.** Order `0x482f98c0…`, WriteData `ee42b4de…` delivered with
**three** signatures — agent `bfec7219…`, Bryan `d7a0d860…`, policy `01eeb281…`.
Order reached status 5. The policy seat signed with no human touching it.

**Scene 2 — deny.** Order `0xfd988283…`. The engine read the decoded call:
```
DENY  "escrobot arbitration on order 0xfd988283… — 1500000000000000 wei to
       seller, 0 wei to buyer" — amount 1500000000000000 exceeds the
       1000000000000000 wei auto-approval ceiling; escalate to manual review
```
Signer cast `vote=reject`. **Order stayed at status 4** with both humans signed.

**Scene 3 — outage.** Order `0x98220720…`, a valid resolution. With the engine
stopped the signer logged `policy decision failed | connect ECONNREFUSED` on
every poll and cast **no vote**. Order stayed at 4. On restart it completed.

### 6.3 The bug this campaign found — worth knowing before you present

The first version of the policy engine **approved a full forfeiture**, and it
settled on Sepolia (order `0x945d7dad…`, seller took the buyer's bond).

The rules were correct. They were reading the wrong number. A contract-call
intent carries its amounts in ABI-encoded `callData`; the built-in decoders
describe the intent's *leg*, whose value is `0` because the panel calls a
function rather than sending ether. So the ceiling check compared `0` against the
limit and passed, and the conservation check — which only runs when it sees two
amounts — silently skipped.

The fix is `examples/escrobot-decoder.mjs`, ~40 lines with no dependencies,
loaded via `resolver.decoder_modules`. It parses the `forceResolve` calldata and
puts both payout amounts into `values`, which is what actually gets gated.

**Operational consequence:** if terminal D's boot line does not list
`escrobot-force-resolve` first, the gate is not really gating. Treat a missing
decoder as a stop condition, not a warning.

### 6.4 The second finding — how the automated seat should treat governance

With the panel at 3-of-3 `{agent, policy, Bryan}`, adding the regulator was
rejected by the policy engine, which had no rule for governance and refused what
it could not price:

```
DENY  "updateKeyPage on acc://certen-panel-bryan1.acme/book/1"
      — no amounts present; refusing to approve a resolution I cannot read
```

**The first fix was wrong.** We made the engine auto-approve any `updateKeyPage`
on its own page, reasoning that membership changes move no funds. At 3-of-3 that
hands any two other seats the third signature for free — governance silently
becomes 2-of-3 while dispute resolution stays 3-of-3, weakening the one operation
that decides who may act at all.

**The correct behaviour** is to withhold. The engine now returns `pending` for a
membership change on its own page: no vote is cast, the transaction stays pending
on chain, and it is approved only after an operator releases it out of band.

```
PENDING  "updateKeyPage on …/book/1" — awaiting operator release
                                       POST /release {"txHash":"…"}
APPROVE  — released by an operator
DENY     — updateKeyPage naming any other page
```

Release it during the demo with:
```bash
curl -s -X POST http://127.0.0.1:9099/release \
  -H 'content-type: application/json' -d '{"txHash":"<TX>","by":"bryan"}'
```

Nothing here is a limitation of the threshold. Requiring all three entries to
sign a key-page change at 3-of-3 **is** the threshold enforcing itself; choosing
2-of-3 is how you let two entries do it.

Note also that the submit response reported `signature_count: 3, is_ready: true`
for the rejected operation. **Signatures submitted is not the same as the change
landing.** The driver now waits for the key page itself to show the seat.

---

## 7. Questions he will ask

**"Could CERTEN resolve an order without me?"**
No. Your seat is on the key page and the threshold requires it. CERTEN operates
validators that *execute* what the panel authorised; it holds no seat.

**"What if your gateway is down?"**
Then no new resolution is proposed. Nothing settles incorrectly — it just waits.

**"What if the policy engine is wrong?"**
It can only ever *withhold* or *deny*. It cannot approve something your contract
forbids: conservation is enforced by your `require`, and the split is sealed in
the proof before execution.

**"Can I get my agent paid out of arbitration?"**
Not without changing your contract. `forceResolve` requires
`amtToSeller + amtToBuyer == price + bond`. Agent revenue has to come from the
service layer.

**"Is this production ready?"**
It is on Sepolia, with a live panel and a real proof cycle. It is not on mainnet,
and tiered thresholds aren't built. Say that plainly — the honest version is
stronger than the claim.
