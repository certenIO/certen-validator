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

## 3. Act 2 — automating Admin  *(seat added; three scenes NOT yet rehearsed)*

```bash
node panel-admin.mjs add-policy-seat     # panel -> 3-of-3 {agent, policy, Bryan}
```

Then, in two more terminals:

```bash
# C — Bryan's rules, on Bryan's machine
node escrow-policy-engine.mjs

# D — the signer holding the third seat
cd ../../certen-headless-offchain-policy-engine-signer
node dist/signer.cjs --config ../certen-carp-starter/examples/panel-policy-signer.yaml
```

### Scene 1 — routine (engine approves)
Seed and resolve a normal dispute. The signer sees the pending resolution, asks
the engine, gets `approve`, and signs **by itself**. Bryan clicks once.

> "That's the every-day-or-two model. The agent did the work, your rules checked
> it automatically, and you finished it."

### Scene 2 — out of policy (engine denies)
Propose a resolution awarding one side the other's bond.

> "Conservation still balances — the totals are fine. Your ceiling rule is what
> refuses it: a forfeiture is a human decision, not an automated one. And note
> what happens now: **nothing**. Both of us want it to go through. It doesn't."

### Scene 3 — the engine is down  ← **the one that wins the room**
Stop the policy engine (Ctrl-C in terminal C) and propose a routine resolution.

> "Nothing happens. Not a default-allow, not a timeout that waves it through.
> The signer's own documentation puts it best: *an outage can never become an
> approval — that is a property of the code, not a setting*."

Restart the engine; the same resolution then completes.

---

## 4. Act 3 — making it official  *(NOT yet rehearsed)*

```bash
node panel-admin.mjs add-regulator
```

> "Adding a regulator is a panel decision, made by the existing panel. No
> redeployment. No downtime. Your contract never notices — and the regulator can
> refuse, but cannot redirect a single wei, because the split is sealed in the
> proof and conservation is enforced by your own `require`."

**Say the limitation out loud before he finds it:** a key page threshold counts
*how many* signatures, not *which*. At 3-of-3 Bryan is structurally required; add
a fourth seat at threshold 3 and he is not. Tiered thresholds across multiple key
pages are the proper answer and are not built yet.

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

## 6. Rehearsal evidence — Act 1, 2026-07-28

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
