# escrobot × CERTEN — Panel Demo Manual

**Audience:** Bryan (boardy.ai), and anyone judging whether escrobot's Admin
function is trustworthy enough for real commerce.

**What it proves:** the lone Admin key is gone, and what replaced it is
automatable right up to a single human click.

All three acts were rehearsed end to end on **2026-07-28** against the updated
validator fleet. Every hash in §7 is from that run.

**Runtime:** ~20 minutes. ~0.0015 ETH per order, six orders per full run.

## Running it as a script

`run-demo.mjs` drives the same stages this manual documents, one command per act,
pausing between beats and printing the line to say:

```bash
node run-demo.mjs preflight     # checks only
node run-demo.mjs act1          # a disputed order resolved by the panel
node run-demo.mjs act2          # the automated seat: approve / deny / outage
node run-demo.mjs act3          # regulator voted in, with the release step
node run-demo.mjs reset         # back to 2-of-2 {bryan, agent}
node run-demo.mjs all           # everything, then reset

  --auto            no pauses (unattended verification run)
  --auto-release    release pending membership changes automatically
```

It shells out to `panel-admin.mjs` for every step, so the script and this manual
cannot drift apart. It does **not** start the policy engine or the signer — on a
projector you want those visible in their own terminals — but it checks they are
up and refuses to continue if they are not.

Read the rest of this manual before presenting: the script runs the demo, it does
not tell you what to watch for.

---

## 0. Pre-flight — 3 minutes, do not skip

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

```bash
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'cd /root/api-gateway && git log --oneline -1;
   docker ps --format "{{.Names}} {{.Status}}" | grep -c "certen-validator.*healthy"'

cast balance 0x32422604b797f0a135d8F28B84Ce72EefA185FC8 \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com --ether
```

| Check | Want | If wrong |
|---|---|---|
| Key page | **`2-of-2 {bryan, agent}`** | `node panel-admin.mjs restore-panel-v1` |
| `escrobot admin` | `0x895b2871…F9f3` | **Stop.** The panel is not the admin. |
| Gateway commit | `0b0ef45` or later | Redeploy — §6 |
| Validators healthy | `7` | **Stop and investigate.** |
| Funder | > 0.05 ETH | Top up |

**The failure that has bitten twice:** an API key that does not own the panel
identity — every call 404s `Identity not found`. The driver now defaults to the
right one; if you override `CK`, use the key from `certen-carp-KEYS.txt`.

---

## 1. Screen setup

**Terminal A — the demo.** The `examples/` directory, large font. This is where
every command below is typed.

**Terminal B — the fleet.**
```bash
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'docker logs -f certen-validator-1 2>&1 | grep --line-buffered -E \
   "DISCOVERED|ELECTED|EVM-EXEC|executed successfully"'
```
> `DISCOVERED` and `executed successfully` appear on **every** node. `ELECTED`
> and `EVM-EXEC` appear **only on the node that won the election** — so don't
> promise those two lines on validator-1 specifically.

**Terminals C and D** — started in Act 2 (§3). Leave them closed until then.

**Browser tab 1 — Etherscan**, on the escrow contract:
`https://sepolia.etherscan.io/address/0x9F452b98e33fF3F973a12ee9333B33082D824816`

**Browser tab 2 — the Accumulate explorer.** Open
`https://explorer.accumulatenetwork.io/` and **switch the network selector
(top right) to Kermit Testnet BEFORE the demo.** Then:
`https://explorer.accumulatenetwork.io/acc/certen-panel-bryan1.acme/book/1`

It shows `Key Page · Threshold · Keys · Transactions`, and updates live as seats
are added and removed. The choice is stored in `localStorage.networkName`, so it
sticks once set. **A direct URL without switching first defaults to Mainnet and
renders 404** — that is what the room will see if you paste a link cold.

The explorer lists keys as `MHz126…` addresses, so it won't tell you *which* seat
is which. Use it for the authoritative threshold and key count; use `proof` for
named seats.

**Slides:** `docs/demo/carp-panel-brief.pptx` (5 slides).

---

## 2. Act 1 — the disputed order  *(~5 min)*

### 2.1 The panel is the admin

```bash
node panel-admin.mjs panel-status
```

> "Your contract is untouched. `forceResolve` is exactly as you wrote it, and
> `isAdmin` is exactly as you wrote it. The only thing that moved is the address
> in `admin` — and it is now a two-seat panel: you, and your agent."

### 2.2 Seed a real order  *(~60s)*

```bash
node panel-admin.mjs seed-dispute
```

LISTED → PAID → SHIPPED. **Read the order id out.**

> "escrobot only allows arbitration on a SHIPPED order. That's your rule."

### 2.3 The parties fall out, on chain  *(~20s)*

```bash
node panel-admin.mjs raise-dispute
```

> "The buyer says it never arrived. The seller says tracking shows delivered.
> Both are `Noted` events on Ethereum now, signed by their own addresses. The
> panel is about to rule on a public record, not on a story I'm telling you."

### 2.4 The panel resolves it  *(~3 min)*

```bash
node panel-admin.mjs force-resolve
```

**The beat that matters** — after the agent's signature and before Bryan's:

> "That's his agent proposing a resolution. One signature of two. Right now
> nothing can happen — and this pause is the product."

Then Bryan's lands. **Switch to Terminal B**, point at `DISCOVERED` and
`executed successfully`.

**Three separate gates had to be satisfied before a wei moved**, and all three
are in his contract:

| Gate | Enforced by |
|---|---|
| Order must be SHIPPED | `require(status == State.SHIPPED)` |
| Payout must equal price + bond | `require(amtToSeller + amtToBuyer == …)` |
| Caller must be Admin — now the panel | `isAdmin` |

### 2.5 Prove it

```bash
node panel-admin.mjs proof
```

One screen: the key page and its **named** seats, the resolution's WriteData
showing **which seat cast each signature**, and the effect on Sepolia
(`admin()`, order status, both payouts).

Then hand over the order id and let them run it themselves:

```bash
cast call 0x9F452b98e33fF3F973a12ee9333B33082D824816 "status(bytes32)(uint8)" \
  <ORDER_ID> --rpc-url https://ethereum-sepolia-rpc.publicnode.com
```

> "Status 5. Seller got the price, buyer got the bond back, and the reason the
> panel gave is written into your contract's own `note()` — permanently."

---

## 3. Act 2 — automating Admin  *(~8 min — the heart of it)*

### 3.1 Add the automated seat

```bash
node panel-admin.mjs add-policy-seat      # 2-of-2 -> 3-of-3 {agent, policy, Bryan}
```

Show the explorer tab: **Threshold 3, Keys 3**, live.

### 3.2 Start terminals C and D

**The config path is positional, not `--config`.**

```bash
# C — Bryan's rules, on Bryan's machine
cd C:/Accumulate_Stuff/certen/certen-carp-starter/examples
node escrow-policy-engine.mjs
```

```bash
# D — the signer holding the third seat (pretty-printed for the projector)
cd C:/Accumulate_Stuff/certen/certen-carp-starter/examples
node ../../certen-headless-offchain-policy-engine-signer/dist/signer.cjs \
  ./panel-policy-signer.yaml 2>&1 | node -e '
  require("readline").createInterface({input:process.stdin}).on("line",l=>{
    try{const j=JSON.parse(l);
      const extra = j.decoders ? " "+JSON.stringify(j.decoders)
                  : j.vote    ? " vote="+j.vote
                  : j.reason  ? " | "+String(j.reason).slice(0,70) : "";
      console.log(new Date(j.time).toISOString().slice(11,19), (j.msg||"")+extra);
    }catch{console.log(l)}
  })'
```

**STOP CONDITION.** Terminal D's boot must show both lines:

```
intent decoder chain (first claim wins) ["escrobot-force-resolve", …]
SR6 self-check OK: pubkey matches page
```

If `escrobot-force-resolve` is missing, the engine gates on the intent leg value
(`0`) instead of the payout and **will approve a forfeiture** — see §7.3. Keep
`j.decoders` in the formatter above; an earlier version swallowed it.

### 3.3 Scene 1 — routine *(engine approves)*  ~4 min

```bash
node panel-admin.mjs seed-dispute
node panel-admin.mjs force-resolve
```

C prints `APPROVE`; D prints `vote=approve`. Nobody touched it.

> "The agent proposed it, your rules checked it automatically, and you finished
> it with one signature. That's the every-day-or-two model, running."

### 3.4 Scene 2 — out of policy *(engine denies)*  ~2 min

```bash
node panel-admin.mjs seed-dispute
node panel-admin.mjs force-resolve-forfeit
```

C prints `DENY … exceeds the … ceiling; escalate to manual review`; D prints
`vote=reject`. **The order stays at 4.**

> "Conservation balances — escrobot would happily execute this. Your ceiling rule
> refuses it, because awarding one party the other's bond is a human decision.
> And notice what happens now: both of us signed. It still doesn't happen."

### 3.5 Scene 3 — the engine is down ← **wins the room**  ~4 min

Ctrl-C **terminal C**, then:

```bash
node panel-admin.mjs seed-dispute
node panel-admin.mjs force-resolve        # a PERFECTLY VALID resolution
```

D repeats `policy decision failed | connect ECONNREFUSED` and **casts no vote at
all** — it withholds rather than rejecting.

> "Nothing happens. Not a default-allow, not a timeout that waves it through.
> An outage can never become an approval — that's a property of the code, not a
> setting."

Restart terminal C. The same resolution completes on its own.

> "It wasn't lost. It was waiting."

---

## 4. Act 3 — the threshold is the control  *(~3 min)*

```bash
node panel-admin.mjs add-regulator
```

It goes **`PENDING` and the page does not change.** That is the point:

> "Changing who can act is never automatic. If the automated seat auto-approved
> this, any two other seats would get the third signature for free — governance
> would quietly become 2-of-3 while resolution stayed 3-of-3."

Take the `txHash` from terminal C and release it:

```bash
curl -s -X POST http://127.0.0.1:9099/release \
  -H 'content-type: application/json' -d '{"txHash":"<TX>","by":"bryan"}'
```

Now it lands: **`3-of-4 {policy, bryan, agent, regulator}`**. Show the explorer.

**Then make the threshold point, because it is the whole control.** A threshold
counts how many signatures, not which. At 3-of-3 an `updateKeyPage` needs every
current entry — that is the enforcement, not an obstacle. Want two seats to be
able to change membership? Set 2-of-3 — and accept that two seats can settle
disputes too. One number governs both.

**Say this out loud:** adding the regulator moved the panel to 3-of-4 and
**stopped requiring Bryan** — `{agent, policy, regulator}` could now resolve
without him. Adding a seat is also a decision about who is necessary.

---

## 5. Reset after the demo

```bash
node panel-admin.mjs restore-panel-v1
```

Drives the panel back to `2-of-2 {bryan, agent}` from any configuration. **While
the policy seat is still seated, its governance operations need releases** —
watch terminal C for `PENDING` and release each `txHash` as it appears:

```bash
curl -s -X POST http://127.0.0.1:9099/release \
  -H 'content-type: application/json' -d '{"txHash":"<TX>","by":"bryan"}'
```

In the last dry run that was **two releases** (lowering the threshold, and one
membership step). Removing the regulator needed none — three human/agent
signatures already met the threshold — and removing the policy seat needed none
once the threshold was down to 2.

Finish by stopping terminals C and D, then confirm:

```bash
node panel-admin.mjs panel-status     # 2-of-2 {bryan, agent}
```

---

## 6. If something breaks

| Symptom | Cause | Do this |
|---|---|---|
| `Identity not found` (404) | Wrong API key | Use the key from `certen-carp-KEYS.txt` |
| Agent's intent rejected 400 | Gateway predates `0b0ef45` | Redeploy (below) |
| api-bridge 500 on submit | Half-deployed fix | Redeploy |
| Cloudflare 502 | Transient | Retry — the driver already retries |
| Driver prints `status=anchoring` | **Gateway status lag, not failure** | Check the CONTRACT: `status(order)` |
| Resolution never executes | Threshold not met | `panel-status`, then `proof` for the signature count |
| Terminal C or D vanished | Has happened mid-run | Restart it; the scene continues correctly |

```bash
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'cd /root/api-gateway && git fetch && git reset --hard origin/main && \
   docker compose up -d --build --force-recreate certen-gateway'
```

**Never present the driver's poll line.** It printed `status=anchoring` through
both rehearsals while the resolution had already settled on Sepolia — a gateway
status-tracking gap, not a failure. The validator logs and the contract were
correct throughout. Verify effect on the contract.

Every stage is idempotent and reads its state file — re-run the failed stage
rather than starting over.

---

## 7. Evidence from the final dry run — 2026-07-28

Verified on-chain, not from the demo's own output.

| Act | Order | Expected | Actual |
|---|---|---|---|
| 1 — panel resolves | `0x8ce143b7…` | 5 | **5** |
| 2·1 — approve | `0x8d631416…` | 5 | **5** |
| 2·2 — deny | `0x5c284d3e…` | **4, refused** | **4** |
| 2·3 — outage | `0x85076279…` | 5 after recovery | **5** |

Act 3: governance `PENDING`, page unchanged, then `3-of-4` after release. Panel
reset to `2-of-2`.

### 7.1 A fully-detailed Act 1 (earlier run, same day)

```
order            0x77b8b764…c8e3
buyer complaint  0x68a70bae…6ccc   block 11367729
seller rebuttal  0x5ecbdca7…5620   block 11367730
RESOLUTION       0xe0e1233f…69da   block 11367750
```

That transaction contains, in order: `Noted` with the panel's reason and
`noter = 0x895b2871…`; two withdrawal-queued events carrying escrobot's own
force-resolve reason codes (5 = seller, 6 = buyer); and
`Completed(order, 0x895b28715FA81F6F4d6994cDda4e5323cC07F9f3)` — **the panel**.

On Accumulate: WriteData `dafa54f7…`, delivered and anchored, **2 signatures** —
agent `bfec7219…` opened it, Bryan `d7a0d860…` finalized it. Validator-6 elected;
all 7 agreed. Settlement: seller 0.001 ETH, buyer 0.0005 ETH bond returned.

### 7.2 The decoder is not optional

An early policy engine **approved a full forfeiture**, and it settled on Sepolia
(order `0x945d7dad…`, seller took the buyer's bond).

The rules were correct — they were reading the wrong number. A contract-call
intent carries its amounts in ABI-encoded `callData`; the built-in decoders
describe the intent's *leg*, whose value is `0` because the panel calls a
function rather than sending ether. The ceiling compared `0` against the limit
and passed; conservation, which only runs on two amounts, silently skipped.

Fix: `examples/escrobot-decoder.mjs` (~40 lines, no dependencies) loaded via
`resolver.decoder_modules`. **Treat a missing decoder as a stop condition.**

### 7.3 How the automated seat treats governance

At 3-of-3 the policy seat is required for membership changes too. Our first fix
auto-approved them, which handed any two other seats the third signature for
free. The correct behaviour is to withhold:

```
PENDING  "updateKeyPage on …/book/1" — awaiting operator release
APPROVE  — released by an operator
DENY     — updateKeyPage naming any other page
```

Nothing here is a limitation of the threshold. Requiring all three entries at
3-of-3 **is** the threshold enforcing itself; 2-of-3 is how you let two do it.

Note also that a submit response reported `signature_count: 3, is_ready: true`
for an operation that was actually **rejected**. Signatures submitted ≠ change
landed. The driver now waits for the key page itself.

---

## 8. Questions he will ask

**"Could CERTEN resolve an order without me?"**
No. Your seat is on the key page and the threshold requires it. CERTEN runs
validators that *execute* what the panel authorised; it holds no seat.

**"What if your gateway is down?"**
No new resolution is proposed. Nothing settles incorrectly — it waits.

**"What if the policy engine is wrong?"**
It can only withhold or deny. It cannot approve what your contract forbids:
conservation is your `require`, and the split is sealed in the proof.

**"Can my agent get paid out of arbitration?"**
Not without changing your contract. `forceResolve` enforces
`amtToSeller + amtToBuyer == price + bond`. Agent revenue comes from the service
layer.

**"Is this production ready?"**
On Sepolia, with a live panel and a real proof cycle — yes. Not on mainnet, and
tiered thresholds across multiple key pages aren't built. Say it plainly.

---

## Appendix — what lives where

| File | Purpose |
|---|---|
| `certen-carp-starter/examples/panel-admin.mjs` | the driver — every stage below |
| `…/escrow-policy-engine.mjs` | Bryan's rules (terminal C) |
| `…/escrobot-decoder.mjs` | teaches the signer to read `forceResolve` |
| `…/panel-policy-signer.yaml` | signer config (terminal D) |
| `…/panel-admin.state.json` | seats, ids, tx hashes — **contains private keys** |
| `…/policy-seat.seed` | the policy seat's key — **never ship this** |
| `docs/demo/carp-panel-brief.pptx` | 5 slides |
| `docs/demo/slides/*.jpg` | the same slides as images |
| `docs/demo/build-pptx.mjs` | rebuild both from `carp-panel-brief.md` |

**Driver stages:** `panel-status` · `proof` · `restore-panel-v1` ·
`seed-dispute` · `raise-dispute` · `force-resolve` · `force-resolve-forfeit` ·
`add-policy-seat` · `add-regulator` · `evidence`
