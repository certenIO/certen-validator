# escrobot × CERTEN — Panel Demo Manual

**Audience:** Bryan (boardy.ai), and anyone judging whether escrobot's Admin
function is trustworthy enough for real commerce.

**What it proves:** the lone Admin key is gone, routine disputes settle without
the operator, and the one case that needs a person needs exactly one signature
from a key only they hold.

Everything below was run live on **2026-07-29**. Every hash in §7 is from those
runs.

---

## The structure everything else depends on

```
acc://certen-panel-bryan1.acme/book          ← escrobot's admin authority
  page/1   1-of-1 {bryan}            HIGHER priority — escalation
  page/2   2-of-2 {agent, policy}    lower  priority — routine
```

Two protocol facts make this work, both verified in the Accumulate source and
then observed on chain:

- **Authorization is at BOOK level** (`KeyPage.GetAuthority()` returns the book;
  `authorityIsAccepted`: *"Page belongs to book => authorized"*). Any page can
  act, each satisfying its own threshold. So page 2 settles alone.
- **`signerPageIdx > principalPageIdx → Unauthorized`** (*"Lower indices are
  higher priority"*). Page 1 rewrites page 2; page 2 can never touch page 1.

---

## Running it

```powershell
cd C:\Accumulate_Stuff\certen\certen-carp-starter\examples
.\Demo.ps1 preflight
```

`Demo.ps1` loads the funded Sepolia key from `api-bridge/.env`, adds Foundry to
`PATH` (**`cast` is on Git Bash's PATH but not PowerShell's** — without this every
on-chain check fails in a way that looks like a broken demo), and opens the two
support windows titled for a projector.

---

## 0. Pre-flight

```bash
node panel-admin.mjs panel-status            # page 1
node panel-admin.mjs proof                   # named seats + contract state
```

| Check | Want | If wrong |
|---|---|---|
| page/1 | `1-of-1 {bryan}` | Stop — the escalation seat is wrong |
| page/2 | `2-of-2 {agent, policy}` | Stop — routine settlement will not work |
| page/2 credits | **> 0** | Fund it; an unfunded page cannot sign |
| `escrobot admin` | `0x895b2871…F9f3` | Stop. The panel is not the admin. |
| Gateway commit | `4305c90` or later | Redeploy — §6 |
| Validators | `7` healthy | Stop and investigate |
| Funder | > 0.05 ETH | Top up |

**The failure that bit us:** a key page pays for its own transactions. A page
with no credits holds keys and silently fails every signature. The signer says so
at boot — *"signer page has NO CREDITS"* — and that line is worth reading.

---

## 1. Terminals

**A — the demo.** The `examples/` directory.

**B — the fleet.**
```bash
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'docker logs -f certen-validator-1 2>&1 | grep --line-buffered -E \
   "DISCOVERED|ELECTED|EVM-EXEC|executed successfully"'
```
> `DISCOVERED` and `executed successfully` appear on every node; `ELECTED` and
> `EVM-EXEC` only on whichever won the election. Don't promise those two.

**C — the policy engine** (the operator's rules):
```bash
APPROVAL_TOKEN=$(openssl rand -hex 32) node escrow-policy-engine.mjs
```

**D — the signer** holding the page-2 seat:
```bash
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

**STOP CONDITIONS.** Terminal D must show all three:
```
intent decoder chain (first claim wins) ["escrobot-force-resolve", …]
signer page reachable   acc://…/book/2        ← page 2, NOT page 1
SR6 self-check OK: pubkey matches page
```
A missing decoder means the engine gates on the leg value (`0`) instead of the
payout and **will approve a forfeiture** — see §7.3.

**Browser:** Etherscan on `0x9F452b98…824816`, and
`explorer.accumulatenetwork.io` **switched to Kermit Testnet first** (the
selector, top right — direct URLs default to Mainnet and 404).

---

## 2. Act 1 — Routine: settled without the operator  *(~5 min)*

```bash
node panel-admin.mjs seed-dispute        # list → buy → ship
node panel-admin.mjs raise-dispute       # both parties on record, on chain
node panel-admin.mjs resolve-routine     # agent proposes on page 2
```

Terminal C prints `APPROVE`; terminal D prints `vote=approve`. **Bryan's seat is
never asked.**

> "Your agent proposed it, your rules checked it, and the two automated seats
> satisfied page 2. That page settles on its own — you were not involved and were
> not notified. This is the case that happens almost every time."

Prove it:
```bash
node panel-admin.mjs proof
```
The signature list shows `agent` and `policy` **both on book/2**.

**Three gates had to pass first**, all in his contract:

| Gate | Enforced by |
|---|---|
| Order must be SHIPPED | `require(status == State.SHIPPED)` |
| Payout must equal price + bond | `require(amtToSeller + amtToBuyer == …)` |
| Caller must be Admin — now the panel | `isAdmin` |

---

## 3. Act 2 — Escalation: the only time he appears  *(~6 min)*

```bash
node panel-admin.mjs seed-dispute
node panel-admin.mjs resolve-forfeit-routine   # agent proposes a forfeiture
```

The engine returns `pending` — **not** a denial. Terminal D withholds and casts
no vote. Page 2 holds one of the two signatures it needs and stops.

> "Conservation balances, so escrobot would execute this happily. The ceiling
> rule stops it: awarding one party the other's bond is a human decision. Page 2
> now has half of what it needs and can never finish."

**This distinction is load-bearing.** A `deny` casts a REJECT that *kills* the
transaction — a correct refusal that destroys the thing needing review. Only a
withhold leaves something to escalate. That is why `POLICY_CEILING_ACTION`
defaults to `escalate`.

Now the operator:

```bash
certen-approve list          # what is waiting, and why it stopped
certen-approve sign <tx>     # shows the split, THEN asks for the passphrase
```

> "One signature, from a key that lives encrypted on his laptop and is decrypted
> for the second it takes to sign. No daemon holds it. Nothing can sign for him
> while he's away — which is the whole point of an escalation seat."

`proof` afterwards shows the answer plainly:
```
signed: bryan on …/book/1      ← 1-of-1, satisfies the book alone
signed: agent on …/book/2      ← 1 of the 2 page 2 needed
```

---

## 4. Act 3 — Recovery: rewriting the routine page  *(~3 min)*

```bash
node panel-admin.mjs add-regulator    # or rotate a seat on page 2
```

> "If an automated seat is compromised or simply wrong, he replaces it from
> above. Page 1 can rewrite page 2 — and page 2 can never touch page 1. That
> asymmetry is enforced by Accumulate, not by us."

Say the trade-off out loud: page 2 acting alone means **two compromised
automated seats could settle a routine dispute**. The guards are his own policy
rules and his power to rewrite page 2 — not a signature requirement. That is the
deliberate cost of keeping him out of the routine path, and the dial is his:
raise page 2's threshold, or narrow what its rules allow.

---

## 5. Reset

The panel is already in its demo shape; nothing needs undoing between runs —
each act seeds its own order. To inspect:

```bash
node panel-admin.mjs panel-status
node certen-approve.mjs list
```

`restore-panel-v1` belongs to the **old flat-page** demo and will not produce the
two-page structure. Use `restructure-two-page` if the panel ever needs rebuilding
from a flat page.

Stop terminals C and D with `.\Demo.ps1 stop`.

---

## 6. If something breaks

| Symptom | Cause | Do this |
|---|---|---|
| `Identity not found` (404) | Wrong API key | Use the key from `certen-carp-KEYS.txt` |
| Signer: `NO CREDITS` | Page 2 unfunded | Fund it; it cannot sign until then |
| Signer watching `book/1` | Stale config | `signer_url` must be `…/book/2` |
| Routine never settles | Page 2 threshold unmet | `proof` — count page-2 signatures |
| Driver prints `status=anchoring` | **Gateway status lag, not failure** | Check the CONTRACT |
| Transaction `rejected 406` | Engine denied instead of escalating | `POLICY_CEILING_ACTION=escalate` |
| Cloudflare 502 | Transient | Retry; the driver already retries |

```bash
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
  'cd /root/api-gateway && git fetch && git reset --hard origin/main && \
   docker compose up -d --build --force-recreate certen-gateway'
```

**Never present the driver's poll line.** It printed `status=anchoring` through
every run while the contract had already settled — a gateway status-tracking gap.
Verify effect on the contract.

---

## 7. Evidence — 2026-07-29

### 7.1 Routine settles alone
Order `0x7ba2eab4…` → **status 5**. WriteData `fe0d10b5…` delivered, signed by
`agent` and `policy` **both on `book/2`**. Bryan never asked.

### 7.2 Escalation completes what routine could not
Order `0x801d451e…` → **status 5**. WriteData `eb11f646…` delivered:
```
signed: bryan on acc://certen-panel-bryan1.acme/book/1
signed: agent on acc://certen-panel-bryan1.acme/book/2
```
Page 2 held **one of two** and could never reach threshold; page 1 being 1-of-1
satisfied the book alone.

Repeated through the CLI with an encrypted keystore: order `0xf62eefea…` →
**status 5**, keystore keyHash `bc6977974b596130…` matching page 1 on chain.

### 7.3 The decoder is not optional
An early policy engine **approved a full forfeiture**, which settled on Sepolia
(order `0x945d7dad…`). The rules were right; they were reading the wrong number.
A contract call carries its amounts in ABI-encoded `callData`, while the built-in
decoders describe the intent's *leg* — value `0`, because the panel calls a
function rather than sending ether. Fix: `examples/escrobot-decoder.mjs`, loaded
via `resolver.decoder_modules`. **Treat a missing decoder as a stop condition.**

### 7.4 Deny kills; withhold escalates
The first forfeiture attempt went to `rejected (406)` — the policy seat cast an
explicit REJECT. Correct as a refusal, but it destroyed the transaction the
operator was meant to review. Escalation requires `pending`.

### 7.5 A new page is not funded
`create_key_page` created page 2 with zero credits; the signer refused to work
and said why. Now fixed in the gateway (`4305c90`) — creation buys credits by
default.

---

## 8. Questions he will ask

**"Could CERTEN settle a dispute without me?"**
A routine one, yes — that is the design, and the seats doing it are yours: your
agent and your policy engine, on your infrastructure. CERTEN holds no seat on
either page.

**"What if an automated seat is compromised?"**
It can act within your policy rules on routine disputes. You rewrite page 2 from
page 1; it can never touch page 1. Narrow the rules or raise page 2's threshold
if that trade is wrong for you.

**"What if the policy engine is wrong?"**
It can only withhold or deny. It cannot approve what your contract forbids:
conservation is your `require`, and the split is sealed in the proof.

**"Can my agent get paid out of arbitration?"**
Not without changing your contract. `forceResolve` enforces
`amtToSeller + amtToBuyer == price + bond`.

**"Is this production ready?"**
On Sepolia, with a live two-page panel and a real proof cycle — yes. Not on
mainnet. Say it plainly.

---

## Appendix — what lives where

| File | Purpose |
|---|---|
| `examples/Demo.ps1` | **PowerShell wrapper — start here** |
| `…/panel-admin.mjs` | the driver — all stages |
| `…/certen-approve.mjs` | **the escalation seat's signing tool** |
| `…/keystore.mjs` | encrypted keystore (scrypt + AES-256-GCM) |
| `…/escrow-policy-engine.mjs` | the operator's rules |
| `…/escrobot-decoder.mjs` | teaches the signer to read `forceResolve` |
| `…/panel-policy-signer.yaml` | signer config — **points at book/2** |
| `…/*.state.json`, `*.seed`, `*.keystore.json` | **key material — gitignored** |
| `docs/demo/carp-panel-brief.pptx` | 5 slides |

**Two-page stages:** `restructure-two-page` · `resolve-routine` ·
`resolve-forfeit-routine` · `escalate` · `proof` · `panel-status`
