# Writes addendum_v1.golden.json: the certen:finality:v1 addendum chain and evidence encodings for fixed inputs, computed here
# independently of the Go implementation (pkg/finality) so the two are checked against each other. Run once; the golden is
# specification and is never regenerated over (a new encoding gets a new tag and a new file).
#   python addendum_v1_golden_generator.py > addendum_v1.golden.json
import hashlib, json, struct

DOMAIN = b"certen:finality:v1"

def lp(b):
    return struct.pack(">I", len(b)) + b

def sha(b):
    return hashlib.sha256(b).digest()

def evidence(kind, number, block_hash, tx_hash, body):
    return struct.pack(">I", 1) + lp(kind.encode()) + struct.pack(">Q", number) + block_hash + tx_hash + lp(body)

def own_hash(original, prev, seq, level, chain, kind, ev):
    fields = [DOMAIN, original, prev, struct.pack(">Q", seq), bytes([level]), struct.pack(">Q", chain), kind.encode(), sha(ev)]
    return sha(b"".join(lp(f) for f in fields))

original = sha(b"certen:finality:v1:golden:original-proof")
chain = 84532
number = 47368146
block_hash = bytes([0x11]) * 32
tx_hash = bytes([0x22]) * 32
names = {1: "included", 2: "l1_posted", 3: "finalized"}
kinds = {1: "included.eth-mpt/v1", 2: "golden.l1/v1", 3: "golden.final/v1"}
prev = bytes(32)
addenda, evs = [], []
for seq, level in enumerate([1, 2, 3], start=1):
    ev = evidence(kinds[level], number, block_hash, tx_hash, ("golden-body-%d" % level).encode())
    own = own_hash(original, prev, seq, level, chain, kinds[level], ev)
    addenda.append({
        "proofId": "golden-proof-1", "seq": seq, "level": names[level], "chain": chain, "kind": kinds[level],
        "evidence": ev.hex(), "prevHash": prev.hex(), "ownHash": own.hex(), "originalDigest": original.hex(),
    })
    prev = own
print(json.dumps({"domain": DOMAIN.decode(), "originalDigest": original.hex(), "addenda": addenda}, indent=2))
