#!/usr/bin/env python3
"""Writes the stream cases of finality_base_posted2 by assembling every span batch byte by hand (no Go code, no code under test).

Usage: python gen2.py <set directory>   (writes streams/*.json, manifest.json, MANIFEST.sha256; README.md is hand-written)
Every number is Go's binary.PutUvarint; every stream is the RLP string `0x01 || span payload` the channel decompresses to."""
import hashlib, json, os, sys

TWO64 = 1 << 64
G, B, CHAIN = 1695768288, 2, 84532  # Base Sepolia L2 genesis time, L2 block time, L2 chain id (pins/main.json of set 1)


def uv(v):
    out = bytearray()
    while v >= 128:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def rlp_string(b):
    n = len(b)
    if n == 1 and b[0] < 0x80:
        return b
    if n < 56:
        return bytes([0x80 + n]) + b
    lb = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0xB7 + len(lb)]) + lb + b


def rlp_int(v):
    return rlp_string(v.to_bytes((v.bit_length() + 7) // 8, 'big')) if v else b'\x80'


def rlp_list(items):
    body = b''.join(items)
    n = len(body)
    if n < 56:
        return bytes([0xC0 + n]) + body
    lb = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0xF7 + len(lb)]) + lb + body


PC, OC = b'\x11' * 20, b'\x22' * 20
SIG = (1).to_bytes(32, 'big') + (1).to_bytes(32, 'big')  # r = s = 1
TO = b'\x09' * 20
# the span-batch form of one type-2 transaction: Value, GasTipCap, GasFeeCap, Data, AccessList (the type byte first)
TXDATA = bytes([0x02]) + rlp_list([rlp_int(1), rlp_int(1), rlp_int(2), b'\x80', b'\xc0'])
ONE_TX = b'\x00' + b'\x00' + SIG + TO + TXDATA + uv(1) + uv(21000)  # creation bits, y parity bits, sigs, tos, datas, nonces, gases
# the consensus encoding the verifier must rebuild from it: 0x02 || rlp([chainId, nonce, tip, fee, gas, to, value, data, accessList, v, r, s])
REBUILT = b'\x02' + rlp_list([rlp_int(CHAIN), rlp_int(1), rlp_int(1), rlp_int(2), rlp_int(21000), rlp_string(TO), rlp_int(1), b'\x80', b'\xc0', b'\x80', rlp_int(1), rlp_int(1)])


def payload(counts, rest=b''):
    n = len(counts)
    return uv(0) + uv(9) + PC + OC + uv(n) + bytes((n + 7) // 8) + b''.join(uv(c) for c in counts) + rest


def stream(p):
    return rlp_string(b'\x01' + p)


def batch(index, blocks, txs):
    return {
        'type': '1', 'epoch_num': '9', 'timestamp': str(G + B * index), 'span_index': str(index), 'span_blocks': str(blocks),
        'parent_len': '20' if index == 0 else '0', 'epoch_len': '20' if index == blocks - 1 else '0',
        'txs': ['0x' + t.hex() for t in txs],
    }


MAL = {'result': 'state', 'code': 'channel_malformed', 'fields': {}}
SERR = {'result': 'stream_error'}
CASES = [
    ('span_counts_wrap_to_zero', 'block tx counts [1, 2^64-1]: the uint64 sum wraps to 0 and slips under the 2^20 bound; the first block then reads a transaction that was never declared. The verifier refuses the stream and does not panic.',
     payload([1, TWO64 - 1]), SERR, MAL),
    ('span_counts_wrap_to_zero_five', 'block tx counts [5, 2^64-5]: the same wrap to 0 with a larger first count.',
     payload([5, TWO64 - 5]), SERR, MAL),
    ('span_counts_wrap_to_one_with_a_valid_tx', 'block tx counts [2, 2^64-1]: the wrapped sum is 1 and the payload carries one well-formed transaction, so the first block reads a second one that was never declared.',
     payload([2, TWO64 - 1], ONE_TX), SERR, MAL),
    ('span_first_count_is_2_64_minus_1', 'block tx counts [2^64-1, 2]: the first count alone is over the 2^20 bound.',
     payload([TWO64 - 1, 2]), SERR, MAL),
    ('span_counts_total_is_bound_plus_one', 'block tx counts [2^20, 1]: the exact total 2^20+1 is over the bound.',
     payload([1 << 20, 1]), SERR, MAL),
    ('span_counts_total_is_the_bound_but_short', 'block tx counts [2^20]: the total is exactly the bound, so within it, but the payload carries none of the 2^20 transactions it declares.',
     payload([1 << 20]), SERR, MAL),
    ('span_two_empty_blocks_are_decoded', 'block tx counts [0, 0]: a well-formed span batch of two blocks without transactions is decoded (positive control). Judged against an L2 block at timestamp 1790000000 the verifier names batch_not_found with n_batches 2.',
     payload([0, 0]), {'result': 'ok', 'batches': [batch(0, 2, []), batch(1, 2, [])]},
     {'result': 'state', 'code': 'batch_not_found', 'fields': {'n_batches': '2', 'timestamp': '1790000000'}}),
    ('span_one_block_with_one_transaction_is_decoded', 'block tx counts [1] with one well-formed type-2 transaction (positive control): the rebuilt consensus encoding is the hand-assembled one.',
     payload([1], ONE_TX), {'result': 'ok', 'batches': [batch(0, 1, [REBUILT])]},
     {'result': 'state', 'code': 'batch_not_found', 'fields': {'n_batches': '1', 'timestamp': '1790000000'}}),
]


def main():
    d = sys.argv[1]
    os.makedirs(os.path.join(d, 'streams'), exist_ok=True)
    ids = []
    for cid, desc, p, dec, ver in CASES:
        doc = {
            'format': 'certen-base-posted-stream/1', 'id': cid, 'description': desc,
            'params': {'l2_genesis_time': str(G), 'l2_block_time': str(B), 'chain_id': str(CHAIN)},
            'stream': '0x' + stream(p).hex(), 'decode': dec, 'verifier': ver,
        }
        with open(os.path.join(d, 'streams', cid + '.json'), 'w', newline='\n') as f:
            f.write(json.dumps(doc, indent=2, sort_keys=True) + '\n')
        ids.append(cid)
    files = {}
    for root, _, names in os.walk(d):
        for n in names:
            rel = os.path.relpath(os.path.join(root, n), d).replace(os.sep, '/')
            if rel in ('manifest.json', 'MANIFEST.sha256'):
                continue
            files[rel] = hashlib.sha256(open(os.path.join(root, n), 'rb').read()).hexdigest()
    man = {'format': 'certen-base-posted-stream-set/1', 'set': 'finality_base_posted2', 'cases': sorted(ids), 'files': dict(sorted(files.items()))}
    raw = (json.dumps(man, indent=2, sort_keys=True) + '\n').encode()
    open(os.path.join(d, 'manifest.json'), 'wb').write(raw)
    open(os.path.join(d, 'MANIFEST.sha256'), 'w', newline='\n').write(hashlib.sha256(raw).hexdigest() + '\n')


if __name__ == '__main__':
    main()
