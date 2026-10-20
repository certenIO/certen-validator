#!/usr/bin/env python3
"""Writes the cases of finality_base_posted3 by assembling every byte by hand (no Go code, no code under test).

Usage: python gen3.py <set directory>   (writes cases/*.json, manifest.json, MANIFEST.sha256; README.md is hand-written)
Standard library only. The only two literals that are not assembled here are BATCHER and CHANNEL_ID, the identities of the
synthetic world of the Go suite (README, "The world"); the expected verdicts are written by hand from them, never by running a verifier."""
import hashlib, json, os, sys

CHAIN = 84532
BATCHER = '0x56ef7824ba2b83ee659c5fb8a2512e23dc0fca54'
CHANNEL_ID = '0xb1d9bb384c97b60657b57c9ef2b09a91'


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


PARENT, EPOCH_HASH = b'\x11' * 32, b'\x22' * 32
EPOCH, TS = 990, 1790000000


def l1_info_deposit(number, epoch_hash):
    # selector | baseFeeScalar 4 | blobBaseFeeScalar 4 | sequenceNumber 8 | timestamp 8 | number 8 | baseFee 32 | blobBaseFee 32 | hash 32 | batcherHash 32
    data = bytes.fromhex('098999be') + bytes(24) + number.to_bytes(8, 'big') + bytes(32) + bytes(32) + epoch_hash + bytes(32)
    assert len(data) == 164 and data[28:36] == number.to_bytes(8, 'big') and data[100:132] == epoch_hash
    return b'\x7e' + rlp_list([rlp_string(b'\x33' * 32), rlp_string(b'\xde\xad' + bytes(18)), rlp_string(b'\x42' + bytes(19)),
                               rlp_int(0), rlp_int(0), rlp_int(1000000), b'\x80', rlp_string(data)])


def user_deposit(tag):
    return b'\x7e' + rlp_list([rlp_string(bytes([tag]) * 32), rlp_string(b'\x44' * 20), rlp_string(b'\x55' * 20),
                               rlp_int(0), rlp_int(1), rlp_int(21000), b'\x80', b'\x80'])


def user_tx(nonce):
    return b'\x02' + rlp_list([rlp_int(CHAIN), rlp_int(nonce), rlp_int(1), rlp_int(2), rlp_int(21000), rlp_string(b'\x09' * 20),
                               rlp_int(1), b'\x80', b'\xc0', b'\x80', rlp_int(1), rlp_int(1)])


def singular_stream(txs, ts=TS):
    """The decompressed channel: one RLP string `0x00 || rlp([parent, epoch_num, epoch_hash, timestamp, [tx...]])`."""
    batch = b'\x00' + rlp_list([rlp_string(PARENT), rlp_int(EPOCH), rlp_string(EPOCH_HASH), rlp_int(ts), rlp_list([rlp_string(t) for t in txs])])
    return rlp_string(batch)


def hx(b):
    return '0x' + b.hex()


D0, DX = l1_info_deposit(EPOCH, EPOCH_HASH), user_deposit(0x66)
U1, U2 = user_tx(1), user_tx(2)

G = 1790000000 + 1100   # the Granite time of the straddle cases: L1 block 1100 (time 1790001100) is the first Granite block
PAST, FAR = 1723478400, 1790000000 + 1000000  # Granite long past (the real one) / Granite after every synthetic L1 block
TO = {'result': 'state', 'code': 'channel_timed_out', 'fields': {}}


def ok(blocks):
    return {'result': 'ok', 'fields': {'batch_type': '0', 'batcher': BATCHER, 'channel_id': CHANNEL_ID, 'epoch_hash_bits': '256',
                                       'finalized_epoch': '0', 'finalized_slot': '0', 'l1_blocks': [str(b) for b in sorted(set(blocks))],
                                       'parent_hash_bits': '256', 'span_blocks': '1', 'span_index': '0'}}


def bind(field):
    return {'result': 'state', 'code': 'batch_binding_mismatch', 'fields': {'field': field}}


def case(id_, desc, expect, batch_txs, deposits, l2_txs, blocks=(1000,), granite=PAST, ct=300, ctg=50):
    return {'format': 'certen-base-posted-binding/1', 'id': id_, 'description': desc,
            'pins': {'channel_timeout': str(ct), 'channel_timeout_granite': str(ctg), 'granite_time': str(granite)},
            'l1_time_base': '1790000000', 'frame_l1_blocks': [str(b) for b in blocks],
            'stream': hx(singular_stream(batch_txs)),
            'l2': {'timestamp': str(TS), 'parent_hash': hx(PARENT), 'txs': [hx(t) for t in l2_txs]},
            'deposits': [hx(d) for d in deposits], 'expect': expect}


def cases():
    out = []
    blk = [D0, U1, U2]
    out.append(case('deposits_positive_one_deposit_two_user_txs', 'positive control: the L2 block is [L1-info deposit, u1, u2]; depositTxs [L1-info deposit], the batch carries [u1, u2].',
                    ok([1000]), [U1, U2], [D0], blk))
    out.append(case('deposits_positive_two_deposits_then_user_txs', 'positive control: the block is [L1-info deposit, user deposit, u1, u2]; both leading transactions are type 0x7e and in depositTxs, the batch carries [u1, u2].',
                    ok([1000]), [U1, U2], [D0, DX], [D0, DX, U1, U2]))
    out.append(case('deposit_list_padded_with_a_user_tx', "the block is [L1-info deposit, u1, u2] but the batch carries only [u2]: u1, which the batcher never posted, is moved into depositTxs; the recomputed root still equals the header's. depositTxs[1] is not a type 0x7e transaction.",
                    bind('deposit_txs'), [U2], [D0, U1], blk))
    out.append(case('deposit_list_holds_every_block_tx_batch_empty', 'the batch carries no transaction at all and every user transaction of the block is moved into depositTxs.',
                    bind('deposit_txs'), [], [D0, U1, U2], blk))
    out.append(case('deposit_list_ends_with_a_user_tx', 'the block is [L1-info deposit, user deposit, u1]; the batch carries [] and depositTxs is all three: the last entry is not type 0x7e.',
                    bind('deposit_txs'), [], [D0, DX, U1], [D0, DX, U1]))
    out.append(case('deposit_list_holds_an_empty_entry', 'depositTxs[1] is the empty byte string.',
                    bind('deposit_txs'), [U1, U2], [D0, b''], blk))
    out.append(case('batch_carries_a_deposit_typed_tx', 'the batch itself carries a type 0x7e transaction (OP derivation drops such a batch); the block is [L1-info deposit, user deposit] with the user deposit supplied by the batch and depositTxs [L1-info deposit].',
                    bind('batch_txs'), [DX], [D0], [D0, DX]))
    out.append(case('batch_carries_an_empty_tx', 'the batch carries the empty byte string as a transaction (OP derivation drops such a batch).',
                    bind('batch_txs'), [U1, b''], [D0], [D0, U1, b'']))
    out.append(case('batch_deposit_typed_tx_in_the_middle', 'a 0x7e transaction in the middle of the batch: [u1, deposit, u2]; depositTxs is clean.',
                    bind('batch_txs'), [U1, DX, U2], [D0], [D0, U1, DX, U2]))
    for gap, exp in ((50, 'ok'), (51, 'to'), (250, 'to'), (300, 'to'), (301, 'to')):
        out.append(case('granite_frames_%d_blocks_apart' % gap,
                        'frames at L1 blocks 1000 and %d, Granite long past (granite_time 1723478400): the channel timeout is channel_timeout_granite = 50, so %s.'
                        % (1000 + gap, 'a gap of 50 is within it' if exp == 'ok' else 'a gap of %d is timed out' % gap),
                        ok([1000, 1000 + gap]) if exp == 'ok' else TO, [U1, U2], [D0], blk, blocks=(1000, 1000 + gap)))
    for gap, exp in ((250, 'ok'), (300, 'ok'), (301, 'to')):
        out.append(case('bedrock_frames_%d_blocks_apart' % gap,
                        'frames at L1 blocks 1000 and %d, Granite after every L1 block of the world: the channel timeout is channel_timeout = 300.' % (1000 + gap),
                        ok([1000, 1000 + gap]) if exp == 'ok' else TO, [U1, U2], [D0], blk, blocks=(1000, 1000 + gap), granite=FAR))
    out.append(case('straddle_both_frames_before_granite',
                    'granite_time = 1790001100 (L1 block 1100 is the first Granite block); frames at L1 blocks 1000 and 1099, both before it: gap 99 <= 300.',
                    ok([1000, 1099]), [U1, U2], [D0], blk, blocks=(1000, 1099), granite=G))
    out.append(case('straddle_second_frame_in_the_first_granite_block',
                    'granite_time = 1790001100; frames at L1 blocks 1000 and 1100 (block time == granite_time, Granite applies at >=): gap 100 > 50.',
                    TO, [U1, U2], [D0], blk, blocks=(1000, 1100), granite=G))
    out.append(case('straddle_first_frame_before_granite_second_after',
                    'granite_time = 1790001100; frames at L1 blocks 1000 (before Granite) and 1150: gap 150 > 50. An implementation that selected the timeout by the FIRST frame block (300) would accept; op-node selects it by the block that holds the frame being ingested.',
                    TO, [U1, U2], [D0], blk, blocks=(1000, 1150), granite=G))
    out.append(case('straddle_both_frames_after_granite_within_50',
                    'granite_time = 1790001100; frames at L1 blocks 1100 and 1150, both Granite blocks: gap 50 <= 50.',
                    ok([1100, 1150]), [U1, U2], [D0], blk, blocks=(1100, 1150), granite=G))
    return out


def main(d):
    os.makedirs(os.path.join(d, 'cases'), exist_ok=True)
    ids, files = [], {}
    for c in cases():
        ids.append(c['id'])
        b = (json.dumps(c, indent=2, sort_keys=True) + '\n').encode()
        open(os.path.join(d, 'cases', c['id'] + '.json'), 'wb').write(b)
        files['cases/%s.json' % c['id']] = hashlib.sha256(b).hexdigest()
    for extra in ('README.md', 'generator/gen3.py'):
        files[extra] = hashlib.sha256(open(os.path.join(d, extra), 'rb').read()).hexdigest()
    m = {'format': 'certen-base-posted-binding-set/1', 'set': 'finality_base_posted3', 'cases': sorted(ids), 'files': dict(sorted(files.items()))}
    mb = (json.dumps(m, indent=2, sort_keys=True) + '\n').encode()
    open(os.path.join(d, 'manifest.json'), 'wb').write(mb)
    open(os.path.join(d, 'MANIFEST.sha256'), 'w').write(hashlib.sha256(mb).hexdigest() + '\n')


if __name__ == '__main__':
    main(sys.argv[1])
