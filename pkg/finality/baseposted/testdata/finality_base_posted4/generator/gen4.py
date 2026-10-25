#!/usr/bin/env python3
"""Writes the cases of finality_base_posted4 (the streamed-channel shape of base-sepolia/l1_posted/v1) by assembling every byte by hand.

Usage: python -I gen4.py <set directory>   (writes cases/*.json, manifest.json, MANIFEST.sha256; README.md is hand-written)
Standard library only. The stream, deposits and L2 block of every case are the ones of finality_base_posted3 (its generator gen3.py is
loaded from the sibling set, which is never edited): epoch number 990, sequencing window 3600, so the completing frame may lie in
L1 blocks <= 4590. The expected verdicts are written by hand from the OP derivation rule, never by running a verifier."""
import hashlib, importlib.util, json, os, sys

sys.dont_write_bytecode = True  # importing gen3 must not write a __pycache__ into the sibling (published) set

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location('gen3', os.path.join(HERE, '..', '..', 'finality_base_posted3', 'generator', 'gen3.py'))
g = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(g)

OUT = {'result': 'state', 'code': 'batch_outside_sequencing_window', 'fields': {}}
BLK = [g.D0, g.U1, g.U2]


def c(id_, desc, expect, blocks, granite=g.PAST):
    return g.case(id_, desc, expect, [g.U1, g.U2], [g.D0], BLK, blocks=blocks, granite=granite)


def cases():
    return [
        c('streamed_first_frame_below_epoch',
          'frames at L1 blocks 980 and 995, the batch epoch is 990: op-batcher streams the ready frames of an open channel (outputReadyFrames), so the first frame precedes the epoch of a later block. The window is judged on the completing frame (995 - 990 <= 3600): kept.',
          g.ok([980, 995]), (980, 995)),
        c('streamed_first_frame_290_below_epoch_bedrock',
          'frames at L1 blocks 700 and 990, Granite after every L1 block of the world (channel_timeout 300): the first frame is 290 blocks below the epoch, the completing frame is the epoch block itself: kept.',
          g.ok([700, 990]), (700, 990), g.FAR),
        c('streamed_all_frames_below_epoch',
          'frames at L1 blocks 985 and 989, both below the epoch 990: OP derivation has no rule that drops a batch whose inclusion block is lower than its epoch number (only epoch_num + sequence_window_size < inclusion_block_number), so the window rule keeps it.',
          g.ok([985, 989]), (985, 989)),
        c('streamed_completing_frame_at_the_window_edge',
          'frames at L1 blocks 4550 and 4590: the completing frame is at epoch + sequence_window_size (990 + 3600), the last kept inclusion block.',
          g.ok([4550, 4590]), (4550, 4590)),
        c('streamed_completing_frame_one_past_the_window',
          'frames at L1 blocks 4550 and 4591: the completing frame is at epoch + sequence_window_size + 1, the batch is dropped as untimely.',
          OUT, (4550, 4591)),
        c('streamed_bedrock_early_frame_window_edge',
          'frames at L1 blocks 4300 and 4590, channel_timeout 300 (gap 290): an early frame well inside the window does not change the verdict, the completing frame at the edge is kept.',
          g.ok([4300, 4590]), (4300, 4590), g.FAR),
        c('streamed_bedrock_early_frame_completing_frame_one_past',
          'frames at L1 blocks 4300 and 4591, channel_timeout 300 (gap 291): the completing frame is one past the window, so the batch is dropped whatever the earlier frames did.',
          OUT, (4300, 4591), g.FAR),
        c('single_frame_one_past_the_window',
          'one frame at L1 block 4591: the sole, completing frame is one past the window.',
          OUT, (4591,)),
    ]


def main(d):
    os.makedirs(os.path.join(d, 'cases'), exist_ok=True)
    ids, files = [], {}
    for cs in cases():
        ids.append(cs['id'])
        b = (json.dumps(cs, indent=2, sort_keys=True) + '\n').encode()
        open(os.path.join(d, 'cases', cs['id'] + '.json'), 'wb').write(b)
        files['cases/%s.json' % cs['id']] = hashlib.sha256(b).hexdigest()
    for extra in ('README.md', 'generator/gen4.py'):
        files[extra] = hashlib.sha256(open(os.path.join(d, extra), 'rb').read()).hexdigest()
    m = {'format': 'certen-base-posted-binding-set/1', 'set': 'finality_base_posted4', 'cases': sorted(ids), 'files': dict(sorted(files.items()))}
    mb = (json.dumps(m, indent=2, sort_keys=True) + '\n').encode()
    open(os.path.join(d, 'manifest.json'), 'wb').write(mb)
    open(os.path.join(d, 'MANIFEST.sha256'), 'w').write(hashlib.sha256(mb).hexdigest() + '\n')


if __name__ == '__main__':
    main(sys.argv[1])
