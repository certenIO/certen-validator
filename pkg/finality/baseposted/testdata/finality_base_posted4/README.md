# finality_base_posted4 - streamed-channel vectors for base-sepolia/l1_posted/v1 (R12-SPEC-Q1)

Companion of `finality_base_posted3` (same case format `certen-base-posted-binding/1`, same synthetic world, same stream: epoch number 990, `sequence_window_size` 3600); sets 1 to 3 are never edited. The Go verifier is `pkg/finality/baseposted`; a TypeScript verifier consumes a byte-identical copy and must judge every case the same way.

`manifest.json` lists the SHA-256 of every other file (this README included); `MANIFEST.sha256` is the SHA-256 of `manifest.json`.

## What the cases pin

The sequencing-window rule of OP derivation: a batch is dropped when `batch.epoch_num + sequence_window_size < inclusion_block_number`, where the inclusion block is the L1 block whose frame COMPLETES the channel (`specs/protocol/derivation.md`). There is no lower bound. Before this set the verifier also refused any frame whose L1 block was below the batch's epoch (`l < epoch_num`), a rule the derivation spec does not have: op-batcher streams the ready frames of an open channel while L2 blocks are still being added (`op-batcher/batcher/channel_builder.go` `outputReadyFrames`, "already generate frames and send them off as txs while still collecting blocks in the channel builder"; `channel_manager.go` `getReadyChannel` runs `outputFrames` on the not-yet-full current channel), so the first frame of a channel can precede the L1 origin of a later block in it. The channel-timeout rule (50 from Granite, 300 before, selected per frame) is unchanged and still bounds how far apart the frames are.

The decision, the sources and the code change are in `research/R12-SPEC-Q1.md` (RESOLVED).

- The cases that carry a frame below the epoch (`streamed_first_frame_below_epoch`, `streamed_first_frame_290_below_epoch_bedrock`, `streamed_all_frames_below_epoch`) were refused `batch_outside_sequencing_window` by the previous verifier and are kept now.
- The cases at `epoch + sequence_window_size` (4590) are kept and at 4591 are refused, judged on the completing frame whatever the earlier frames did.

Case file, world and `expect` as in `finality_base_posted3/README.md`. Regenerate: `python -I generator/gen4.py <set directory>` (rewrites `cases/`, `manifest.json`, `MANIFEST.sha256`; it loads `generator/gen3.py` of the sibling set; this README is hand-written and is listed in the manifest, so regenerate after editing it).
