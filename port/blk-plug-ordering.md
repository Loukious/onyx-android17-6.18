# Plug timestamp ordering across preemption

The scheduler's `blk_plug_invalidate_ts()` relies on `PF_BLOCK_TS` implying
that the task still has a plug. Clang r596125 with the public GKI AutoFDO
profile can inline `__blk_flush_plug()` and move the plug detachment ahead
of the flag clear. Preemption between those stores exposes a null plug
to the scheduler and can produce a write fault at address `0x20`.

The correction adds `barrier()` after `__blk_flush_plug(plug, false)` and
before `current->plug = NULL` in `blk_finish_plug()`. It orders the accesses
for the compiler and does not introduce a hardware memory fence. AutoFDO,
the compiler selection, and the optimization level remain unchanged.

The affected scheduler behavior comes from
[fad156c2af22](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fad156c2af227f42ca796cbb20ddc354a6dd9932).
The correction is carried in the checked-in common source and in
[the required patch recipe](common-patches/manifest.json), so both hosted
kernel builds and the ROM source-build path reproduce it. The build archives
the patched source and its hashes through the existing common-fix receipt.

## Detecting an upstream correction

The manifest selects `blk-plug-timestamp-ordering-v1` for `block/blk-core.c`.
The CI updater checks the actual source on the newly pinned Android LTS
revision before choosing the effective patch. It recognizes these reviewed
forms, ignoring comments and whitespace:

- The original flush and teardown need the local barrier.
- An unconditional `barrier()` between the flush call and pointer detachment
  establishes the required ordering upstream.
- An unconditional `barrier()` at the end of the flush helper, immediately
  after clearing `PF_BLOCK_TS`, also establishes the ordering upstream.

The helper must retain the reviewed unconditional flag clear. A conditional
barrier, a barrier before the flush or after detachment, a comment mentioning
one, or a different function containing one cannot retire this patch. The
check also rejects conditional or ambiguous definitions and relevant local
macro overrides. It is a conservative recognizer, not a general C proof:
other implementations, including different synchronization primitives or
larger control-flow changes, stop the update for human review.

Only the reviewed barrier-only delta may use this check. Additional changes
to the same file cannot be silently discarded as part of retirement.
The effective patch and source hashes are refreshed only after all common
fixes and diagnostics succeed. The manifest records the observed ordering
and whether it is local or upstream. The full replay patch remains intact;
if a subsequent upstream revision reverts the correction, the updater
automatically includes the local barrier again.

The new detector is in the repository's `ci` branch, in
`ci/blk_plug_ordering.py`; its integration is in `ci/refresh_recipe.py`.
No kernel-version threshold or speculative upstream commit ID is used.

## Validation

[The validation receipt](validation/blk-plug-ordering-20261109.json) records
the source hashes, recipe replay, compiler/profile identity, and emitted
store order. Focused arm64 translation-unit compilation with AutoFDO shows
the unsafe order before the patch and flag clearing before detachment after
it. This compilation uses the existing local header configuration and is
not a full GKI build or a reproduction of the complete official image.

The CI unit tests exercise application, exact and equivalent upstream fixes,
reactivation after a revert, misleading barriers, changed helpers, and
preservation of all inputs on an unresolved update. The real combined recipe
is also replayed and checked against its recorded source hashes, including
the build context's restoration of the original inputs.

Full kernel rebuild, on-device validation, and performance measurements are
still required for a new release. The saved panic identifies the fault
signature but does not retain the interrupted instruction pointer; the
historical interruption point remains inferred.
