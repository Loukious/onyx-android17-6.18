# KernelSU Next dev with built-in SUSFS

`../kernelsu-lock.json` records the exact
[`pershoot/KernelSU-Next` `dev-susfs` commit](https://github.com/pershoot/KernelSU-Next/tree/dev-susfs),
its source archive hash and the included official KernelSU Next dev commit in
`upstream_revision`. The current fork is `39b15dead6fa`, with official base
`aa235b99574b`. Manager-facing metadata comes from that official base:
tag `v3.4.2`, 3,554 commits and version `33554`.

The tracker monitors official dev and the fork. It selects a new fork only after
proving that it contains the latest detected official dev tip. While the fork
lags, the existing built-in pin remains in use and GKI/source updates can
continue. Candidate updates pass replay and build validation before promotion.
Builds never substitute a newer branch tip for the locked inputs. Historical
official-only locks remain supported when verifying older source revisions.

`../integrate_kernelsu.py` materializes the verified archive under
`common/drivers/kernelsu`, enables built-in `CONFIG_KSU=y`, and resolves version
metadata before entering Kleaf. Manager authentication, policy profiles and
debug defaults retain upstream behavior. Artifact inputs archive the exact
source snapshot and receipt.

The recipe compiles SUSFS v2.4.0 into `common/fs` using WildKernels' Android 17 / 6.18
integration at `2e82dcc4aabd`. `../features/lock.json` pins its source, kernel
patch and local compatibility adaptations independently of the KernelSU fork.
Balanced and Performance both enable the built-in implementation. No SUSFS
LKM or loader addon ZIP is needed; an optional compatible sidex15 module can
configure hiding rules. Feature verification checks source hashes, configuration,
linked kernel entry points and the exact recorded source pins.

As of **2026-11-19**, source and host checks pass, but the new built-in kernel
has not yet been compiled or runtime-validated. Earlier matched-LKM device
results apply to those historical kernels. Runtime feature activation and
hiding behavior for this implementation require separate device verification.
See [feature profiles and installation](../features/README.md).

Use a compatible official Next Manager. Compilation and input verification do
not establish on-device root or hiding behavior.
