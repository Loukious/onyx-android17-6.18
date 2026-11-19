# Onyx kernel feature profiles

Both profiles include the same peripheral support, KernelSU Next from the
synchronized `pershoot/dev-susfs` fork, built-in SUSFS v2.4.0, NoMount's kernel
backend, OverlayFS for
Mountify, Baseband Guard, WireGuard, BBRv1/BBRv3 and the other TCP algorithms,
IPSet, IPv6 NAT, TTL/hop-limit targets, connection marking, CAKE, CIFS xattrs,
TMPFS xattrs/ACLs, BPF/BTF/tracing/FUSE-BPF, NTSync, USB DVD emulation, Unicode
basename protection during file creation and Droidspaces' required namespaces/IPC support.

`manifest.json` is the canonical feature/configuration/profile inventory.
`lock.json` binds NoMount's source archive and WildKernels' Android 17 / 6.18
SUSFS v2.4.0 source, patch and local compatibility files. `../kernelsu-lock.json`
separately pins the `dev-susfs` integration and its included official Next dev base.
The ordered, hash-bound patches reproduce the committed Common source snapshot.
Conflicting upstream updates stop the tracker and preserve the accepted source.

| Profile | Configuration | TCP default | Kernel suffix |
| --- | --- | --- | --- |
| Balanced | Existing tuning defaults | CUBIC | `-4k-onyx-balanced` |
| Performance | Applicable, reviewed performance tuning | BBRv3 | `-4k-onyx-performance` |

Each release includes both complete, matched kernel/module sets and installers.
Its `release.json` contains a `variants` array with each profile's features,
tuning description, kernel release, revisions, download names and checksums.
Publication requires both variants to pass the build and artifact checks.
These checks establish build compatibility; device behavior is recorded separately.

## Mounting modules

Install either the official [NoMount metamodule](https://github.com/maxsteeel/nomount/releases)
or [Mountify](https://github.com/backslashxx/mountify/releases) using KernelSU Next.
Both kernel backends are available. NoMount starts with empty rules and stays
dormant until configured. KernelSU Next allows one metamodule at a time; remove
the selected metamodule and reboot before installing the other. For Mountify's
KernelSU unmount integration, use its documented `MOUNT_DEVICE_NAME="KSU"` option.
A future NoMount module requiring a newer API needs a matching kernel update.

## Built-in SUSFS

The pinned WildKernels integration adds SUSFS to `common/fs` and the kernel's
filesystem hooks. Both profiles select `CONFIG_KSU=y`, `CONFIG_KSU_SUSFS=y`
and the enabled SUSFS features in `manifest.json`. They use the same v2.4.0
source and compile it into each kernel image.

No `susfs_guard_lkm.ko`, special loader or matched SUSFS addon ZIP is required.
A source-built ROM includes this implementation in its kernel. The optional
[SUSFS configuration module](https://github.com/sidex15/susfs4ksu-module/releases)
can configure hiding rules; its userspace configuration role is separate from
the former LKM loader addon.

Artifact verification checks the exact vendor-source inventory and hashes,
required configuration, linked kernel entry points and recorded KernelSU/SUSFS
pins. It rejects stale standalone addon files. These checks record
`runtime_verified: false`; active hooks and hiding behavior need device tests.
As of **2026-11-19**, the new built-in kernel has not yet been compiled or tested
on the development phone.

### Earlier LKM releases — before the 2026-11-19 transition

Earlier releases used official Next's standalone SUSFS LKM and a matching
KernelSU special-loader addon bound to the exact kernel build. Their published
runtime results and addon downloads describe that implementation. They do not
establish runtime behavior for the new built-in v2.4.0 kernel.

## Building

Run `port/build.py WORKSPACE --variant balanced` or `--variant performance`.
Each build uses its own variant identifier and matched module vermagic.
`--output-root`, `--artifact-root` and `--cache-dir` can place large generated
files on a separate build drive.
`--bazel-batch` starts a fresh build process while retaining compiled objects,
which avoids rescanning the previous profile's large configuration trees.
Source-ROM builds default to Balanced; use
`port/rom/build.py --variant performance` or `ONYX_KERNEL_VARIANT=performance`
for the source build adapter. See [Droidspaces setup and validation](DROIDSPACES.md)
and `kernel-addons.json` for the individual source/tuning adaptations.
