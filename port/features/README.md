# Onyx kernel feature profiles

Both profiles include the same peripheral support, KernelSU Next dev, a matched
SUSFS LKM from that exact Next commit, NoMount's kernel backend, OverlayFS for
Mountify, Baseband Guard, WireGuard, BBRv1/BBRv3 and the other TCP algorithms,
IPSet, IPv6 NAT, TTL/hop-limit targets, connection marking, CAKE, CIFS xattrs,
TMPFS xattrs/ACLs, BPF/BTF/tracing/FUSE-BPF, NTSync, USB DVD emulation, Unicode
basename protection during file creation and Droidspaces' required namespaces/IPC support.

`manifest.json` is the canonical feature/configuration/profile inventory.
`lock.json` binds NoMount's source archive; SUSFS always follows
`../kernelsu-lock.json`, rather than an independently selected source revision.
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

## Activating SUSFS

The build adapter preserves the official SUSFS Makefile and adds its required
Android GKI filesystem namespace declaration. Install the release's SUSFS
KernelSU addon for the selected profile. It uses
Next's `ksud insmod` special loader and checks the running kernel's linker-note
fingerprint as well as its version. This also rejects old addons after a
KernelSU-only update that leaves the kernel version unchanged.
Ordinary `modules.load`/modprobe must not load this module: it resolves private
kernel symbols through the official Next loader. The addon checks the reported
active hooks at boot and records its result in `runtime-status.txt`.
Use a compatible [SUSFS configuration module](https://github.com/sidex15/susfs4ksu-module/releases)
to configure hiding rules. Classic in-built SUSFS must not be combined with
this LKM implementation. Reported hook activation needs separate behavioral tests.

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
