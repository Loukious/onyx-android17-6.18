# Droidspaces on the Onyx Android 17 / 6.18 kernel

Both kernel profiles apply `patches/droidspaces-618.patch` to the
6.18 common source and merges `droidspaces.fragment` into the GKI configuration.
It also adds `droidspaces-kmi-symbols` to the active KMI list. This enables the
kernel facilities needed by the upstream runtime; the Android app, backend and
Linux distribution remain optional, separately installed software.

The requirements follow [Droidspaces' GKI guide at cdadb9eb5d0f](https://github.com/ravindu644/Droidspaces-OSS/blob/cdadb9eb5d0f86aacffff60776333e6f6b73a30a/Documentation/Kernel-Configuration.md).
The older upstream task-padding patches are replaced by a 6.18-specific port.

## IPC state and ABI

`CONFIG_SYSVIPC` normally inserts 24 bytes into the middle of `task_struct`.
This port stores a pointer to owned semaphore undo and shared-memory creator-list
state in the fourth existing 8-byte Android kABI reserve. Its literal `u64`
declaration stays unchanged; private accessors cast the pointer bits through
`unsigned long`. This requires the existing 64-bit Android reserve configuration.
The bootstrap task has a
static state object. Every duplicated task receives a fresh zeroed object after
its stack/shadow-stack allocation and before publication. Allocation failure
unwinds the shadow stack, thread stack and task allocation. A successful task's
state remains alive until final `free_task()`, after IPC exit cleanup.

`CLONE_SYSVSEM` still shares only the reference-counted semaphore undo list.
The shared-memory creator list retains the original task lock and RCU lifetime
rules. There is no lazy allocation on a published IPC object, global lookup
table, or task-pointer recycling window.

Keeping the literal reserve also preserves Rust's generated binding graph.
An `ANDROID_KABI_USE` union retained the C layout and C symbol CRCs, but bindgen
gave its wrapper a new anonymous-member label that changed ten Rust export CRCs.
The literal-reserve implementation reproduces the baseline Rust `task_struct`
declaration without replacing CRC values.

`init_ipc_ns` and `put_ipc_ns` are exported GPL symbols for modular Rust Binder
and binderfs. Enabling IPC namespaces preserves the existing `nsproxy` layout;
its `ipc_ns` member was already unconditional in this tree.

The fragment includes PID/IPC/user namespaces, devtmpfs, NAT66/macvlan,
tmpfs xattrs/ACLs, UFW/Fail2Ban facilities, and required existing GKI facilities.
Memory control, CPU bandwidth control and process limits were already enabled
in this particular 6.18 GKI. No additional scheduler-layout options are added.
The runtime can use the existing legacy iptables NAT support; enabling nftables
is outside this fragment because it adds members to this tree's `struct net`.

## Verification

Build with the repository's feature selection and retain the matching kernel
and module artifacts. Verify the final generated configuration and all existing
exported CRCs against a baseline built from the same source and toolchain:

```sh
python3 port/features/verify_droidspaces.py \
  --config PATH_TO_ENABLED_DOT_CONFIG \
  --symvers PATH_TO_ENABLED_MODULE_SYMVERS \
  --baseline-symvers PATH_TO_BASELINE_MODULE_SYMVERS
```

The gate rejects a missing requirement, missing modular Binder export, any
removed baseline symbol, or any changed baseline CRC. New symbols are allowed.
Source compile/type checks are recorded in `droidspaces-source-validation.json`;
these do not replace a complete build/KMI comparison or an on-device test.

`tests/droidspaces_types.c` provides real kernel type graphs for repeatable
Clang/DWARF checks. Compile it once with the frozen baseline header/configuration
and once with the enabled configuration, then compare `gendwarfksyms --stable`
versions and symtypes for all six `probe_*` symbols.

Compile the syscall regression binary with the Android NDK's
`aarch64-linux-android35-clang -O2 -static`, then install it under
`/data/local/tmp` using **Windows `adb.exe`** and run it through `su -c`.
It creates a disposable IPC namespace before allocating anything, tests SysV
message queues and shared memory, SEM_UNDO through fork/share/unshare, 64
creator-exit/reap/removal cycles, POSIX mqueues, and mount/UTS/network/cgroup/user/
PID namespace creation. Exit 0 means pass; exit 77 means its root/kernel
prerequisites were unavailable and the runtime test did not run. Allocation
failure unwinding has source/compile coverage; kernel fault injection has not
been exercised.

## Install the runtime and distribution

After the matching kernel and modules are installed, use the official APK from
[Droidspaces releases](https://github.com/ravindu644/Droidspaces-OSS/releases).
Grant KernelSU root access, let the app install its backend, and follow its
requested reboot. Run **Settings → Requirements → Check Requirements**; the
must-have and recommended checks should pass.

Use **Containers → + → Repository** to download an ARM64 distribution, install
it, and start it. The app manages the rootfs/image and its boot service under
`/data/local/Droidspaces`; do not package a distribution into the kernel image.
For an externally prepared rootfs/image, follow the upstream
[Linux installation guide](https://github.com/ravindu644/Droidspaces-OSS/blob/cdadb9eb5d0f86aacffff60776333e6f6b73a30a/Documentation/Installation-Linux.md).
NAT, macvlan, Docker/Podman, NixOS and hardware access still require their normal
runtime/container settings in addition to these kernel facilities.
