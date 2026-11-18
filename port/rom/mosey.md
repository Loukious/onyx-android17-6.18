# Native Mosey product integration

The real Onyx ROM checkout uses `vendor/extra/mosey/product.mk`, inherited by
`vendor/extra/product.mk`, to directly inherit the existing
`vendor/gms-mosey/mosey/mosey-vendor.mk` package. Android evaluates product
inheritance as a graph; setting `TARGET_INCLUDE_MOSEY` in a child fragment alone
does not reliably enable the parent's earlier conditional.
The product builds `libmosey_onyx_config` and `onyx_mosey_launcher`, and scopes
the preload configuration to the native service through
`system_ext/etc/init/onyx-mosey.rc`. The original Mosey APK, native blobs,
Google framework HAL declaration, and permission files remain in use.

The adapter selects the current FFI v5 Wonder backend (radio 2) and enables
protobuf field 5, protocol channel rotation. The app's channel list and all
other protocol configuration are retained. Its implementation and exact
binary contract evidence are documented in the ROM's
`vendor/extra/mosey/README.md`.

The generated kernel module layout must package and load `wonder.ko` with
cfg80211/mac80211 and `qca_cld3_wcn7750.ko`. Module dependency resolution and
auxiliary matching handle either provider registration order. The existing
vendor `modules.options` enables the QCACLD monitor coexistence paths and the
Wonder provider. Android's flat options file matches the verified export layout;
experimental off-channel STA probing remains disabled.

The current native FFI rotates channels with SET_FREQUENCY; it does not submit
the newer channel schedule, TSF, station, or feature commands. Safe standalone
channel changes and associated-STA behavior must therefore be supported on
that path. The native fixed rate request can use HT/20 MHz or VHT/80 MHz with
0.8 us GI and configured NSS/MCS. Native GET_CAP reads MTU, hardware AMSDU,
and hardware AMPDU fields.

The source adapter and launcher pass offline source-including host validation,
including argument/protobuf preservation, failures, and concurrent lookup/start
calls under ASan/UBSan. Isolated Android NDK links produce AArch64 binaries with
16 KiB LOAD alignment; the library exports only `dlsym` and imports the expected
`dlvsym@LIBC_N`. The two native targets also pass the normal Onyx Soong build and
inspection of the installed ARM64 binaries, 16 KiB alignment, dynamic exports
and product variables. Those receipts are
`/home/loukious/Android/onyx-wonder-coex-dev-20261117/product-source-validation/targeted-soong-validation.json`
and `targeted-soong-artifacts.json` in the same directory. These checks do not
validate complete Evolution images, runtime SELinux transitions, loaded preloads,
or RF behavior. The earlier source-including host receipt is
`/home/loukious/Android/onyx-wonder-continuation-20261116/mosey-offline-validation/run-20261117-02/native-validation.json`.

`port/validation/collect_mosey.py --dry-run` displays the read-only native capture
plan without contacting a device or writing files. After a later authorized
deployment, use an explicit device serial and a **new directory**:

```sh
python3 port/validation/collect_mosey.py --serial DEVICE_SERIAL --root \
    --output /path/to/new-mosey-capture
```

The collector requires Windows `adb.exe`. It records service state, native file
hashes, SELinux domain, UID/groups/capabilities, binary auxiliary-vector
`AT_SECURE`, library mappings, and the two process configuration variables.
It journals command metadata before execution and retains raw stdout/stderr and
SHA256 hashes, including permission failures, partial timeouts, and interrupted
snapshots. Process start ticks bracket each
process snapshot to expose PID reuse or restarts. `--duration` repeats snapshots;
`--expected-artifacts` accepts expected hashes for the named native artifacts.
The isolated NDK output hashes should be replaced by actual packaged Soong
artifact hashes when comparing a product build. The collector never starts or
reconfigures the service or radio. Its 16 offline fixtures are in
`port/tests/test_collect_mosey.py`.

The full ordinary Kleaf build and verified 550-module export pass; the receipt is
`/home/loukious/Android/onyx-wonder-coex-dev-20261117/kernel-package-validation/kernel-export-validation.json`.
The complete ROM/service product and its shipped OTA still need validation before
deployment. Device operations, APK changes, and RF/transfer
testing remain deferred. Isolated kernel host builds and software validation are documented in
[Wonder bring-up](../wonder-awdl.md#build-source-gates-and-verification).
