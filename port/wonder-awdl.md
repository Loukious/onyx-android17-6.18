# Onyx Wonder / AWDL bring-up

The implementation connects Google's Wonder core to Onyx's ICNSS2/WCN7750
WLAN driver. The v15 data path has passed native multicast, stock Owly discovery
and a complete WSL-to-phone file transfer on channel 6. Apple-device
interoperability remains unverified. The source base is the Linux 6.18.63
component-catalog redesign at `945bc4499192bd44aa3c44e43529428a843428ba`.

## Source and transport

Google Wonder is pinned to
[`f70b3a428939460201f8ebbca0bf309027dd7320`](https://android.googlesource.com/kernel/common-modules/wonder/+/f70b3a428939460201f8ebbca0bf309027dd7320/).
Upstream files retain Git blob locks and source SHA256 checksums. Patches
0260–0265 preserve the initial provider and transport changes; subsequent
patches record the extended scheduling, PM and PPDU implementation.

The provider lives in `qca_cld3_wcn7750.ko` and registers the software auxiliary
device `qca_cld3_wcn7750.wondertap`, using interface version 3.6.6. Onyx keeps
its existing integrated ICNSS2/IPCI transport, WPSS firmware loading and WLAN
recovery. The provider owns `wondertap0`; the native service creates `wonder0`.

Unicast TX uses the existing HDD/WMA raw-injection path and its real helper,
queue admission, power limits and completion processing. Native AWDL group data
uses the WMI path described below. RX uses monitor delivery
and the Wonder RX handler. The firmware receive-address matcher binds the AWDL
MAC to the actual helper and requires the firmware's accepted SET response.
Its submit-only CLEAR cannot authorize ID reuse: routing is retired only by
actual helper deletion or a drained firmware restart. Helper lifetime cookies
prevent an old numeric vdev ID from becoming a new session's identity.

The transport encodes HT, VHT and HE SU radiotap settings explicitly and checks
rates against the prepared helper's actual channel, bandwidth, NSS and PHY
limits. Unsupported settings return errors and preserve the last accepted
cache. Management/discovery frames use the existing OFDM injection settings.
Submission counters do not prove RF transmission or receiver ACKs. Aggregation
and firmware rate adaptation remain unsupported.

[OPAirDrop](https://github.com/Weverses/OPAirDrop/tree/28a3a1dbc9f515fa5705417a3973616e5ae6180d/kernel)
and the
[Kodiak implementation](https://github.com/Reeky-ux/lineage_kernel_google_kodiak/tree/188b1a271525545f55579e6180b67f5673cd6186/google-modules/wlan/qcom/wcn7760/wlan)
are references. Their PCIe/CNSS2 registration, firmware PAS substitution and
NDI workaround are not prerequisites of this integrated Onyx transport.

## V15 native AWDL data path

Patch 0268 replays the eight-patch companion source series across 12 files,
including the earlier monitor lifecycle/RX fixes, scan lease, AP-free native
startup and destination-compatible rates. Its result matches the v15 source
hashes. No firmware image is replaced.

Unprotected, unfragmented ordinary and QoS AWDL group data on the established
exclusive channel uses WMI raw transmit command 0x7009. The group destination
and AWDL payload remain intact. This dedicated route permits firmware-assigned
outer 802.11 sequence numbers and intrinsic group no-ACK behavior; it does not
claim to preserve an injected outer Sequence Control value. Generic WMI
metadata checks remain strict. Helper cookies, channel generation, regulatory
power and final publication authorization remain required.

Each command reserves a unique low-16-bit descriptor ID before queue admission.
IDs are never recycled during a boot, including canceled sends. Exhaustion or
queue rejection is synchronous and leaves the packet with its caller. mDNS can
then use the existing per-peer unicast fallback, preserving its multicast IP
packet. Successfully queued native mDNS does not use that fallback. Completion
retains DMA and module ownership until the real response, including when the
response races the return from command submission.

The separately packaged driver v15 was verified after reboot with SELinux
enforcing. Through the normal Wonder path on channel 6, the USB monitor received
14 ordinary and 12 QoS native group probes, with their multicast destination
preserved, and both matched unicast controls. WMI reported 60 sent/completed
commands with no failures or outstanding DMA ownership. Stock Owly then found
the phone by name using native AirDrop mDNS multicast and delivered 208,896 bytes
with SHA-256 `88a3b76fb7cba053c2b89da960a7f75ac06e40f2271840ef6e1b2304910d9d87`.
Closing Quick Share restored ordinary Wi-Fi automatically.

The provider's later country-only migration removes its TN-to-channel-6 test
override. Normal policy selected channel 149 (5745 MHz), and firmware/interface
startup and Wi-Fi restoration passed. This establishes 5 GHz selection and
startup only: the current RTL8188CU peer cannot receive 5 GHz. Over-air 5 GHz
discovery, native multicast, file transfer, ordinary social-channel hopping and
Apple interoperability still need a suitable peer. The driver accepts enabled
2.4/5 GHz channels; native multicast uses 20 MHz. Shared STA off-channel operation
retains its explicit probe-only restrictions.

The source hashes of the packaged v15 result are
`f69152c987d1c7548cfbca30fc867a2dea3be6bb6fb5885c27feed3eec550b24`
for `wlan_hdd_wonder.c` and
`fcad6becd82b8cad17e6a99baa78615ffcd09497c03f5048ac3575b16f366b05`
for `wma_data.c`. The module SHA-256 is
`3b2e60fd74a61cb931f2d79c16658b3d551cf2f5bc82df5fe642c0cfd2f8dc51`.
The companion `source-series-v15.json` records all 12 baseline/result hashes and
the original eight patch identities. These observations apply to that packaged
module; they do not establish the result of a new complete kernel/ROM build.

## Scheduling, PM and channel ownership

Host scheduling uses real firmware TSF/QTIMER pairs from the prepared injection
helper. Binding includes its vdev ID and lifetime cookie. Each completed
helper/channel transition recaptures the firmware's TSF-register and LMAC IDs;
active schedules stop if the clock resets or those IDs change. Switch completion
and subsequent deadlines use the new capture. Cached register IDs and host uptime
cannot substitute for a firmware sample.

Suspend retains the vendor netdev, RX registration and scheduler clock witness,
while gating traffic and draining scheduler work. Resume compares the new paired
TSF/QTIMER values and counter IDs against that witness. QTIMER accounts for time
spent asleep. The core replays the accepted channel list, roles, dwell time,
next index and original TSF phase only after provider restoration succeeds.
Failure leaves traffic gated. The 32-bit command ABI makes sufficiently old
anchors ambiguous; replay rejects those anchors after roughly 35.8 minutes,
and the session must be restarted. Empty-list cancellation needs no TSF capture.

PPDU accounting uses decoded frequency, MAC TSF and PHY duration once per PPDU.
TX consumes raw COMMON TLVs before per-user or delayed-BA rewriting and remains
compiled when Onyx disables enhanced statistics and packet logging. RX requires
real PPDU start/end metadata and never assigns a missing frequency from the
current monitor channel. Reports are deduplicated per hardware MAC/direction;
the scheduler also requires the active generation and matching LMAC. Reporting
ownership preserves other consumers' requested HTT upload masks.

Standalone channel changes are implemented. Same-channel STA/AP sharing uses
the existing owner/generation controls without disconnecting ordinary Wi-Fi.
Normal off-channel STA control returns `-EOPNOTSUPP`. Patch0267 adds an explicit
`wonder_sta_offchan_probe=1` module-load option for experimental 20 MHz dwell
probes; it defaults off. STA off-channel and HBS/DBS coexistence remain
unadvertised. Competing monitor ownership, transitional WLAN
states and unsupported regulatory/channel settings are rejected. Station command
records describe mac80211 destinations; they do not create firmware destination
peers or enable aggregation.

Firmware capture latency and the relationship between the helper TSF register
and actual PPDU timestamps still need hardware evidence. Host scheduling cannot
guarantee that firmware completes a switch within an AWDL dwell interval.

The private probe reserves a single-channel SCM scan on the real monitor vdev,
keeps the associated STA's HOME identity and helper unchanged, and requests
off-channel data permission. Only its matching firmware `FOREIGN_CHANNEL`
event can authorize traffic. Scan-manager cancellation and timeout notifications
do not prove firmware retirement. A target-event observer runs before SCM's
active-queue filter so a later real completion can retire the old reservation.
Activation rechecks the exact channel after admission, and ordinary scans retain
their existing monitor invalidation behavior.

Readiness ends at the original schedule-slot deadline, at most 32 ms, and on
channel exit, HOME return, preemption, suspend, contradictory channel events,
or owner invalidation. Queued packets retain their original scan tuple and
deadline, so a later dwell on the same frequency cannot authorize them. RX
uses an exact PPDU's measured frequency; HOME fallback metadata cannot establish
off-channel reception. Final TX/RX publication serializes with dwell revocation.
Wonder-owned monitor delivery uses `netif_rx` backlog publication while those
locks are held. This defers Wonder/mac80211 consumption until after publication,
preventing synchronous RX-to-TX reentry from acquiring the same locks. Generic
monitor delivery keeps its existing NAPI/BH selection.

Stock WMI7009 completion has a sixteen-bit descriptor identity and target MAC
plus one. The host validates/normalizes that identity and retires each mapped
frame only on its matching real TX completion. Failed sends unmap immediately;
scan completion never releases TX DMA. Lost firmware completion keeps ownership
reserved and can prevent reuse or module unload. Descriptor IDs are not reused
within the WMI lifetime and exhaustion rejects further submissions.

The stock command lacks proven GI/LTF, preserve-sequence, and unicast NOACK
controls. Normal Wonder frames request preserve-sequence and data frames supply
GI. The probe rejects those unsupported options; it is not functional AWDL STA
coexistence. The preserved firmware sequence-number copy and rate metadata do
not establish final RF behavior. The focused evidence is in the development
artifact directory's `firmware-tx-semantics/report.md`.

An Onyx phone plus a controlled receiver can test service123, monitor scan
eligibility, actual channel occupancy, packet options, RX/ACK routing, and HOME
internet continuity. Apple hardware is needed for AWDL peer interoperability and
end-to-end transfers. These are distinct acceptance checks; an offline build
does not establish either result.

## Build, source gates and verification

The component catalog owns the module recipe, export requests, generated build
files and source imports. Loading policy ships `wonder.ko` in vendor DLKM and
selects the Wonder load group. The ROM module layout includes it and enables
the QCACLD provider. `wonder_enabled=0` disables provider registration.

```bash
python3 port/catalog.py --check
python3 port/generate_imports.py /path/to/pinned-workspace --check
python3 port/stage.py /path/to/pinned-workspace
python3 port/verify_wonder.py modules
python3 port/verify_wonder_sched.py modules
python3 port/verify_wonder_dwell.py modules
python3 port/verify_wonder_coex.py modules
python3 port/verify_wonder_scan.py modules
python3 port/verify_wmi_offchan.py modules
python3 port/verify_wma_offchan.py modules
python3 port/verify_wonder_native_tx.py modules
python3 port/verify_wonder_airtime.py modules
```

The isolated helpers reuse matching Linux 6.18.63 Kleaf outputs and compile into
separate output directories. They do not produce release installers or install
anything on a phone:

```bash
python3 port/validation/build_wonder.py --workspace /path/to/kleaf-workspace \
  --native-wireless-dir /path/to/verified-native-wireless-build
python3 port/validation/build_qcacld.py --workspace /path/to/kleaf-workspace \
  --native-wireless-dir /path/to/verified-native-wireless-build
```

The [transport checkpoint](wonder-host-validation.json) preserves the earlier
scheduler/PM/PPDU implementation results. The separate
[off-channel development receipt](wonder-coex-host-validation.json) records the
new probe's exact source hashes, complete module builds, source replay and
software contracts. Each receipt applies to its recorded source checkpoint.

Transport, control/PM, RX, scheduler/TSF and PPDU/upload-ownership fixtures execute
production functions with bounded mocks for packet allocation, firmware and
kernel primitives. Negative controls check that selected broken guards are
rejected. These fixtures validate software contracts; firmware behavior,
concurrent kernel/RTNL scheduling, radio ACKs and Apple transfers still need
device evidence. Run the scheduler and airtime commands separately from
`verify_wonder.py`.

The transport checkpoint retained all 993 baseline exports with 355 changed
CRCs. Its 561 audited host artifacts contained no external QCACLD imports, so
no scanned sibling requires rebuilding solely for those changes. Deployment still
requires a matching ROM, kernel and complete module package. Downstream QCACLD
consumers outside that audit need their own symbol-version checks or rebuild.
The off-channel receipt records a separate audit of the original Kleaf target's
399 external module artifacts against its recorded final QCACLD symbol table.

Before a target test, collect module/probe state, native process identity and
raw observation snapshots using `port/validation/collect_mosey.py`. The
`wonder_coex_stats` and `wonder_offchan_stats` parameters distinguish active
scan ownership from pending mapped TX buffers. Capture uses Windows `adb.exe`,
creates a new directory and preserves command failures/timeouts. `--dry-run`
shows the capture plan without accessing a device. Details and existing native
ABI validation are in [Mosey integration](rom/mosey.md).

The [Android-local raw probe utility](validation/wonder_offchan_probe.md)
constructs its socket and frame before requesting a dwell, checks a fresh
firmware-authorized lease, and submits a bounded action or data frame on
`wondertap0`. Its default dry-run accesses no radio or sysfs state. The
offline receipt covers 585 assertions, 23 cases, 15 negative controls and an
Android AArch64 PIE with verified 16 KiB LOAD alignment. The retained binary
has not been executed on a phone; submission and scan retirement never count
as RF transmission or mapped-buffer completion.

```bash
python3 port/verify_wonder_offchan_probe.py \
  --output /absolute/path/to/new/raw-probe-validation
```

## Native service and device acceptance

[Native Mosey product integration](rom/mosey.md) describes the existing Evolution
FFI v5 service and the scoped configuration adapter under `vendor/extra/mosey` in
the ROM checkout. The launcher preserves init's normal SELinux transition and
executes the unchanged daemon in the same domain. The adapter selects the Wonder
backend and protocol channel rotation while preserving other FFI arguments.
The current native FFI rotates through SET_FREQUENCY and does not submit the newer
schedule, TSF, station or feature commands.

The native service, policy and module image set need a matching ROM build before
deployment. The current extension APK and Google native blobs are retained.
The v15 package observations above supersede the earlier bring-up checkpoint's
pending channel-6 discovery and data-path checks. A new complete kernel/ROM
image still needs its own deployment validation.

Remaining device work includes over-air 5 GHz discovery and transfers, normal
social-channel hopping, Apple-device interoperability, long-duration stability,
and repeated suspend/resume, failed starts and WLAN recovery. The current peer
cannot establish those 5 GHz results, and no Apple peer is available.
