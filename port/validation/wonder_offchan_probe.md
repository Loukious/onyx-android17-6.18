# Wonder raw off-channel probe

`wonder_offchan_probe.c` is a small Android-local utility with no libnl or
`iw` runtime dependency. It resolves nl80211, submits Wonder SET_FREQ on
`wonder0`, observes a fresh ready lease, and submits one raw frame directly
on the provider-owned `wondertap0`. It never creates interfaces, sets module
parameters, prepares the provider, or closes the provider session.

Default execution is a dry-run. It opens no sockets or device/sysfs files,
reads no device state, and emits JSON lines containing packet and control
bytes. Family ID, interface index and netlink PID are explicitly marked as
placeholders in that output.

```sh
./wonder_offchan_probe --frequency 2437 \
  --source 02:11:22:33:44:55 --receiver 02:66:77:88:99:aa \
  --bssid 02:aa:bb:cc:dd:ee --nonce 0x574f4e44
```

The action frame contains a vendor category, OUI `001a11`, local type `57`,
nonce, zero-based packet index and `WONDER-OFFCHAN-PROBE` marker. `--data`
selects a non-QoS data frame with LLC/SNAP and local experimental EtherType
`88b5`. Both use the actual raw interface MAC as source in live mode, the
specified unicast receiver, and the supplied configured BSSID. Sequence
control is diagnostic; firmware preservation is unverified.

Both formats use only radiotap RATE and CHANNEL: 6 Mbps and 20 MHz. For
2437 MHz the exact 14-byte header is:

```text
00 00 0e 00 0c 00 00 00 0c 00 85 09 c0 00
```

There are no FLAGS, TX_FLAGS, MCS, VHT, HE, GI/LTF, NOSEQNO or NOACK fields.
The SET_FREQ vendor payload is:

```text
08 00 01 00 85 09 00 00 06 00 02 00 00 00 00 00
```

Vendor ID is `0x001a11`, subcommand is `1`; attribute 1 is u32 MHz and
attribute 2 is u16 bandwidth enum `0` (20 MHz). The outer request carries
the resolved family and `wonder0` interface index.

Live execution is a separate, explicit mode for later authorized device
testing. Before using it, prepare a Wonder monitor session: create
`wonder0` on phy `wonder`, cache supported frequency, fixed rate (6 Mbps),
BSSID and the matching current country through vendor subcommands 1–4
before bringing `wonder0` UP. The provider then owns and opens
`wondertap0`; do not create it manually. Both interfaces must remain UP,
and the associated STA must have a valid HOME channel different from the
target. `wonder_enabled` and `wonder_sta_offchan_probe` must already be
enabled in `qca_cld3_wcn7750`; the latter defaults off. The BSSID argument
must match the prepared session. Other services must relinquish manual
channel control for the duration of this probe.

From an Android shell with the required permissions, a prepared session can
be probed with:

```sh
./wonder_offchan_probe --execute --frequency 2437 \
  --receiver 02:66:77:88:99:aa --bssid 02:aa:bb:cc:dd:ee \
  --nonce 0x574f4e44 --count 1
```

`--source` is required in dry-run and rejected in live mode. `--count` is
bounded to 1–4 (default 1); `--wait-ms` is bounded to 1–5000 (default 1000)
and controls read-only retirement and netlink response waits. The kernel's
original absolute 32 ms lease is never extended by this utility.

Sockets, family resolution and packet construction precede SET_FREQ.
SET_FREQ waits synchronously for a genuine ready event. Any control error,
including EAGAIN, aborts without retry. Two immediate observations must
identify the same fresh generation, helper cookie, requester, scan ID,
target, entry and deadline, with more than 1 ms remaining. The kernel's
final admission check remains authoritative. The last stats read and raw
send are not atomic: a competing frequency controller could change the
lease between them. The kernel captures and validates its own queue token;
the userspace tuple in the log is an observation, not proof of the packet's
actual queue tuple. Use a manually prepared session with no competing
frequency controller. After successful control the
utility waits boundedly for phase IDLE and firmware_ref zero before another
request, including when a later readiness check or send fails.

`submitted` means only that the raw send syscall accepted the whole packet.
Every JSON record reports `rf_verified:false`. `scan_retired_observed`
records scan ownership/reference retirement; it establishes neither WMA
mapped TX DMA completion nor RF HOME restoration.
Independent receiver capture, nonce/index correlation, frame decoding and
channel timing are still required to establish RF behavior.

Offline validation compiles and runs instrumented host fixtures under
ASan/UBSan, validates dry-run behavior and malformed controls, then links
an AArch64 Android API 35 PIE with 16 KiB PT_LOAD alignment. It checks the
actual ELF headers, LOAD congruence and `/system/bin/linker64` interpreter.
The Android artifact is retained without execution or deployment.

```sh
python3 port/verify_wonder_offchan_probe.py \
  --output /absolute/path/to/new/raw-probe-validation
```

The receipt hashes the source, harness, verifier, relevant kernel ABI
sources, compilers, logs and retained binaries. Host mocks establish wire
encoding and userspace ordering; they do not establish on-device nl80211,
driver, WMI or RF acceptance. No firmware patch or APK change is part of
this utility.
