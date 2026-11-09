# WCN7750 monitor injection testing

The monitor transmitter used to accept only management frames. Authentication
and association could work while all EAPOL/WPS data frames were discarded. Patch
0246 accepts validated data frames, including EAPOL, and carries per-packet
transmit settings through the queued raw datapath to the existing HTT firmware
metadata. It also prevents short control frames from entering Ethernet/QoS
parsers that assume longer headers.

The firmware injection helper also needs the address used by the monitor
netdev. On this MLO-capable adapter that address differs from the monitor
link's MAC. Deriving another helper MAC left replies addressed to userspace
without reliable firmware handling. Patch 0246 snapshots the netdev MAC with
each queued packet, uses it for the helper, and drains pending completions
before replacing a helper whose interface, channel or MAC changed. Arbitrary
transmitter addresses in injected frames do not change the helper identity.
Layouts where the monitor and netdev share an address retain the earlier
distinct helper address to avoid colliding with the monitor's self peer;
automatic reply handling on those layouts has not been validated.

On 2026-11-09, the Onyx/WCN7750 test with Reaver 1.6.6 and an ASUS RT-AX86U
completed known-PIN credential retrieval in two seconds using the default
monitor MAC and standard Reaver behavior (no `-m` or `-N`). The
capture contains M1 through M7 with zero AP EAP retries, and the returned
credential matches the router configuration. The original module and Android
Wi-Fi connection were restored after testing.

## Host support

| Input | Behavior |
| --- | --- |
| Management and data | Validated headers, including QoS, four addresses and HT control; maximum 2352 bytes |
| EAPOL | Validates the EAPOL length; sends raw data through the standalone host-data exception pool |
| Control | ACK/CTS, RTS, PS-Poll, CF-End/CF-End+ACK, single-TID BAR and basic/compressed BA |
| Radiotap FCS / DATAPAD | Removes the supplied FCS and alignment padding before transmission |
| RATE | Maps 1, 2, 5.5, 11 and 6–54 Mbps legacy rates to HTT parameters |
| MCS | Single-stream HT MCS 0–7, 20/40 MHz and long/short guard interval |
| DATA_RETRIES | 0–14 retries, encoded as 1–15 total attempts |
| NOACK | Requests one attempt; this does **not** establish firmware no-ACK timing semantics |
| NOSEQNO | Preserves supplied frame/sequence bytes in the host; firmware preservation needs an RF capture |
| CHANNEL | Must agree with the monitor interface channel; does not retune the radio |

Unsupported requests are dropped with a rate-limited error, rather than silently
discarding their settings: RTS/CTS protection, TX ordering, explicit antenna or
power selection, short CCK preamble, hardware encryption/fragmentation requests,
multi-stream MCS, greenfield/LDPC/STBC selection, VHT/HE/EHT, vendor namespaces,
extended/multi-TID BA formats and GSO packets. The successful WPS test validates
the data exchange; accurate RF settings need separate measurement. The WMI
management fallback cannot send data/control or
the new HTT rate options and returns an explicit failure for those requests.

Reaver 1.6.6 always supplies NOACK|NOSEQNO (`0x18`). Those flags are accepted.
The driver prints a one-time notice describing the remaining firmware limits.

## Validation and diagnostics

Run `python3 port/verify_wlan_injection.py modules` in the source tree. The
same verifier runs before a full build. It compiles the real cfg80211 radiotap
iterator, the HDD frame parser, HTT metadata encoder, and WMA queue/cleanup
functions, including helper MAC selection and identity checks, under ASan/UBSan.
Scheduling, SKBs and DMA are mocked; these checks
do not emulate firmware or prove an over-the-air WPS exchange.

The module exposes `/sys/module/qca_cld3_wcn7750/parameters/injection_stats`:

- `accepted`: accepted by the WMA pending queue.
- `submitted`, `data`, `eapol`, `control`: accepted by the transport.
- `send_failed`: transport/setup/channel failures after queuing.
- `completed`: a tracked direct-DP buffer completed or was released.
- `completion_failed`: a hardware completion reported a nonzero status.
- `completion_unknown`: the free path released the buffer without RF status.
- `timed_out`: a descriptor exceeded the completion timeout.

These counters are cumulative for the loaded module. A submitted/released
buffer is not proof the router received or acknowledged it. Network-interface
TX/drop counters also include monitor submissions and parser rejections.

## Temporary device bundle

Build against the exact running kernel configuration and provider symbol
versions, retaining the original module. A prepared bundle contains these two
scripts, original/candidate modules and their GNU build-ID notes, checksum and
ABI reports, `identity.conf`, and a private `router.conf`. Its identity guard
checks kernel release, device model, both installed provider files and the
currently loaded WLAN module before any replacement. The build-ID files are
the complete binary `.note.gnu.build-id` ELF section, not a text hex string.

The bundle can be staged under `/data/local/tmp/onyx-wps-test-YYYYMMDD` with
`adb.exe`. From an Android root shell, run:

```sh
sh /data/local/tmp/onyx-wps-test-YYYYMMDD/driver.sh check
sh /data/local/tmp/onyx-wps-test-YYYYMMDD/driver.sh load
sh /data/local/tmp/onyx-wps-test-YYYYMMDD/test-known-pin.sh
```

Loading temporarily restarts Wi-Fi using normal `rmmod`/`insmod`, verifies
the newly loaded build ID, and waits for interfaces if Android Wi-Fi was enabled.
It does not alter boot/vendor partitions or install a boot hook. Failed candidate
insertion or asynchronous probe triggers normal removal and original-module
restoration. Busy or unrecognized modules are not forced out. `restore` reloads the
original module and restores the previous Android Wi-Fi setting; rebooting
also reloads the installed original driver.

The loader performs one memory compaction before insertion. Repeated hot
reloads on a busy phone can still fail the driver's large contiguous
allocations. For the observed `dp_prealloc_init` allocation failure, an optional
`WLAN_TEST_RECLAIM=1 sh driver.sh load` also reclaims clean page cache before
insertion. The same option works with `restore`; it changes no persistent VM
setting. Module identity alone does not establish a successful firmware probe.

The test script waits up to 20 seconds for WLAN interfaces after a reload,
temporarily pauses Android Wi-Fi management, uses the existing monitor
interface or recreates it, selects
the configured channel, captures only traffic involving the configured AP,
and runs at most one PIN attempt for at most 60 seconds. It uses a fresh Reaver
session and the exact known AP PIN, with the normal monitor MAC and Reaver WPS
handling. Earlier tests needed `-N` to tolerate repeated M1 messages while the
helper MAC was wrong. The final test script uses neither `-m` nor `-N`.
Immediate packet capture and a short drain preserve the final WPS response burst.
The script propagates Reaver's exit status, leaves results in the private bundle
directory, and restores the previous Android Wi-Fi setting on exit, including
setup or capture failures. Router configuration and result logs can contain credentials and
are not source-repository artifacts.

Check the AP's current channel before testing; automatic channel selection can
move it between runs. If the private `router.conf` changes, regenerate the
bundle's `SHA256SUMS` before running the loader.

Success requires Reaver to finish the known-PIN exchange and return the expected
credential. Identity, M1 or M3 alone is partial progress. Reaver retrieves the
credential from M7 and terminates with WSC NACK; this can leave hostapd's last
WPS status as "Failed" despite successful credential retrieval. It does not
perform an M8 configuration update. Capturing our own outgoing packet
on the same monitor socket does not establish RF transmission; use replies
from the AP or an independent receiver. Verify rates, retries and sequence
numbers with an independent receiver before claiming those firmware behaviors.

```sh
sh /data/local/tmp/onyx-wps-test-YYYYMMDD/driver.sh stats
sh /data/local/tmp/onyx-wps-test-YYYYMMDD/driver.sh restore
```
