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

On 2026-11-09, the standalone Onyx/WCN7750 test with Reaver 1.6.6 and an ASUS
RT-AX86U completed known-PIN credential retrieval in two seconds using the default
monitor MAC and standard Reaver behavior (no `-m` or `-N`). The
capture contains M1 through M7 with zero AP EAP retries, and the returned
credential matches the router configuration. The original module and Android
Wi-Fi connection were restored after testing.

## Keep Android Wi-Fi connected

Patch 0251 adds experimental STA/monitor coexistence for WCN7750. It is
**disabled by default**. Enable it by loading the matched WLAN module with
`sta_monitor_coexist=1`; the parameter is read-only after loading, so it cannot
be enabled through sysfs on an already loaded module. Module replacement still
requires the normal framework shutdown and drain of users of the old driver.
The coexistence option does not make a live module replacement safe.

After loading the opt-in module and connecting Android normally, keep its
managed STA interface and Wi-Fi HAL active. Add a separate monitor interface.
The session starts with exactly one connected STA and one active link, sharing
that link's **full channel definition**: primary frequency, bandwidth, center
frequencies and puncturing. Other APs on that channel can appear in the capture.
Both interfaces share airtime and processing resources; heavy injection can
affect Android throughput and latency.

Channel requests now have these effects:

| Current mode and request | Result |
| --- | --- |
| Shared; identical full channel definition | Success with Android still connected and no radio retune. |
| Shared; same primary but different width, center or puncturing | Rejected without disconnecting Android. Tools must preserve the full existing definition. |
| Shared; different supported primary | Android disconnects and the monitor takes exclusive use of the radio. The same `mon0`, ifindex and open capture are retained. |
| Exclusive; another supported channel definition | The monitor retunes on the same interface. Android remains disconnected. |
| Unsupported exclusive target | Rejected before a shared Android connection is disconnected. |

Exclusive targets must be enabled 2.4/5 GHz channels with 20/40/80 MHz bandwidth,
no DFS or passive-only restriction, no puncturing and no second center frequency.
A 6 GHz target or an active MLO association is rejected before handoff. MLO-capable
hardware using a legacy association is supported. These target restrictions do
not require retuning Android's existing shared channel.

For example, a monitor initially sharing Android's 5 GHz channel 52 can request
2.4 GHz channel 1. Android then disconnects and the monitor uses channel 1;
the two channels do not operate independently at the same time. New STA scans
and connection attempts are blocked while the monitor is exclusive. A valid
Android scheduled background-scan request (PNO) can be deferred and resumed
when the monitor is closed. Cancelled or replaced requests must not be replayed.
Android remains responsible for reconnecting after teardown. Use a separate
supported adapter when both channels must stay active independently.

For a Kali hostapd AP, use the separate [AP/monitor workflow](#run-a-kali-hostapd-ap-with-mon0).
The internal injection helper is distinct from that real AP and does not
provide a hotspot with connected clients. The automatic-handoff and
shared-channel WPS results below qualify the STA workflow.

### Setup and teardown

Patch 0254 also supports stock `airmon-ng` with the coexistence options enabled.
Monitor interface names are no longer restricted to `mon0`; for example,
`wlan0mon` can be used with the separate-interface setup below. `mon0` remains
a convenient name outside the WLAN-style names enumerated by some Android HALs.

Stock `airmon-ng start wlan0` brings the station down, creates `wlan0mon`, and
selects channel 10 when no channel argument is supplied. This enters standalone
monitoring and disconnects Android Wi-Fi. Supply a supported channel explicitly
when needed, such as `airmon-ng start wlan0 6`. `airmon-ng stop wlan0mon` removes
the monitor; the driver preserves and reopens Android's station interface so
Android can reconnect normally. The tool and Kali package need no modification.
Use the separate-interface setup below to keep an existing Android connection.

From a root shell with `iw` and `ip` available, after the matched opt-in driver
is loaded and Android is connected:

```sh
iw dev wlan0 interface add mon0 type monitor
ip link set mon0 up
# Capture or test on the existing channel, then stop those processes.
ip link set mon0 down
iw dev mon0 del
```

Use the device's actual managed interface name if it differs from `wlan0`.
Record the STA connection, monitor ifindex and both full channel definitions
before and after the session. For shared operation, keep Android traffic
running through creation, use and deletion. For an exclusive handoff, record
the expected Android disconnect and verify reconnection after monitor teardown.

With `mon0` already open and sharing a different primary, a normal channel
request performs the handoff. For example, when Android is on channel 52:

```sh
iw dev mon0 set channel 1 HT20
iw dev mon0 info
```

Keep the existing capture open across that request. After testing, stop capture
and injection, bring `mon0` down and delete it as above. A scheduled Android scan
that remains valid can resume after exclusive ownership ends. Scan requests
that would compete with the exclusive session can return `Device or resource
busy`; unsupported channel requests return `Operation not supported`.

Unplanned connection, channel, link and other relevant state changes invalidate
the session and pause monitor delivery and injection. A controlled channel
handoff quiesces the old session before publishing the new one. Native stop,
pending-completion drain and deletion must finish before resources can be
reused. If firmware or stop state is uncertain, resources remain in quarantine
and unsafe reuse is rejected.
A failed stop or deletion is incomplete teardown. The driver does not replay
the monitor session automatically after a subsystem restart (SSR). Frames
already submitted to firmware or transmitted over RF cannot be recalled.

### Capture limits

| Receive source | Capture contract |
| --- | --- |
| Available RAW monitor and helper frames | Retain their original 802.11 frame data; consult each packet's radiotap metadata for FCS presence. |
| WMI management copies | Preserve the management bytes supplied by firmware, but have no captured FCS or full TSF. Radiotap reports only available metadata and leaves the FCS flag clear. |
| Plaintext EAPOL addressed to the private helper | A completed, single-MSDU FromDS frame can be copied from its captured RX_HEADER and matching Ethernet payload. Header type, length, PPDU, addresses, frame control, sequence and payload prefix must agree. The copy has no FCS, RSSI, TSF or radiotap CHANNEL field; it does not infer the received frame's channel from a later channel request. |
| RAW replies from an AP without an Android peer entry | A complete, linear, unfragmented three-address FromDS frame addressed to the current helper can be copied from unknown-peer REO handling. Its RX_HEADER, compact metadata and actual DMA buffer prefix must agree. The copy retains the hardware FCS and omits radiotap CHANNEL instead of inferring it from the current session; the original buffer remains owned by the existing receive path. |
| Other normal STA data decapped to Ethernet | Normal Android delivery is preserved. There is no general conversion into monitor frames; the helper copy excludes protected frames, fragments and A-MSDUs. |

WMI management copies may duplicate frames also delivered through RAW reception.
Hardware filtering and capture drops can still leave gaps; seeing some data or
control frames does not establish complete beacon or probe-response reception.
Do not infer one global FCS format from the first packet in a mixed capture.

### Native tool compatibility

The tested [Bully 2.0 fork](https://github.com/Loukious/bully/tree/fix/preserve-monitor-channel)
at commit `449ad51995d98477b69468be8f380bd93948bc65` includes these native
compatibility fixes:

- Include ACK frames addressed to the monitor in its capture filter.
- Preserve the existing full channel definition when the requested primary
  frequency already matches, instead of issuing a narrower channel request.
- Read radiotap FCS presence per packet, so management copies without an FCS do
  not disable CRC checks for later RAW frames. Explicit `-N`/`--nofcs` remains
  an override.
- Retain addressed authentication, association and EAPOL replies that arrive
  while waiting for a separately delivered ACK, then use them for the next
  matching protocol read. An acknowledged send still requires its ACK.
- Use supported rates for the selected band in probe requests.
- Answer repeated EAP Identity requests, including identifier zero, within
  one M1 deadline and honor cancellation during that wait.

Run a build containing all these fixes directly; no wrapper or compatibility
preload is required. The standalone ACK-filter fix alone is insufficient for
this mode. The Kali chroot must have `/dev` mounted so Bully can access the
device files it requires. Use the normal chroot launcher to establish these
mounts before running WPS.

### Automatic handoff validation

The 2026-11-10 driver with automatic handoff and deferred PNO passed the
following device tests. Both known-PIN credentials matched the owned ASUS
RT-AX86U configuration. Tests used the native Bully build linked above.

| Check | Observed result |
| --- | --- |
| Start shared on channel 52, 80 MHz, center 5,290 MHz | Android stayed associated; all 10 baseline pings replied. |
| Select channel 1 at 20 MHz | Handoff returned in 0.19 seconds. Android disconnected; monitor ifindex, MAC and capture PID were retained. |
| Exclusive retunes to 6/20, 36/80 and back to 1/20 | All passed on the same interface. Ordinary scans were rejected while exclusive. |
| Same-primary width mismatch and unsupported DFS target | Both were rejected before disconnecting Android. |
| Known-PIN WPS on channel 1 after handoff | Credential retrieval completed in 0.56 seconds. |
| Close the exclusive monitor | PNO resumed after monitor-vdev destruction. Android associated 1.28 seconds later, detected by the two-second link poll, without a post-close scan request or Wi-Fi toggle. |
| WPS against a different BSSID on the shared channel 52/80 | Credential retrieval completed in 0.40 seconds; all 1,400 overlapping pings and 10 subsequent pings replied. |

The first three pings immediately after reassociation were lost while network
setup settled; the next seven replied and Android reported a validated
connection. The subsequent sustained shared-channel traffic test had no loss.
Across the two runs, all 26 submitted injections completed, including 14 EAPOL
frames, with no reported send/completion failure, unknown completion or timeout.
Module references returned to zero and the kernel boot ID remained unchanged.

Both captures contain all 13 owned-router EAPOL frames with exactly matching
payloads and directions. Each run's six AP-to-helper RAW EAPOL frames have
independently valid FCS values and omit inferred channel metadata. Tcpdump
reported 822 kernel drops during handoff and 485 in the shared run, so these
captures are not complete records of all traffic. The observed deferred PNO
request used request ID zero; cancellation of a still-deferred request, nonzero
request IDs and concurrent cancellation races were reviewed in source
but were not exercised by these device trials.

The post-teardown stability observation for this exact module passed all 48
checkpoints over 2,114.98 seconds of device uptime. Android stayed connected,
the boot and loaded module remained unchanged, and module references stayed
at zero. Injection counters did not change. No critical kernel fault,
zero-physical-address event, trace loss or missed probe was recorded.

Two receive pools retired before these monitor tests still retained one page
each. The tests therefore do not establish complete page-pool retirement or
rule out every delayed crash. Earlier measurements below are retained as
results of the preceding shared-mode driver.

### Earlier shared-mode qualification

The 2026-11-10 RX09 revision06 candidate completed known-PIN WPS with native
Bully 2.0 against the owned ASUS RT-AX86U in both configurations below. Android
and the target shared channel 52, 80 MHz bandwidth and center frequency
5,290 MHz. Both recovered credentials matched the router configuration.

| Android connection relative to WPS target | WPS duration | Ping replies strictly during monitor use |
| --- | --- | --- |
| Different BSSID | 0.41 seconds | 973 |
| Same BSSID | 0.52 seconds | 972 |

Each run received all 1,400 Android pings across creation, WPS, capture and
teardown, plus all 10 subsequent pings. The STA identity, full channel
definition and Android settings were preserved, module references returned
to zero, and no reboot occurred. Each run submitted and completed 13 injected
frames, including seven EAPOL frames, with no reported failures or timeouts.
Both filtered captures decoded without malformed records or reported socket
drops; this does not establish complete reception of all over-the-air traffic.

For the different-BSSID run, all 13 ordered EAPOL records matched the router
capture byte for byte through M7. All six AP-to-helper EAPOL frames retained
their RAW frame data and independently valid FCS. The earlier failure was a
host receive-path gap: replies from an AP absent from Android's peer table
arrived through unknown-peer REO handling and were skipped. The bounded RAW
copy handles those replies without changing peer tables or firmware filters.

Passive capture, full-MTU Android traffic and received-header layout checks
also passed. All 30 DF pings with 1,472-byte payloads arrived both before and
during monitor use. The header-enabled WCN7750 layout uses a 264-byte prefix
and at least 2,048-byte data and monitor buffers to retain full-MTU reception;
this increases receive-buffer memory use.

The final post-teardown observation passed all 48 checkpoints over 2,115
seconds of device uptime. Android remained connected, the boot and loaded
module stayed unchanged, injection counters remained at their post-test values,
and module references remained zero. The guards recorded no critical kernel
fault or zero-physical-address event, trace loss or missed probes.

A receive pool retired during the preceding module replacement still retained
five pages. Its destruction fell between the old and new recorder sessions,
so its original ownership was not recovered. The successful bounded observation
does not establish that every delayed crash or unrelated Android error is fixed.

## Run a Kali hostapd AP with mon0

Patch 0252 adds experimental AP/monitor coexistence for the internal WCN7750.
Bounded device checks passed on channel 5 at 20 MHz. This is a Kali hostapd
workflow using ordinary nl80211 AP operations; it does not integrate Android's hotspot
framework. Load the matched driver with `ap_monitor_coexist=1` in the normal
module-loading step. The flag defaults to off and is read-only after loading.
Module replacement still requires the framework shutdown and driver drain
described above.

For example, the module-loading command can include both independent opt-ins:

```sh
insmod /path/to/qca_cld3_wcn7750.ko ap_monitor_coexist=1 sta_monitor_coexist=1
```

`sta_monitor_coexist=1` is optional and enables the alternative connected-STA
workflow. Those two flags alone do not permit connected STA+AP+MON operation;
the [separate triple-interface option](#keep-android-wi-fi-connected-with-a-kali-ap-and-monitor)
is described below. For this AP-only workflow, before starting hostapd, fully
stop Android Wi-Fi management, its HAL/supplicant ownership, and
background or scheduled scanning, including scan-always-available and PNO.
Verify that no STA connection or scan remains; disabling the Wi-Fi toggle
alone can leave background scanning enabled. Keep Android's Wi-Fi management
stopped for the AP session.

Start one real, non-MLO AP first. Admission requires a ready BSS on an enabled,
non-DFS 2.4/5 GHz channel with 20, 40 or 80 MHz bandwidth. `mon0` inherits the
AP's **full channel definition**, including primary frequency, bandwidth and
center frequency. A second center segment, puncturing, 6 GHz, CAC, an ongoing
channel change, or another active owner prevents admission. Use a fixed legal
channel in hostapd's configuration, with `interface=wlan0` and
`driver=nl80211` (adjust the interface name for the device).

With Android management already stopped and the matched opt-in driver loaded,
run the following in Kali:

```sh
hostapd -B /path/to/hostapd.conf
# Wait for AP-ENABLED in hostapd's log before creating the monitor.
iw dev wlan0 info
iw dev wlan0 interface add mon0 type monitor
ip link set mon0 up
iw dev mon0 info
# Capture or inject on the inherited channel, then stop those processes.
ip link set mon0 down
iw dev mon0 del
```

Keep hostapd running through monitor creation, use and teardown. Closing and
deleting `mon0` releases the native monitor and private helper; it does not
stop the real AP or delete its clients, keys or beacon. Stop or reconfigure
hostapd after the monitor has fully closed.

| Operation while the AP monitor owns resources | Result |
| --- | --- |
| Monitor requests the identical full channel definition | Success with no radio retune. |
| Monitor requests a different primary, width, center or puncturing | Busy before any handoff, drain or AP disconnection. |
| User requests AP CSA or another competing radio operation | Busy; close the monitor before changing the AP channel or starting another role. |
| Normal on-channel AP management and client traffic | Continues through the real AP's normal paths. |
| Required regulatory, firmware or AP-stop transition | Invalidates optional capture/injection; it does not promise continuous monitor service. |

The AP, monitor and separate non-beaconing injection helper share airtime and
radio/vdev/peer resources. Firmware capability and resource checks can reject
helper setup. Heavy capture or injection can affect client throughput and
latency. Stop failure or uncertain firmware completion retains resources and
rejects unsafe reuse. There is no automatic monitor replay or seamless AP and
client recovery across a Wi-Fi subsystem restart (SSR). A failed or deferred
AP transition keeps monitor admission closed until a fresh successful AP
completion or restart.

The existing [capture contracts](#capture-limits) still apply. The bounded
Ethernet/EAPOL fallback accepts plaintext FromDS traffic addressed to the
private helper; it does not establish complete capture of the real AP's
clients' ToDS traffic. Capturing the AP's own transmitted beacons is also
unqualified. RAW and WMI management reception may provide useful frames, with
their documented metadata and filtering limits. The earlier STA/WPS results
qualify the separate STA workflow; AP checks are recorded below.

### AP device check (2026-11-10)

The matched driver built locally in 102 seconds. Its SHA256 was
`62e4fa177654ac0f897fd71cb63863cfaad3417a0976e0085689710b2fb4f3bf`.
Three immediate-start checks completed all 60 injected frames without a
transmit error. These checks cover the fix that refreshes the real AP's
current transmit-power limits before monitor admission; a late regulatory
update could otherwise leave the initial power cache invalid.

A separate USB Wi-Fi client joined the Kali hostapd WPA2 AP on channel 5 at
20 MHz and obtained a DHCP lease. It received all 243 UDP echoes in the
measured window before the deliberate client deauthentication. Monitor
creation, quiet injection, rejected channel requests, and monitor close/reopen
preserved the AP and client association. All 21 new injected frames completed
without send failures, failed or unknown completions, or timeouts.

The single directed deauthentication caused the test client to reconnect and
complete a new WPA2 handshake. All 11 missed UDP replies followed that event;
the next 287 replies succeeded. Overall, 599 of 610 requests received replies.
Traffic also passed during the monitor itself (180/180), across monitor
close/reopen (59/59), and after reopening before deauthentication (10/10).

The two monitor captures contained 1,032 received records and 21 outgoing TX
copies. Received records included 419 beacons from the other AP on channel 5
and nine management frames from the lab client. All received records reported
2432 MHz. The filtered capture contained no local AP beacons, local client data
or plaintext EAPOL; successful client traffic does not imply those frames are
available through `mon0`.

The different-channel monitor request returned busy, and hostapd rejected a
requested channel switch while the monitor was active. Stopping hostapd with
the monitor still open brought the monitor down and released the helper's
module references. Cleanup restored Android's previous Wi-Fi connection and
removed the temporary client profile and lab route. The phone's boot ID was
unchanged, and the PC's primary Wi-Fi connection stayed on its original network.
The trial's kernel-log interval had no panic, oops or SSR signature. Existing
DP/MLO/TPC/beacon warnings remained; this is not a claim of warning-free logs.

This is a bounded 2.4 GHz/20 MHz check. AP operation at other supported widths
or on 5 GHz, long-duration stability, and recovery across SSR remain unqualified.

## Keep Android Wi-Fi connected with a Kali AP and monitor

Patch 0253 adds a separate experimental `sta_ap_monitor_coexist=1` module
parameter for the internal WCN7750. It defaults to off and is read-only after
loading. The existing STA/monitor and AP/monitor parameters enable their
alternative workflows; neither is a substitute for this third opt-in. Load
the exact matched driver using the normal framework shutdown and drain, then
reconnect Android before starting the AP. Android manages its station normally
during this session.

Admission requires exactly one stable connected non-MLO STA and one ready
non-MLO AP on the same physical radio and **full channel definition**: primary
frequency, width, center frequencies and puncturing. Driver admission limits
are enabled non-DFS 2.4/5 GHz at 20/40/80 MHz, with no second center segment or
puncturing; device qualification covers only channel 5 at 20 MHz. Firmware must
also grant enough vdev IDs, peers and beacon capacity for the real STA/AP,
monitor and private non-beaconing injection helper. Down or deleting interfaces
can still consume resources.

Keep Android connected and create a separate, idle AP interface. Adjust the
station name and use a private hostapd configuration with `interface=ap0`,
`driver=nl80211` and the station's complete current channel definition. Wait
for `AP-ENABLED` before creating the separate monitor. For a plain hostapd
session, run these commands inside Kali:

```sh
iw dev wlan0 info
iw dev wlan0 link
iw dev wlan0 interface add ap0 type __ap
hostapd -B /path/to/hostapd.conf
# Wait for AP-ENABLED in the owned hostapd log.
iw dev ap0 info
iw dev wlan0 interface add mon0 type monitor
ip link set mon0 up
iw dev mon0 info
# Capture or inject on the inherited channel, then stop those processes.
ip link set mon0 down
iw dev mon0 del
# Stop the owned hostapd process after monitor teardown.
iw dev ap0 del
```

Plain hostapd does not configure AP-client DHCP or Internet forwarding. For
application-managed DHCP, scoped forwarding/NAT and directed injection, use
the [Wifipumpkin3 v6 bundle](wifipumpkin3/README.md), including its Android BPF
mount preparation and explicit upstream DNS selection.

The AP owns the monitor's channel and transmit power; the station is a second
tracked owner. All roles share airtime. Monitor retuning, scanning, off-channel
work and competing connection requests are blocked while the AP lease is
held. Station disconnect or a mandatory owner/channel transition quiesces
optional monitor injection. After the station reconnects on the same complete
channel, recreate/reopen the monitor; this path does not automatically resume
it or allow an exclusive channel handoff. AP teardown also quiesces the monitor
and releases its helper. Close/delete the monitor before an ordinary AP stop
or reconfiguration. Uncertain native stop or DMA completion keeps resources
quarantined and prevents unsafe reuse.

The existing [capture contracts](#capture-limits) and AP-client capture limits
above still apply. Successful forwarding and injection do not establish full
capture of the local AP's beacons, client ToDS data or plaintext EAPOL through
`mon0`.

### Triple-interface device checks (2026-11-11)

The frozen v6 application passed all 17 main runtime audit checks on
Onyx/WCN7750, non-MLO channel 5, 2432 MHz, HT20/20 MHz. Static mode, noproxy and
Python DHCP were used with interception, AP-local DNS and packet-sniffing
backends disabled. A separate USB AP client completed source-bound SSH banner
retrieval, certificate-validated TLS 1.3 HTTPS with HTTP 200, and DNS queries
forwarded to an explicit upstream resolver, both before monitor creation and
during monitor/injection. Correlated AP and STA packet captures verified
forwarding, SNAT, replies and matching payloads.

The USB client received all 423 UDP echoes before the deliberate directed
frame. Across the complete trial it received 561 of 568 replies, with seven
timeouts and no unexpected replies. Wifipumpkin3's actual `ModPump`/
`ThreadDeauth` worker sent one AP-to-client frame; together with 20 quiet test
frames, all 21 driver completions succeeded with no send failures, failed or
unknown completions, or timeouts. Completion counters alone do not prove RF
receipt. Stopping the AP owner quiesced the monitor and helper.

The actual application exited with status zero. Its current scoped-network
journal was restored with no pending cleanup; the firewall was restored exactly
apart from counters and printer timestamps. All 137 ordered policy rules and
12 routes were restored with every recorded field retained, along with the
forwarding setting. The boot remained unchanged.

A separate companion lifecycle check passed all 30 assertions with
observations: disconnecting the station quiesced the monitor while the AP
remained enabled; reconnecting on the same channel and recreating/reopening
the monitor restored injection, with 20 successful completions before and 20
after reconnect and no injection errors. AP stop quiesced the monitor while
the station stayed connected. Scoped cleanup removed only owned resources and
restored the firewall and forwarding setting. Four Android/Netd policy rules
added during reconnection were retained, so this separate check does not claim
exact restoration of the entire policy-rule list. Its boot and module identity
were unchanged, and its bounded log interval contained no crash or SSR marker.

These results cover this short non-MLO 2.4 GHz/20 MHz profile. Other channels
and widths, DFS, MLO, AP-local DNS, interception/sniffing backends, long-duration
stability and SSR recovery remain unqualified. The companion test establishes
lifecycle and completions; its separate result does not independently establish
RF receipt or client Internet/DNS behavior.

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

## Temporary standalone device bundle

The scripts below implement the standalone test path. They temporarily pause
Android Wi-Fi management and may select a monitor channel. They are not the
coexistence qualification workflow described above.

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
