# Wifipumpkin3 with Android Wi-Fi, an AP and monitor

This optional application patch retains normal IPv4 forwarding and NAT so AP
clients can use Android's connected station for Internet access. It owns the
AP's address, dedicated firewall chains and policy routes, allowing their
cleanup to preserve Android's existing networking.

The bundle targets Kali `wifipumpkin3 1.1.7-0kali3`, source revision
`14b8c4d960cd33816ba9c64cb1fba69a44170b10` with its distro patches applied. V6
includes address-free AP identity handling and uses the AP address's generated
connected route so hostapd link cycles do not discard a private routing-table
copy. It also verifies owned routes before cleanup, supports explicit DHCP DNS,
and runs bounded directed deauthentication through an existing monitor.
The manifest records the exact nine original and ten patched files.
Upstream application files retain their Apache 2.0 license and copyright
headers; [LICENSE.md](LICENSE.md) contains the upstream license.

## Install the application patch

Copy this directory into Kali, for example `/root/wfp3-coexist`, and install the
matching Kali package. Locate its installed package parent with
`dpkg -L wifipumpkin3`; it is normally `/usr/lib/python3/dist-packages`.
Run these commands **inside Kali as root**:

```sh
cd /root/wfp3-coexist
python3 verify_overlay.py --root /usr/lib/python3/dist-packages --state before
tar -czf /root/wifipumpkin3-package-before.tar.gz \
    -C /usr/lib/python3/dist-packages wifipumpkin3
patch --dry-run --batch --forward --fuzz=0 -p1 \
    -d /usr/lib/python3/dist-packages < preserve-upstream-v6.patch
patch --batch --forward --fuzz=0 -p1 \
    -d /usr/lib/python3/dist-packages < preserve-upstream-v6.patch
python3 verify_overlay.py --root /usr/lib/python3/dist-packages --state after
```

The verifier must pass before applying the full patch. An already patched
package must be restored to the matching original files or updated with an
appropriate verified incremental patch. The optional source overlay contains
the same ten patched files; apply either the patch or overlay once.

To restore the package, stop Wifipumpkin3 and complete its scoped cleanup,
restore the saved package files, remove the newly added
`wifipumpkin3/core/common/scoped_network.py`, and verify the `before` state.
Keep application configuration and backups private.

## Prepare the driver and AP profile

Load the matching WLAN driver with `sta_ap_monitor_coexist=1` and connect Android
normally. This parameter is disabled by default and read-only after loading.
The driver requires one stable non-MLO STA and one non-MLO AP on the same
physical radio and **complete channel definition**: primary frequency, width,
center frequencies and puncturing. It also checks space for the monitor and
private native injection helper. All interfaces share the radio's airtime.

Create a separate, idle AP interface, substituting the actual station name:

```sh
iw dev wlan0 interface add ap0 type __ap
iw dev wlan0 info
iw dev wlan0 link
ip link show dev ap0
```

The AP must have no IPv4 address before the application starts. Its subnet must
avoid existing interface subnets. The selected upstream must be up with an
unambiguous IPv4 gateway and connected address. Android remains responsible for
its station association and reconnection.

Fill every placeholder in [example.pulp.in](example.pulp.in), including the real
AP interface MAC as `bssid`, a private SSID/PSK and the upstream's current
channel. Save the completed file inside Kali with mode `0600`. Its example
hostapd settings use 2.4 GHz at 20 MHz; change the complete hostapd channel
configuration to match the station before use. Matching only the channel number
is insufficient when the negotiated width or center frequency differs.

The application profile uses `static`, `noproxy`, and Python DHCP, with
interception, packet sniffing and DNS-server backends disabled. Forwarding/NAT
remain enabled. Choose a known DNS resolver reachable through the selected
upstream, such as the DNS service on your own router, and pass its IPv4 address
with `--dhcp-dns`. Repeat the option for each resolver you explicitly select.
This supplies the AP gateway and chosen DNS addresses in both DHCP OFFER and
ACK replies. A missing resolver is rejected before AP setup when upstream
preservation is enabled and the local DNS server is disabled.

`--lab-dhcp` separately omits gateway and DNS options for a test client that
keeps another network connection. Omission takes precedence even when
`--dhcp-dns` is supplied. Use lab mode only for such a test fixture. With
upstream preservation disabled and no explicit DNS option, stock Kali DHCP
behavior remains unchanged. An AP-local DNS backend needs separate qualification.

## Launch from Android

Copy `wifipumpkin3-android.sh` to `/data/local/tmp`. Run it from an **Android
root shell outside Kali**:

```sh
sh /data/local/tmp/wifipumpkin3-android.sh check
sh /data/local/tmp/wifipumpkin3-android.sh prepare
sh /data/local/tmp/wifipumpkin3-android.sh run \
    --ap ap0 --upstream wlan0 -- -m static \
    --dhcp-dns __UPSTREAM_DNS_IPV4__ --pulp /root/ap.pulp
```

Replace `__UPSTREAM_DNS_IPV4__` with your selected reachable resolver address.

The helper targets `/data/local/nhsystem/kali-arm64`, clears Android's inherited
`HOME` and `LD_PRELOAD`, and always passes `--preserve-upstream`. Wifipumpkin3
arguments and file paths after `--` refer to the Kali environment. The helper
requires both interface names explicitly.

Android's legacy iptables rules reference pinned BPF programs under
`/sys/fs/bpf`. Kali must see the same objects before it can update those tables.
The helper reads the actual paths with Android's native `iptables-save`, checks
the bpffs mount and inode identities, and binds Android bpffs into an empty,
unmounted Kali target when needed. A matching mount is reused. The bind remains
available for later launches until chroot teardown or reboot; run the launcher
in the same Android mount namespace as the prepared chroot.

Wait for hostapd's `AP-ENABLED` and verify the AP and STA channel definitions
before adding the monitor:

```sh
iw dev wlan0 interface add mon0 type monitor
ip link set mon0 up
iw dev ap0 info
iw dev mon0 info
```

## Use the application's directed deauth module

With the AP and existing monitor running on that complete channel definition,
use the application's own module from the Wifipumpkin3 console. Substitute the
MAC of your own AP client and the BSSID of your own test AP:

```text
use wifi.wifideauth
set interface mon0
set client __OWN_AP_CLIENT_MAC__
set count 1
set direction ap-to-client
add __OWN_AP_BSSID__
start
```

The preserved-upstream profile validates the already-up monitor, AP and STA as
distinct interfaces on the same radio and complete channel. It disables channel
hopping and uses the existing monitor without converting the AP or station
interface. The target BSSID must be supplied explicitly on the current channel.
The sample sends one frame toward the selected unicast client. This profile
requires a finite `count` from 1 to 1,000 and accepts `ap-to-client` or `both`;
the qualification targets `count 1` with `ap-to-client`.

Wait for the bounded worker to finish, then use `back` to return to the main
prompt. Use the module's `stop` command to finish any running worker before
monitor teardown.

## Stop and clean up

Stop capture/injection and remove the monitor before stopping the application:

```sh
ip link set mon0 down
iw dev mon0 del
# Use Wifipumpkin3's stop/exit commands, or send SIGINT to its owned process.
# After application shutdown and cleanup:
iw dev ap0 del
```

`--run-seconds N` provides a bounded headless pulp run for 1–300 seconds. It uses
the Qt event loop and the real application controllers, hostapd and Python DHCP.
Readiness requires `AP-ENABLED`; startup or cleanup failures produce a nonzero
exit. Its timer starts after pulp initialization, so an external watchdog is
still needed when bounding initialization or a process crash.

## Validation and limits

Forty-six host checks pass for interface identity, scoped networking and setup
rollback, hostapd link cycling, verified route cleanup, DHCP serialization and
CLI propagation, owned service lifecycle and directed deauth. DHCP and Scapy
packet checks use their real serializers; Qt, process and radio adapters are
simulated.

The frozen v6 application passed all 17 main runtime audit checks on
Onyx/WCN7750 on 2026-11-11: non-MLO channel 5, 2432 MHz, HT20/20 MHz, static mode,
noproxy and Python DHCP. Android remained connected while a separate USB AP
client retrieved a source-bound SSH banner, completed certificate-validated
TLS 1.3 HTTPS with HTTP 200, and obtained DNS answers through an explicit
upstream resolver, before monitor creation and during monitor/injection.
Correlated AP and STA captures verified forwarding, SNAT, replies and payloads.
DNS forwarding is qualified; the AP-local DNS server remains unqualified.

The AP client received 423 of 423 UDP echoes before the deliberate directed
frame and 561 of 568 across the full trial, with seven timeouts and no unexpected
replies. The application's actual `ModPump`/`ThreadDeauth` worker sent one
AP-to-client frame. Together with 20 quiet test frames, all 21 driver
completions succeeded without send failures, failed or unknown completions,
or timeouts. These counters alone do not prove RF receipt. AP-owner shutdown
quiesced the monitor and helper.

The application exited zero and restored its current scoped-network journal
without pending cleanup. Firewall rules were restored exactly apart from
counters and printer timestamps, as were all 137 ordered policy rules, all 12
full-field routes and the forwarding setting. The boot remained unchanged.
The Android launcher separately passed its expected failure before BPF bind,
bind preparation, matching-pin check and `run` CLI-help check; full application
services were qualified in the independent runtime trial above.

A [separate companion lifecycle check](../README.md#triple-interface-device-checks-2026-11-11)
verified station disconnect quiescence while the AP remained enabled, same-channel
reconnection and monitor reopening, and 20 successful completions before and
20 after reconnect without injection errors. Four new Android/Netd policy rules
were preserved, so that check does not claim exact whole-rule-list restoration.

Interception, DNS poisoning, AP-local DNS and packet-sniffing backends, other
channels or widths, DFS, MLO, multiple application instances, long-duration
stability and SSR recovery are outside this qualification. The driver can
reject unsupported channel/resource combinations before monitor creation.
Retuning while the AP lease is held is blocked; an owner disconnect or
mandatory channel change revokes optional monitor injection. Restore a stable
same-channel station and recreate/reopen the monitor before resuming injection.

The application journal is
`~/.config/wifipumpkin3/scoped-network-<token>.json`, mode `0600`. Failed cleanup
retains pending inverse actions for review and retry. There is no automatic
recovery after SIGKILL or arbitration between multiple instances. Run one
instance and use normal application shutdown so its scoped cleanup completes.
