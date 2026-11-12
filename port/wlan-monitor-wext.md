# WCN7750 monitor WEXT channel compatibility

Stock Reaver/Wash 1.6.6 selects monitor channels with `SIOCSIWFREQ`.
The monitor handler previously exposed the frequency getter without its
setter, so the ioctl returned `EOPNOTSUPP` even when nl80211 tuning worked.
Reaver logged channel switches before checking the ioctl result. Wash could
decode captured WPS beacons offline while its live channel gate suppressed
the same access points.

Patch `0256-add-monitor-wext-channel-compatibility.patch` adds the setter only
to monitor interfaces. It reuses the existing cfg80211 monitor operation
under WEXT's RTNL lock, the wiphy lock, and a psoc operation. No Reaver,
Wash, Bully, airmon-ng, firmware, or Android userspace changes are required.

Channel numbers and exact MHz frequencies are accepted for single-link
2.4/5 GHz monitors. Malformed and automatic requests, disabled channels,
6 GHz, and multi-link operation are refused. A request for the active
primary is a verified no-op preserving width, centers, and puncturing.
A changed primary requests 20 MHz through the existing monitor channel
path, including regulatory, AP ownership, injection drain, and firmware
completion checks. Success requires matching active channel readback.

Shared monitors stay on the complete STA/AP channel. Selecting another
primary invokes the driver's existing exclusive capture handoff, which can
disconnect Android Wi-Fi until capture ends; an AP owner refuses that handoff.
This compatibility bridge does not create independent simultaneous channels.

Verification on 2026-11-11:

- The extracted production parser, getter, bridge, and callback passed
  63 ASan/UBSan cases. Programming and firmware primitives are mocked.
- A full cached WLAN-module rebuild compiled all 814 objects in 88.832 s,
  regenerated export CRCs, checked 554 imports against the running kernel,
  and retained all 993 existing exported symbol CRCs.
- Patch 0256 applied with zero fuzz to the three base source files and
  reproduced the compiled files byte for byte.
- On Onyx, same-primary WEXT preserved channel 52/80 MHz and the associated
  station. Stock airmon-ng start/stop and WEXT channels 1/6/11/36 matched
  nl80211 readback. The 2.462 GHz frequency encoding matched channel 11.
- Invalid channel 0/197 and a 6 GHz request failed without changing channel.
  All 100 captured beacons were structurally valid. Unmodified Wash survey
  mode with zero probes showed three fixed-channel WPS rows and five rows
  while hopping, including the originally missing channel-11 access point.
- Cleanup removed every test monitor, restored the original validated
  Android network and all three coexistence flags, and left zero WLAN helper
  references. The kernel boot ID stayed unchanged.

The built module SHA-256 is
`6f3491ed3f96c6fe6e338ac3e0c56b3875f2cc66bd36b2affb244646ed044052`.
It targets `6.18.38-android17-6-maybe-dirty-4k`; module artifacts and private
runtime evidence are retained outside this repository.

The qualified module is installed and saved in the existing KernelSU WLAN
payload. The module and checksum manifest were replaced through a guarded
file transaction; the prior `6fec2ff9...` module is retained for rollback.
The loader script, module metadata, ABI table, and ABI verifier retained
their exact bytes, inodes, ownership, modes, and SELinux labels. Fresh-boot
automatic loading remains untested.

Run the host checks with:

```sh
python3 port/verify_wlan_monitor_wext.py modules
```

`port/stage.py` applies patch 0256 after the existing monitor compatibility
and RX filter patches. The host and replay receipts are stored beside this
document.

No active WPS/PIN exchange or reboot was performed. Reaver's channel ioctl
is qualified through the same stock-Wash path; successful PIN authentication
is not established. Bully's blocking libpcap timeout issue remains separate
and unfixed. AP ownership, MLO, 6 GHz, wide/punctured retunes, and long-duration
operation were not freshly qualified. The existing WEXT getter can expose
stale desired state after a failed retune; the new setter verifies active
state instead. A deferred page-pool shutdown warning for pool 124 was present
before WEXT qualification and continued; no new pool ID or critical kernel
marker appeared during these checks.
