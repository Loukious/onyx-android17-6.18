# Qualified monitor fixes and native WLAN loading

The development Onyx/WCN7750 loaded the qualified WLAN driver directly from
`vendor_dlkm` after a fastbootd installation and reboot on 2026-11-12. The
optional KernelSU WLAN manager was removed. Android Wi-Fi reconnected, with
Wi-Fi and background scanning enabled.

The installed driver comes from source commit
`72fc4683206acedb0a47dd1ed5578717e692c699` and targets
`6.18.38-android17-6-maybe-dirty-4k`.

- Module SHA256: `2805550b10df8d901d14b0dfa7a08a28ca992eb3c82dd66079ed7ab2360fec5e`.
- Loaded build-note SHA256: `b13ac377901161a65fdec6f0704036c98b6a10652fcacb2b8acd0914789d2172`.

Patch 0256 supplies the monitor WEXT frequency setter used by stock Wash and
Reaver. Its extracted production parser, bridge and callback passed 63
ASan/UBSan cases. Live WEXT channel-number and frequency requests agreed with
nl80211 readback, and stock Wash survey mode received WPS beacons.

Patches 0257/0258 accept compatible narrower shared-channel requests, reset
receive pause when arming a new monitor generation and return Linux errors
for failed monitor opens. The complete driver rebuild compiled 814 objects,
checked 555 imports and retained all 993 existing exported symbol CRCs.
Three monitor restarts received 80 valid beacons. Two passive upstream
hcxdumptool runs received 133 and 134 beacons while Android stayed connected.

Native boot options:

```text
options qca_cld3_wcn7750 sta_monitor_coexist=1 ap_monitor_coexist=1 sta_ap_monitor_coexist=1
```

The source-build ROM profile supplies this line through
`port/rom/module-layout.json` and
`port/rom/module-config/vendor_dlkm/modules.options`. Driver defaults remain
opt-in on installations that do not supply these options.

The tested image replaced only the driver and added `modules.options`.
All 465 resulting entries were checked; existing file bytes, ownership,
modes, timestamps, SELinux labels and filesystem UUID were preserved.
The AVB hashtree/footer was regenerated for the existing disabled-verification
configuration. After reboot, the full partition readback and loaded build
note matched, all three coexistence parameters were `Y`, vendor module
loading completed and the KernelSU WLAN module directory was absent.

The phone shares physical `vendor_dlkm` extents between its two slots, so
the driver-only flash also changed the bytes visible to the inactive slot.
Only the active slot was boot-tested. This result does not qualify the
complete recovery installer, every ROM layout, another kernel/ABI or
long-duration RF capture. Shared-monitor arbitrary MAC changes remain
unsupported, and passive capture can drop packets. Original partition and
module backups, raw captures and device-specific logs remain private.
