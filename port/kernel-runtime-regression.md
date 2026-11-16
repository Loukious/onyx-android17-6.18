# Linux 6.18.63 runtime regression

The full recovery installer reached Android's boot animation on Onyx, then
panicked. Restoring the exact six kernel and driver images from the installed
Evolution X ROM recovered Android on Linux 6.18.39 without wiping userdata. All
six restored partition hashes matched that ROM's OTA manifest.

The captured blackbox contained three consecutive 6.18.63 crash records. Two
reported a modem IPA fatal interrupt, followed by a remoteproc panic or modem
shutdown-notifier timeout. The third reported an IPA SMMU translation fault
before the driver's fatal-fault BUG. Recovery ADB also failed USB enumeration.
The oops partition held older 6.18.38/39 records; pstore was empty.

The ARM SMMU adaptation now records successfully unmapped bytes in the core
IOMMU gather. Linux 6.18.63 skips the domain sync callback for an empty gather;
the Qualcomm backend previously recorded pending invalidations only in its
private state. Without a core range, strict unmap could return before the
required context flush. Patch 0271 restores that synchronization contract.

Patch 0270 removes an obsolete dentry member from the FunctionFS logger's copy
of the private endpoint structure. It restores the endpoint-name field offset
used by the current common kernel. The other copied FunctionFS structures were
checked against their current definitions.

The targeted host regression executes the production common unmap loop, gather
helpers and vendor wrapper under ASan/UBSan. The fixed source passes eleven
cases. The exact pre-fix source fails five Qualcomm cases with simulated stale
DMA reaching reused memory; the six control cases still pass. Run it with:

```bash
python3 port/verify_iommu_gather.py
```

The host backend models the device and context flush. This verifies the software
synchronization contract; it does not establish that the hardware panics are
fully resolved. The corrected recovery package rebuilds the two affected
modules against the unchanged 6.18.63 kernel. Wonder builds and radio testing
remain deferred.

## Fixed4 device check — 2026-11-16

The matching 6.18.63 Fixed4 package booted Android on the global POCO F7.
Android reported boot complete with the boot animation stopped. Both corrected
module file hashes and the loaded ELF build-id notes matched the package:

| Module | SHA256 |
| --- | --- |
| `arm_smmu.ko` | `29c5a8772e32bd581248353fdecc35d5fc5546fc3fba59ca9a2c8261f9b643c1` |
| `f_fs_ipc_log.ko` | `45488ed9fdc57181a6e4b7dfd4842ab547d0f60aa1035ac0bc773395fea5d887` |

The final uptime was 642 seconds (10.7 minutes), beyond the earlier 12–38 second
crash window. Twelve samples over 332 seconds retained the same boot ID, running
modem and configured USB state. Kernel taint stayed at 4096, reflecting only
out-of-tree modules. Initial and final kernel logs contained no prior IPA/SMMU
fatal signature, kernel BUG/Oops or warning stack. Pstore was empty and crash
partition hashes remained unchanged during testing.

Three 32 MiB ADB transfers in each direction passed device and host SHA256
checks: 96 MiB uploaded and 96 MiB downloaded. Wi-Fi gateway and Internet probes
received all 40 and 20 packets respectively. Both SIMs registered on LTE. Mobile
data was disabled, so cellular traffic was not tested.

This establishes a successful initial Android boot and basic USB/network behavior
in one boot. The tester subsequently reported working ADB in recovery. The saved
follow-up capture was taken after Android had started, so recovery logs and
transfer checks were not independently captured. Long-term stability, cellular
traffic and suspend/resume remain pending. Wonder/AWDL testing remains deferred.
