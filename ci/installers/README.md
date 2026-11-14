# Release installers

`ci/installer_assets.py` packages the exact verified `gki/Image` and
`platform/qca_cld3_wcn7750.ko` from a build bundle. Installer ZIPs are recreated during
release validation; altered ZIP bytes are rejected even if the outer checksums
were regenerated. Archive ordering, modes and timestamps are deterministic.

Current releases also include `Onyx-NetHunter-External-WiFi-KSU-Module.zip`.
It packages the nine Realtek/Ralink/Atheros USB WLAN modules, their complete
dependency closure (14 binaries for the current recipe), and all 16 requested
firmware files with redistribution notices and corresponding ATH source. Module
selection uses verified platform metadata and the matching native module archive;
an absent dependency, conflicting provider, changed firmware or mismatched kernel
release aborts packaging. Public ZIP names and manager versions omit the raw
kernel release; the exact release and source identities remain in `installer.json`
and runtime checks. Legacy release bundles still recreate their original bytes.

Install the external module from KernelSU Next or Magisk after booting the matching
kernel, then reboot. Its manager ID remains `nethunter-extra-modules`, so this
updates the earlier package rather than running two firmware loaders. Existing
loaded drivers, including shared cfg80211/mac80211 providers, are kept. Only missing
modules are inserted in dependency order, and a failed insertion stops loading.
The internal WCN7750 replacement stays in its separate installer.

Firmware is exposed by a read-only bind at an existing kernel firmware search
directory, such as `/odm/firmware/o10u`. The helper copies the complete ROM tree,
including nested/hidden files and symlinks, restores each original SELinux context,
and adds the named payload files with root ownership, 0755 directories and 0644
files. A differing ROM firmware file or symlink collision aborts; no ROM files or
kernel search paths are changed. Re-execution recognizes its own bind, and uninstall
only unmounts that source. Reboot removes loaded additions safely. Disconnect and
reconnect an adapter after reboot so a previously failed firmware probe can retry.

AnyKernel3 core and its official `arm64-tools` branch are vendored separately.
`provenance.json` records both commits and archive hashes. The upstream license
is included in the AnyKernel ZIP. Onyx needs the ARM64 tools, not the 32-bit ARM
executables from upstream master.

The freestanding `module-abi.c` helper verifies classic and extended ELF symbol
CRCs. The ZIPs carry the helper source, compiler identity and build flags.
Rebuild with the recorded Android Clang using:

```python
import json, subprocess, hashlib
from pathlib import Path
root = Path('ci/installers')
p = json.loads((root / 'provenance.json').read_text())
subprocess.run(['clang', *p['compile_flags'], str(root / 'module-abi.c'),
                '-o', str(root / 'tools/module-abi')], check=True)
for key, name in [('module_abi_source_sha256', 'module-abi.c'),
                  ('module_abi_binary_sha256', 'tools/module-abi')]:
    p[key] = hashlib.sha256((root / name).read_bytes()).hexdigest()
(root / 'provenance.json').write_text(json.dumps(p, indent=2) + '\n')
```

Validation covers malformed ELF/CRC data, complete bundle round trips and
tampering, and WLAN dependency, refcount, unload failure, reload failure and
Wi-Fi state behavior. External-module tests execute the real shell loaders with
mocked Android tools, covering dependency/load failures, retaining loaded modules,
payload/ABI failures, full firmware tree preservation, symlink/conflict rejection,
SELinux and bind/remount failures, re-execution and mount ownership. The ARM64
tools and ABI helper also passed read-only
execution on Onyx: the matching release WLAN module was accepted, the installed
older KMI module was rejected, and vendor-boot v4 modules were extracted from a
copied partition image. This does not claim a recovery flash or device boot test
of the generated release ZIPs.
