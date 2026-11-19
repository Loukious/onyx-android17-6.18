# KernelSU Next from official dev

`kernelsu-lock.json` records the exact official dev commit, source archive hash,
version and tag used by every build. The upstream tracker discovers new dev
commits and validates candidate updates before promoting the accepted source.
Builds never substitute a newer branch tip for the locked inputs.

`integrate_kernelsu.py` materializes the verified archive under
`common/drivers/kernelsu`, enables built-in `CONFIG_KSU=y`, and resolves version
metadata before entering Kleaf. Manager authentication, policy profiles and
debug defaults retain upstream behavior. Artifact inputs archive the exact
source snapshot and receipt.

The same official snapshot's `kernel/susfs` builds as a separate matched LKM.
No classic SUSFS kernel patches or independent KernelSU fork are mixed into it.
Both Balanced and Performance include the matching module and special-loader
addon. Feature verification checks configuration, module vermagic/export CRCs,
private symbol availability and the KernelSU allow-predicate integration.
Runtime feature activation and behavior require separate device verification.
See [feature profiles and installation](../features/README.md).

Use a compatible official Next Manager. Compilation and input verification do
not establish on-device root or hiding behavior.
