#!/usr/bin/env python3
"""Package immutable verified build outputs as recovery and manager installers."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
import zipfile

from release_naming import archive_name, asset_format, write_checksums

HERE = Path(__file__).resolve().parent / 'installers'
WLAN = 'qca_cld3_wcn7750.ko'
USB_WIFI = ('rtl8xxxu.ko', 'rt2x00lib.ko', 'rt2x00usb.ko', 'rt2800lib.ko',
            'rt2800usb.ko', 'ath.ko', 'ath9k_hw.ko', 'ath9k_common.ko', 'ath9k_htc.ko')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def names(release, asset_format=1):
    if not re.fullmatch(r'6\.18\.\d+-android17-\d+-[A-Za-z0-9.-]+', release):
        raise ValueError('Unsupported installer kernel release')
    if asset_format == 1:
        return (f'Konoha-AnyKernel3-{release}.zip', f'nethunter-wlan-injection-{release}.zip')
    if asset_format != 2:
        raise ValueError('Unsupported installer asset format')
    return ('Onyx-GKI-6.18-AnyKernel3.zip', 'Onyx-NetHunter-Internal-WiFi-KSU-Module.zip',
            'Onyx-NetHunter-External-WiFi-KSU-Module.zip')


def module_name(filename):
    return Path(filename).name.removesuffix('.ko').replace('-', '_')


def verified_file(artifact, report, filename):
    path = artifact / filename
    data = path.read_bytes()
    if path.is_symlink() or report['sha256'].get(filename) != sha(data):
        raise ValueError('Unverified installer input: ' + filename)
    return data


def external_payload(artifact, report, release):
    """Select the complete USB WLAN dependency closure and its firmware package."""
    records = {entry['module']: entry for entry in report['module_verification']}
    if len(records) != len(report['module_verification']):
        raise ValueError('Duplicate platform module record')
    providers = {}
    for name, record in records.items():
        providers[module_name(name)] = ('platform/' + name, None, record)
    native_name = 'gki/modules_staging_dir.tar.gz'
    native = verified_file(artifact, report, native_name)
    native_providers = set()
    with tarfile.open(fileobj=io.BytesIO(native), mode='r:gz') as archive:
        for member in archive:
            if not member.name.endswith('.ko'):
                continue
            if not member.isfile() or member.name.startswith('/') or '..' in Path(member.name).parts:
                raise ValueError('Unsafe native module archive member')
            name = module_name(member.name)
            if name in native_providers:
                raise ValueError('Ambiguous module provider: ' + name)
            native_providers.add(name)
            # The Onyx catalog deliberately replaces some native providers;
            # its explicitly verified platform binary is authoritative.
            if name not in providers:
                providers[name] = (member.name, archive.extractfile(member).read(), None)
    builtins = {module_name(name) for name in
                verified_file(artifact, report, 'gki/modules.builtin').decode().splitlines()}
    files, order, visiting, done = {}, [], set(), set()
    dependencies = {}

    def visit(name):
        if name in done or name in builtins:
            return
        if name in visiting:
            raise ValueError('Cyclic USB WLAN module dependency: ' + name)
        if name not in providers:
            raise ValueError('Missing USB WLAN module dependency: ' + name)
        visiting.add(name)
        path, data, record = providers[name]
        if record is not None:
            data = verified_file(artifact, report, path)
            if (record['sha256'] != sha(data) or record.get('imports_checked', 0) <= 0 or
                    not record.get('vermagic', '').startswith(release + ' ')):
                raise ValueError('Unverified USB WLAN platform module: ' + name)
            deps = record.get('depends', '')
        else:
            with tempfile.TemporaryDirectory(prefix='onyx-native-module-') as temporary:
                module = Path(temporary) / (name + '.ko')
                module.write_bytes(data)
                vermagic = subprocess.check_output(['modinfo', '-F', 'vermagic', str(module)], text=True).strip()
                if not vermagic.startswith(release + ' '):
                    raise ValueError('Native USB WLAN dependency has a different kernel release: ' + name)
                deps = subprocess.check_output(['modinfo', '-F', 'depends', str(module)], text=True).strip()
        if data[:6] != b'\x7fELF\x02\x01' or data[18:20] != b'\xb7\x00':
            raise ValueError('Expected ARM64 USB WLAN module: ' + name)
        wanted = deps.split(',') if deps else []
        if any(not re.fullmatch(r'[A-Za-z0-9_-]+', dep) for dep in wanted):
            raise ValueError('Invalid USB WLAN module dependencies')
        # Built-in exports are already present in the running kernel and need
        # no load or /sys/module directory (some built-ins have no parameters).
        dependencies[name] = [dep.replace('-', '_') for dep in wanted
                              if dep.replace('-', '_') not in builtins]
        for dep in dependencies[name]:
            visit(dep)
        files['drivers/' + name + '.ko'] = (data, False)
        order.append(name)
        visiting.remove(name)
        done.add(name)

    for filename in USB_WIFI:
        visit(module_name(filename))
    files['modules.load'] = (''.join(name + '\n' for name in order).encode(), False)
    files['modules.dep'] = (''.join(name + ':' + ' '.join(dependencies[name]) + '\n'
                                    for name in order).encode(), False)
    firmware_manifest = json.loads(verified_file(artifact, report, 'firmware/manifest.json'))
    firmware_names = [entry['path'] for entry in firmware_manifest['blobs']]
    requirements = json.loads(verified_file(artifact, report, 'inputs/nethunter-native-modules.json'))
    if len(firmware_names) != 16 or set(firmware_names) != set(requirements['wireless_firmware']):
        raise ValueError('USB WLAN firmware inventory is incomplete or duplicated')
    for entry in firmware_manifest['blobs']:
        name = entry['path']
        if not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', name) or '..' in Path(name).parts:
            raise ValueError('Unsafe USB WLAN firmware filename')
        data = verified_file(artifact, report, 'firmware/firmware/' + name)
        if sha(data) != entry['sha256'] or len(data) != entry['bytes']:
            raise ValueError('USB WLAN firmware differs from its manifest: ' + name)
        if not (artifact / 'firmware' / entry['license']).is_file():
            raise ValueError('USB WLAN firmware license is missing')
        files['firmware/' + name] = (data, False)
    files['firmware.paths'] = (''.join(name + '\n' for name in sorted(firmware_names)).encode(), False)
    for source in requirements['firmware_source_archives']:
        data = verified_file(artifact, report, 'firmware/' + source['path'])
        if sha(data) != source['sha256']:
            raise ValueError('USB WLAN corresponding firmware source changed')
    for path in sorted((artifact / 'firmware').rglob('*')):
        if not path.is_file() or 'firmware' in path.relative_to(artifact / 'firmware').parts[:-1]:
            continue
        relative = path.relative_to(artifact / 'firmware').as_posix()
        files['firmware-notices/' + relative] = (verified_file(artifact, report, 'firmware/' + relative), False)
    return files, {'external_wifi_modules': order, 'external_wifi_firmware': sorted(firmware_names)}


def abi_table(artifact):
    result = {}
    for path in [artifact / 'gki/kernel_aarch64_Module.symvers', *sorted((artifact / 'platform').glob('*Module.symvers'))]:
        for line in path.read_text().splitlines():
            fields = line.split()
            if len(fields) < 3:
                raise ValueError('Invalid symvers row')
            crc, name = int(fields[0], 16), fields[1]
            if not re.fullmatch(r'[A-Za-z0-9_.$]+', name) or crc > 0xffffffff:
                raise ValueError('Invalid ABI export')
            if name in result and result[name] != crc:
                raise ValueError('Conflicting ABI exports: ' + name)
            result[name] = crc
    if not result:
        raise ValueError('Empty ABI export table')
    return ''.join(f'{crc:08x} {name}\n' for name, crc in sorted(result.items())).encode()


def zip_bytes(files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, (data, executable) in sorted(files.items()):
            info = zipfile.ZipInfo(name, (2026, 11, 6, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data, compresslevel=9)
    return out.getvalue()


def payload(files, members):
    return ''.join(f'{sha(files[n][0])}  {n}\n' for n in sorted(members)).encode()


def build(artifact, identity):
    report = json.loads((artifact / 'report.json').read_text())
    release = identity['kernel_release']
    version = asset_format(identity)
    filenames = names(release, version)
    ak_name, wlan_name = filenames[:2]
    if report['kernel_release'] != release:
        raise ValueError('Installer release differs from build')
    image = (artifact / 'gki/Image').read_bytes()
    if len(image) < 64 or image[56:60] != b'ARM\x64':
        raise ValueError('Expected uncompressed ARM64 Image')
    records = [r for r in report['module_verification'] if r['module'] == WLAN]
    if len(records) != 1 or records[0]['imports_checked'] <= 0:
        raise ValueError('Verified internal WLAN module is missing')
    wlan = (artifact / 'platform' / WLAN).read_bytes()
    if sha(wlan) != records[0]['sha256'] or b'hdd_monitor_mode_tx_inject' not in wlan:
        raise ValueError('WLAN module does not contain the verified injection implementation')
    deps = records[0]['depends'].split(',')
    if not deps or any(not re.fullmatch('[A-Za-z0-9_-]+', dep) for dep in deps):
        raise ValueError('Invalid WLAN dependencies')
    abi = abi_table(artifact)
    provenance = json.loads((HERE / 'provenance.json').read_text())
    source = (HERE / 'module-abi.c').read_bytes()
    guard = (HERE / 'tools/module-abi').read_bytes()
    upstream = (HERE / 'vendor/AnyKernel3.tar.gz').read_bytes()
    arm64_tools = (HERE / 'vendor/AnyKernel3-arm64-tools.tar.gz').read_bytes()
    if (sha(source) != provenance['module_abi_source_sha256'] or
        sha(guard) != provenance['module_abi_binary_sha256'] or
        sha(upstream) != provenance['anykernel_archive_sha256'] or
        sha(arm64_tools) != provenance['anykernel_arm64_archive_sha256']):
        raise ValueError('Installer tools changed without provenance update')
    substitutions = {'@RELEASE@': release, '@KMI@': release.split('-')[2],
                     '@DEPS@': ' '.join(dep.replace('-', '_') for dep in deps)}
    def template(name):
        value = (HERE / name).read_text()
        for key, replacement in substitutions.items():
            value = value.replace(key, replacement)
        if version == 2:
            value = value.replace('Konoha', 'Onyx')
            if name == 'anykernel.sh':
                value = value.replace('kernel.string=Onyx ' + release,
                                      'kernel.string=Onyx GKI 6.18 / KernelSU Next')
        return value.encode()
    metadata = {'format': 1, 'source_revision': identity['source_revision'],
        'common_revision': identity['common_revision'], 'kernelsu_revision': identity['kernelsu_revision'],
        'kernel_release': release, 'kernel_sha256': sha(image), 'wlan_sha256': sha(wlan),
        'abi_sha256': sha(abi), 'anykernel_revision': provenance['anykernel_revision'],
        'anykernel_arm64_revision': provenance['anykernel_arm64_revision'],
        'module_abi_sha256': sha(guard), 'requires': 'Onyx with matching 6.18 modules; kernel-only ZIP is not a 6.6 migration'}
    if version == 2:
        extra, extra_metadata = external_payload(artifact, report, release)
        metadata.update(extra_metadata)
        metadata['format'] = 2
    meta = (json.dumps(metadata, indent=2)+'\n').encode()
    version_code = int(datetime.strptime(identity['artifact_root'][:15], '%Y%m%dT%H%M%S').replace(tzinfo=timezone.utc).timestamp())
    ak = {}
    with tarfile.open(fileobj=io.BytesIO(upstream), mode='r:gz') as archive:
        for member in archive:
            if member.name == 'LICENSE' or member.name == 'README.md' or member.name.startswith(('tools/', 'META-INF/')):
                if member.isdir():
                    continue
                if not member.isfile() or '..' in Path(member.name).parts or member.name.startswith('/'):
                    raise ValueError('Unsafe AnyKernel archive entry')
                ak[member.name] = (archive.extractfile(member).read(), bool(member.mode & 0o111))
    # Onyx is ARM64-only. Upstream master carries 32-bit ARM executables;
    # replace them with the separately pinned official arm64-tools branch.
    with tarfile.open(fileobj=io.BytesIO(arm64_tools), mode='r:gz') as archive:
        for member in archive:
            if not member.isfile() or '/' in member.name or 'tools/' + member.name not in ak:
                raise ValueError('Unexpected AnyKernel ARM64 tool')
            data = archive.extractfile(member).read()
            if data[:6] != b'\x7fELF\x02\x01' or data[18:20] != b'\xb7\x00':
                raise ValueError('Expected ARM64 AnyKernel executable')
            ak['tools/' + member.name] = (data, True)
    for name, (data, _) in ak.items():
        if name.startswith('tools/') and data.startswith(b'\x7fELF') and data[18:20] != b'\xb7\x00':
            raise ValueError('Non-ARM64 AnyKernel executable: ' + name)
    ak.update({'Image': (image, False), 'anykernel.sh': (template('anykernel.sh'), True),
        'tools/module-abi': (guard, True), 'kernel-abi.tsv': (abi, False),
        'installer.json': (meta, False), 'installer-source/module-abi.c': (source, False),
        'installer-source/provenance.json': ((HERE/'provenance.json').read_bytes(), False)})
    ak['payload.sha256'] = (payload(ak, ['Image', 'kernel-abi.tsv', 'tools/module-abi']), False)
    module = {'wlan/'+WLAN: (wlan, False), 'service.sh': (template('wlan-service.sh'), True),
        'customize.sh': (template('wlan-customize.sh'), False), 'skip_mount': (b'', False),
        'module-abi': (guard, True), 'kernel-abi.tsv': (abi, False), 'installer.json': (meta, False),
        'installer-source/module-abi.c': (source, False),
        'installer-source/provenance.json': ((HERE/'provenance.json').read_bytes(), False),
        'module.prop': ((f'id=nethunter-wlan-injection\nname=NetHunter WLAN Injection (Onyx)\n'
            f'version={release + "-s" + identity["source_revision"][:12] if version == 1 else "s" + identity["source_revision"][:12]}\nversionCode={version_code}\n'
            'author=Loukious\ndescription=Matched WCN7750 monitor mode and frame injection. Reboot to activate.\n').encode(), False),
        'META-INF/com/google/android/update-binary': ((HERE/'wlan-update-binary.sh').read_bytes(), True),
        'META-INF/com/google/android/updater-script': (b'#MAGISK\n', False)}
    module['payload.sha256'] = (payload(module, ['wlan/'+WLAN, 'module-abi', 'kernel-abi.tsv']), False)
    products = {ak_name: zip_bytes(ak), wlan_name: zip_bytes(module)}
    if version == 2:
        extra.update({'service.sh': (template('extra-service.sh'), True),
            'firmware-overlay.sh': (template('extra-firmware.sh'), True),
            'customize.sh': (template('extra-customize.sh'), False),
            'uninstall.sh': (template('extra-uninstall.sh'), True), 'skip_mount': (b'', False),
            'module-abi': (guard, True), 'kernel-abi.tsv': (abi, False), 'installer.json': (meta, False),
            'installer-source/module-abi.c': (source, False),
            'installer-source/provenance.json': ((HERE/'provenance.json').read_bytes(), False),
            # Retain the earlier manager ID so installing this replaces its old
            # 6.6 loader instead of running two competing firmware overlays.
            'module.prop': ((f'id=nethunter-extra-modules\nname=Onyx NetHunter External Wi-Fi\n'
                f'version=s{identity["source_revision"][:12]}\nversionCode={version_code}\n'
                'author=Loukious\ndescription=Matched Realtek, Ralink and Atheros USB Wi-Fi drivers and firmware. Reboot to activate.\n').encode(), False),
            'META-INF/com/google/android/update-binary': ((HERE/'wlan-update-binary.sh').read_bytes(), True),
            'META-INF/com/google/android/updater-script': (b'#MAGISK\n', False)})
        extra['payload.sha256'] = (payload(extra, list(extra)), False)
        products[filenames[2]] = zip_bytes(extra)
    metadata['sha256'] = {name: sha(data) for name, data in products.items()}
    products['installers.json'] = (json.dumps(metadata, indent=2)+'\n').encode()
    return products


def verify(artifact, bundle, identity):
    # Recreate expected archives from verified build outputs and pinned tools.
    for name, data in build(artifact, identity).items():
        if (bundle / name).read_bytes() != data:
            raise ValueError('Installer differs from verified inputs: ' + name)


def add_to_bundle(bundle, source):
    import publish_release
    identity = json.loads((bundle / 'release.json').read_text())
    publish_release.validate_bundle(bundle, source, identity['source_revision'], identity['common_revision'],
        identity['kernelsu_revision'], identity['run_id'], identity['run_attempt'])
    if identity.get('installers'):
        return identity
    with tempfile.TemporaryDirectory(prefix='onyx-installer-') as tmp:
        with tarfile.open(bundle / archive_name(asset_format(identity))) as archive:
            archive.extractall(tmp, filter='data')  # Full inventory validated above.
        products = build(Path(tmp) / identity['artifact_root'], identity)
        for name, data in products.items():
            (bundle / name).write_bytes(data)
    identity['installers'] = sorted(products)
    identity['sha256'].update({name: sha(data) for name, data in products.items()})
    (bundle / 'release.json').write_text(json.dumps(identity, indent=2)+'\n')
    write_checksums(bundle)
    return identity


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    print(json.dumps(add_to_bundle(args.bundle, args.source), indent=2))
