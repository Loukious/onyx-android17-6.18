#!/usr/bin/env python3
"""Validate the complete build inventory before exporting or releasing it."""
import hashlib
import importlib.util
import json
from pathlib import PurePosixPath
import re
import sys
import tarfile


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or str(path) != name:
        raise ValueError('Unsafe artifact path: ' + name)
    return path


def module_identity(name):
    return PurePosixPath(name).name.removesuffix('.ko').replace('-', '_')


def inventory_summary(report):
    external = report['module_verification']
    native = report.get('native_module_verification')
    if native is None:
        return {}
    addons = report.get('platform_addon_verification', [])
    result = {'total_modules': len({module_identity(row['module']) for row in external + native + addons}),
              'native_modules': len(native)}
    if addons:
        result['feature_addon_modules'] = len(addons)
    return result


def verify_features(artifact, source_root, report):
    committed = source_root / 'port/features'
    if not (committed / 'manifest.json').is_file():
        if 'variant' in report or report.get('platform_addon_verification'):
            raise ValueError('Variant feature builds require a committed feature manifest')
        return
    variant = report.get('variant')
    if (not isinstance(variant, dict) or set(variant) != {'id', 'label', 'features', 'profile'}
            or variant.get('id') not in ('balanced', 'performance')
            or not isinstance(variant.get('label'), str) or not variant['label']
            or not isinstance(variant.get('features'), list)
            or any(not isinstance(value, str) or not value for value in variant['features'])
            or len(set(variant['features'])) != len(variant['features'])
            or not isinstance(variant.get('profile'), dict)
            or not report['kernel_release'].endswith('-onyx-' + variant['id'])):
        raise ValueError('Built variant identity or kernel release is missing')
    expected = {path.relative_to(committed).as_posix(): path for path in committed.rglob('*')
                if path.is_file() and '__pycache__' not in path.parts and not path.name.endswith('.pyc')}
    archived = artifact / 'inputs/features'
    actual = {path.relative_to(archived).as_posix(): path for path in archived.rglob('*') if path.is_file()}
    if set(expected) != set(actual) or any(digest(path) != digest(actual[name]) for name, path in expected.items()):
        raise ValueError('Archived feature locks, patches or sources differ from the selected source')
    helper = source_root / 'port/features.py'
    if digest(helper) != digest(artifact / 'inputs/features.py'):
        raise ValueError('Archived feature verifier differs from the selected source')
    # Re-run the source-owned verifier instead of treating a recorded module
    # load or smoke test as proof that each requested feature was built.
    name = '_onyx_feature_artifact_verifier'
    spec = importlib.util.spec_from_file_location(name, helper)
    module = importlib.util.module_from_spec(spec)
    old_path = list(sys.path)
    try:
        sys.path.insert(0, str(source_root / 'port'))
        sys.modules[name] = module
        spec.loader.exec_module(module)
        module.verify_artifact(artifact, report)
    finally:
        sys.path[:] = old_path
        sys.modules.pop(name, None)
    records = report.get('platform_addon_verification')
    if not isinstance(records, list) or [row.get('module') for row in records] != ['susfs_guard_lkm.ko']:
        raise ValueError('Verified SUSFS addon inventory is missing')
    for row in records:
        path = 'platform-addon/' + row['module']
        if (report['sha256'].get(path) != row.get('sha256')
                or not row.get('vermagic', '').startswith(report['kernel_release'] + ' ')
                or type(row.get('imports_checked')) is not int or row['imports_checked'] <= 0):
            raise ValueError('SUSFS addon hash, vermagic or import verification differs')


def verify_native_abi(artifact, source_root, catalog, entries, prefix, report):
    providers = {row['output'].removesuffix('.ko'): row.get('required_exports', [])
                 for row in catalog['components'] if row['kind'] == 'native_common'}
    required = {symbol for symbols in providers.values() for symbol in symbols}
    if (any(not isinstance(symbol, str) or not re.fullmatch('[A-Za-z0-9_]+', symbol)
            for symbol in required)
            or sum(len(symbols) for symbols in providers.values()) != len(required)):
        raise ValueError('Invalid or duplicate catalog native ABI exports')
    records = report.get('native_abi_validation')
    if not isinstance(records, list):
        raise ValueError('Complete native ABI validation is missing')
    names = [row.get('provider') for row in records]
    if (any(not isinstance(name, str) for name in names)
            or len(names) != len(set(names)) or set(names) != set(providers)):
        raise ValueError('Incomplete or duplicate native ABI providers')
    symvers = {}
    for line in (artifact / 'gki/kernel_aarch64_Module.symvers').read_text().splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[1] not in required:
            continue
        if (len(fields) < 4 or fields[1] in symvers
                or not re.fullmatch('0x[0-9a-fA-F]{8}', fields[0])):
            raise ValueError('Invalid or duplicate native ABI symbol provider')
        symvers[fields[1]] = (fields[2], int(fields[0], 16))
    if set(symvers) != required:
        raise ValueError('Required native ABI exports are missing from Common symvers')
    for row in records:
        provider = row['provider']
        exports = row.get('required_exports')
        if not isinstance(exports, list):
            raise ValueError('Native ABI export validation is missing: ' + provider)
        if [entry.get('symbol') for entry in exports] != sorted(providers[provider]):
            raise ValueError('Native ABI exports differ from the component catalog: ' + provider)
        if not exports:
            continue
        if row.get('sha256') != entries[prefix + provider + '.ko']:
            raise ValueError('Native ABI validation differs from the module hash: ' + provider)
        for entry in exports:
            flags, crc = entry.get('flags'), entry.get('crc')
            if (type(flags) is not int or flags not in (0, 1)
                    or not isinstance(crc, str) or not re.fullmatch('0x[0-9a-f]{8}', crc)
                    or symvers[entry['symbol']] != (provider, int(crc, 16))):
                raise ValueError('Native ABI export flags, CRC or Common provider differ: ' + entry['symbol'])
    verifier = artifact / 'inputs/verify_native_abi.py'
    committed = source_root / 'port/verify_native_abi.py'
    if required and (not verifier.is_file() or not committed.is_file()
                     or digest(verifier) != digest(committed)):
        raise ValueError('Native ABI source verifier differs from the selected source')


def verify_native(artifact, source_root, report, expected):
    catalog_path = source_root / 'port/components.json'
    if not catalog_path.is_file():
        if report.get('native_module_verification'):
            raise ValueError('Native module records require a committed component catalog')
        return
    catalog = json.loads(catalog_path.read_text())
    archived = json.loads((artifact / 'inputs/components.json').read_text())
    if archived != catalog or catalog.get('schema_version') != 1:
        raise ValueError('Build component catalog differs from the selected source')
    required = [row['output'] for row in catalog['components'] if row['kind'] == 'native_common']
    if len(set(required)) != len(required):
        raise ValueError('Duplicated native component inventory')
    records = report.get('native_module_verification')
    if not isinstance(records, list) or not records:
        raise ValueError('Complete native module verification is missing')
    release = report['kernel_release']
    prefix = 'lib/modules/' + release + '/kernel/'
    wanted = {prefix + str(relative(name)) for name in required}
    entries = {}
    identities = set()
    with tarfile.open(artifact / 'gki/modules_staging_dir.tar.gz') as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            if member.isdir() and name in ('', '.'):
                continue
            relative(name)
            if not name.endswith('.ko'):
                continue
            identity = module_identity(name)
            if (not member.isfile() or member.size <= 0 or not name.startswith(prefix)
                    or name in entries or identity in identities):
                raise ValueError('Invalid or duplicate native module archive member: ' + name)
            identities.add(identity)
            with archive.extractfile(member) as stream:
                entries[name] = hashlib.file_digest(stream, 'sha256').hexdigest()
    members = [row.get('archive_member') for row in records]
    names = [row.get('module') for row in records]
    if (any(not isinstance(name, str) for name in members + names)
            or len(set(members)) != len(members) or len(set(names)) != len(names)
            or set(members) != set(entries) or not wanted <= set(entries)):
        raise ValueError('Incomplete or duplicated native module inventory')
    for row in records:
        member = str(relative(row['archive_member']))
        if (PurePosixPath(member).name != row['module'] or entries[member] != row.get('sha256')
                or not row.get('vermagic', '').startswith(release + ' ')
                or 'modversions' not in row['vermagic'].split()):
            raise ValueError('Native module hash or vermagic differs: ' + row['module'])
        if type(row.get('imports_checked')) is not int or row['imports_checked'] <= 0:
            raise ValueError('Native module import verification is missing')
    verify_native_abi(artifact, source_root, catalog, entries, prefix, report)
    overrides = {module_identity(row['output']): row['replaces_gki']
                 for row in expected if 'replaces_gki' in row}
    external = {module_identity(row['module']) for row in report['module_verification']}
    overlap = external & identities
    if overlap != set(overrides):
        raise ValueError('Unreviewed GKI/platform module overlap')
    for name, replacement in overrides.items():
        member = 'lib/modules/' + release + '/' + str(relative(replacement))
        if member not in entries or module_identity(member) != name:
            raise ValueError('Reviewed GKI module replacement differs: ' + name)
    policy = source_root / 'port/module-loading.json'
    if not policy.is_file() or json.loads((artifact / 'inputs/module-loading.json').read_text()) != json.loads(policy.read_text()):
        raise ValueError('Build module loading policy differs from the selected source')
    lock = source_root / 'port/kernelsu-lock.json'
    if (not lock.is_file() or json.loads((artifact / 'inputs/kernelsu-lock.json').read_text()) != json.loads(lock.read_text())
            or json.loads(lock.read_text()) != json.loads((artifact / 'inputs/kernelsu-next/source.json').read_text())):
        raise ValueError('Build KernelSU lock differs from the selected source')
    automation = report.get('automation_revision')
    if automation is not None and not re.fullmatch('[0-9a-f]{40}', automation):
        raise ValueError('CI automation revision must be an exact commit')


def verify(artifact, source_root):
    report = json.loads((artifact / 'report.json').read_text())
    expected = json.loads((source_root / 'port/modules.json').read_text())
    wanted = [entry['output'] for entry in expected]
    records = report['module_verification']
    names = [entry['module'] for entry in records]
    if len(set(wanted)) != len(wanted) or len(set(names)) != len(names) or set(names) != set(wanted):
        raise ValueError('Incomplete or duplicated platform module inventory')
    if {path.name for path in (artifact / 'platform').glob('*.ko')} != set(wanted):
        raise ValueError('Unexpected platform module files')
    hashes = report['sha256']
    actual = set()
    for path in artifact.rglob('*'):
        if path.is_symlink():
            raise ValueError('Unexpected artifact symlink')
        if path.is_file():
            actual.add(path.relative_to(artifact).as_posix())
    if actual != set(hashes) | {'report.json'} or 'report.json' in hashes:
        raise ValueError('Build hash inventory does not cover every artifact')
    for name, checksum in hashes.items():
        relative(name)
        if not re.fullmatch('[0-9a-f]{64}', checksum) or digest(artifact / name) != checksum:
            raise ValueError('Build artifact changed: ' + name)
    pins = json.loads((artifact / 'inputs/sources.json').read_text())
    committed = json.loads((source_root / 'port/sources.json').read_text())
    if pins != committed:
        raise ValueError('Build source pins differ from the selected source')
    if json.loads((artifact / 'inputs/modules.json').read_text()) != expected:
        raise ValueError('Build module catalog differs from the selected source')
    release = report['kernel_release']
    if not release.startswith(pins['common']['kernel'] + '-android17-'):
        raise ValueError('Built kernel release differs from source pins')
    for entry in records:
        name = 'platform/' + entry['module']
        if hashes.get(name) != entry['sha256'] or not entry['vermagic'].startswith(release + ' '):
            raise ValueError('Module hash or vermagic differs: ' + entry['module'])
        if not isinstance(entry['imports_checked'], int) or entry['imports_checked'] < 0:
            raise ValueError('Module import verification is missing')
    ksu = report['kernelsu_next']
    if not all(re.fullmatch('[0-9a-f]{40}', value) for value in (pins['common']['revision'], ksu['revision'])):
        raise ValueError('Build must record exact GKI and KernelSU Next revisions')
    archived_ksu = json.loads((artifact / 'inputs/kernelsu-next/source.json').read_text())
    if any(ksu.get(key) != value for key, value in archived_ksu.items()):
        raise ValueError('KernelSU Next identity differs from the archived source')
    if digest(artifact / 'inputs/kernelsu-next/source.tar') != ksu['sha256']:
        raise ValueError('KernelSU Next source archive changed')
    config = (artifact / 'gki/kernel_aarch64_dot_config').read_text().splitlines()
    if 'CONFIG_KSU=y' not in config or 'CONFIG_MODVERSIONS=y' not in config:
        raise ValueError('Built kernel lacks KernelSU Next or module versioning')
    if any('CONFIG_' + option + '=y' in config for option in ('KSU_DEBUG', 'KSU_DISABLE_MANAGER', 'KSU_DISABLE_POLICY')):
        raise ValueError('Unexpected KernelSU Next configuration')
    if (artifact / 'gki/kernel.release').read_text().strip() != release:
        raise ValueError('Kernel release file differs from build report')
    for name in ('gki/Image', 'gki/kernel_aarch64_Module.symvers', 'devicetrees/dtb.img', 'devicetrees/dtbo.img'):
        if not (artifact / name).stat().st_size:
            raise ValueError('Empty required build artifact: ' + name)
    dt = report['devicetree_verification']
    dt_report = json.loads((artifact / 'devicetrees/report.json').read_text())
    for key in ('overlay_engines_agree', 'bootloader_ids_preserved', 'dtbo_table_verified'):
        if dt.get(key) is not True or dt_report.get(key) is not True:
            raise ValueError('Device-tree verification failed: ' + key)
    trees = json.loads((source_root / 'port/devicetrees.json').read_text())['dtb_order']
    if set(dt_report['trees']) != set(trees):
        raise ValueError('Device-tree variants are incomplete')
    for name in trees:
        if not (artifact / 'devicetrees/checked' / relative(name)).is_file():
            raise ValueError('Checked device tree is missing: ' + name)
    verify_native(artifact, source_root, report, expected)
    verify_features(artifact, source_root, report)
    return report, pins, len(wanted)
