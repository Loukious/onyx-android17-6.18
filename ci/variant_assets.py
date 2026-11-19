"""Matched variant bundle identities and unique public download filenames."""
import re
from release_naming import VARIANT_ASSET_FORMAT, VARIANTS, archive_name, variant_prefix


SHARED = ('source_revision', 'common_revision', 'kernelsu_revision', 'run_id', 'run_attempt',
          'automation_revision')


def susfs_builtin(row):
    return 'susfs-next-builtin' in row.get('features', [])


def verify_builtin_susfs_payload(artifact, report, row):
    """A built-in implementation must not ship a stale loadable addon."""
    if not susfs_builtin(row):
        return False
    if (report.get('platform_addon_verification') != []
            or any(path.is_file() or path.is_symlink()
                   for path in (artifact / 'platform-addon').rglob('*'))
            or any(name.startswith('platform-addon/') for name in report.get('sha256', {}))):
        raise ValueError('Built-in SUSFS cannot include a loadable addon payload')
    return True


def evidence_names(variant):
    prefix = variant_prefix(variant)
    return {'report': prefix + 'report.json', 'build_log': prefix + 'build.log',
            'module_abi': prefix + 'Module.symvers', 'kernel_release': prefix + 'kernel.release',
            'kernel_config': prefix + 'kernel_aarch64_dot_config'}


def installer_metadata_name(variant):
    return variant_prefix(variant) + 'installers.json'


def rows(identity):
    if not isinstance(identity.get('automation_revision'), str) or not re.fullmatch('[0-9a-f]{40}', identity['automation_revision']):
        raise ValueError('Variant releases require the exact CI automation revision')
    values = identity.get('variants')
    if (not isinstance(values, list) or len(values) != len(VARIANTS)
            or any(not isinstance(value, dict) for value in values)
            or [value.get('id') for value in values] != list(VARIANTS)):
        raise ValueError('Release requires exactly balanced and performance variants')
    releases, roots = set(), set()
    for value in values:
        if value.get('asset_format') != VARIANT_ASSET_FORMAT:
            raise ValueError('Variant uses a different asset format')
        if any(value.get(key) != identity.get(key) for key in SHARED):
            raise ValueError('Variants must share exact build and source revisions')
        release, root = value.get('kernel_release'), value.get('artifact_root')
        if (not isinstance(release, str) or not release.endswith('-onyx-' + value['id'])
                or release in releases or not isinstance(root, str) or root in roots):
            raise ValueError('Variant kernel releases and artifact roots must be distinct')
        if (not isinstance(value.get('features'), list)
                or any(not isinstance(feature, str) or not feature for feature in value['features'])
                or len(set(value['features'])) != len(value['features'])
                or not isinstance(value.get('profile'), dict)
                or not isinstance(value.get('label'), str) or not value['label']):
            raise ValueError('Variant feature/profile metadata is incomplete')
        releases.add(release)
        roots.add(root)
    # Retain the balanced identity aliases for old consumers, binding them to
    # the first complete variant rather than allowing independently supplied values.
    for key in ('kernel_release', 'artifact_root', 'modules'):
        if identity.get(key) != values[0].get(key):
            raise ValueError('Legacy release aliases differ from the balanced variant')
    return values


def core_files(row):
    return set(evidence_names(row['id']).values()) | {archive_name(VARIANT_ASSET_FORMAT, row['id'])}


def download_map(row):
    import installer_assets
    import recovery_assets
    value = {**evidence_names(row['id']),
             'rom_integration': archive_name(VARIANT_ASSET_FORMAT, row['id'])}
    if row.get('installers'):
        ak, internal, external, susfs = installer_assets.names(row['kernel_release'], VARIANT_ASSET_FORMAT, row['id'])
        value.update(anykernel=ak, internal_wifi=internal, external_wifi=external,
                     installer_metadata=installer_metadata_name(row['id']))
        if not susfs_builtin(row):
            value['susfs_module'] = susfs
    if row.get('full_recovery'):
        full, metadata = recovery_assets.names(row['kernel_release'], VARIANT_ASSET_FORMAT, row['id'])
        value.update(full_recovery=full, recovery_metadata=metadata)
    return value


def merge_products(identity, products_by_id, field):
    """Prepare both inventories before the caller writes any bundle asset."""
    import hashlib
    result = {}
    for row in rows(identity):
        products = products_by_id[row['id']]
        if set(result) & set(products):
            raise ValueError('Variant installer assets collide')
        result.update(products)
        row[field] = sorted(products)
        row['sha256'].update({name: hashlib.sha256(data).hexdigest()
                              for name, data in products.items()})
        row['downloads'] = download_map(row)
    identity['sha256'] = {name: checksum for row in identity['variants']
                         for name, checksum in row['sha256'].items()}
    return result
