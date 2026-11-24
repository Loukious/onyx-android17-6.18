#!/usr/bin/env python3
"""Publish complete verified build assets, then let CI record accepted inputs."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
from urllib.parse import quote

from verify_artifacts import digest, relative, verify, inventory_summary
import installer_assets
import recovery_assets
import google_changelog
from release_naming import archive_name, artifact_name, asset_format, checksum_paths, release_title, asset_timestamp
import variant_assets

TRACK = json.loads((Path(__file__).resolve().parent / 'upstream.json').read_text())
FILES = {
    'report.json', 'build.log', archive_name(),
    'kernel-abi/Module.symvers', 'kernel-abi/kernel.release', 'kernel-abi/kernel_aarch64_dot_config',
}


def bundle_files(identity):
    version = asset_format(identity)
    if version == 3:
        files = set()
        for row in variant_assets.rows(identity):
            extra, complete = row.get('installers', []), row.get('full_recovery', [])
            if extra and (len(extra) != len(set(extra)) or set(extra) !=
                    set(installer_assets.expected_names(row)) |
                    {variant_assets.installer_metadata_name(row['id'], asset_timestamp(row))}):
                raise ValueError('Invalid variant installer asset inventory')
            if complete and (len(complete) != len(set(complete)) or set(complete) !=
                    set(recovery_assets.names(row['kernel_release'], 3, row['id'], asset_timestamp(row)))):
                raise ValueError('Invalid variant recovery asset inventory')
            current = variant_assets.core_files(row) | set(extra) | set(complete)
            if files & current or set(row.get('sha256', {})) != current:
                raise ValueError('Incomplete or colliding variant assets')
            if row.get('downloads') != variant_assets.download_map(row):
                raise ValueError('Variant downloads differ from its verified assets')
            files.update(current)
        if any(bool(row.get(field)) != bool(identity['variants'][0].get(field))
               for row in identity['variants'] for field in ('installers', 'full_recovery')):
            raise ValueError('Variant packaging is incomplete')
        if identity.get('sha256') != {name: value for row in identity['variants']
                                      for name, value in row['sha256'].items()}:
            raise ValueError('Variant checksums differ from release checksums')
        return files
    extra = identity.get('installers', [])
    if extra and set(extra) != set(installer_assets.names(identity['kernel_release'], version)) | {'installers.json'}:
        raise ValueError('Invalid installer asset inventory')
    if len(extra) != len(set(extra)):
        raise ValueError('Duplicated installer assets')
    complete = identity.get('full_recovery', [])
    if complete and set(complete) != set(recovery_assets.names(identity['kernel_release'], version)):
        raise ValueError('Invalid complete recovery asset inventory')
    if len(complete) != len(set(complete)):
        raise ValueError('Duplicated complete recovery assets')
    return (FILES - {archive_name()}) | {archive_name(version)} | set(extra) | set(complete)


def api(path, optional=False, *, method='GET', data=None, input_file=None):
    if data is not None and input_file is not None:
        raise ValueError('API request cannot contain both JSON and a file')
    args = ['gh', 'api', path, '--method', method]
    if data is not None:
        args += ['--input', '-']
    if input_file is not None:
        args += ['--input', str(input_file), '--header', 'Content-Type: application/octet-stream']
    result = subprocess.run(args, input=json.dumps(data) if data is not None else None,
                            text=True, capture_output=True)
    if optional and result.returncode and '(HTTP 404)' in result.stderr:
        return None
    if result.returncode:
        raise RuntimeError(result.stderr)
    return json.loads(result.stdout) if result.stdout.strip() else None


def listed(path, key=None):
    """Read all pages; authenticated inventories include unpublished drafts."""
    page = 1
    while True:
        response = api(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
        entries = response[key] if key else response
        if not isinstance(entries, list):
            raise ValueError('GitHub inventory is not a list')
        yield from entries
        if len(entries) < 100:
            return
        page += 1


def release_by_tag(prefix, tag):
    release = api(prefix + '/releases/tags/' + tag, optional=True)
    if release:
        return release
    matches = [release for release in listed(prefix + '/releases') if release.get('tag_name') == tag]
    if len(matches) > 1:
        raise ValueError('Release tag matches multiple releases')
    return matches[0] if matches else None


def release_inputs(release, tag, source, kernel, kernelsu):
    if (not isinstance(release, dict) or type(release.get('id')) is not int or release['id'] < 1 or
            release.get('tag_name') != tag or
            release.get('target_commitish') != source or
            not isinstance(release.get('body'), str) or
            any(value not in release.get('body', '') for value in (source, kernel, kernelsu))):
        raise ValueError('Existing release tag identifies different inputs')


def validate_bundle(bundle, source_root, source, kernel, kernelsu, run_id, attempt, *, automation_revision=None):
    identity = json.loads((bundle / 'release.json').read_text())
    version = asset_format(identity)
    if version == 3 and automation_revision is not None and identity.get('automation_revision') != automation_revision:
        raise ValueError('Release CI revision differs from the authenticated build attempt')
    expected = {'source_revision': source, 'common_revision': kernel, 'kernelsu_revision': kernelsu,
                'run_id': str(run_id), 'run_attempt': str(attempt),
                'artifact_name': artifact_name(run_id, attempt, version)}
    if any(identity.get(key) != value for key, value in expected.items()):
        raise ValueError('Release bundle belongs to different build inputs or run')
    actual = {p.relative_to(bundle).as_posix() for p in bundle.rglob('*') if p.is_file()}
    files = bundle_files(identity)
    if actual != files | {'release.json', 'SHA256SUMS'} or any(p.is_symlink() for p in bundle.rglob('*')):
        raise ValueError('Release bundle inventory is incomplete or unsafe')
    hashes = {}
    for line in (bundle / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match or match[2] in hashes:
            raise ValueError('Invalid or duplicated release checksum')
        relative(match[2])
        hashes[match[2]] = match[1]
    labels = checksum_paths(actual - {'SHA256SUMS'}, version)
    if set(hashes) != set(labels) or set(identity['sha256']) != files:
        raise ValueError('Release checksums do not cover every asset')
    hashes = {labels[name]: checksum for name, checksum in hashes.items()}
    for name, checksum in hashes.items():
        if digest(bundle / name) != checksum:
            raise ValueError('Release asset changed: ' + name)
    if any(hashes[name] != checksum for name, checksum in identity['sha256'].items()):
        raise ValueError('Release identity and checksums differ')
    if version == 3:
        manifest = json.loads((source_root / 'port/features/manifest.json').read_text())
        if identity.get('install_options') != manifest.get('install_options', {}):
            raise ValueError('Release install options differ from the selected source')
        for row in variant_assets.rows(identity):
            validate_variant_archive(bundle, source_root, row, hashes)
        return identity
    root_name = str(relative(identity['artifact_root']))
    if '/' in root_name:
        raise ValueError('Invalid archive root')
    with tempfile.TemporaryDirectory(prefix='onyx-release-verify-') as temporary:
        root = Path(temporary)
        with tarfile.open(bundle / archive_name(version), 'r:gz') as archive:
            seen = set()
            for member in archive.getmembers():
                name = str(relative(member.name.rstrip('/')))
                if name in seen or name.split('/')[0] != root_name or not (member.isfile() or member.isdir()):
                    raise ValueError('Unsafe or duplicated build archive member')
                seen.add(name)
            archive.extractall(root, filter='data')
        artifact = root / root_name
        report, pins, count = verify(artifact, source_root)
        if report.get('qdss_diagnostic') is not False:
            raise ValueError('Diagnostic builds cannot become automatic releases')
        if (pins['common']['revision'], report['kernelsu_next']['revision'], report['kernel_release'], count) != (
                kernel, kernelsu, identity['kernel_release'], identity['modules']):
            raise ValueError('Archived build identity differs from release metadata')
        counts = inventory_summary(report)
        if counts:
            catalog = json.loads((source_root / 'port/components.json').read_text())
            counts['native_component_modules'] = sum(row['kind'] == 'native_common' for row in catalog['components'])
            if any(identity.get(key) != value for key, value in counts.items()):
                raise ValueError('Native module counts differ from the verified build')
        if identity.get('automation_revision') != report.get('automation_revision'):
            raise ValueError('CI automation revision differs from the verified build')
        if digest(artifact / 'report.json') != hashes['report.json'] or digest(artifact / 'build.log') != hashes['build.log']:
            raise ValueError('Exported evidence differs from the build archive')
        for exported, archived in (
                ('Module.symvers', 'kernel_aarch64_Module.symvers'),
                ('kernel.release', 'kernel.release'), ('kernel_aarch64_dot_config', 'kernel_aarch64_dot_config')):
            if digest(bundle / 'kernel-abi' / exported) != digest(artifact / 'gki' / archived):
                raise ValueError('Exported ABI differs from the build archive')
        if identity.get('installers'):
            installer_assets.verify(artifact, bundle, identity)
        if identity.get('full_recovery'):
            recovery_assets.verify(artifact, bundle, identity)
    return identity


def validate_variant_archive(bundle, source_root, row, hashes):
    root_name = str(relative(row['artifact_root']))
    if '/' in root_name:
        raise ValueError('Invalid variant archive root')
    with tempfile.TemporaryDirectory(prefix='onyx-variant-verify-') as temporary:
        root = Path(temporary)
        with tarfile.open(bundle / archive_name(3, row['id'], asset_timestamp(row)), 'r:gz') as archive:
            seen = set()
            for member in archive.getmembers():
                name = str(relative(member.name.rstrip('/')))
                if name in seen or name.split('/')[0] != root_name or not (member.isfile() or member.isdir()):
                    raise ValueError('Unsafe or duplicated variant archive member')
                seen.add(name)
            archive.extractall(root, filter='data')
        artifact = root / root_name
        report, pins, count = verify(artifact, source_root)
        if report.get('qdss_diagnostic') is not False:
            raise ValueError('Diagnostic builds cannot become automatic releases')
        if (pins['common']['revision'], report['kernelsu_next']['revision'], report['kernel_release'], count) != (
                row['common_revision'], row['kernelsu_revision'], row['kernel_release'], row['modules']):
            raise ValueError('Archived variant identity differs from release metadata')
        if report.get('variant') != {key: row[key] for key in ('id', 'label', 'features', 'profile')}:
            raise ValueError('Variant feature/profile metadata differs from its build')
        if row.get('automation_revision') != report.get('automation_revision'):
            raise ValueError('Variant CI automation revision differs from its build')
        counts = inventory_summary(report)
        if counts:
            catalog = json.loads((source_root / 'port/components.json').read_text())
            counts['native_component_modules'] = sum(item['kind'] == 'native_common' for item in catalog['components'])
            if any(row.get(key) != value for key, value in counts.items()):
                raise ValueError('Variant module counts differ from its build')
        evidence = variant_assets.evidence_names(row['id'], asset_timestamp(row))
        for exported, archived in [(evidence['report'], 'report.json'), (evidence['build_log'], 'build.log'),
                (evidence['module_abi'], 'gki/kernel_aarch64_Module.symvers'),
                (evidence['kernel_release'], 'gki/kernel.release'),
                (evidence['kernel_config'], 'gki/kernel_aarch64_dot_config')]:
            if digest(artifact / archived) != hashes[exported]:
                raise ValueError('Exported variant evidence differs from its archive')
        if row.get('installers'):
            installer_assets.verify(artifact, bundle, row)
        if row.get('full_recovery'):
            recovery_assets.verify(artifact, bundle, row)


def variant_release_notes(repository, identity):
    rows = variant_assets.rows(identity)
    version = identity['kernel_release'].split('-')[0]
    tag = f'gki-{version}-s{identity["source_revision"][:12]}-k{identity["kernelsu_revision"][:12]}'
    def download(name):
        return f'[{name}](https://github.com/{repository}/releases/download/{tag}/{quote(name, safe="")})'
    notes = ('Onyx Android 17 / GKI 6.18 with **Balanced** and **Performance** kernels. '
             'Each download includes modules built for that exact kernel.\n\n'
             '| Variant | TCP default | Full recovery installer | SUSFS |\n'
             '| --- | --- | --- | --- |\n')
    for row in rows:
        downloads = row['downloads']
        tcp = row['profile'].get('configs', {}).get('CONFIG_DEFAULT_TCP_CONG', row['id']).strip('"')
        full = download(downloads['full_recovery']) if downloads.get('full_recovery') else 'unavailable'
        susfs = ('Built into kernel' if variant_assets.susfs_builtin(row)
                 else download(downloads['susfs_module']) if downloads.get('susfs_module')
                 else 'unavailable')
        notes += f'| {row["label"]} | {tcp} | {full} | {susfs} |\n'
    notes += '\nThe complete ' + download('release.json') + ' lists both variants, features and checksums.\n'
    for row in rows:
        notes += f'\n<details>\n<summary>{row["label"]}: features and tuning</summary>\n\n'
        notes += f'Kernel: `{row["kernel_release"]}`. ROM archive: ' + download(row['downloads']['rom_integration']) + '.\n\n'
        notes += ', '.join(row['features']) + '.\n\n'
        notes += '```json\n' + json.dumps(row['profile'], indent=2, sort_keys=True) + '\n```\n\n</details>\n'
    notes += ('\nUse one variant’s matched kernel and modules together. The full recovery ZIP supports '
              'the existing compatible Onyx ROM layouts and reviewed 6.6 migration, retaining ROM ramdisks '
              'and applying the existing backup/readback/rollback checks. Kernel-only AnyKernel3 ZIPs '
              'require modules already matching the target variant.\n\n'
              'Both profiles passed source replay, complete module inventory, import CRC, configuration, '
              'feature build gates, hashes and device-tree verification. Feature build gates do not '
              'establish on-device performance, container, root-hiding or USB behavior. '
              '`release.json` contains the variants array, exact shared build revisions, download names '
              'and per-variant checksums; `SHA256SUMS` covers every public download.\n\n'
              f'- Source commit: `{identity["source_revision"]}`\n'
              f'- Google GKI revision: `{identity["common_revision"]}`\n'
              f'- KernelSU Next revision: `{identity["kernelsu_revision"]}`\n'
              f'- Verified build: https://github.com/{repository}/actions/runs/{identity["run_id"]} '
              f'(attempt {identity["run_attempt"]})\n')
    if all(variant_assets.susfs_builtin(row) for row in rows):
        notes += ('\nSUSFS is built into both kernels; no matching SUSFS loader addon is required. '
                  '[SUSFS userspace settings](https://github.com/sidex15/susfs4ksu-module) '
                  'can configure the built-in features. ')
    else:
        notes += ('\nVariants with a SUSFS addon load its kernel module through KernelSU’s '
                  'special loader. Install that variant’s matched addon to activate it; '
                  '[SUSFS userspace settings](https://github.com/sidex15/susfs4ksu-module) '
                  'remain optional. ')
    notes += ('Choose a compatible [NoMount](https://github.com/maxsteeel/nomount) or '
              '[Mountify](https://github.com/backslashxx/mountify) metamodule separately when needed. '
              'Kernel backend support does not install or activate either metamodule.\n')
    return notes


def release_notes(repository, identity):
    if asset_format(identity) == 3:
        return variant_release_notes(repository, identity)
    source, kernel, kernelsu = (identity[k] for k in ('source_revision', 'common_revision', 'kernelsu_revision'))
    run_id, attempt = identity['run_id'], identity['run_attempt']
    url = f'https://github.com/{repository}/actions/runs/{run_id}'
    version = asset_format(identity)
    notes = (
        'Automatically built **Onyx GKI 6.18 for Android 17**, '
        f'KernelSU Next dev, and all **{identity["modules"]} Onyx platform modules**.\n\n'
    )
    if identity.get('full_recovery') or identity.get('installers'):
        notes += '### Installers\n\n'
    if identity.get('full_recovery'):
        complete, _ = recovery_assets.names(identity['kernel_release'], version)
        notes += (
            f'- **`{complete}`** updates the active slot\'s kernel, WLAN and matching modules, '
            'device trees, and recovery modules. It repacks the installed ROM\'s own boot and recovery '
            'ramdisks, retaining its files, labels, boot configuration and module options.\n'
            '- Supports compatible Onyx ROM layouts, including the reviewed 6.6 migration. Requires '
            'an unlocked bootloader, already-disabled AVB/verity, no pending OTA snapshots, '
            'separate writable DLKM extents and sufficient recovery/backup space. Unsupported '
            'layouts or unknown drivers abort before partition writes.\n'
            '- All six images are prepared and verified before installation, with persistent original '
            'backups and complete rollback on a detected write/readback failure. '
            '`full-recovery.json` records the ZIP and tool provenance. This ZIP has offline image '
            'and transaction validation; it has not been flashed on a device.\n'
        )
    if identity.get('installers'):
        ak, wlan, *external = installer_assets.names(identity['kernel_release'], version)
        notes += (
            f'- `{ak}` — AnyKernel3 kernel update for Onyx with matching Android 17 / 6.18 modules. '
            'Checks installed DLKM and vendor-ramdisk module CRCs before writing boot.\n'
            f'- `{wlan}` — KernelSU Next/Magisk internal WCN7750 monitor-mode and frame-injection module. '
            'Install after booting the matching kernel, then reboot.\n'
        )
        if external:
            notes += (
                f'- `{external[0]}` — KernelSU Next/Magisk external USB Wi-Fi driver and firmware module '
                'for the included Realtek, Ralink/MediaTek and Atheros adapters. '
                'Install on the matching kernel, then reboot.\n'
            )
        notes += (
            '\n'
            'A kernel-only ZIP cannot migrate a 6.6 ROM or a different KMI generation to 6.18. '
            + ('Use the complete recovery ZIP for compatible layouts. ' if identity.get('full_recovery') else
               'Use the matched ROM/module migration procedure for that transition. ') +
            '`installers.json` binds the manager and kernel installers to the verified build inputs.\n'
        )
    notes += (
        '\n### For ROM maintainers and developers\n\n'
        f'`{archive_name(version)}` is the complete build-output archive for ROM integration and '
        'installer generation. It contains the matching kernel, modules, device trees, firmware, ABI, '
        'configuration, source inputs and logs. It is not directly flashable; users installing a ROM '
        'or an installer ZIP do not normally need it.\n\n'
        'Complete source replay, module import CRCs, artifact hashes and both device-tree variants passed. '
        '`release.json` and `SHA256SUMS` identify the exact assets. Build and installer checks do not '
        'establish device boot or adapter injection validation. '
        f'[Installation instructions](https://github.com/{repository}/blob/ci/README.md#install-a-release).\n\n'
        f'- Exact kernel release: `{identity["kernel_release"]}`\n'
        f'- Source commit: `{source}`\n- Google GKI revision: `{kernel}`\n'
        f'- KernelSU Next revision: `{kernelsu}`\n- Verified build: {url} (attempt {attempt})\n'
    )
    return notes


def publish(repository, bundle, source_root, source, kernel, kernelsu, run_id, attempt):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid repository')
    if not all(re.fullmatch('[0-9a-f]{40}', value) for value in (source, kernel, kernelsu)):
        raise ValueError('Release requires exact source revisions')
    if not str(run_id).isdigit() or not str(attempt).isdigit():
        raise ValueError('Release requires an exact Actions run and attempt')
    prefix = 'repos/' + repository
    build_run = api(prefix + '/actions/runs/' + str(run_id) + '/attempts/' + str(attempt))
    if build_run['head_branch'] != TRACK['ci_branch'] or build_run['path'] != '.github/workflows/build.yml':
        raise ValueError('Release must come from the CI build workflow')
    supplied = json.loads((bundle / 'release.json').read_text())
    if asset_format(supplied) == 3 and (not isinstance(build_run.get('head_sha'), str)
            or not re.fullmatch('[0-9a-f]{40}', build_run['head_sha'])
            or supplied.get('automation_revision') != build_run['head_sha']):
        raise ValueError('Release CI revision differs from the authenticated build attempt')
    jobs = api(prefix + '/actions/runs/' + str(run_id) + '/attempts/' + str(attempt) + '/jobs')['jobs']
    if not any(job['name'] == 'build' and job['conclusion'] == 'success' for job in jobs):
        raise ValueError('Full build and artifact upload have not succeeded')
    identity = validate_bundle(bundle, source_root, source, kernel, kernelsu, run_id, attempt,
                               automation_revision=build_run.get('head_sha') if asset_format(supplied) == 3 else None)
    if asset_format(identity) == 3 and any(not row.get('installers') or not row.get('full_recovery')
                                           for row in variant_assets.rows(identity)):
        raise ValueError('Both variants require all matched installers before publication')
    accepted = api(prefix + '/git/ref/heads/' + TRACK['source_branch'])['object']['sha']
    if accepted != source:
        # Accepted source can advance while the full build is running.
        # Keep the verified artifact, but neither publish nor record old inputs.
        return {'status': 'superseded build', 'release_ready': False,
                'built_source': source, 'accepted_source': accepted}
    version = identity['kernel_release'].split('-')[0]
    tag = f'gki-{version}-s{source[:12]}-k{kernelsu[:12]}'
    assets = sorted(bundle / name for name in bundle_files(identity) | {'release.json', 'SHA256SUMS'})
    asset_names = {path.name for path in assets}
    existing = release_by_tag(prefix, tag)
    if existing:
        release_inputs(existing, tag, source, kernel, kernelsu)
        if not existing['draft']:
            if {asset['name'] for asset in existing['assets']} != asset_names or any(asset['size'] < 1 for asset in existing['assets']):
                raise ValueError('Published release has incomplete assets; refusing to overwrite it')
            return {'status': 'verified inputs already released', 'release_ready': True,
                    'tag': tag, 'url': existing['html_url']}
    notes = release_notes(repository, identity)
    notes += google_changelog.summary(list(listed(prefix + '/releases')), tag, kernel)
    if not existing:
        # Draft tags and release listings may not expose a just-created release.
        # The creation response supplies its ID; keep that identity for every
        # later read, upload and publication instead of resolving the tag again.
        existing = api(prefix + '/releases', method='POST', data={
            'tag_name': tag, 'target_commitish': source, 'draft': True,
            'name': release_title(identity), 'body': notes,
        })
        release_inputs(existing, tag, source, kernel, kernelsu)
        if existing.get('draft') is not True:
            raise ValueError('Created release is not the expected draft')
    release_id = existing['id']
    release_path = prefix + '/releases/' + str(release_id)
    draft = api(release_path)
    release_inputs(draft, tag, source, kernel, kernelsu)
    if draft['id'] != release_id or draft.get('draft') is not True:
        raise ValueError('Selected release is no longer the expected draft')
    for path in assets:
        matches = [asset for asset in draft['assets'] if asset['name'] == path.name]
        if len(matches) > 1:
            raise ValueError('Draft contains duplicate asset names: ' + path.name)
        if matches:
            asset = matches[0]
            if (asset.get('state') == 'uploaded' and asset['size'] == path.stat().st_size and
                    asset.get('digest') == 'sha256:' + digest(path)):
                continue  # Resume an interrupted upload without replacing verified bytes.
            if type(asset.get('id')) is not int or asset['id'] < 1:
                raise ValueError('Draft asset has an invalid ID: ' + path.name)
            api(prefix + '/releases/assets/' + str(asset['id']), method='DELETE')
        api('https://uploads.github.com/' + release_path + '/assets?name=' + quote(path.name, safe=''),
            method='POST', input_file=path)
    uploaded = api(release_path)
    release_inputs(uploaded, tag, source, kernel, kernelsu)
    if uploaded['id'] != release_id or uploaded.get('draft') is not True:
        raise ValueError('Uploaded release is no longer the expected draft')
    if (len(uploaded['assets']) != len(assets) or
            {asset['name'] for asset in uploaded['assets']} != asset_names):
        raise ValueError('Draft release upload is incomplete')
    for asset in uploaded['assets']:
        local = next(path for path in assets if path.name == asset['name'])
        if (asset.get('state') != 'uploaded' or asset['size'] != local.stat().st_size or
                asset.get('digest') not in (None, 'sha256:' + digest(local))):
            raise ValueError('Uploaded release asset differs: ' + asset['name'])
    # A source push may land during a long upload. Publishing an older
    # draft as Latest must not supersede a newer accepted-source release.
    accepted = api(prefix + '/git/ref/heads/' + TRACK['source_branch'])['object']['sha']
    if accepted != source:
        return {'status': 'superseded build', 'release_ready': False,
                'built_source': source, 'accepted_source': accepted}
    published = api(release_path, method='PATCH', data={
        'draft': False, 'make_latest': 'true', 'name': release_title(identity), 'body': notes})
    release_inputs(published, tag, source, kernel, kernelsu)
    if published['id'] != release_id or published.get('draft') is not False:
        raise ValueError('Release publication did not return the expected published release')
    return {'status': 'verified build released', 'release_ready': True, 'tag': tag,
            'url': f'https://github.com/{repository}/releases/tag/{tag}'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('source')
    parser.add_argument('kernel')
    parser.add_argument('kernelsu')
    parser.add_argument('--build-run-id', default=os.environ.get('GITHUB_RUN_ID'))
    parser.add_argument('--build-run-attempt', default=os.environ.get('BUILD_RUN_ATTEMPT'))
    args = parser.parse_args()
    result = publish(os.environ['GITHUB_REPOSITORY'], args.bundle,
                     Path(os.environ['KONOHA_SOURCE_ROOT']), args.source, args.kernel, args.kernelsu,
                     args.build_run_id, args.build_run_attempt)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('release_ready=' + str(result['release_ready']).lower() + '\n')
            if result['release_ready']:
                stream.write('release_tag=' + result['tag'] + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
