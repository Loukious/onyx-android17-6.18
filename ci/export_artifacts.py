#!/usr/bin/env python3
"""Export a verified build and bind its release bundle to exact input revisions."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

from verify_artifacts import digest, verify, inventory_summary
from release_naming import ASSET_FORMAT, VARIANT_ASSET_FORMAT, VARIANTS, archive_name, artifact_name, write_checksums, build_timestamp
import variant_assets


def export_variants(builds, output, source_root, source_revision, run_id, run_attempt):
    verified = {}
    for artifact in builds:
        report, pins, count = verify(artifact, source_root)
        variant = report.get('variant', {})
        identifier = variant.get('id')
        if identifier not in VARIANTS or identifier in verified:
            raise ValueError('Expected one verified build of each kernel variant')
        verified[identifier] = artifact, report, pins, count
    if set(verified) != set(VARIANTS):
        raise ValueError('Both balanced and performance builds are required before export')
    first = verified[VARIANTS[0]][1]
    if not isinstance(first.get('automation_revision'), str) or not re.fullmatch('[0-9a-f]{40}', first['automation_revision']):
        raise ValueError('Variant exports require the exact CI automation revision')
    common = verified[VARIANTS[0]][2]['common']['revision']
    identity = {'source_revision': source_revision, 'common_revision': common,
                'kernelsu_revision': first['kernelsu_next']['revision'],
                'run_id': str(run_id), 'run_attempt': str(run_attempt),
                'asset_format': VARIANT_ASSET_FORMAT,
                'artifact_name': artifact_name(run_id, run_attempt, VARIANT_ASSET_FORMAT),
                'variants': []}
    if first.get('automation_revision'):
        identity['automation_revision'] = first['automation_revision']
    manifest = json.loads((source_root / 'port/features/manifest.json').read_text())
    identity['install_options'] = manifest.get('install_options', {})
    # Verify all identities before creating the publishable bundle directory.
    for _, report, pins, _ in verified.values():
        if (pins['common']['revision'] != common
                or report['kernelsu_next'] != first['kernelsu_next']
                or report.get('automation_revision') != first.get('automation_revision')):
            raise ValueError('Variant builds use different immutable input revisions')
    output.mkdir(parents=True, exist_ok=False)
    for identifier in VARIANTS:
        artifact, report, pins, count = verified[identifier]
        row = {key: identity[key] for key in variant_assets.SHARED if key in identity}
        row.update(report['variant'])
        row.update(asset_format=VARIANT_ASSET_FORMAT, kernel_release=report['kernel_release'],
                   artifact_root=artifact.name, modules=count, asset_timestamp=build_timestamp(artifact.name))
        evidence = variant_assets.evidence_names(identifier, row['asset_timestamp'])
        for source, destination in [('report.json', evidence['report']), ('build.log', evidence['build_log']),
                ('gki/kernel_aarch64_Module.symvers', evidence['module_abi']),
                ('gki/kernel.release', evidence['kernel_release']),
                ('gki/kernel_aarch64_dot_config', evidence['kernel_config'])]:
            shutil.copyfile(artifact / source, output / destination)
        filename = archive_name(VARIANT_ASSET_FORMAT, identifier, row['asset_timestamp'])
        with tarfile.open(output / filename, 'w:gz') as archive:
            archive.add(artifact, arcname=artifact.name)
        row.update(inventory_summary(report))
        if (source_root / 'port/components.json').is_file():
            catalog = json.loads((source_root / 'port/components.json').read_text())
            row['native_component_modules'] = sum(item['kind'] == 'native_common' for item in catalog['components'])
        row['sha256'] = {name: digest(output / name) for name in variant_assets.core_files(row)}
        row['downloads'] = variant_assets.download_map(row)
        identity['variants'].append(row)
    for key in ('kernel_release', 'artifact_root', 'modules'):
        identity[key] = identity['variants'][0][key]
    variant_assets.rows(identity)
    identity['sha256'] = {name: checksum for row in identity['variants'] for name, checksum in row['sha256'].items()}
    (output / 'release.json').write_text(json.dumps(identity, indent=2) + '\n')
    write_checksums(output)
    emit_outputs(identity)
    return identity


def emit_outputs(identity):
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            for key in ('kernel_revision', 'kernelsu_revision'):
                stream.write(key + '=' + identity['common_revision' if key == 'kernel_revision' else key] + '\n')
            stream.write('artifact_name=' + identity['artifact_name'] + '\n')
            stream.write('build_attempt=' + identity['run_attempt'] + '\n')


def export(workspace, output, source_root, source_revision, run_id, run_attempt):
    if not re.fullmatch('[0-9a-f]{40}', source_revision):
        raise ValueError('Export requires an exact source commit')
    builds = sorted(d for d in (workspace / 'artifacts').iterdir() if (d / 'report.json').is_file())
    if any('variant' in json.loads((artifact / 'report.json').read_text()) for artifact in builds):
        return export_variants(builds, output, source_root, source_revision, run_id, run_attempt)
    if len(builds) != 1:
        raise ValueError('Expected one complete build in a fresh CI workspace')
    artifact = builds[0]
    report, pins, count = verify(artifact, source_root)
    output.mkdir(parents=True, exist_ok=False)
    for name in ('report.json', 'build.log'):
        shutil.copyfile(artifact / name, output / name)
    with tarfile.open(output / archive_name(ASSET_FORMAT), 'w:gz') as tar:
        tar.add(artifact, arcname=artifact.name)
    abi = output / 'kernel-abi'
    abi.mkdir()
    for name in ('kernel_aarch64_Module.symvers', 'kernel.release', 'kernel_aarch64_dot_config'):
        shutil.copyfile(artifact / 'gki' / name, abi / ('Module.symvers' if name.endswith('_Module.symvers') else name))
    identity = {
        'source_revision': source_revision, 'common_revision': pins['common']['revision'],
        'kernelsu_revision': report['kernelsu_next']['revision'], 'kernel_release': report['kernel_release'],
        'modules': count, 'run_id': str(run_id), 'run_attempt': str(run_attempt),
        'asset_format': ASSET_FORMAT,
        'artifact_name': artifact_name(run_id, run_attempt, ASSET_FORMAT),
        'artifact_root': artifact.name,
        'sha256': {p.relative_to(output).as_posix(): digest(p) for p in sorted(output.rglob('*')) if p.is_file()},
    }
    identity.update(inventory_summary(report))
    if (source_root / 'port/components.json').is_file():
        catalog = json.loads((source_root / 'port/components.json').read_text())
        identity['native_component_modules'] = sum(row['kind'] == 'native_common' for row in catalog['components'])
    if report.get('automation_revision'):
        identity['automation_revision'] = report['automation_revision']
    (output / 'release.json').write_text(json.dumps(identity, indent=2) + '\n')
    write_checksums(output)
    emit_outputs(identity)
    return identity


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('workspace', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    source = Path(os.environ.get('KONOHA_SOURCE_ROOT', Path(__file__).resolve().parents[1]))
    revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    print(json.dumps(export(args.workspace, args.output, source, revision,
                            os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']), indent=2))
