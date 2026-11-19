#!/usr/bin/env python3
"""Transfer verified per-runner outputs to the existing complete-build gate."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

from release_naming import VARIANTS
from verify_artifacts import digest, relative, verify

SHARED = ('source_revision', 'automation_revision', 'kernelsu_revision', 'run_id', 'run_attempt')


def validate_context(context):
    if set(context) != set(SHARED):
        raise ValueError('Incomplete matrix build context')
    for key in SHARED:
        pattern = '[1-9][0-9]*' if key in ('run_id', 'run_attempt') else '[0-9a-f]{40}'
        if not isinstance(context[key], str) or not re.fullmatch(pattern, context[key]):
            raise ValueError('Invalid matrix build identity: ' + key)


def name(variant, context):
    if variant not in VARIANTS:
        raise ValueError('Unsupported compiler variant')
    validate_context(context)
    return f'Onyx-GKI-Input-{variant}-{context["run_id"]}-{context["run_attempt"]}'


def check_build(artifact, source, variant, context):
    report, pins, _ = verify(artifact, source)
    if (report.get('variant', {}).get('id') != variant
            or report.get('automation_revision') != context['automation_revision']
            or report['kernelsu_next']['revision'] != context['kernelsu_revision']):
        raise ValueError('Compiler output differs from the resolved variant or build inputs')
    return report, pins


def pack(workspace, output, source, variant, context):
    validate_context(context)
    artifacts = sorted(path for path in (workspace / 'artifacts').iterdir()
                       if (path / 'report.json').is_file())
    if len(artifacts) != 1:
        raise ValueError('Each compiler runner must produce exactly one complete variant')
    artifact = artifacts[0]
    report, pins = check_build(artifact, source, variant, context)
    root = artifact.name + '-' + variant
    relative(root)
    output.mkdir(parents=True, exist_ok=False)
    archive_path = output / 'payload.tar.gz'
    with tarfile.open(archive_path, 'w:gz') as archive:
        archive.add(artifact, arcname=root)
    identity = {**context, 'schema': 1, 'variant': variant, 'artifact_root': root,
                'common_revision': pins['common']['revision'], 'kernel_release': report['kernel_release'],
                'report_sha256': digest(artifact / 'report.json'), 'payload_sha256': digest(archive_path)}
    (output / 'input.json').write_text(json.dumps(identity, indent=2) + '\n')
    return {'artifact_name': name(variant, context), 'variant': variant, **context}


def collect(inputs, workspace, source, context):
    validate_context(context)
    expected = {name(variant, context): variant for variant in VARIANTS}
    if inputs.is_symlink() or {path.name for path in inputs.iterdir()} != set(expected):
        raise ValueError('Exactly both current-run compiler artifacts are required')
    records, roots = [], set()
    for folder, variant in expected.items():
        directory = inputs / folder
        if (directory.is_symlink() or not directory.is_dir()
                or {path.name for path in directory.iterdir()} != {'input.json', 'payload.tar.gz'}
                or any(path.is_symlink() or not path.is_file() for path in directory.iterdir())):
            raise ValueError('Compiler transfer inventory is incomplete or unsafe')
        identity = json.loads((directory / 'input.json').read_text())
        if (identity.get('schema') != 1 or identity.get('variant') != variant
                or any(identity.get(key) != context[key] for key in SHARED)):
            raise ValueError('Compiler artifact belongs to a different variant, commit, run or attempt')
        root = identity['artifact_root']
        if len(relative(root).parts) != 1 or root in roots:
            raise ValueError('Compiler artifact roots are unsafe or duplicated')
        roots.add(root)
        payload = directory / 'payload.tar.gz'
        if identity.get('payload_sha256') != digest(payload):
            raise ValueError('Compiler transfer archive changed')
        records.append((variant, identity, payload))
    if len({identity['common_revision'] for _, identity, _ in records}) != 1:
        raise ValueError('Compiler outputs use different pinned Common sources')
    workspace.mkdir(parents=True, exist_ok=True)
    output = workspace / 'artifacts'
    if output.exists() or output.is_symlink():
        raise ValueError('Compiler collection requires a fresh artifact directory')
    with tempfile.TemporaryDirectory(prefix='matrix-verify-', dir=workspace) as temporary:
        staging = Path(temporary)
        for variant, identity, payload in records:
            with tarfile.open(payload, 'r:gz') as archive:
                seen = set()
                for member in archive.getmembers():
                    member_path = str(relative(member.name.rstrip('/')))
                    if (member_path in seen or member_path.split('/')[0] != identity['artifact_root']
                            or not (member.isdir() or member.isfile())):
                        raise ValueError('Unsafe or duplicated compiler archive member')
                    seen.add(member_path)
                archive.extractall(staging, filter='data')
            artifact = staging / identity['artifact_root']
            report, pins = check_build(artifact, source, variant, context)
            if (identity.get('report_sha256') != digest(artifact / 'report.json')
                    or identity.get('common_revision') != pins['common']['revision']
                    or identity.get('kernel_release') != report['kernel_release']):
                raise ValueError('Compiler receipt differs from its verified build')
        # Both inputs pass the full source/configuration/ABI/hash verifier before
        # either becomes visible to the existing exporter and installer builders.
        assembled = staging / 'assembled'
        assembled.mkdir()
        for root in roots:
            shutil.move(str(staging / root), assembled / root)
        assembled.rename(output)
    return {'variants': list(VARIANTS), **context}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('pack', 'collect'))
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--source', type=Path, default=Path(os.environ.get('KONOHA_SOURCE_ROOT', 'source')))
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--automation-revision', required=True)
    parser.add_argument('--kernelsu-revision', required=True)
    parser.add_argument('--run-id', default=os.environ.get('GITHUB_RUN_ID'))
    parser.add_argument('--run-attempt', default=os.environ.get('GITHUB_RUN_ATTEMPT'))
    parser.add_argument('--variant', choices=VARIANTS)
    args = parser.parse_args()
    if (args.command == 'pack') != bool(args.variant):
        parser.error('--variant is required only when packing one compiler output')
    context = {key: getattr(args, key) for key in SHARED}
    actual = subprocess.check_output(['git', '-C', str(args.source), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != context['source_revision']:
        parser.error('Selected source checkout differs from the once-resolved commit')
    result = (pack(args.input, args.output, args.source, args.variant, context) if args.command == 'pack'
              else collect(args.input, args.output, args.source, context))
    if os.environ.get('GITHUB_OUTPUT') and args.command == 'pack':
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('artifact_name=' + result['artifact_name'] + '\n')
    print(json.dumps(result, indent=2))
