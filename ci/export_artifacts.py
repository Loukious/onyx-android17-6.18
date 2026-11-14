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

from verify_artifacts import digest, verify
from release_naming import ASSET_FORMAT, archive_name, artifact_name, write_checksums


def export(workspace, output, source_root, source_revision, run_id, run_attempt):
    if not re.fullmatch('[0-9a-f]{40}', source_revision):
        raise ValueError('Export requires an exact source commit')
    builds = sorted(d for d in (workspace / 'artifacts').iterdir() if (d / 'report.json').is_file())
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
    (output / 'release.json').write_text(json.dumps(identity, indent=2) + '\n')
    write_checksums(output)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            for key in ('kernel_revision', 'kernelsu_revision'):
                f.write(key + '=' + identity['common_revision' if key == 'kernel_revision' else key] + '\n')
            f.write('artifact_name=' + identity['artifact_name'] + '\n')
            f.write('build_attempt=' + identity['run_attempt'] + '\n')
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
