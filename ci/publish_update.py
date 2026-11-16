#!/usr/bin/env python3
"""Publish a replayed LTS candidate without overwriting the accepted kernel."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from dispatch_build import should_dispatch
import kernelsu_lock

CI_ROOT = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get('KONOHA_SOURCE_ROOT', CI_ROOT))
TRACK = json.loads((CI_ROOT / 'ci/upstream.json').read_text())


def run(args, **kwargs):
    return subprocess.check_output(args, cwd=ROOT, text=True, **kwargs).strip()


def publish(revision, kernelsu=None, *, pin_source=False):
    """Publish a candidate; the tracker CLI pins source, legacy API callers may omit it."""
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('Invalid upstream revision')
    if kernelsu is not None and not re.fullmatch('[0-9a-f]{40}', kernelsu):
        raise ValueError('Invalid detected KernelSU Next revision')
    pins = json.loads((ROOT / 'port/sources.json').read_text())
    if pins['common']['revision'] != revision:
        raise ValueError('Candidate does not match detected upstream')
    # Recording build state must not create another candidate for the same
    # recipe. Recipe changes, however, need a fresh branch and complete build.
    base_tree = run(['git', 'rev-parse', 'HEAD:port'])
    frozen = kernelsu_lock.read(ROOT / 'port')
    if frozen:
        if kernelsu and kernelsu != frozen['revision']:
            raise ValueError('Candidate KernelSU input differs from the source lock')
        kernelsu = frozen['revision']
        base = hashlib.sha256((base_tree + ' ' + kernelsu).encode()).hexdigest()[:12]
    else:
        base = base_tree[:12]
    branch = f'upstream/android17-6.18-lts-{revision[:12]}-{base}'
    existing = run(['git', 'ls-remote', 'origin', 'refs/heads/' + branch])
    version = pins['common']['kernel']
    if not existing:
        run(['git', 'checkout', '-b', branch])
        # Upstream .gitignore files can match files deliberately tracked by
        # upstream. The verified archive, not ignore patterns, defines GKI.
        run(['git', 'add', 'port', 'modules'])
        run(['git', 'add', '-f', 'common'])
        run(['git', 'commit', '-m', f'Track Android 17 LTS {version} ({revision[:12]})'])
        run(['git', 'push', '-u', 'origin', branch])
    # Recover after a failed PR creation or dispatch without overwriting a
    # candidate branch that may contain manual conflict repairs.
    proposals = json.loads(run(['gh', 'pr', 'list', '--head', branch, '--state', 'all',
                               '--json', 'url,state']))
    if proposals and proposals[0]['state'] != 'OPEN':
        return {'status': 'candidate already reviewed; preserving its disposition', 'branch': branch}
    count = len(list((ROOT / 'port/patches').glob('*.patch')))
    modules = len(json.loads((ROOT / 'port/modules.json').read_text()))
    body = (
        f'Update the Onyx port to Android 17 LTS {version} at `{revision}`. '
        'Common-header imports and the complete modified module snapshot are refreshed; '
        f'all {count} module patches must replay exactly. CoreSight changes already in upstream '
        'are detected and excluded from the effective patch.\n\n'
        'The linked build workflow builds the selected KernelSU source, GKI, '
        f'all {modules} platform modules and both device-tree variants, including symbol/CRC '
        'verification. Conflicts and build failures require a source repair. '
        'No device installation or hardware validation is performed by CI.\n'
    )
    if proposals:
        url = proposals[0]['url']
    else:
        with tempfile.TemporaryDirectory(prefix='konoha-pr-') as temporary:
            path = Path(temporary) / 'body.md'
            path.write_text(body)
            url = run(['gh', 'pr', 'create', '--base', TRACK['source_branch'], '--head', branch,
                       '--title', f'Android 17 LTS {version}', '--body-file', str(path)])
    source = None
    if pin_source:
        ref = 'refs/heads/' + branch
        remote = run(['git', 'ls-remote', 'origin', ref]).splitlines()
        fields = remote[0].split() if len(remote) == 1 else []
        if len(fields) != 2 or not re.fullmatch('[0-9a-f]{40}', fields[0]) or fields[1] != ref:
            raise ValueError('Candidate source ref must resolve to one exact commit')
        source = fields[0]
    builds = json.loads(run(['gh', 'run', 'list', '--workflow', 'build.yml', '--branch', TRACK['ci_branch'],
                            '--limit', '100', '--json', 'displayTitle,status,conclusion,url']))
    legacy_title = 'Build ' + branch + (' / KSU ' + kernelsu if kernelsu else '')
    title = 'Build ' + branch + (' @ ' + source if source else '') + (' / KSU ' + kernelsu if kernelsu else '')
    builds = [build for build in builds if build['displayTitle'] == title or
              (source and build['displayTitle'] == legacy_title and build['status'] != 'completed')]
    if not should_dispatch(builds):
        return {'status': 'candidate build active, successful, or retry limit reached', 'branch': branch,
                'url': url, 'builds': builds}
    # GITHUB_TOKEN pushes do not trigger another workflow; dispatch explicitly.
    dispatch = ['gh', 'workflow', 'run', 'build.yml', '--ref', TRACK['ci_branch'], '-f', 'source_ref=' + branch]
    if source:
        dispatch += ['-f', 'source_revision=' + source]
    if kernelsu:
        dispatch += ['-f', 'kernelsu_revision=' + kernelsu]
    run(dispatch)
    return {'status': 'candidate PR opened; complete build dispatched', 'branch': branch, 'url': url}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('revision')
    p.add_argument('--kernelsu', help='expected committed KernelSU revision for the source candidate')
    a = p.parse_args()
    print(json.dumps(publish(a.revision, a.kernelsu, pin_source=True), indent=2))
