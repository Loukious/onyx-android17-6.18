#!/usr/bin/env python3
"""Detect upstream changes and refresh explicit source pins without merging."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET

import kernel_toolchains
import kernelsu_lock
import wifi_imports

ROOT = Path(__file__).resolve().parents[1]
PORT = Path(os.environ.get('KONOHA_SOURCE_ROOT', ROOT)) / 'port'
TRACK = json.loads((ROOT / 'ci/upstream.json').read_text())


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


def remote_head(repository, branch):
    ref = 'refs/heads/' + branch
    result = subprocess.check_output(['git', 'ls-remote', '--exit-code', repository, ref], text=True)
    lines = result.strip().splitlines()
    if len(lines) != 1:
        raise ValueError('Expected exactly one upstream branch')
    revision, actual = lines[0].split()
    if actual != ref or not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('Invalid upstream revision')
    return revision


def contains_official_revision(repository, revision, upstream_repository, upstream_revision):
    """Prove ancestry using the resolved immutable commits, without changing source pins."""
    with tempfile.TemporaryDirectory(prefix='onyx-kernelsu-ancestry-') as temporary:
        subprocess.run(['git', 'init', '-q', temporary], check=True)
        for remote, commit in ((repository, revision), (upstream_repository, upstream_revision)):
            subprocess.run(['git', '-C', temporary, 'fetch', '--quiet', '--no-tags', remote, commit],
                           check=True)
        result = subprocess.run(['git', '-C', temporary, 'merge-base', '--is-ancestor',
                                 upstream_revision, revision], check=False)
        if result.returncode not in (0, 1):
            raise ValueError('Could not verify the SUSFS fork against official KernelSU dev')
        return result.returncode == 0


def detect():
    pins = json.loads((PORT / 'sources.json').read_text())
    current = pins['common']['revision']
    latest = remote_head(TRACK['repository'], TRACK['branch'])
    latest_official_ksu = remote_head(TRACK['kernelsu_repository'], TRACK['kernelsu_branch'])
    locked_ksu = kernelsu_lock.read(PORT)
    if (PORT / 'components.json').is_file() and locked_ksu is None:
        raise ValueError('Component sources require a committed KernelSU lock')
    latest_ksu = latest_official_ksu
    latest_repository, latest_branch = TRACK['kernelsu_repository'], TRACK['kernelsu_branch']
    latest_upstream, waiting = '', False
    if locked_ksu and locked_ksu['repository'] == kernelsu_lock.SUSFS_REPOSITORY:
        latest_repository, latest_branch = TRACK['kernelsu_susfs_repository'], TRACK['kernelsu_susfs_branch']
        fork_tip = remote_head(latest_repository, latest_branch)
        unchanged = (fork_tip == locked_ksu['revision']
                     and latest_official_ksu == locked_ksu['upstream_revision'])
        compatible = unchanged or contains_official_revision(
            latest_repository, fork_tip, TRACK['kernelsu_repository'], latest_official_ksu)
        waiting = not compatible
        latest_ksu = fork_tip if compatible else locked_ksu['revision']
        latest_upstream = latest_official_ksu if compatible else locked_ksu['upstream_revision']
    ksu = locked_ksu['revision'] if locked_ksu else latest_ksu
    update_needed = bool(locked_ksu and (latest_ksu != ksu
                         or latest_upstream and latest_upstream != locked_ksu.get('upstream_revision')))
    source_revision = git(PORT.parent, 'rev-parse', 'HEAD')
    state_path = ROOT / 'ci/last-built.json'
    last = json.loads(state_path.read_text()) if state_path.exists() else {}
    result = {'current': current, 'latest': latest, 'kernelsu': ksu,
              'latest_kernelsu': latest_ksu,
              'latest_kernelsu_repository': latest_repository,
              'latest_kernelsu_branch': latest_branch,
              'latest_kernelsu_upstream_revision': latest_upstream,
              'latest_official_kernelsu': latest_official_ksu,
              'kernelsu_upstream_waiting': waiting,
              'kernelsu_update_needed': update_needed,
              'candidate_needed': latest != current or update_needed,
              'kernel_changed': latest != current,
              'source_revision': source_revision,
              'source_changed': source_revision != last.get('source_revision'),
              'release_needed': not last.get('release_tag'),
              'kernelsu_changed': ksu != last.get('kernelsu_revision') or current != last.get('common_revision')}
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            for key, value in result.items():
                f.write(f'{key}={str(value).lower() if isinstance(value, bool) else value}\n')
    return result


def update(repo, revision):
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('Revision must be a complete commit hash')
    if git(repo, 'rev-parse', 'HEAD') != revision:
        raise ValueError('Updater source does not match detected revision')
    makefile = git(repo, 'show', revision + ':Makefile')
    fields = dict(re.findall(r'^(VERSION|PATCHLEVEL|SUBLEVEL)\s*=\s*(\d+)\s*$', makefile, re.M))
    if (fields.get('VERSION'), fields.get('PATCHLEVEL')) != ('6', '18'):
        raise ValueError('Refusing a kernel outside Linux 6.18')
    pins = json.loads((PORT / 'sources.json').read_text())
    dependency_path = PORT / 'dependency-lock.xml'
    old_dependencies = dependency_path.read_text() if dependency_path.exists() else None
    pins['common'], dependencies = kernel_toolchains.refresh(
        repo, revision, pins['common'], old_dependencies)
    pins['common']['revision'] = revision
    pins['common']['kernel'] = '.'.join(fields[k] for k in ('VERSION', 'PATCHLEVEL', 'SUBLEVEL'))
    imports = json.loads((PORT / 'imports.json').read_text())
    build_path, config_path = PORT / 'BUILD.bazel', PORT / 'platform_defconfig'
    old_build = build_path.read_text() if build_path.exists() else None
    fragment = config_path.read_text() if config_path.exists() else None
    native_wifi = False
    catalog_path = PORT / 'components.json'
    if catalog_path.is_file():
        catalog = json.loads(catalog_path.read_text())
        native = {row['name'] for row in catalog['components'] if row['kind'] == 'native_common'}
        native_wifi = {'cfg80211', 'mac80211'} <= native
        if native_wifi and any(wifi_imports.owned(row['path']) for row in imports):
            raise ValueError('Native Wi-Fi catalog retains copied wireless imports')
    if native_wifi:
        build = old_build
    else:
        imports, build = wifi_imports.refresh(repo, revision, imports, old_build, fragment)
    for source in imports:
        if source['project'] == 'common':
            source['revision'] = revision
            source['blob'] = git(repo, 'rev-parse', revision + ':' + source['path'])
    xml = ET.parse(PORT / 'onyx-port.xml')
    entry = xml.getroot().find("extend-project[@name='kernel/common']")
    if entry is None:
        raise ValueError('Common project missing from source manifest')
    entry.set('revision', revision)
    entry.set('upstream', TRACK['branch'])
    ET.indent(xml)
    # Validate every imported path before changing any recipe file.
    (PORT / 'sources.json').write_text(json.dumps(pins, indent=2) + '\n')
    (PORT / 'imports.json').write_text(json.dumps(imports, indent=2) + '\n')
    if build != old_build:
        build_path.write_text(build)
    if dependencies != old_dependencies:
        dependency_path.write_text(dependencies)
    xml.write(PORT / 'onyx-port.xml', encoding='utf-8', xml_declaration=True)
    return {'revision': revision, 'kernel': pins['common']['kernel']}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--update', type=Path, help='clean common checkout to use for a detected update')
    p.add_argument('--revision')
    a = p.parse_args()
    if bool(a.update) != bool(a.revision):
        p.error('--update and --revision must be supplied together')
    print(json.dumps(update(a.update, a.revision) if a.update else detect(), indent=2))
