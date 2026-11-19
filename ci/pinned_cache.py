#!/usr/bin/env python3
"""Bounded, exact-pin Git object references; never cache dependency worktrees."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from bounded_cache import SOURCE_LIMIT, TOOLCHAIN_LIMIT, digest, directory, files, size, summary, budgets

LIMITS = {'sources': SOURCE_LIMIT, 'toolchains': TOOLCHAIN_LIMIT}


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True,
                                   env={**os.environ, 'GIT_CONFIG_NOSYSTEM': '1',
                                        'GIT_CONFIG_GLOBAL': '/dev/null'}).strip()


def safe_name(value):
    if (not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.+/-]+', value)
            or value.startswith('/') or any(part in ('', '.', '..') for part in value.split('/'))):
        raise ValueError('Unsafe locked project path')
    return value


def projects(source):
    port = source / 'port'
    pins = json.loads((port / 'sources.json').read_text())
    rows = [{'name': 'kernel/common', 'path': 'common', 'revision': pins['common']['revision']}]
    rows += [dict(name=p.get('name'), path=p.get('path'), revision=p.get('revision'))
             for p in ET.parse(port / 'dependency-lock.xml').getroot()]
    rows += [dict(name=p['repo'], path=p['workspace_path'], revision=p['revision'])
             for p in pins['baseline']]
    result = {'sources': [], 'toolchains': []}
    for row in rows:
        for field in ('name', 'path'):
            safe_name(row[field])
        if not re.fullmatch('[0-9a-f]{40}', row['revision']):
            raise ValueError('Dependency cache requires immutable Git pins')
        result['toolchains' if row['path'].startswith('prebuilts/') else 'sources'].append(row)
    # Bind fetch definitions as well as pins; a changed source endpoint cannot reuse a cache.
    transport = {'source_manifest': digest(port / 'onyx-port.xml')}
    transport['manifest_url'] = pins['manifest']['url']
    return result, transport


def identity(source, bucket):
    import hashlib
    rows, transport = projects(source)
    if bucket == 'toolchains':
        transport = {'manifest_url': transport['manifest_url']}
    record = {'schema': 1, 'bucket': bucket, 'projects': sorted(rows[bucket], key=lambda p: p['path']),
              'limit_bytes': budgets()[bucket],
              'transport': transport, 'helper_sha256': digest(Path(__file__)),
              'guards_sha256': digest(Path(__file__).with_name('bounded_cache.py'))}
    key = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
    return record, f'onyx-pins-v1-Linux-{bucket}-{key}'


def validate(root, expected, limit):
    directory(root)
    if size(root) > limit:
        raise ValueError('Pinned Git cache exceeds its size limit')
    report = json.loads((root / 'cache.json').read_text())
    if report.get('identity') != expected:
        raise ValueError('Restored Git cache does not match the dependency pins')
    stored = report.get('repositories')
    if not isinstance(stored, dict):
        raise ValueError('Invalid Git cache index')
    expected_by_name = {}
    for row in expected['projects']:
        expected_by_name.setdefault(row['name'], set()).add(row['revision'])
    names = {'cache.json'}
    for name, entry in stored.items():
        safe_name(name)
        if name not in expected_by_name or set(entry['revisions']) != expected_by_name[name]:
            raise ValueError('Unexpected cached Git repository or revision')
        repo = root / (name + '.git')
        actual = {str(path.relative_to(repo)): digest(path) for path, _ in files(repo)}
        if actual != entry['files']:
            raise ValueError('Git object cache checksum mismatch: ' + name)
        names.update(str(path.relative_to(root)) for path, _ in files(repo))
        for revision in entry['revisions']:
            if git(repo, 'rev-parse', 'refs/heads/pin-' + revision) != revision:
                raise ValueError('Git reference mismatch')
        git(repo, 'fsck', '--full', '--no-reflogs')
    if {str(path.relative_to(root)) for path, _ in files(root)} != names:
        raise ValueError('Unexpected files in pinned cache')
    return report


def restore(root, reference, source, bucket, matched_key):
    expected, key = identity(source, bucket)
    directory(root)
    reference = directory(reference)
    if not matched_key:
        if files(root):
            raise ValueError('Cold dependency cache directory must be empty')
        summary(f'{bucket}: cold pinned cache `{key}`.')
        return {'key': key, 'repositories': 0}
    if matched_key != key:
        raise ValueError('Dependency caches allow exact keys only')
    report = validate(root, expected, budgets()[bucket])
    for name in report['repositories']:
        target = reference / (name + '.git')
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            raise ValueError('Duplicate dependency reference')
        target.symlink_to(root / (name + '.git'), target_is_directory=True)
    summary(f'{bucket}: verified pinned cache hit; {len(report["repositories"])} repositories, '
            f'{size(root) / 1024**3:.2f} GiB.')
    return report


def save(root, workspace, source, bucket):
    root = directory(root)
    if files(root):
        raise ValueError('Save requires a cold, empty dependency cache')
    expected, key = identity(source, bucket)
    grouped = {}
    for row in expected['projects']:
        if git(workspace / row['path'], 'rev-parse', 'HEAD') != row['revision']:
            raise ValueError('Cannot cache a dependency at an unpinned revision')
        grouped.setdefault(row['name'], []).append(row)
    # Retain the expensive downloads first, then smaller repositories. Evict
    # whole repositories only: dropping arbitrary Git objects corrupts a cache.
    def priority(name):
        return (0 if 'prebuilts/clang/host/' in name else
                1 if 'prebuilts/rust-toolchain/' in name else
                2 if name == 'kernel/common' else 3, name)
    report = {'identity': expected, 'repositories': {}, 'omitted': []}
    used = 0
    for name in sorted(grouped, key=priority):
        rows = grouped[name]
        origin = workspace / '.repo/project-objects' / (name + '.git')
        objects = directory(origin / 'objects')
        # Exact hits need no resave. Cold saves must be self-contained; never
        # retain alternates that point into a runner scheduled for deletion.
        if (objects / 'info/alternates').exists():
            raise ValueError('Cold Git cache cannot contain object alternates')
        entries = files(objects)
        estimated = sum(max(info.st_size, info.st_blocks * 512) for _, info in entries)
        if used + estimated + 1024 * 1024 > budgets()[bucket]:
            report['omitted'].append({'name': name, 'bytes': estimated})
            continue
        repo = root / (name + '.git')
        repo.mkdir(parents=True)
        subprocess.run(['git', 'init', '--bare', '--quiet', str(repo)], check=True)
        shutil.rmtree(repo / 'hooks')
        shutil.rmtree(repo / 'info')
        shallow = set()
        for row in rows:
            project = workspace / row['path']
            shallow_path = Path(git(project, 'rev-parse', '--path-format=absolute', '--git-path', 'shallow'))
            if shallow_path.exists():
                shallow.update(shallow_path.read_text().splitlines())
        if shallow:
            (repo / 'shallow').write_text(''.join(pin + '\n' for pin in sorted(shallow)))
        for path, _ in entries:
            target = repo / 'objects' / path.relative_to(objects)
            target.parent.mkdir(parents=True, exist_ok=True)
            # Git objects are immutable. Hardlinks avoid another multi-GiB
            # local copy while Actions archives them as independent files.
            os.link(path, target)
        revisions = sorted({row['revision'] for row in rows})
        for revision in revisions:
            git(repo, 'update-ref', 'refs/heads/pin-' + revision, revision)
        git(repo, 'symbolic-ref', 'HEAD', 'refs/heads/pin-' + revisions[0])
        git(repo, 'fsck', '--full', '--no-reflogs')
        entry = {'revisions': revisions, 'files': {str(path.relative_to(repo)): digest(path)
                                                   for path, _ in files(repo)}}
        report['repositories'][name] = entry
        used += size(repo)
    (root / 'cache.json').write_text(json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n')
    validate(root, expected, budgets()[bucket])
    summary(f'{bucket}: prepared {size(root) / 1024**3:.2f} GiB pinned cache '
            f'(limit {budgets()[bucket] / 1024**3:.2f} GiB); '
            f'{len(report["omitted"])} whole repositories omitted by the bound.')
    return {'key': key, 'bytes': size(root), 'omitted': report['omitted']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('keys', 'restore', 'save'))
    parser.add_argument('--source', type=Path, default=Path('source'))
    parser.add_argument('--bucket', choices=LIMITS)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--workspace', type=Path)
    parser.add_argument('--matched-key', default='')
    args = parser.parse_args()
    if args.command == 'keys':
        result = {bucket + '_key': identity(args.source, bucket)[1] for bucket in LIMITS}
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                stream.write(''.join(key + '=' + value + '\n' for key, value in result.items()))
    elif args.command == 'restore':
        result = restore(args.root, args.reference, args.source, args.bucket, args.matched_key)
    else:
        result = save(args.root, args.workspace, args.source, args.bucket)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
