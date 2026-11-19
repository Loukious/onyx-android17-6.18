#!/usr/bin/env python3
"""Freeze a reviewed KernelSU revision and verify build inputs against its lock."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

REPOSITORY = 'https://github.com/KernelSU-Next/KernelSU-Next.git'
BRANCH = 'dev'
SUSFS_REPOSITORY = 'https://github.com/pershoot/KernelSU-Next.git'
SUSFS_BRANCH = 'dev-susfs'
FIELDS = {'repository', 'branch', 'revision', 'tag', 'git_commit_count', 'version', 'sha256'}


def validate(pin):
    if not isinstance(pin, dict):
        raise ValueError('Invalid committed KernelSU source lock')
    official = (set(pin) == FIELDS and pin.get('repository') == REPOSITORY
                and pin.get('branch') == BRANCH)
    builtin = (set(pin) == FIELDS | {'upstream_revision'}
               and pin.get('repository') == SUSFS_REPOSITORY and pin.get('branch') == SUSFS_BRANCH
               and isinstance(pin.get('upstream_revision'), str)
               and re.fullmatch('[0-9a-f]{40}', pin['upstream_revision']))
    if (not (official or builtin)
            or not isinstance(pin['revision'], str)
            or not re.fullmatch('[0-9a-f]{40}', pin['revision'])
            or not isinstance(pin['sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', pin['sha256'])
            or type(pin['git_commit_count']) is not int or pin['git_commit_count'] < 1
            or pin['version'] != 30000 + pin['git_commit_count']
            or not isinstance(pin['tag'], str)
            or not re.fullmatch('[A-Za-z0-9_.+-]+', pin['tag'])):
        raise ValueError('Invalid committed KernelSU source lock')
    return pin


def read(port):
    path = Path(port) / 'kernelsu-lock.json'
    return validate(json.loads(path.read_text())) if path.is_file() else None


def check(port, expected=''):
    pin = read(port)
    if expected and not re.fullmatch('[0-9a-f]{40}', expected):
        raise ValueError('Expected KernelSU revision must be a complete commit')
    if pin is None:
        if (Path(port) / 'components.json').is_file():
            raise ValueError('Component sources require a committed KernelSU lock')
        return {'policy': 'legacy_source_integration', 'revision': expected}
    if expected and expected != pin['revision']:
        raise ValueError('Requested KernelSU revision differs from the committed source lock')
    return {'policy': 'committed_source_lock', 'revision': pin['revision']}


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


def freeze(repo, revision, upstream_revision=''):
    repository, branch = ((SUSFS_REPOSITORY, SUSFS_BRANCH) if upstream_revision
                          else (REPOSITORY, BRANCH))
    if (not re.fullmatch('[0-9a-f]{40}', revision)
            or upstream_revision and not re.fullmatch('[0-9a-f]{40}', upstream_revision)
            or git(repo, 'rev-parse', 'HEAD') != revision
            or git(repo, 'remote', 'get-url', 'origin') != repository
            or git(repo, 'rev-parse', '--is-shallow-repository') != 'false'):
        raise ValueError('KernelSU lock requires the exact selected full-history checkout')
    if upstream_revision:
        ancestor = subprocess.run(['git', '-C', str(repo), 'merge-base', '--is-ancestor',
                                   upstream_revision, revision], check=False)
        if ancestor.returncode != 0:
            raise ValueError('SUSFS KernelSU source must contain the detected official dev revision')
    version_revision = upstream_revision or revision
    count = int(git(repo, 'rev-list', '--count', version_revision))
    data = subprocess.check_output(['git', '-C', str(repo), 'archive', '--format=tar',
                                    revision, 'kernel', 'uapi', 'LICENSE'])
    pin = {'repository': repository, 'branch': branch, 'revision': revision,
           'tag': git(repo, 'describe', '--tags', '--abbrev=0', version_revision),
           'git_commit_count': count, 'version': 30000 + count,
           'sha256': hashlib.sha256(data).hexdigest()}
    if upstream_revision:
        pin['upstream_revision'] = upstream_revision
    return validate(pin)


def update(port, repo, revision, upstream_revision=''):
    previous = read(port)
    if previous is None:
        raise ValueError('KernelSU candidate updates require an existing committed lock')
    if previous['repository'] == SUSFS_REPOSITORY and not upstream_revision:
        raise ValueError('Builtin SUSFS candidates require a pinned official dev ancestor')
    pin = freeze(repo, revision, upstream_revision)
    (Path(port) / 'kernelsu-lock.json').write_text(json.dumps(pin, indent=2) + '\n')
    return pin


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path,
                        default=Path(os.environ.get('KONOHA_SOURCE_ROOT', Path(__file__).resolve().parents[1])))
    parser.add_argument('--expected', default='')
    parser.add_argument('--update', type=Path)
    parser.add_argument('--revision')
    parser.add_argument('--upstream-revision', default='', help='official dev ancestor of a builtin SUSFS fork')
    args = parser.parse_args()
    if bool(args.update) != bool(args.revision):
        parser.error('--update and --revision must be supplied together')
    if args.upstream_revision and not args.update:
        parser.error('--upstream-revision requires --update')
    print(json.dumps(update(args.source / 'port', args.update, args.revision, args.upstream_revision) if args.update
                     else check(args.source / 'port', args.expected), indent=2))
