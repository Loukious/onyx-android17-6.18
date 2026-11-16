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
FIELDS = {'repository', 'branch', 'revision', 'tag', 'git_commit_count', 'version', 'sha256'}


def validate(pin):
    if (not isinstance(pin, dict) or set(pin) != FIELDS
            or pin['repository'] != REPOSITORY or pin['branch'] != BRANCH
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


def freeze(repo, revision):
    if (not re.fullmatch('[0-9a-f]{40}', revision)
            or git(repo, 'rev-parse', 'HEAD') != revision
            or git(repo, 'remote', 'get-url', 'origin') != REPOSITORY
            or git(repo, 'rev-parse', '--is-shallow-repository') != 'false'):
        raise ValueError('KernelSU lock requires the exact official full-history checkout')
    count = int(git(repo, 'rev-list', '--count', revision))
    data = subprocess.check_output(['git', '-C', str(repo), 'archive', '--format=tar',
                                    revision, 'kernel', 'uapi', 'LICENSE'])
    return validate({'repository': REPOSITORY, 'branch': BRANCH, 'revision': revision,
                     'tag': git(repo, 'describe', '--tags', '--abbrev=0', revision),
                     'git_commit_count': count, 'version': 30000 + count,
                     'sha256': hashlib.sha256(data).hexdigest()})


def update(port, repo, revision):
    if read(port) is None:
        raise ValueError('KernelSU candidate updates require an existing committed lock')
    pin = freeze(repo, revision)
    (Path(port) / 'kernelsu-lock.json').write_text(json.dumps(pin, indent=2) + '\n')
    return pin


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path,
                        default=Path(os.environ.get('KONOHA_SOURCE_ROOT', Path(__file__).resolve().parents[1])))
    parser.add_argument('--expected', default='')
    parser.add_argument('--update', type=Path)
    parser.add_argument('--revision')
    args = parser.parse_args()
    if bool(args.update) != bool(args.revision):
        parser.error('--update and --revision must be supplied together')
    print(json.dumps(update(args.source / 'port', args.update, args.revision) if args.update
                     else check(args.source / 'port', args.expected), indent=2))
