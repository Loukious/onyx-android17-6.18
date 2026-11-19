#!/usr/bin/env python3
"""Resolve source and KernelSU inputs once before scheduling compiler runners."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

import kernelsu_lock


def resolve(source, automation, expected_kernelsu=''):
    def revision(root):
        value = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
        if not re.fullmatch('[0-9a-f]{40}', value):
            raise ValueError('Build inputs require complete committed revisions')
        return value
    pin = kernelsu_lock.check(source / 'port', expected_kernelsu)
    features = (source / 'port/features/manifest.json').is_file()
    if features and not pin['revision']:
        raise ValueError('Parallel feature builds require a committed KernelSU source lock')
    return {'source_revision': revision(source), 'automation_revision': revision(automation),
            'kernelsu_revision': pin['revision'], 'feature_variants': str(features).lower()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(os.environ.get('KONOHA_SOURCE_ROOT', 'source')))
    parser.add_argument('--expected-kernelsu', default='')
    args = parser.parse_args()
    result = resolve(args.source, Path(__file__).resolve().parents[1], args.expected_kernelsu)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            for key, value in result.items():
                stream.write(key + '=' + value + '\n')
    print(json.dumps(result, indent=2))
