#!/usr/bin/env python3
"""Confirm that GitHub really retained each requested opt-in cache entry."""
import json
import os
import re
import subprocess
import sys
import time
from urllib.parse import urlencode

from bounded_cache import summary


def api(path, method='GET'):
    return json.loads(subprocess.check_output(['gh', 'api', '--method', method, path], text=True) or 'null')


def confirm(repository, keys, query=api, delay=time.sleep):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid cache repository')
    prefix = 'repos/' + repository + '/actions/caches'
    confirmed = []
    for key in keys:
        pattern = r'onyx-(?:ccache-v1-Linux-(?:balanced|performance)-[0-9a-f]{64}-[1-9][0-9]*-[1-9][0-9]*|pins-v1-Linux-(?:sources|toolchains)-[0-9a-f]{64})'
        if not re.fullmatch(pattern, key):
            raise ValueError('Invalid opt-in cache key')
        entries = []
        for attempt in range(4):
            entries = [entry for entry in query(prefix + '?' + urlencode({'key': key, 'per_page': 100}))['actions_caches']
                       if entry['key'] == key and entry['ref'] == 'refs/heads/ci']
            if len(entries) == 1 and entries[0].get('size_in_bytes', 0) > 0:
                break
            if attempt != 3:
                delay(5)
        else:
            summary(f'Cache `{key}` was **not retained**; its next restore may be cold.')
            raise ValueError('GitHub did not retain the requested cache')
        confirmed.append(entries[0])
        summary(f'Confirmed retained `{key}` ({entries[0]["size_in_bytes"] / 1024**3:.2f} GiB).')
    return confirmed


if __name__ == '__main__':
    print(json.dumps(confirm(os.environ['GITHUB_REPOSITORY'], sys.argv[1:]), indent=2))
