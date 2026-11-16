#!/usr/bin/env python3
"""Remove merged tracker refs after their commits have been released."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import quote

from publish_release import api, listed

TRACK = json.loads((Path(__file__).resolve().parent / 'upstream.json').read_text())
CANDIDATE = re.compile(r'upstream/android17-6\.18-lts-[0-9a-f]{12}-[0-9a-f]{12}')
SHA = re.compile(r'[0-9a-f]{40}')
ACTIVE = ('requested', 'pending', 'queued', 'waiting', 'in_progress')


def ancestor(prefix, before, after):
    return api(prefix + '/compare/' + before + '...' + after)['status'] in ('ahead', 'identical')


def cleanup(repository, released_source, current_run=None, dry_run=False):
    if not isinstance(repository, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid repository')
    if not SHA.fullmatch(released_source):
        raise ValueError('Cleanup requires the exact released source commit')
    prefix = 'repos/' + repository
    accepted = api(prefix + '/git/ref/heads/' + TRACK['source_branch'])['object']['sha']
    if not SHA.fullmatch(accepted) or not ancestor(prefix, released_source, accepted):
        return {'status': 'Released source is no longer accepted; preserving branches'}
    branches = list(listed(prefix + '/branches'))
    candidates = [b for b in branches if CANDIDATE.fullmatch(b['name'])]
    if not candidates:
        return {'status': 'No tracker branches to clean up', 'branches': []}
    open_prs = list(listed(prefix + '/pulls?state=open'))
    references = {pr[side]['ref'] for pr in open_prs for side in ('head', 'base')
                  if (pr[side].get('repo') or {}).get('full_name') == repository}
    active_titles = []
    for status in ACTIVE:
        for run in listed(prefix + '/actions/workflows/build.yml/runs?status=' + status, 'workflow_runs'):
            if str(run['id']) != str(current_run) and run['status'] != 'completed':
                title = run.get('display_title')
                if not isinstance(title, str):
                    raise ValueError('Active build has no source-selection title')
                active_titles.append(title)
    results = []
    for branch in candidates:
        name, head = branch['name'], branch['commit']['sha']
        reason = None
        if branch.get('protected') is not False:
            reason = 'protected branch'
        elif not SHA.fullmatch(head):
            raise ValueError('Tracker branch has an invalid commit')
        elif name in references:
            reason = 'referenced by an open pull request'
        elif any(title == 'Build ' + name or title.startswith('Build ' + name + ' ')
                 for title in active_titles):
            reason = 'another build still uses this branch'
        if reason:
            results.append({'branch': name, 'status': 'preserved', 'reason': reason})
            continue
        proposals = list(listed(prefix + '/pulls?state=closed&head=' + quote(repository.split('/')[0] + ':' + name, safe='')
                                + '&base=' + quote(TRACK['source_branch'], safe='')))
        matching = [pr for pr in proposals if pr.get('merged_at') and pr['head']['sha'] == head
                    and pr['head']['ref'] == name and pr['base']['ref'] == TRACK['source_branch']
                    and (pr['head'].get('repo') or {}).get('full_name') == repository
                    and (pr['base'].get('repo') or {}).get('full_name') == repository]
        if len(matching) != 1:
            results.append({'branch': name, 'status': 'preserved', 'reason': 'no single matching merged pull request'})
            continue
        proposal = api(prefix + '/pulls/' + str(matching[0]['number']))
        if proposal.get('merged') is not True or proposal['head']['sha'] != head or not ancestor(prefix, head, released_source):
            results.append({'branch': name, 'status': 'preserved', 'reason': 'branch commit is not a released merge'})
            continue
        ref_path = prefix + '/git/ref/heads/' + name
        current = api(ref_path, optional=True)
        if current is None:
            results.append({'branch': name, 'status': 'already absent'})
            continue
        if current['object']['sha'] != head:
            results.append({'branch': name, 'status': 'preserved', 'reason': 'branch changed during cleanup'})
            continue
        if dry_run:
            results.append({'branch': name, 'status': 'would delete', 'sha': head})
            continue
        ref = 'refs/heads/' + name
        result = subprocess.run(['git', 'push', '--force-with-lease=' + ref + ':' + head,
                                 'https://github.com/' + repository + '.git', ':' + ref],
                                text=True, capture_output=True)
        if result.returncode:
            current = api(ref_path, optional=True)
            if current is None:
                results.append({'branch': name, 'status': 'already absent'})
                continue
            if current['object']['sha'] != head:
                results.append({'branch': name, 'status': 'preserved', 'reason': 'branch moved before deletion'})
                continue
            raise RuntimeError(result.stderr)
        results.append({'branch': name, 'status': 'deleted', 'sha': head})
    return {'status': 'Released tracker branch cleanup complete', 'dry_run': dry_run, 'branches': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('released_source')
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    print(json.dumps(cleanup(args.repository, args.released_source, os.environ.get('GITHUB_RUN_ID'), args.dry_run), indent=2))
