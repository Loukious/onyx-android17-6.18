#!/usr/bin/env python3
"""Run the production Wonder dwell state core with callback reordering checks."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
CORE = 'qcacld-3.0/core/hdd/src/wlan_hdd_wonder_dwell.c'
API = 'qcacld-3.0/core/hdd/inc/wlan_hdd_wonder_dwell.h'


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Negative control no longer uniquely matches: ' + old)
    return text.replace(old, new, 1)


def without_includes(text):
    return re.sub(r'^#include[^\n]*\n', '', text, flags=re.M)


def verify(root, compiler='cc'):
    root = Path(root)
    sources = {name: (root / name).read_text() for name in (CORE, API)}
    core, api = map(without_includes, (sources[CORE], sources[API]))
    fixture = (HERE / 'tests/wonder_dwell.c').read_text()
    variants = {'fixed': core}
    variants['reserve_authorizes'] = replace_once(core,
        'dwell->deadline_ns = deadline;\n\tdwell->phase = HDD_WONDER_DWELL_PENDING;',
        'dwell->deadline_ns = deadline;\n\tdwell->phase = HDD_WONDER_DWELL_READY;')
    variants['ignore_owner'] = replace_once(core,
        'return owner && dwell->owner.generation == owner->generation &&\n'
        '\t\tdwell->owner.helper_cookie == owner->helper_cookie;',
        '(void)dwell;\n\treturn owner != NULL;')
    variants['ignore_event_scan_id'] = replace_once(core,
        'dwell->scan.scan_id != event->scan_id)', 'false)')
    variants['cancel_releases_pending'] = replace_once(core,
        'dwell->phase = HDD_WONDER_DWELL_CANCEL_PENDING;\n\treturn true;',
        'dwell->phase = HDD_WONDER_DWELL_IDLE;\n\treturn true;')
    variants['entry_refreshes_deadline'] = replace_once(core,
        'case HDD_WONDER_DWELL_FOREIGN_CHANNEL:\n\t\tdwell->started = true;',
        'case HDD_WONDER_DWELL_FOREIGN_CHANNEL:\n'
        '\t\tdwell->deadline_ns = now_ns + dwell->max_duration_ns;\n'
        '\t\tdwell->started = true;')
    variants['ignore_deadline'] = replace_once(core,
        'now_ns >= dwell->deadline_ns)', 'false && now_ns >= dwell->deadline_ns)')
    variants['missing_revocation_latch'] = replace_once(core,
        'dwell->revoked = true;\n\tif (dwell->phase == HDD_WONDER_DWELL_READY)',
        '/* Negative control: forget revocation after departure. */\n'
        '\tif (dwell->phase == HDD_WONDER_DWELL_READY)')
    variants['scan_overwrites_home'] = replace_once(core,
        'dwell->scan = *scan;', 'dwell->scan = *scan;\n\tdwell->home_freq = scan->freq;')
    variants['not_submitted_after_firmware_entry'] = replace_once(core,
        'dwell->phase == HDD_WONDER_DWELL_IDLE || dwell->started ||',
        'dwell->phase == HDD_WONDER_DWELL_IDLE ||')
    variants['frequency_conflict_retains_authorization'] = replace_once(core,
        'if (event->freq)\n\t\t\thdd_wonder_dwell_revoke(dwell);',
        '(void)event->freq;')
    witnesses = {
        'reserve_authorizes': 'reserve_never_authorizes',
        'ignore_owner': 'stale_identity_never_authorizes',
        'ignore_event_scan_id': 'stale_identity_never_authorizes',
        'cancel_releases_pending': 'cancel_retains_pending_and_old_owner',
        'entry_refreshes_deadline': 'deadline_is_absolute_and_bounded',
        'ignore_deadline': 'deadline_is_absolute_and_bounded',
        'missing_revocation_latch': 'revoke_latches_until_terminal',
        'scan_overwrites_home': 'reserve_never_authorizes',
        'not_submitted_after_firmware_entry': 'trusted_not_submitted_after_local_revocation',
        'frequency_conflict_retains_authorization': 'attributed_frequency_conflict_revokes_ready',
    }
    results = {}
    with tempfile.TemporaryDirectory(prefix='onyx-wonder-dwell-') as temporary:
        directory = Path(temporary)
        for label, body in variants.items():
            code = fixture.replace('/* INSERT_API */', api).replace('/* INSERT_CORE */', body)
            source, binary = directory / (label + '.c'), directory / label
            source.write_text(code)
            command = [*shlex.split(compiler), '-std=gnu11', '-O1', '-g',
                       '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                       '-fno-sanitize-recover=all', '-fno-pie', '-no-pie',
                       str(source), '-o', str(binary)]
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
            if compiled.returncode:
                raise RuntimeError(label + ' failed to compile:\n' + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            result = json.loads(run.stdout)
            result.update(returncode=run.returncode, stderr=run.stderr,
                          translation_unit_sha256=hashlib.sha256(code.encode()).hexdigest())
            results[label] = result
    if results['fixed']['returncode'] or results['fixed']['failed']:
        raise AssertionError(json.dumps(results['fixed'], indent=2))
    for label, witness in witnesses.items():
        failures = {case['name'] for case in results[label]['cases'] if not case['passed']}
        if results[label]['returncode'] != 1 or witness not in failures:
            raise AssertionError('Negative control did not witness guard: ' + label)
        results[label]['required_failure_witness'] = witness
    return {
        'status': 'PASS',
        'compiler': subprocess.check_output([*shlex.split(compiler), '--version'],
                                            text=True).splitlines()[0],
        'sanitizers': ['ASan', 'UBSan'],
        'source_sha256': {name: hashlib.sha256(text.encode()).hexdigest()
                          for name, text in sources.items()},
        'fixture_sha256': hashlib.sha256(fixture.encode()).hexdigest(),
        'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'fixed': results.pop('fixed'),
        'negative_controls': results,
        'limits': [
            'Complete production state core and header execute; only Linux types/includes are adapted for host compilation.',
            'All 24 STARTED/FOREIGN/EXIT/terminal callback orders, stale attribution, deadlines, cancellation and invalidation are tested.',
            'Caller serialization and callback-context lifetime are contracts, not concurrent kernel or radio validation.',
            'Target timestamps are optional local ordering observations, not TSF/QTIMER or proof of RF entry timing.',
            'Revocation intentionally latches until terminal; scan re-entry needs a new reservation.',
            'Negative controls change temporary translation units only, never production files.',
        ],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path, help='Repository modules/ or prepared module tree')
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    report = verify(args.root, args.cc)
    rendered = json.dumps(report, indent=2) + '\n'
    if args.receipt:
        args.receipt.write_text(rendered)
    print(rendered, end='')
