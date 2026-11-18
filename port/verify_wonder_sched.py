#!/usr/bin/env python3
"""Exercise production Wonder scheduler and firmware TSF capture on the host."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
SCHED = 'qcacld-3.0/core/hdd/src/wlan_hdd_wonder_sched.c'
SCHED_API = 'qcacld-3.0/core/hdd/inc/wlan_hdd_wonder_sched.h'
WMA = 'qcacld-3.0/core/wma/src/wma_wonder_tsf.c'
WMA_API = 'qcacld-3.0/core/wma/inc/wma_wonder_tsf.h'
PUBLIC = 'wonder/include/wondertap.h'
SIR = 'qcacld-3.0/core/mac/inc/sir_api.h'


def declaration(source, name, kind='struct'):
    match = re.search(r'\b' + kind + r' ' + re.escape(name) + r'\s*\{.*?\n\};', source, re.S)
    if not match:
        raise ValueError('Missing production declaration: ' + name)
    return match[0]


def without_includes(source):
    return re.sub(r'^#include[^\n]*\n', '', source, flags=re.M)


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('Negative control no longer matches its production guard')
    return source.replace(old, new, 1)


def verify(root, compiler='cc'):
    root = Path(root)
    paths = [SCHED, SCHED_API, WMA, WMA_API, PUBLIC, SIR]
    sources = {name: (root / name).read_text() for name in paths}
    public = sources[PUBLIC]
    types = '\n'.join(declaration(public, name, 'enum') for name in
                      ('wondertap_rate_bw', 'wondertap_role'))
    types += '\n' + '\n'.join(declaration(public, name) for name in (
        'wondertap_channel_list_params', 'channel_schedule_request',
        'wondertap_channel_status', 'wondertap_channel_status_report',
        'wondertap_set_freq_params'))
    types += '\n' + declaration(sources[SIR], 'stsf')
    types += '\n' + without_includes(sources[WMA_API])
    types += '\n' + without_includes(sources[SCHED_API])
    template = (HERE / 'tests/wonder_sched.c').read_text()
    sched, wma = without_includes(sources[SCHED]), without_includes(sources[WMA])
    variants = {'fixed': (sched, wma)}
    variants['no_helper_cookie_recheck'] = (sched, replace_once(wma,
        'if (!ret && !wma_wonder_helper_identity_valid(monitor_id, vdev_id,\n'
        '\t\t\t\t\t\t     helper_cookie))', 'if (false)'))
    variants['no_clock_identity_recheck'] = (replace_once(sched,
        'if (!sched->running || !sched->tsf_bound ||\n'
        '\t    sched->identity_sequence != identity_sequence ||\n'
        '\t    sched->tsf_vdev_id != vdev_id ||\n'
        '\t    sched->tsf_helper_cookie != helper_cookie)',
        'if (false && (identity_sequence || vdev_id || helper_cookie))'), wma)
    variants['no_epoch_continuity_guard'] = (
        replace_once(sched, 'if (discontinuity) {', 'if (false && discontinuity) {'), wma)
    variants['host_monotonic_for_suspend'] = (replace_once(sched,
        'qtimer_delta = sample.qtimer_us - previous.sample.qtimer_us;',
        'qtimer_delta = (sample_host_ns - previous.sample_host_ns) / NSEC_PER_USEC;'), wma)
    variants['old_clock_after_switch'] = (replace_once(sched,
        'clock = sched->clock;\n\tif (!ret && (!sched->tsf_bound || !clock.valid))',
        '/* Negative control: keep pre-switch clock. */\n'
        '\tif (!ret && (!sched->tsf_bound || !clock.valid))'), wma)
    variants['missing_recorded_bandwidth'] = (replace_once(sched,
        'sched->current_bandwidth = bandwidth;', '(void)bandwidth;'), wma)
    variants['host_based_slot_end'] = (replace_once(sched,
        'hdd_wonder_clock_host(&clock,\n'
        '\t\t\t\t\t\tplan->next_tsf + plan->dwell_us)',
        'now_ns + plan->dwell_us * NSEC_PER_USEC'), wma)
    variants['unbounded_slot_duration'] = (replace_once(sched,
        'if (plan->switch_duration_ns > plan->switch_end_host_ns - now_ns)',
        'if (false && plan->switch_duration_ns > plan->switch_end_host_ns - now_ns)'), wma)
    variants['retry_recomputes_slot_bounds'] = (replace_once(sched,
        'if (!plan->switch_pending) {', 'if (true) {'), wma)
    variants['missing_pending_expiry'] = (replace_once(sched,
        'if (plan->switch_pending && now_ns >= plan->switch_end_host_ns)',
        'if (false && plan->switch_pending && now_ns >= plan->switch_end_host_ns)'), wma)
    variants['retry_timer_past_slot_end'] = (replace_once(sched,
        'if (next_ns > slot_end_host_ns)', 'if (false && next_ns > slot_end_host_ns)'), wma)
    variants['expired_completion_is_published'] = (replace_once(sched,
        'if (!ret && completion_ns >= slot_end_host_ns)',
        'if (false && !ret && completion_ns >= slot_end_host_ns)'), wma)
    variants['clock_loss_drops_pending_expiry_timer'] = (replace_once(sched,
        'if (plan->switch_pending)\n\t\t\tnext_ns = plan->switch_end_host_ns;',
        'if (false && plan->switch_pending)\n\t\t\tnext_ns = plan->switch_end_host_ns;'), wma)
    results = {}
    with tempfile.TemporaryDirectory(prefix='onyx-wonder-sched-') as temporary:
        directory = Path(temporary)
        for label, (sched_body, wma_body) in variants.items():
            code = template.replace('/* INSERT_TYPES */', types).replace(
                '/* INSERT_WMA */', wma_body).replace('/* INSERT_SCHED */', sched_body)
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
    witnesses = {
        'no_helper_cookie_recheck': {'helper_cookie_changes_during_capture'},
        'no_clock_identity_recheck': {'unbind_during_capture'},
        'no_epoch_continuity_guard': {'active_lmac_changes', 'active_tsf_register_changes',
                                    'active_tsf_jump', 'suspend_counter_reset',
                                    'suspend_lmac_changes', 'suspend_tsf_register_changes',
                                    'idle_manual_new_epoch', 'channel_counter_discontinuity'},
        'host_monotonic_for_suspend': {'suspend_qtimer_continuity'},
        'old_clock_after_switch': {'fresh_clock_after_channel_completion'},
        'missing_recorded_bandwidth': {'nop_keeps_recorded_channel'},
        'host_based_slot_end': {'delayed_slot_bounds_duration', 'slot_deadline_uses_paired_clock',
                               'retries_keep_slot_bounds', 'expired_retry_does_not_acquire_new_dwell'},
        'unbounded_slot_duration': {'delayed_slot_bounds_duration', 'slot_deadline_uses_paired_clock',
                                   'retries_keep_slot_bounds'},
        'retry_recomputes_slot_bounds': {'retries_keep_slot_bounds',
                                        'refresh_cannot_extend_pending_slot'},
        'missing_pending_expiry': {'expired_retry_does_not_acquire_new_dwell',
                                   'pending_deadline_survives_clock_loss'},
        'retry_timer_past_slot_end': {'expired_retry_does_not_acquire_new_dwell'},
        'expired_completion_is_published': {'completion_after_slot_expiry'},
        'clock_loss_drops_pending_expiry_timer': {'pending_deadline_survives_clock_loss'},
    }
    for name, expected in witnesses.items():
        actual = {case['name'] for case in results[name]['cases'] if not case['passed']}
        if results[name]['returncode'] != 1 or expected != actual:
            raise AssertionError('Negative control failed to witness guard: ' + name +
                                 '\n' + json.dumps(results[name], indent=2))
        results[name]['required_failure_witnesses'] = sorted(expected)
    return {
        'status': 'PASS',
        'compiler': subprocess.check_output([*shlex.split(compiler), '--version'],
                                           text=True).splitlines()[0],
        'sanitizers': ['ASan', 'UBSan'],
        'source_sha256': {name: hashlib.sha256(text.encode()).hexdigest()
                          for name, text in sources.items()},
        'fixture_sha256': hashlib.sha256(template.encode()).hexdigest(),
        'fixed': results.pop('fixed'),
        'negative_controls': results,
        'limits': [
            'Complete production scheduler and WMA capture/event functions execute with real API declarations.',
            'Firmware captures and helper identity service replies are bounded mock inputs; no radio or phone is accessed.',
            'Kernel work queues, timers, synchronization and vdev operation guards are synchronous recording shims; concurrent kernel/RTNL behavior is not established.',
            'Negative controls modify temporary translation units only, never repository source.',
            'Firmware capture latency, PPDU counter identity, suspend hardware behavior and AirDrop transfers need device validation.',
        ],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path, help='Prepared modules tree or repository modules/')
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    report = verify(args.root, args.cc)
    rendered = json.dumps(report, indent=2) + '\n'
    if args.receipt:
        args.receipt.write_text(rendered)
    print(rendered, end='')
