#!/usr/bin/env python3
"""Exercise production dwell/coex packet leases and callback lifetime on host."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

from verify_wlan_injection import declaration, function
from verify_wonder_dwell import replace_once, without_includes

HERE = Path(__file__).resolve().parent
DWELL = 'qcacld-3.0/core/hdd/src/wlan_hdd_wonder_dwell.c'
DWELL_API = 'qcacld-3.0/core/hdd/inc/wlan_hdd_wonder_dwell.h'
COEX = 'qcacld-3.0/core/hdd/src/wlan_hdd_wonder_coex.c'
COEX_API = 'qcacld-3.0/core/hdd/inc/wlan_hdd_wonder_coex.h'
PROVIDER = 'qcacld-3.0/core/hdd/src/wlan_hdd_wonder.c'
MLME_API = 'qcacld-3.0/components/mlme/dispatcher/inc/wlan_mlme_sta_mon.h'
SCAN = 'qca-wifi-host-cmn/umac/scan/dispatcher/inc/wlan_scan_public_structs.h'
INJECTION = 'qca-wifi-host-cmn/dp/inc/cdp_txrx_injection.h'
WONDER_API = 'wonder/include/wondertap.h'


def verify(root, compiler='cc'):
    root = Path(root)
    sources = {name: (root / name).read_text() for name in (
        DWELL, DWELL_API, COEX, COEX_API, PROVIDER, MLME_API, SCAN, INJECTION, WONDER_API)}
    fixture = (HERE / 'tests/wonder_coex.c').read_text()
    provider = '\n'.join(function(sources[PROVIDER], name) for name in [
        'hdd_wonder_publish_begin_locked',
        'wlan_injection_wonder_home_tx_begin_locked',
        'wlan_injection_wonder_home_tx_end_locked',
        'wlan_injection_wonder_rx_begin', 'wlan_injection_wonder_rx_end',
        'hdd_wonder_netdev_transport_ready',
    ])
    close = function(sources[PROVIDER], 'hdd_wonder_close_session')
    if close.index('wlan_mlme_sta_mon_update_begin(') >= close.index(
            'rcu_assign_pointer(hdd_wonder_active, NULL)'):
        raise AssertionError('Provider teardown must revoke admission before removing the RCU packet gate')
    callback = function(sources[PROVIDER], 'hdd_wonder_netdev_transport_ready')
    if 'hdd_wonder_coex_ready(' in callback or 'wlan_mlme_sta_mon_' in callback:
        raise AssertionError('RX callback must not reenter held admission/dwell locks')
    body = fixture
    preflight = '\n'.join(function(sources[PROVIDER], name) for name in [
        'hdd_wonder_bandwidth', 'hdd_wonder_validate_channel',
    ])
    for marker, text in {
        'SCAN_TYPES': '\n'.join(declaration(sources[SCAN], pattern) for pattern in [
            r'enum scan_event_type \{.*?\n\};',
            r'enum scan_completion_reason \{.*?\n\};',
            r'struct scan_event \{.*?\n\};',
        ]),
        'MLME_TYPES': '\n'.join(declaration(sources[MLME_API], pattern) for pattern in [
            r'struct wlan_mlme_sta_mon_snapshot \{.*?\n\};',
            r'struct wlan_mlme_sta_mon_scan_reservation \{.*?\n\};',
            r'enum wlan_mlme_sta_mon_scan_notice \{.*?\n\};',
            r'typedef void \(\*wlan_mlme_sta_mon_scan_cb\)\(.*?\);',
        ]).replace('uint64_t', 'u64'),
        'RX_LEASE': declaration(sources[INJECTION], r'struct cdp_wonder_rx_lease \{.*?\n\};'),
        'CHANNEL_TYPES': '\n'.join(declaration(sources[WONDER_API], pattern) for pattern in [
            r'enum wondertap_rate_bw \{.*?\n\};',
            r'struct wondertap_set_freq_params \{.*?\n\};',
        ]),
        'PROBE_PARAMETER': declaration(sources[PROVIDER], r'^static bool wonder_sta_offchan_probe[^\n]*;'),
        'DWELL_API': without_includes(sources[DWELL_API]),
        'COEX_API': without_includes(sources[COEX_API]),
        'DWELL_CORE': without_includes(sources[DWELL]),
        'COEX_CORE': without_includes(sources[COEX]),
        'PROVIDER_PUBLICATION': provider,
        'PROVIDER_PREFLIGHT': preflight,
    }.items():
        body = body.replace('/* INSERT_' + marker + ' */', text)

    token = function(sources[COEX], 'hdd_wonder_coex_tx_token')
    synthetic = function(sources[COEX], 'hdd_wonder_coex_scm_event')
    mutations = {
        'old_token_authorized': (COEX,
            'if (coex->dwell.deadline_ns == token->deadline_ns &&',
            'if (true || coex->dwell.deadline_ns == token->deadline_ns &&',
            'old_queued_tuple_same_frequency_denied'),
        'old_tuple_same_deadline_authorized': (COEX,
            '&token->owner, &token->scan,', '&coex->owner, &coex->dwell.scan,',
            'old_queued_tuple_same_frequency_denied'),
        'home_ready_while_pending': (COEX,
            'return coex->dwell.phase == HDD_WONDER_DWELL_IDLE;',
            'return true;', 'home_and_unknown_packets_blocked_until_terminal'),
        'old_expiry_cancels_current_early': (COEX,
            'now_ns >= coex->dwell.deadline_ns) {',
            '(true || now_ns >= coex->dwell.deadline_ns)) {',
            'expiry_deadline_underflow_and_new_scan'),
        'remaining_duration_underflows': (COEX,
            'remaining_ns = deadline_ns > now_ns ? deadline_ns - now_ns : 0;',
            'remaining_ns = deadline_ns - now_ns;',
            'delayed_submission_does_not_wrap_expiry'),
        'generic_foreign_rx_authorized': (PROVIDER,
            'if (home_tx || !frequency || frequency == home_frequency)',
            'if (true || home_tx || !frequency || frequency == home_frequency)',
            'generic_shared_home_only'),
        'rx_dwell_lock_not_released': (PROVIDER,
            'hdd_wonder_coex_rx_end_locked(lease->coex);',
            '(void)hdd_wonder_coex_rx_end_locked;',
            'home_and_unknown_packets_blocked_until_terminal'),
    }
    variants = {'fixed': body}
    witnesses = {}
    for name, (source_name, before, after, witness) in mutations.items():
        original = without_includes(sources[source_name]) if source_name == COEX else provider
        changed = replace_once(original, before, after)
        variants[name] = replace_once(body, original, changed)
        witnesses[name] = witness
    token_without_pin = replace_once(token, 'kref_get(&coex->ref);', '(void)coex->ref;')
    variants['queued_token_not_pinned'] = replace_once(body, token, token_without_pin)
    witnesses['queued_token_not_pinned'] = 'old_queued_tuple_same_frequency_denied'
    synthetic_drain = replace_once(synthetic,
        '\t(void)vdev;\n\t(void)event;\n\t(void)arg;',
        '\t(void)vdev;\n\t(void)event;\n\t(void)arg;\n'
        '\tstruct hdd_wonder_coex *coex = scan_arg;\n'
        '\tif (coex && coex->scan_ref) {\n'
        '\t\tcoex->scan_ref = false;\n'
        '\t\tkref_put(&coex->ref, hdd_wonder_coex_release);\n\t}')
    variants['synthetic_completion_retires_firmware'] = replace_once(body, synthetic, synthetic_drain)
    witnesses['synthetic_completion_retires_firmware'] = 'context_retained_through_synthetic_cancel'
    probe_ungated = replace_once(preflight,
        '!READ_ONCE(wonder_sta_offchan_probe) || width != CH_WIDTH_20MHZ ||',
        'width != CH_WIDTH_20MHZ ||')
    variants['normal_foreign_channel_probe_ungated'] = replace_once(body, preflight, probe_ungated)
    witnesses['normal_foreign_channel_probe_ungated'] = 'probe_preflight_preserves_home_and_reservation'
    probe_ap_allowed = replace_once(preflight, 'snapshot.ap_owner || snapshot.exclusive)',
                                   'snapshot.exclusive)')
    variants['shared_ap_foreign_channel_allowed'] = replace_once(body, preflight, probe_ap_allowed)
    witnesses['shared_ap_foreign_channel_allowed'] = 'probe_preflight_preserves_home_and_reservation'

    results = {}
    with tempfile.TemporaryDirectory(prefix='onyx-wonder-coex-') as temporary:
        directory = Path(temporary)
        for name, code in variants.items():
            source, binary = directory / (name + '.c'), directory / name
            source.write_text(code)
            command = [*shlex.split(compiler), '-std=gnu11', '-O1', '-g',
                       '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                       '-Wno-parentheses', '-fsanitize=address,undefined',
                       '-fno-sanitize-recover=all', '-fno-pie', '-no-pie', '-pthread',
                       str(source), '-o', str(binary)]
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
            if compiled.returncode:
                raise RuntimeError(name + ' failed to compile:\n' + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
            result = {'returncode': run.returncode, 'stderr': run.stderr,
                      'translation_unit_sha256': hashlib.sha256(code.encode()).hexdigest()}
            if name == 'fixed':
                if run.returncode:
                    raise AssertionError(run.stderr)
                result.update(json.loads(run.stdout))
            else:
                if not run.returncode or witnesses[name] not in run.stderr:
                    raise AssertionError('Negative control missed witness: ' + name + '\n' + run.stderr)
                result['required_failure_witness'] = witnesses[name]
            results[name] = result

    return {
        'status': 'PASS',
        'compiler': subprocess.check_output([*shlex.split(compiler), '--version'],
                                            text=True).splitlines()[0],
        'sanitizers': ['ASan', 'UBSan'],
        'source_sha256': {name: hashlib.sha256(text.encode()).hexdigest()
                          for name, text in sources.items()},
        'fixture_sha256': hashlib.sha256(fixture.encode()).hexdigest(),
        'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'fixed': results.pop('fixed'), 'negative_controls': results,
        'limits': [
            'Complete production dwell/coex sources and headers execute; provider packet publication wrappers are extracted from production.',
            'MLME routing/admission, object manager, scan request services, scheduler and module pins are explicit host mocks; actual MLME scan routing has separate injection fixture coverage.',
            'Host pthread admission and dwell locks check publication serialization against an EXIT event; this is not a kernel race or radio test.',
            'The actual RX netdev callback gate executes while publication locks are held; provider teardown revocation before gate removal is checked against source wiring.',
            'Actual foreign-channel preflight requires explicit probe opt-in, STA ownership and regulatory 20 MHz approval; denied preflight does not reserve scans or rewrite HOME.',
            'Packets queued for an old same-frequency tuple, failed/expired scans, HOME and unknown-frequency publication, and teardown context pins are checked.',
            'Firmware timing, scan-manager internals, WMI/DMA transfer ownership and device behavior are excluded.',
            'Negative controls modify temporary translation units only.',
        ],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    report = verify(args.root, args.cc)
    rendered = json.dumps(report, indent=2) + '\n'
    if args.receipt:
        args.receipt.write_text(rendered)
    print(rendered, end='')
