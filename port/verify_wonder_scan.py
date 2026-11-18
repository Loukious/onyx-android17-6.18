#!/usr/bin/env python3
"""Exercise actual Wonder scan submission, provenance and late-event paths."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from verify_wmi_offchan import HERE, function, struct


def enum(source, name):
    match = re.search(r'(?m)^enum ' + re.escape(name) + r' \{.*?^\};', source, re.S)
    if not match:
        raise ValueError('Enum not found: ' + name)
    return match.group()


def verify(root):
    root = Path(root)
    paths = [
        root / 'qcacld-3.0/components/mlme/dispatcher/src/wlan_mlme_api.c',
        root / 'qcacld-3.0/components/mlme/dispatcher/inc/wlan_mlme_sta_mon.h',
        root / 'qcacld-3.0/components/mlme/core/inc/wlan_mlme_main.h',
        root / 'qca-wifi-host-cmn/umac/scan/dispatcher/src/wlan_scan_api.c',
        root / 'qca-wifi-host-cmn/umac/scan/core/src/wlan_scan_manager.c',
        root / 'qca-wifi-host-cmn/target_if/scan/src/target_if_scan.c',
        root / 'qca-wifi-host-cmn/umac/scan/dispatcher/inc/wlan_scan_public_structs.h',
    ]
    source_bytes = [p.read_bytes() for p in paths]
    mlme, public, private, api, scm, target, scans = [body.decode() for body in source_bytes]
    definitions = [
        enum(scans, 'scan_event_type'), enum(scans, 'scan_completion_reason'),
        enum(scans, 'scan_cancel_req_type'), struct(scans, 'scan_start_request'),
        struct(scans, 'scan_cancel_param'), struct(scans, 'scan_cancel_request'),
        struct(scans, 'scan_event'), struct(scans, 'scan_event_info'),
        public[public.index('enum wlan_mlme_sta_mon_state {'):
               public.index('\nbool wlan_mlme_sta_mon_scan_reserve(')],
        struct(private, 'wlan_mlme_sta_mon_control'),
    ]
    groups = {
        'MLME': (mlme, (
            'sta_mon_control', 'sta_mon_ap_lease_locked',
            'sta_mon_wonder_scan_lease_locked', 'sta_mon_invalidate_locked',
            'wlan_mlme_sta_mon_update_begin', 'wlan_mlme_sta_mon_update_end',
            'sta_mon_scan_tuple_matches', 'wlan_mlme_sta_mon_scan_reserve',
            'wlan_mlme_sta_mon_scan_admission_begin', 'wlan_mlme_sta_mon_scan_activate',
            'sta_mon_scan_notice', 'wlan_mlme_sta_mon_scan_fw_event',
            'wlan_mlme_sta_mon_scan_not_submitted',
            'wlan_mlme_sta_mon_scan_release_unsubmitted',
            'wlan_mlme_sta_mon_admission_end')),
        'SCM': (scm, (
            'scm_release_serialization_command', 'scm_post_internal_scan_complete_event',
            'scm_scan_not_submitted', 'scm_activate_scan_request',
            'scm_cancel_scan_request', 'scm_scan_serialize_callback',
            'scm_scan_start_req', 'scm_scan_update_scan_event',
            'scm_scan_event_handler', 'scm_scan_start_flush_callback')),
        'API': (api, (
            'sta_mon_scan_start_req', 'sta_mon_scan_start_flush',
            'sta_mon_scan_rejected', 'sta_mon_reserved_scan_start_req',
            'sta_mon_reserved_scan_start_flush', 'wlan_scan_start')),
        'TARGET': (target, ('target_if_scan_get_rx_ops', 'target_if_scan_event_handler')),
    }
    harness = HERE / 'tests/wonder_scan.c'
    harness_bytes = harness.read_bytes()
    runner_bytes = Path(__file__).read_bytes()
    helper = HERE / 'verify_wmi_offchan.py'
    helper_bytes = helper.read_bytes()
    code = harness_bytes.decode().replace('/* INSERT_DEFINITIONS */', '\n'.join(definitions))
    for name, (body, names) in groups.items():
        code = code.replace('/* INSERT_' + name + ' */',
                            '\n'.join(function(body, item) for item in names))
    with tempfile.TemporaryDirectory(prefix='onyx-wonder-scan-') as directory:
        source, executable = Path(directory) / 'scan.c', Path(directory) / 'scan'

        def run(body):
            source.write_text(body)
            subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                            '-Werror', '-Wno-sign-compare', '-Wno-unused-parameter',
                            '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                            '-fno-pie', '-no-pie', str(source), '-o', str(executable)],
                           check=True, capture_output=True, text=True)
            return subprocess.run([str(executable)], capture_output=True, text=True, timeout=30)

        result = run(code)
        if result.returncode:
            raise AssertionError(result.stderr[-4000:])
        assertions = int(result.stdout.strip())
        mutations = {
            'cancel_claims_never_submitted_after_target_attempt':
                ('if (!req->target_start_attempted)', 'if (true)'),
            'omit_target_attempt_provenance':
                ('req->target_start_attempted = true;', '/* omit attempt provenance */'),
            'synthetic_completion_claims_firmware':
                ('/* post scan event to registered handlers */',
                 'wlan_mlme_sta_mon_scan_fw_event(wlan_vdev_get_psoc(req->vdev), &event);\n'
                 '\t/* post scan event to registered handlers */'),
            'omit_target_observer_before_scm':
                ('wlan_mlme_sta_mon_scan_fw_event(psoc, &event_info->event);',
                 '/* omit genuine firmware observation */'),
            'reserved_request_invalidates_own_generation':
                ('if (!reserved)\n\t\twlan_mlme_sta_mon_update_begin(psoc);',
                 'if (true)\n\t\twlan_mlme_sta_mon_update_begin(psoc);'),
            'duplicate_admission_retires_accepted_reservation':
                ('\t\tscm_scan_free_scan_request_mem(req);\n\t\treturn QDF_STATUS_E_BUSY;',
                 '\t\tsta_mon_scan_rejected(req);\n\t\tscm_scan_free_scan_request_mem(req);\n'
                 '\t\treturn QDF_STATUS_E_BUSY;'),
            'omit_activation_channel_guard':
                ('ctrl->scan_submission_started && !ctrl->scan_fw_pending &&\n'
                 '\t\t\tchannel_count == 1 && offchan_data_tx &&\n'
                 '\t\t\tfrequency == ctrl->scan_reservation.frequency;',
                 'ctrl->scan_submission_started && !ctrl->scan_fw_pending;'),
            'reserved_tuple_mismatch_bypasses_activation':
                ('bool ok = !reserved_request;', 'bool ok = true;'),
            'serialization_rejection_returns_success':
                ('status = QDF_STATUS_E_FAILURE;\n\t\tgoto err;',
                 'status = QDF_STATUS_SUCCESS;\n\t\tgoto err;'),
        }
        controls = []
        for name, (old, new) in mutations.items():
            if code.count(old) != 1:
                raise AssertionError('Mutation anchor count for ' + name + ': ' + str(code.count(old)))
            result = run(code.replace(old, new))
            if result.returncode == 0:
                raise AssertionError('Ineffective negative control: ' + name)
            controls.append(name)
    if source_bytes != [p.read_bytes() for p in paths] or harness_bytes != harness.read_bytes() or runner_bytes != Path(__file__).read_bytes() or helper_bytes != helper.read_bytes():
        raise AssertionError('Source or fixture changed during validation')
    return {
        'status': 'PASS',
        'scope': 'Actual host scan paths and decoded target-event attribution; no firmware dwell or RF validation',
        'assertions': assertions, 'sanitizers': ['address', 'undefined'],
        'negative_controls': controls,
        'extracted_functions': {name: list(names) for name, (_, names) in groups.items()},
        'source_stable_during_validation': True,
        'source_sha256': {str(p.relative_to(root)): hashlib.sha256(body).hexdigest()
                          for p, body in zip(paths, source_bytes)},
        'harness': 'port/tests/wonder_scan.c',
        'harness_sha256': hashlib.sha256(harness_bytes).hexdigest(),
        'runner_sha256': hashlib.sha256(runner_bytes).hexdigest(),
        'extraction_helper_sha256': hashlib.sha256(helper_bytes).hexdigest(),
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', type=Path, default=HERE.parent / 'modules')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        report = verify(args.root)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.stderr or str(error)) from error
    text = json.dumps(report, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')
