#!/usr/bin/env python3
"""Exercise production WMA off-channel queue, publication and DMA ownership."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from verify_wmi_offchan import HERE, struct


def verify(root):
    root = Path(root)
    paths = [root / 'qcacld-3.0/core/wma/src/wma_data.c',
             root / 'qcacld-3.0/core/wma/inc/wma_api.h',
             root / 'qca-wifi-host-cmn/dp/inc/cdp_txrx_injection.h',
             root / 'qca-wifi-host-cmn/wmi/inc/wmi_unified_param.h']
    source_bytes = [path.read_bytes() for path in paths]
    wma, api, cdp, wmi = [body.decode() for body in source_bytes]
    cdp_types = cdp[cdp.index('enum cdp_tx_injection_preamble {'):
                    cdp.index('\nstatic inline bool cdp_nbuf_is_injection')]
    types = [cdp_types, struct(api, 'wma_wonder_helper_snapshot'),
             struct(wmi, 'tx_send_params'), struct(wmi, 'wmi_offchan_data_tx_params'),
             struct(wmi, 'wmi_host_offchan_data_tx_compl_event')]
    owner_start = wma.index('#define WMA_WONDER_OFFCHAN_SLOTS')
    owner_end = wma.index('#endif /* FEATURE_WLAN_WONDER */', owner_start)
    owner = wma[owner_start:owner_end]
    harness = HERE / 'tests/wma_offchan.c'
    harness_bytes = harness.read_bytes()
    runner_bytes = Path(__file__).read_bytes()
    helper = HERE / 'verify_wmi_offchan.py'
    helper_bytes = helper.read_bytes()
    code = harness_bytes.decode()
    code = code.replace('/* INSERT_TYPES */', '\n'.join(types))
    code = code.replace('/* INSERT_OWNER */', owner)
    with tempfile.TemporaryDirectory(prefix='onyx-wma-offchan-') as directory:
        path = Path(directory)
        source, exe = path / 'offchan.c', path / 'offchan'

        def run(body):
            source.write_text(body)
            subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                            '-Werror', '-Wno-sign-compare',
                            '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                            '-fno-pie', '-no-pie', '-pthread', str(source), '-o', str(exe)],
                           check=True, capture_output=True, text=True)
            return subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)

        result = run(code)
        if result.returncode:
            raise AssertionError(result.stderr[-4000:])
        assertions = int(result.stdout.strip())
        mutations = {
            'reservation_does_not_advance_namespace':
                ('packet->desc_id = ++wma_wonder_offchan.next_desc;',
                 'packet->desc_id = wma_wonder_offchan.next_desc;'),
            'canceled_id_reused':
                ('if (free_frame) {',
                 'if (free_frame) { wma_wonder_offchan.next_desc--;'),
            'invalid_reserved_id_accepted':
                ('!desc_id || desc_id > U16_MAX ||', 'false ||'),
            'bypass_final_authorization': ('if (!begin(arg, &guard_flags))',
                                          'if (begin(arg, &guard_flags) && false)'),
            'retire_before_send_return': ('if (!slot->publishing)', 'if (true)'),
            'ignore_completion_pdev': ('if (slot->pdev_id != event.pdev_id)', 'if (false)'),
            'leak_unsent_drops': ('wma_wonder_offchan_packet_done(packet, QDF_IS_STATUS_ERROR(status));',
                                 'wma_wonder_offchan_packet_done(packet, false);'),
            'reuse_owner_with_pending_dma': ('wma_wonder_offchan.in_flight || wma_wonder_offchan.wmi_handle',
                                            'false || wma_wonder_offchan.wmi_handle'),
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
    return {'status': 'PASS', 'scope': 'Host WMA queue/publication/ownership; no firmware or RF validation',
            'assertions': assertions, 'sanitizers': ['address', 'undefined'],
            'concurrency': 'Real pthread completion before blocked WMI send returns',
            'negative_controls': controls,
            'source_stable_during_validation': True,
            'source_sha256': {str(p.relative_to(root)): hashlib.sha256(body).hexdigest()
                              for p, body in zip(paths, source_bytes)},
            'harness': 'port/tests/wma_offchan.c',
            'harness_sha256': hashlib.sha256(harness_bytes).hexdigest(),
            'runner_sha256': hashlib.sha256(runner_bytes).hexdigest(),
            'extraction_helper_sha256': hashlib.sha256(helper_bytes).hexdigest()}


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
