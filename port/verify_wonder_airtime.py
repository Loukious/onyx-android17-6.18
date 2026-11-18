#!/usr/bin/env python3
"""Exercise production PPDU decoding and HTT reporting ownership on the host."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from verify_wlan_injection import declaration, function

HERE = Path(__file__).resolve().parent
MON = 'qca-wifi-host-cmn/dp/wifi3.0/monitor/dp_mon.c'
HTT = 'qca-wifi-host-cmn/dp/wifi3.0/dp_htt.c'
MON_H = 'qca-wifi-host-cmn/dp/wifi3.0/monitor/dp_mon.h'
HTT_H = 'qca-wifi-host-cmn/dp/wifi3.0/dp_htt.h'
FW = 'fw-api/fw/htt.h'
PPDU = 'fw-api/fw/htt_ppdu_stats.h'


def macros(source, prefixes):
    result = []
    lines = source.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r'#define\s+(\w+)', line)
        if not match or not match[1].startswith(prefixes):
            continue
        body = [line]
        while body[-1].endswith('\\'):
            index += 1
            body.append(lines[index])
        result.append('\n'.join(body))
    return result


def verify(root):
    root = Path(root)
    sources = {name: (root / name).read_text()
               for name in (MON, HTT, MON_H, HTT_H, FW, PPDU)}
    definitions = macros(sources[FW], (
        'HTT_T2H_PPDU_STATS_', 'HTT_H2T_PPDU_STATS_CFG_',
        'HTT_STATS_TLV_', 'HTT_H2T_MSG_TYPE_'))
    definitions += macros(sources[PPDU], (
        'HTT_PPDU_STATS_COMMON_TLV_CHAN_MHZ_',
        'HTT_PPDU_STATS_COMMON_TLV_PHY_PPDU_TX_TIME_US_'))
    definitions += macros(sources[HTT_H], (
        'HTT_PPDU_STATS_COMMON_TLV_', 'HTT_GET_STATS_CMN_INDEX'))
    definitions.append(declaration(sources[PPDU],
                                   r'enum htt_ppdu_stats_tlv_tag \{.*?\n\};'))
    fields = declaration(sources[MON_H],
                         r'\tbool wonder_airtime_enabled;.*?wonder_airtime_last\[MAX_NUM_LMAC_HW\]\[2\];')
    functions = [function(sources[MON], name) for name in (
        'dp_mon_wonder_note_ppdu', 'dp_mon_wonder_rx_ppdu', 'dp_mon_wonder_tx_ppdu')]
    functions += [function(sources[HTT], name) for name in (
        'dp_h2t_cfg_stats_msg_send_locked', 'dp_h2t_cfg_stats_msg_send',
        'dp_htt_wonder_set_airtime')]
    code = (HERE / 'tests/wonder_airtime.c').read_text()
    for marker, body in {'DEFINITIONS': '\n'.join(definitions),
                         'FIELDS': fields, 'FUNCTIONS': '\n'.join(functions)}.items():
        code = code.replace('/* INSERT_' + marker + ' */', body)
    with tempfile.TemporaryDirectory(prefix='onyx-wonder-airtime-') as temp:
        path = Path(temp)
        def run(body):
            (path / 'airtime.c').write_text(body)
            subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                            '-Werror', '-Wno-unused-parameter', '-Wno-sign-compare',
                            '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                            '-fno-pie', '-no-pie', '-pthread', str(path / 'airtime.c'),
                            '-o', str(path / 'airtime')], check=True)
            return subprocess.run([str(path / 'airtime')], capture_output=True,
                                  text=True, timeout=30)
        result = run(code)
        if result.returncode:
            raise AssertionError(result.stderr[-4000:])
        assertions = int(result.stdout.strip())
        controls = {}
        defects = {
            'FES_duration_instead_of_PHY_PPDU_duration': (
                r'duration = HTT_PPDU_STATS_COMMON_TLV_PHY_PPDU_TX_TIME_US_GET\(\s*'
                r'msg_word\[HTT_GET_STATS_CMN_INDEX\(RESV_NUM_UL_BEAM\)\]\);',
                'duration = msg_word[HTT_GET_STATS_CMN_INDEX(FES_DUR_US)];'),
            'missing_PPDU_deduplication': (
                r'tsf > mon_pdev->wonder_airtime_last\[mac_id\]\[direction\]\.tsf',
                'true'),
            'missing_COMMON_reporting_mask': (
                r'stats_type_upload_mask \|= 1U << HTT_PPDU_STATS_COMMON_TLV;',
                'stats_type_upload_mask |= 0;'),
        }
        for name, (pattern, replacement) in defects.items():
            broken, matches = re.subn(pattern, replacement, code)
            if matches != 1:
                raise ValueError('Negative control no longer matches production: ' + name)
            failure = run(broken)
            if not failure.returncode:
                raise AssertionError('Negative control unexpectedly passed: ' + name)
            controls[name] = 'rejected by host assertions'
    return {'status': 'PASS', 'assertions': assertions,
            'scope': 'Production raw TX PPDU decoder, RX airtime forwarding, deduplication and HTT mask ownership',
            'sanitizers': 'ASan+UBSan',
            'negative_controls': controls,
            'source_sha256': {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                              for name in sources},
            'limits': ['HTT submission and buffers are mocked; host tests do not validate firmware reporting.',
                       'RX status ring TLV collection and real MAC TSF clock agreement require device testing.']}


if __name__ == '__main__':
    print(json.dumps(verify(Path(sys.argv[1]) if len(sys.argv) > 1
                            else HERE.parent / 'modules'), indent=2))
