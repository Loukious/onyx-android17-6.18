#!/usr/bin/env python3
"""Exercise production packet parsing and firmware metadata with ASan/UBSan."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
HDD = 'qcacld-3.0/core/hdd/src/wlan_hdd_tx_rx.c'
DP = 'qca-wifi-host-cmn/dp/wifi3.0/dp_tx.c'
WMA = 'qcacld-3.0/core/wma/src/wma_data.c'
PARAMS = 'qca-wifi-host-cmn/dp/inc/cdp_txrx_injection.h'
HTT = 'fw-api/fw/htt.h'


def function(source, name):
    match = re.search(r'(?m)^[\w\s*]+\b' + re.escape(name) +
                      r'\([^;{}]*\)\n\{', source)
    if not match:
        raise ValueError('Function not found: ' + name)
    return source[match.start():source.index('\n}', match.end()) + 2]


def declaration(source, pattern):
    match = re.search(pattern, source, re.S | re.M)
    if not match:
        raise ValueError('Declaration not found: ' + pattern)
    return match.group()


def verify(root):
    root = Path(root)
    # Both the source tree and prepared workspace keep common beside modules.
    kernel = root.parent / 'common'
    def header(name):
        staged = root / 'include' / name
        return (staged if staged.is_file() else kernel / 'include' / name).read_text()
    ieee = header('linux/ieee80211.h')
    radiotap = header('net/ieee80211_radiotap.h')
    cfg = header('net/cfg80211.h')
    hdd = (root / HDD).read_text()
    htt = (root / HTT).read_text()
    definitions = []
    definitions.append(declaration(header('linux/ieee80211-ht.h'),
                                   r'^#define IEEE80211_HT_CTL_LEN[^\n]+'))
    wanted = ('FCTL_', 'FTYPE_', 'STYPE_', 'SCTL_', 'QOS_CTL_LEN',
              'QOS_CTL_TID_MASK', 'HT_CTL_LEN', 'MAX_FRAME_LEN')
    for line in ieee.splitlines():
        if line.startswith('#define IEEE80211_') and any(
                line.split()[1].startswith('IEEE80211_' + prefix) for prefix in wanted):
            definitions.append(line)
    for name in ('ieee80211_has_a4', 'ieee80211_has_morefrags',
                 'ieee80211_has_protected', 'ieee80211_has_order',
                 'ieee80211_is_mgmt', 'ieee80211_is_ctl', 'ieee80211_is_data',
                 'ieee80211_is_data_qos', 'ieee80211_is_ext'):
        definitions.append(function(ieee, name))
    definitions.append(function((root / 'net/wireless/util.c').read_text(),
                                'ieee80211_hdrlen'))
    for name in ('ieee80211_radiotap_presence', 'ieee80211_radiotap_flags',
                 'ieee80211_radiotap_channel_flags', 'ieee80211_radiotap_tx_flags',
                 'ieee80211_radiotap_mcs_have', 'ieee80211_radiotap_mcs_flags'):
        definitions.append(declaration(radiotap, r'enum ' + name + r' \{.*?\n\};'))
    definitions.append(cfg[cfg.index('struct radiotap_align_size {'):
                           cfg.index('\n\nextern const unsigned char rfc1042_header')])
    params = (root / PARAMS).read_text()
    params = params[params.index('enum cdp_tx_injection_preamble {'):
                    params.index('\nstatic inline bool cdp_nbuf_is_injection')]
    rt = (root / 'net/wireless/radiotap.c').read_text()
    rt = rt[rt.index('static const struct radiotap_align_size'):]
    parser = hdd[hdd.index('static int hdd_injection_legacy_rate('):
                 hdd.index('\nstatic void hdd_monitor_mode_tx_inject(')]
    htt_definitions = [
        declaration(htt, r'typedef enum \{\s*HTT_TX_MSDU_EXT2_DESC_PREAM_OFDM.*?\} htt_tx_ext2_preamble_type_t;'),
        declaration(htt, r'struct htt_h2t_rx_buffer_addr_info \{.*?\n\};'),
        declaration(htt, r'PREPACK struct htt_tx_msdu_desc_ext2_t \{.*?\n\} POSTPACK;'),
    ]
    code = (HERE / 'tests/wlan_injection.c').read_text()
    for marker, body in {
        'KERNEL_DEFINITIONS': '\n'.join(definitions),
        'PARAMS': params, 'RADIOTAP': rt, 'PARSER': parser,
        'HTT_DEFINITIONS': '\n'.join(htt_definitions),
        'ENCODER': function((root / DP).read_text(), 'dp_tx_add_injection_metadata'),
    }.items():
        code = code.replace('/* INSERT_' + marker + ' */', body)
    with tempfile.TemporaryDirectory(prefix='onyx-injection-') as directory:
        path = Path(directory)
        c, exe = path / 'injection.c', path / 'injection'
        def run(body):
            c.write_text(body)
            subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                            '-Werror', '-Wno-sign-compare', '-Wno-address-of-packed-member',
                            '-fsanitize=address,undefined',
                            '-fno-sanitize-recover=all', '-fno-pie', '-no-pie',
                            str(c), '-o', str(exe)], check=True)
            result = subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise AssertionError(result.stderr[-4000:])
            return int(result.stdout.strip())
        packet_assertions = run(code)
        wma = (root / WMA).read_text()
        queue = (HERE / 'tests/wlan_injection_queue.c').read_text()
        replacements = {
            'PARAMS': params,
            'SLOT': declaration(wma, r'struct wma_injection_slot \{.*?\n\};'),
            'CB': declaration(wma, r'struct wma_injection_cb \{.*?\n\};'),
            'HELPER': declaration(wma, r'struct wma_injection_helper \{.*?\n\};'),
            'SNAPSHOT': declaration(wma, r'struct wma_injection_helper_snapshot \{.*?\n\};'),
            'SELECT_MAC': function(wma, 'wma_injection_select_mac'),
            'GET_SNAPSHOT': function(wma, 'wma_injection_get_helper_snapshot'),
        }
        for marker, name in {'REFILL': 'wma_injection_refill', 'TX': 'wma_injection_tx',
                             'LOOKUP': 'wma_injection_get_tx_params',
                             'COMPLETE': 'wma_injection_dp_complete',
                             'DEINIT': 'wma_injection_deinit'}.items():
            replacements[marker] = function(wma, name)
        for marker, body in replacements.items():
            queue = queue.replace('/* INSERT_' + marker + ' */', body)
        queue_assertions = run(queue)
    return {
        'status': 'PASS', 'assertions': packet_assertions + queue_assertions,
        'packet_assertions': packet_assertions, 'queue_assertions': queue_assertions,
        'malformed_packets': 12000, 'sanitizers': 'ASan+UBSan',
        'source_sha256': {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                          for name in (HDD, WMA, DP, PARAMS, HTT, 'net/wireless/radiotap.c')},
        'limits': ['Uses actual cfg80211 radiotap iterator, frame parser and HTT encoder.',
                   'Actual WMA queuing, deferred refill, slot lookup, completion and teardown use mocked scheduling/DP.',
                   'Helper MAC selection and snapshot identity use actual WMA functions; firmware address handling needs device testing.',
                   'SKBs, DMA and synchronization primitives are mocks; firmware, ACKs and WPS require device testing.'],
    }


if __name__ == '__main__':
    print(json.dumps(verify(Path(sys.argv[1])), indent=2))
