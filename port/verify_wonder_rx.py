#!/usr/bin/env python3
"""Exercise production Wonder RX handlers with the kernel radiotap iterator."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from verify_wlan_injection import declaration, function

HERE = Path(__file__).resolve().parent


def verify_rx(root):
    root = Path(root)
    kernel = root.parent / 'common'

    def header(name):
        staged = root / 'include' / name
        return (staged if staged.is_file() else kernel / 'include' / name).read_text()

    def wireless(name):
        staged = root / name
        return staged if staged.is_file() else kernel / name

    ieee = header('linux/ieee80211.h')
    radiotap = header('net/ieee80211_radiotap.h')
    cfg = header('net/cfg80211.h')
    mac = header('net/mac80211.h')
    definitions = [line for line in ieee.splitlines()
                   if line.startswith('#define IEEE80211_') and
                   line.split()[1].startswith(('IEEE80211_FCTL_', 'IEEE80211_FTYPE_',
                                               'IEEE80211_STYPE_', 'IEEE80211_QOS_CTL_LEN'))]
    definitions += [declaration(ieee, r'^#define FCS_LEN[^\n]+'),
                    declaration(cfg, r'^#define IEEE80211_MAX_CHAINS[^\n]+'),
                    declaration(header('linux/ieee80211-ht.h'),
                                r'^#define IEEE80211_HT_CTL_LEN[^\n]+')]
    for source, names in ((radiotap, ('ieee80211_radiotap_presence',
                                     'ieee80211_radiotap_flags',
                                     'ieee80211_radiotap_channel_flags',
                                     'ieee80211_radiotap_mcs_flags',
                                     'ieee80211_radiotap_vht_known',
                                     'ieee80211_radiotap_vht_flags')),
                          (mac, ('mac80211_rx_flags', 'mac80211_rx_encoding_flags',
                                 'mac80211_rx_encoding')),
                          (cfg, ('rate_info_bw',)),
                          (header('uapi/linux/nl80211.h'), ('nl80211_band',))):
        definitions += [declaration(source, r'enum ' + name + r' \{.*?\n\};')
                        for name in names]
    definitions += [declaration(ieee, r'struct ieee80211_hdr_3addr \{.*?\n\}[^;]*;'),
                    declaration(mac, r'struct ieee80211_rx_status \{.*?\n\};'),
                    declaration(radiotap, r'struct ieee80211_radiotap_header \{.*?\n\}[^;]*;')]
    definitions += [function(ieee, name) for name in (
        'ieee80211_has_a4', 'ieee80211_has_order', 'ieee80211_is_mgmt',
        'ieee80211_is_ctl', 'ieee80211_is_data', 'ieee80211_is_data_qos',
        'ieee80211_is_ext')]
    definitions.append(function(wireless('net/wireless/util.c').read_text(),
                                'ieee80211_hdrlen'))
    definitions.append(cfg[cfg.index('struct radiotap_align_size {'):
                           cfg.index('\n\nextern const unsigned char rfc1042_header')])
    rt = wireless('net/wireless/radiotap.c').read_text()
    rt = rt[rt.index('static const struct radiotap_align_size'):]
    source = (root / 'wonder/mac80211.c').read_text()
    helper = (root / 'wonder/monitor_rx.h').read_text()
    functions = function(helper, 'wonder_normalize_monitor_rx') + '\n'
    functions += '\n'.join(function(source, name) for name in (
        'wonder_fill_rx_status', 'wonder_rx_80211_frame',
        'wonder_rx_monitor_handler', 'wonder_rx_adhoc_handler'))
    code = (HERE / 'tests/wonder_rx.c').read_text()
    for marker, body in {'DEFINITIONS': '\n'.join(definitions),
                         'RADIOTAP': rt, 'FUNCTIONS': functions}.items():
        code = code.replace('/* INSERT_' + marker + ' */', body)
    with tempfile.TemporaryDirectory(prefix='onyx-wonder-rx-') as directory:
        path = Path(directory)
        (path / 'rx.c').write_text(code)
        subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-Wno-sign-compare', '-Wno-address-of-packed-member',
                        '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                        '-fno-pie', '-no-pie', str(path / 'rx.c'), '-o', str(path / 'rx')],
                       check=True)
        result = subprocess.run([str(path / 'rx')], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr[-4000:])
        assertions = int(result.stdout.strip())
    return {'status': 'PASS', 'assertions': assertions, 'sanitizers': 'ASan+UBSan',
            'scope': 'Production Wonder adhoc and raw monitor RX handlers and cfg80211 iterator',
            'source_sha256': {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                              for name in ('wonder/mac80211.c', 'wonder/monitor_rx.h')},
            'native_source_sha256': {'net/wireless/radiotap.c': hashlib.sha256(
                wireless('net/wireless/radiotap.c').read_bytes()).hexdigest()},
            'limits': ['SKB operations use allocation-bounded head/fragment/clone mocks with failure injection.',
                       'Filtering, mac80211 delivery, stats and synchronization are mocked; actual kernel SKBs, firmware RX and Apple transfers require device testing.']}


if __name__ == '__main__':
    print(json.dumps(verify_rx(Path(sys.argv[1])), indent=2))
