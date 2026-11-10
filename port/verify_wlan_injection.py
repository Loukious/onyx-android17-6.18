#!/usr/bin/env python3
"""Exercise production injection parsing, queues and restart gates with ASan/UBSan."""
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
MLME = 'qcacld-3.0/components/mlme/dispatcher/src/wlan_mlme_api.c'
MLME_HEADER = 'qcacld-3.0/components/mlme/dispatcher/inc/wlan_mlme_sta_mon.h'
MLME_CONTROL = 'qcacld-3.0/components/mlme/core/inc/wlan_mlme_main.h'
PARAMS = 'qca-wifi-host-cmn/dp/inc/cdp_txrx_injection.h'
POWER = 'qca-wifi-host-cmn/umac/regulatory/dispatcher/inc/reg_services_public_struct.h'
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
        mlme = (root / MLME).read_text()
        mlme_header = (root / MLME_HEADER).read_text()
        queue = (HERE / 'tests/wlan_injection_queue.c').read_text()
        replacements = {
            'PARAMS': params,
            'POWER_TYPES': '\n'.join([
                declaration((root / POWER).read_text(),
                            r'struct chan_power_info \{.*?\n\};'),
                declaration((root / POWER).read_text(),
                            r'struct reg_tpc_power_info \{.*?\n\};'),
            ]),
            'SLOT': declaration(wma, r'struct wma_injection_slot \{.*?\n\};'),
            'CB': declaration(wma, r'struct wma_injection_cb \{.*?\n\};'),
            'HELPER': declaration(wma, r'struct wma_injection_helper \{.*?\n\};'),
            'SNAPSHOT': declaration(wma, r'struct wma_injection_helper_snapshot \{.*?\n\};'),
            'CONTEXT': declaration(wma, r'static struct \{.*?\n\} wma_injection_ctx;'),
            'STA_MON_TYPES': '\n'.join([
                declaration(mlme_header, r'enum wlan_mlme_sta_mon_state \{.*?\n\};'),
                declaration(mlme_header, r'enum wlan_mlme_sta_mon_handoff_phase \{.*?\n\};'),
                declaration(mlme_header, r'struct wlan_mlme_sta_mon_snapshot \{.*?\n\};'),
                declaration(mlme_header, r'typedef void \(\*wlan_mlme_sta_mon_stop_cb\)\(void \*arg\);'),
                declaration((root / MLME_CONTROL).read_text(),
                            r'struct wlan_mlme_sta_mon_control \{.*?\n\};'),
            ]),
            'STA_MON_FUNCTIONS': '\n'.join(function(mlme, name) for name in [
                'sta_mon_ap_lease_locked', 'sta_mon_invalidate_locked',
                'wlan_mlme_sta_mon_arm', 'wlan_mlme_sta_mon_set_ready',
                'wlan_mlme_sta_mon_quiesced', 'wlan_mlme_sta_mon_fw_timeout',
                'wlan_mlme_sta_mon_detach', 'wlan_mlme_sta_mon_ap_is_owner',
                'wlan_mlme_sta_mon_admission_begin',
                'wlan_mlme_sta_mon_mgmt_admission_begin',
                'wlan_mlme_sta_mon_ap_csa_admission_begin',
                'wlan_mlme_sta_mon_admission_end',
                'sta_mon_handoff_valid_locked', 'sta_mon_vdev_is_owner',
                'wlan_mlme_sta_mon_mgmt_tx_begin',
                'wlan_mlme_sta_mon_exclusive_reserve',
                'wlan_mlme_sta_mon_handoff_valid', 'wlan_mlme_sta_mon_handoff_start',
                'wlan_mlme_sta_mon_handoff_ready', 'wlan_mlme_sta_mon_disconnect_ind',
                'wlan_mlme_sta_mon_power_changed',
                'wlan_mlme_sta_mon_is_owner', 'wlan_mlme_sta_mon_get_token',
                'wlan_mlme_sta_mon_token_valid', 'wlan_mlme_sta_mon_get_snapshot',
                'wlan_mlme_sta_mon_invalidate_owner', 'wlan_mlme_sta_mon_invalidate',
                'wlan_mlme_sta_mon_update_begin', 'wlan_mlme_sta_mon_update_end',
            ]),
            'POWER': wma[wma.index('struct wma_injection_power_entry {'):
                         wma.index('static void wma_injection_work(')],
            'NATIVE_POWER_START': '\n'.join(function(wma, name) for name in [
                'wma_injection_native_valid', 'wma_injection_helper_start_continue',
                'wma_injection_helper_up_send',
            ]),
            'SELECT_MAC': function(wma, 'wma_injection_select_mac'),
            'GET_SNAPSHOT': function(wma, 'wma_injection_get_helper_snapshot'),
        }
        for marker, name in {'REFILL': 'wma_injection_refill', 'TX': 'wma_injection_tx',
                             'LOOKUP': 'wma_injection_get_tx_params',
                             'COMPLETE': 'wma_injection_dp_complete',
                             'RELEASE': 'wma_injection_dp_release',
                             'RESUME': 'wma_injection_coex_resume',
                             'PRE_STOP': 'wma_injection_pre_stop_cleanup',
                             'INIT': 'wma_injection_init',
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
                          for name in (HDD, WMA, DP, PARAMS, POWER, HTT, MLME,
                                       MLME_HEADER, MLME_CONTROL, 'net/wireless/radiotap.c')},
        'limits': ['Uses actual cfg80211 radiotap iterator, frame parser and HTT encoder.',
                   'Actual WMA queue, refill, lookup, completion/release, init, stop and coex-resume functions use mocked scheduling/DP.',
                   'Actual MLME READY, ownership, snapshot and generation checks cover restart and failed-drain admission.',
                   'Actual private WMA power cache, layout and admission functions cover zero/negative limits, failed/overlapping sends, regulatory changes, overrides and vdev reuse with mocked regulatory and object services.',
                   'Actual native helper START continuation and UP gate reject missing/failed/stale TPC programming; WMI sends and vdev state-machine delivery are mocked.',
                   'Helper MAC selection and snapshot identity use actual WMA functions; firmware address handling needs device testing.',
                   'Native helper creation/STOP/DELETE, HDD channel setup, SKBs, DMA and synchronization primitives are mocks or excluded; firmware, races, ACKs and WPS require device testing.'],
    }


if __name__ == '__main__':
    print(json.dumps(verify(Path(sys.argv[1])), indent=2))
