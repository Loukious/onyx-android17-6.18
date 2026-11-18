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
HDD_API = 'qcacld-3.0/core/hdd/inc/wlan_hdd_main.h'
DP = 'qca-wifi-host-cmn/dp/wifi3.0/dp_tx.c'
DP_MON_RX = 'qca-wifi-host-cmn/dp/wifi3.0/monitor/dp_rx_mon.c'
DP_MON_HEADER = 'qca-wifi-host-cmn/dp/wifi3.0/monitor/dp_mon.h'
DP_MON_STATUS = 'qca-wifi-host-cmn/dp/wifi3.0/monitor/1.0/dp_rx_mon_status_1.0.c'
DP_RX_CORE = 'qcacld-3.0/components/dp/core/src/wlan_dp_txrx.c'
DP_PUBLIC = 'qcacld-3.0/components/dp/dispatcher/inc/wlan_dp_public_struct.h'
OSIF_DP_RX = 'qcacld-3.0/os_if/dp/src/os_if_dp_txrx.c'
WMA = 'qcacld-3.0/core/wma/src/wma_data.c'
WMA_API = 'qcacld-3.0/core/wma/inc/wma_api.h'
WONDER = 'qcacld-3.0/core/hdd/src/wlan_hdd_wonder.c'
MLME = 'qcacld-3.0/components/mlme/dispatcher/src/wlan_mlme_api.c'
MLME_HEADER = 'qcacld-3.0/components/mlme/dispatcher/inc/wlan_mlme_sta_mon.h'
MLME_CONTROL = 'qcacld-3.0/components/mlme/core/inc/wlan_mlme_main.h'
SCAN_PUBLIC = 'qca-wifi-host-cmn/umac/scan/dispatcher/inc/wlan_scan_public_structs.h'
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


def verify(root, extra_packet_helpers='', extra_packet_tests=''):
    root = Path(root)
    # Both the source tree and prepared workspace keep common beside modules.
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
    hdd = (root / HDD).read_text()
    htt = (root / HTT).read_text()
    definitions = ['typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;']
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
    definitions.append(function(wireless('net/wireless/util.c').read_text(),
                                'ieee80211_hdrlen'))
    for name in ('ieee80211_radiotap_presence', 'ieee80211_radiotap_flags',
                 'ieee80211_radiotap_channel_flags', 'ieee80211_radiotap_tx_flags',
                 'ieee80211_radiotap_mcs_have', 'ieee80211_radiotap_mcs_flags',
                 'ieee80211_radiotap_vht_known', 'ieee80211_radiotap_vht_flags',
                 'ieee80211_radiotap_he_bits'):
        definitions.append(declaration(radiotap, r'enum ' + name + r' \{.*?\n\};'))
    definitions.append(declaration(radiotap, r'struct ieee80211_radiotap_he \{.*?\n\};'))
    definitions.append(cfg[cfg.index('struct radiotap_align_size {'):
                           cfg.index('\n\nextern const unsigned char rfc1042_header')])
    params = (root / PARAMS).read_text()
    params = params[params.index('enum cdp_tx_injection_preamble {'):
                    params.index('\nstatic inline bool cdp_nbuf_is_injection')]
    rt = wireless('net/wireless/radiotap.c').read_text()
    rt = rt[rt.index('static const struct radiotap_align_size'):]
    parser = hdd[hdd.index('static int hdd_injection_legacy_rate('):
                 hdd.index('\nstatic void hdd_monitor_mode_tx_inject(')]
    htt_definitions = [
        declaration(htt, r'typedef enum \{\s*HTT_TX_MSDU_EXT2_DESC_PREAM_OFDM.*?\} htt_tx_ext2_preamble_type_t;'),
        declaration(htt, r'struct htt_h2t_rx_buffer_addr_info \{.*?\n\};'),
        declaration(htt, r'PREPACK struct htt_tx_msdu_desc_ext2_t \{.*?\n\} POSTPACK;'),
    ]
    code = (HERE / 'tests/wlan_injection.c').read_text()
    code = code.replace('/* EXTRA_PACKET_HELPERS */', extra_packet_helpers)
    code = code.replace('/* EXTRA_PACKET_TESTS */', extra_packet_tests)
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
        def run(body, extra_flags=()):
            c.write_text(body)
            subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                            '-Werror', '-Wno-sign-compare', '-Wno-address-of-packed-member',
                            '-fsanitize=address,undefined',
                            '-fno-sanitize-recover=all', '-fno-pie', '-no-pie',
                            *extra_flags,
                            str(c), '-o', str(exe)], check=True)
            result = subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise AssertionError(result.stderr[-4000:])
            return int(result.stdout.strip())
        packet_assertions = run(code)
        wma = (root / WMA).read_text()
        mlme = (root / MLME).read_text()
        mlme_header = (root / MLME_HEADER).read_text()
        scan_public = (root / SCAN_PUBLIC).read_text()
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
            'WONDER_SNAPSHOT': declaration((root / WMA_API).read_text(),
                                           r'struct wma_wonder_helper_snapshot \{.*?\n\};'),
            'CONTEXT': declaration(wma, r'static struct \{.*?\n\} wma_injection_ctx;'),
            'STA_MON_TYPES': '\n'.join([
                declaration(scan_public, r'enum scan_event_type \{.*?\n\};'),
                declaration(scan_public, r'enum scan_completion_reason \{.*?\n\};'),
                declaration(scan_public, r'struct scan_event \{.*?\n\};'),
                declaration(mlme_header, r'enum wlan_mlme_sta_mon_state \{.*?\n\};'),
                declaration(mlme_header, r'enum wlan_mlme_sta_mon_handoff_phase \{.*?\n\};'),
                declaration(mlme_header, r'struct wlan_mlme_sta_mon_snapshot \{.*?\n\};'),
                declaration(mlme_header, r'typedef void \(\*wlan_mlme_sta_mon_stop_cb\)\(void \*arg\);'),
                declaration(mlme_header, r'struct wlan_mlme_sta_mon_scan_reservation \{.*?\n\};'),
                declaration(mlme_header, r'enum wlan_mlme_sta_mon_scan_notice \{.*?\n\};'),
                declaration(mlme_header, r'typedef void \(\*wlan_mlme_sta_mon_scan_cb\)\(.*?\);'),
                declaration((root / MLME_CONTROL).read_text(),
                            r'struct wlan_mlme_sta_mon_control \{.*?\n\};'),
            ]),
            'STA_MON_FUNCTIONS': '\n'.join(function(mlme, name) for name in [
                'sta_mon_ap_lease_locked', 'sta_mon_wonder_scan_lease_locked',
                'sta_mon_real_owner_matches',
                'sta_mon_invalidate_locked',
                'wlan_mlme_sta_mon_arm', 'wlan_mlme_sta_mon_vdev_created',
                'wlan_mlme_sta_mon_set_ready',
                'wlan_mlme_sta_mon_quiesced', 'wlan_mlme_sta_mon_fw_timeout',
                'wlan_mlme_sta_mon_detach', 'wlan_mlme_sta_mon_ap_is_owner',
                'wlan_mlme_sta_mon_sta_is_companion',
                'wlan_mlme_sta_mon_admission_begin',
                'sta_mon_scan_tuple_matches', 'wlan_mlme_sta_mon_scan_reserve',
                'wlan_mlme_sta_mon_scan_admission_begin',
                'wlan_mlme_sta_mon_scan_activate', 'sta_mon_scan_notice',
                'wlan_mlme_sta_mon_scan_fw_event',
                'wlan_mlme_sta_mon_scan_not_submitted',
                'wlan_mlme_sta_mon_scan_release_unsubmitted',
                'wlan_mlme_sta_mon_mgmt_admission_begin',
                'wlan_mlme_sta_mon_ap_csa_admission_begin',
                'wlan_mlme_sta_mon_sta_csa_admission_begin',
                'wlan_mlme_sta_mon_admission_end',
                'sta_mon_handoff_valid_locked', 'sta_mon_vdev_is_owner',
                'wlan_mlme_sta_mon_mgmt_tx_begin',
                'wlan_mlme_sta_mon_exclusive_reserve',
                'wlan_mlme_sta_mon_handoff_valid', 'wlan_mlme_sta_mon_handoff_start',
                'wlan_mlme_sta_mon_handoff_ready', 'wlan_mlme_sta_mon_disconnect_ind',
                'wlan_mlme_sta_mon_power_changed', 'wlan_mlme_sta_mon_channel_changed',
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
            'WONDER_HELPER': '\n'.join(function(wma, name) for name in [
                'wma_wonder_standalone_helper_reserved',
                'wma_wonder_helper_prepare', 'wma_wonder_helper_identity_valid',
                'wma_injection_channel_change_begin', 'wma_injection_channel_change_end',
            ]),
            'WONDER_ADMISSION': '\n'.join(function((root / WONDER).read_text(), name)
                                          for name in ['hdd_wonder_vdev_admission',
                                                       'wlan_injection_wonder_vdev_admission']),
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
        mon_rx = (root / DP_MON_RX).read_text()
        mon_header = (root / DP_MON_HEADER).read_text()
        dp_rx_core = (root / DP_RX_CORE).read_text()
        osif_dp_rx = (root / OSIF_DP_RX).read_text()
        rx = (HERE / 'tests/wlan_injection_rx.c').read_text()
        rx_functions = '\n'.join(function(mon_rx, name) for name in [
            'dp_sta_mon_helper_rx_marker', 'dp_sta_mon_find_shared_binding',
            'dp_sta_mon_shared_binding_live', 'dp_sta_mon_publish',
        ])
        rx_functions += '\n#ifdef FEATURE_WLAN_WONDER\n' + function(
            mon_rx, 'dp_sta_mon_measured_frequency') + '\n#endif\n'
        rx_functions += function(mon_rx, 'dp_sta_mon_publish_full')
        for marker, body in {
            'RX_BINDING': declaration(mon_rx,
                                     r'struct dp_sta_mon_helper_binding \{.*?\n\};'),
            'RX_LEASE': declaration((root / PARAMS).read_text(),
                                   r'struct cdp_wonder_rx_lease \{.*?\n\};'),
            'RX_PUSH_ENUM': declaration((root / DP_PUBLIC).read_text(),
                                        r'enum dp_nbuf_push_type \{.*?\n\};'),
            'RX_PRIV_MACRO': declaration((root / HDD_API).read_text(),
                                         r'^#define WLAN_HDD_GET_PRIV_PTR[^\n]*\\\n[^\n]+'),
            'RX_NETWORK_FUNCTIONS': '#ifdef FEATURE_WLAN_WONDER\n' +
                function((root / WONDER).read_text(), 'hdd_wonder_netdev_is_owned') +
                '\n#endif\n' + function(dp_rx_core, 'dp_mon_rx_push_type') +
                '\n' + function(osif_dp_rx, 'osif_dp_rx_pkt_to_nw'),
            'RX_FREQUENCY_FUNCTIONS': '#ifdef FEATURE_WLAN_WONDER\n' +
                '\n'.join(function(mon_header, name) for name in [
                    'dp_mon_wonder_rx_frequency_reset',
                    'dp_mon_wonder_rx_frequency_start',
                ]) + '\n#endif\n',
            'RX_FUNCTIONS': rx_functions,
        }.items():
            rx = rx.replace('/* INSERT_' + marker + ' */', body)
        # Every coex producer must enter the final helper, with zero reserved
        # for copies whose RX descriptor has no measured channel provenance.
        for name, frequency in [
            ('dp_mon_sta_coex_mgmt_rx', 'frequency'),
            ('dp_mon_sta_coex_copy_shared', '0'),
            ('dp_mon_sta_coex_copy_unknown_raw', '0'),
            ('dp_sta_mon_deliver_raw', '0'),
        ]:
            producer = function(mon_rx, name)
            if not re.search(r'dp_sta_mon_publish\([^;]+NULL, ' + frequency +
                             r'\)', producer, re.S):
                raise AssertionError('Missing final provenance gate: ' + name)
            if re.search(r'\bosif_rx_mon\s*\(', producer):
                raise AssertionError('Ungated coex publication: ' + name)
        for name in ['dp_rx_mon_deliver', 'dp_rx_mon_deliver_non_std',
                     'dp_rx_mon_send_mpdu', 'dp_rx_handle_smart_mesh_mode']:
            producer = function(mon_rx, name)
            if 'dp_sta_mon_publish_full(' not in producer or re.search(
                    r'\bosif_rx_mon\s*\(', producer):
                raise AssertionError('Ungated raw monitor publication: ' + name)
        status_source = (root / DP_MON_STATUS).read_text()
        decode = status_source.index('tlv_status = hal_rx_status_get_tlv_info(')
        capture = status_source.index('dp_mon_wonder_rx_frequency_start(', decode)
        fallback = status_source.index('if (qdf_unlikely(mon_mac->ppdu_info.rx_status.chan_freq == 0))')
        if capture >= fallback or 'WIFIRX_PPDU_START_E)' not in status_source[decode:capture]:
            raise AssertionError('Measured frequency must follow PPDU START decoding and precede HOME fallback')
        # Verify the tested selector and OSIF consumer are the production
        # callback route for the last packet, which used to recurse into TX.
        monitor_callback = function(dp_rx_core, 'dp_mon_rx_packet_cbk')
        if not re.search(r'type = dp_mon_rx_push_type\(dp_intf->dev\);\s*'
                         r'status = dp_intf->dp_ctx->dp_ops.dp_nbuf_push_pkt\('
                         r'nbuf,\s*type\);', monitor_callback):
            raise AssertionError('Monitor callback bypasses tested network push selector')
        osif_registration = function(osif_dp_rx, 'os_if_dp_register_txrx_callbacks')
        if 'cb_obj->dp_nbuf_push_pkt = osif_dp_rx_pkt_to_nw;' not in osif_registration:
            raise AssertionError('Monitor network callback bypasses tested OSIF delivery')
        rx_flags = ('-Wno-unused-parameter', '-DFEATURE_WLAN_WONDER')
        rx_assertions = run(rx, rx_flags)
        rx_legacy_assertions = run(rx, ('-Wno-unused-parameter',))
        rx_negative_controls = [
            ('deny_gate_inverted', 'if (!wlan_injection_wonder_rx_begin(',
             'if (wlan_injection_wonder_rx_begin('),
            ('lease_not_released', 'wlan_injection_wonder_rx_end(&lease);',
             '(void)wlan_injection_wonder_rx_end;'),
            ('configured_home_substitution',
             'frequency = dp_sta_mon_measured_frequency(mon_mac);',
             'frequency = mon_mac->mon_chan_freq;'),
            ('stale_ppdu_accepted',
             'mon_mac->wonder_rx_frequency_ppdu_id !=\n\t\t\t\tmon_mac->ppdu_info.com_info.ppdu_id ||', ''),
            ('home_binding_broadened',
             'mon_mac->mon_chan_freq == binding->frequency &&', ''),
            ('wonder_backlog_delivered_recursively',
             '\t\treturn DP_NBUF_PUSH_SIMPLE;', '\t\treturn DP_NBUF_PUSH_NAPI;'),
        ]
        for name, before, after in rx_negative_controls:
            if rx.count(before) != 1:
                raise AssertionError('Negative control has stale source match: ' + name)
            try:
                run(rx.replace(before, after), rx_flags)
            except AssertionError as error:
                if name == 'wonder_backlog_delivered_recursively' and \
                        'recursive Wonder consumption while lease is held' not in str(error):
                    raise AssertionError('Backlog negative control failed without observing '
                                         'recursive consumption under the Wonder lease') from error
            else:
                raise AssertionError('RX fixture missed negative control: ' + name)
    return {
        'status': 'PASS', 'assertions': packet_assertions + queue_assertions +
                                      rx_assertions + rx_legacy_assertions,
        'packet_assertions': packet_assertions, 'queue_assertions': queue_assertions,
        'rx_assertions': rx_assertions, 'rx_legacy_assertions': rx_legacy_assertions,
        'rx_negative_controls': len(rx_negative_controls),
        'malformed_packets': 12000, 'sanitizers': 'ASan+UBSan',
        'host_fixture_sha256': {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                               for name in ('verify_wlan_injection.py', 'tests/wlan_injection.c',
                                            'tests/wlan_injection_queue.c',
                                            'tests/wlan_injection_rx.c')},
        'source_sha256': {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                          for name in (HDD, HDD_API, WMA, WMA_API, WONDER, DP, PARAMS, POWER, HTT, MLME,
                                       MLME_HEADER, MLME_CONTROL, SCAN_PUBLIC,
                                       DP_MON_RX, DP_MON_HEADER, DP_MON_STATUS,
                                       DP_RX_CORE, DP_PUBLIC, OSIF_DP_RX)},
        'native_source_sha256': {'net/wireless/radiotap.c': hashlib.sha256(
            wireless('net/wireless/radiotap.c').read_bytes()).hexdigest()},
        'limits': ['Uses actual cfg80211 radiotap iterator, frame parser and HTT encoder.',
                   'Actual WMA queue, refill, lookup, completion/release, init, stop and coex-resume functions use mocked scheduling/DP.',
                   'Actual MLME READY, ownership, snapshot and generation checks cover restart and failed-drain admission.',
                   'Actual triple-owner controller checks cover malformed ownership, both owners management, companion invalidation/CSA and leases through native drain; HDD/radio admission is excluded.',
                   'Actual private WMA power cache, layout and admission functions cover zero/negative limits, failed/overlapping sends, regulatory changes, overrides and vdev reuse with mocked regulatory and object services.',
                   'Actual native helper START continuation and UP gate reject missing/failed/stale TPC programming; WMI sends and vdev state-machine delivery are mocked.',
                   'Helper MAC selection and snapshot identity use actual WMA functions; firmware address handling needs device testing.',
                   'Actual Wonder helper preparation/identity and channel-change guards cover same-frequency width transitions and DELETE timeout with mocked helper creation/deletion and module pins; HDD matcher CLEAR is excluded.',
                   'Actual provider vdev admission and standalone helper reservation remain blocked after provider teardown until helper deletion drains; vdev creation itself is mocked.',
                   'Actual DP measured-frequency capture and final coex publication helpers cover exact PPDU identity, HOME fallback exclusion, stale owner/binding rejection, and balanced admission held through the callback; the owner lease implementation and RX rings/DMA are mocked.',
                   'Actual HDD ownership predicate, monitor push selector and OSIF network delivery defer Wonder consumption until admission/RCU/monitor locks release; normal monitors retain immediate NAPI/BH delivery. Network consumers and backlog are mocked; a compiled negative control detects recursive Wonder consumption under its held lease.',
                   'Native helper creation/STOP/DELETE, HDD channel setup, SKBs, DMA and synchronization primitives are mocks or excluded; firmware, races, ACKs and WPS require device testing.'],
    }


if __name__ == '__main__':
    print(json.dumps(verify(Path(sys.argv[1])), indent=2))
