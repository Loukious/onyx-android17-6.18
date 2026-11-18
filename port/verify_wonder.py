#!/usr/bin/env python3
"""Run Wonder packets through the real HDD parser and HTT metadata encoder."""
import hashlib
import json
from pathlib import Path
import sys
import subprocess
import tempfile

from verify_wlan_injection import declaration, function, verify
from verify_wonder_rx import verify_rx

HERE = Path(__file__).resolve().parent


def verify_control(root):
    api = (root / 'wonder/include/wondertap.h').read_text()
    internal = (root / 'wonder/wondertap_internal.h').read_text()
    source = (root / 'wonder/wondertap.c').read_text()
    mac = (root / 'wonder/mac80211.c').read_text()
    monitor = (root / 'wonder/include/wondertap_monitor.h').read_text()
    types = '\n'.join(declaration(api, r'enum ' + name + r' \{.*?\n\};')
                      for name in ('wondertap_rate_preamble', 'wondertap_rate_bw',
                                   'wondertap_rate_gi', 'wondertap_role'))
    types += '\n' + declaration(internal, r'enum wondertap_state \{.*?\n\};')
    for name in ('wondertap_set_freq_params', 'wondertap_fixed_tx_rate_params',
                 'wondertap_tx_rate_mask_params', 'wondertap_channel_list_params',
                 'channel_schedule_request', 'wondertap_capability', 'wondertap_init_params'):
        types += '\n' + declaration(api, r'struct ' + name + r' \{.*?\n\};')
    types += '\n' + '\n'.join(line for line in internal.splitlines()
                               if line.startswith('#define WONDERTAP_CACHE_'))
    types += '\n' + declaration(monitor, r'struct wondertap_monitor_ops \{.*?\n\};')
    types += '\n' + declaration((root.parent / 'common/include/uapi/linux/nl80211.h').read_text(),
                                r'enum nl80211_iftype \{.*?\n\};')
    functions = function(monitor, 'wondertap_monitor_validate_rate') + '\n'
    functions += '\n'.join(function(source, name) for name in (
        'wondertap_is_up', 'wondertap_get_mac_tsf', 'wondertap_get_capabilities',
        'wondertap_replay_channel_schedule_locked', 'wondertap_set_fixed_tx_rate',
        'wondertap_set_freq', 'wondertap_set_tx_rate_mask', 'wondertap_channel_schedule_request'))
    functions += '\n' + '\n'.join(function(mac, name) for name in (
        'wonder_monitor_pm_suspend', 'wonder_monitor_vdev_restore', 'wonder_monitor_pm_resume',
        'wonder_force_set_mac', 'wonder_add_interface', 'wonder_remove_interface'))
    fixture = (HERE / 'tests/wonder_control.c').read_text()
    fixture = fixture.replace('/* INSERT_TYPES */', types).replace('/* INSERT_FUNCTIONS */', functions)
    with tempfile.TemporaryDirectory(prefix='onyx-wonder-control-') as directory:
        path = Path(directory)
        (path / 'control.c').write_text(fixture)
        subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                        '-fno-pie', '-no-pie', str(path / 'control.c'), '-o', str(path / 'control')],
                       check=True)
        result = subprocess.run([str(path / 'control')], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr[-4000:])
        return int(result.stdout.strip())


def verify_transport(root):
    root = Path(root)
    api = (root / 'wonder/include/wondertap.h').read_text()
    monitor = (root / 'wonder/include/wondertap_monitor.h').read_text()
    definitions = '\n'.join(declaration(api, r'enum ' + name + r' \{.*?\n\};')
                            for name in ('wondertap_rate_preamble', 'wondertap_rate_bw',
                                         'wondertap_rate_gi'))
    definitions += '\n' + declaration(api, r'struct wondertap_fixed_tx_rate_params \{.*?\n\};')
    definitions += '\ntypedef uint32_t u32; typedef uint16_t u16;\n'
    definitions += '#define cpu_to_le32(x) ((uint32_t)(x))\n'
    definitions += '#define put_unaligned_le16(v, p) put16((p), (v))\n'
    helpers = monitor[monitor.index('/* Bounds for'):
                      monitor.rindex('#endif')]
    fixtures = (HERE / 'tests/wonder_transport.c').read_text()
    result = verify(root, definitions + helpers + fixtures, 'wonder_transport_fixtures();')
    result['control_assertions'] = verify_control(root)
    result['assertions'] += result['control_assertions']
    result['rx'] = verify_rx(root)
    result['rx_assertions'] = result['rx']['assertions']
    result['assertions'] += result['rx_assertions']
    result['scope'] = 'Production Wonder transport, control/PM replay and RX software contracts'
    for name in ('wonder/include/wondertap_monitor.h', 'wonder/include/wondertap.h',
                 'wonder/wondertap.c', 'wonder/wondertap_internal.h'):
        result['source_sha256'][name] = hashlib.sha256((root / name).read_bytes()).hexdigest()
    result['host_fixture_sha256'] = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                                   for name in ('verify_wonder.py', 'verify_wlan_injection.py',
                                                'tests/wonder_control.c', 'tests/wonder_transport.c',
                                                'tests/wonder_rx.c', 'tests/wlan_injection.c',
                                                'tests/wlan_injection_queue.c')}
    result['limits'].append('Firmware channel transitions, RX delivery and Apple transfers are untested.')
    result['limits'].append('Control/PM tests execute production functions with explicit mocked clocks, provider callbacks, locks and netdev state; actual TSF continuity and kernel PM require device validation.')
    result['limits'].extend(result['rx']['limits'])
    return result


if __name__ == '__main__':
    print(json.dumps(verify_transport(Path(sys.argv[1])), indent=2))
