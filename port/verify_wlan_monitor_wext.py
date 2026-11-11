#!/usr/bin/env python3
"""Exercise the production monitor WEXT bridge with ASan and UBSan."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
CFG = 'qcacld-3.0/core/hdd/src/wlan_hdd_cfg80211.c'
MAIN = 'qcacld-3.0/core/hdd/src/wlan_hdd_main.c'
HEADER = 'qcacld-3.0/core/hdd/src/wlan_hdd_cfg80211.h'


def function(source, name):
    match = re.search(r'(?m)^(?:static\s+)?(?:int|void|bool)[\s*]+' +
                      re.escape(name) + r'\([^;{}]*\)\s*\n\{', source)
    if not match:
        raise ValueError('Production function not found: ' + name)
    return source[match.start():source.index('\n}', match.end()) + 2]


def verify(root):
    root = Path(root).resolve()
    cfg = (root / CFG).read_text()
    main = (root / MAIN).read_text()
    header = (root / HEADER).read_text()
    parser = function(cfg, 'hdd_monitor_wext_freq_mhz')
    update = function(cfg, 'wlan_hdd_update_chandef')
    getter = function(cfg, 'hdd_monitor_wext_get_chandef')
    bridge = function(cfg, 'wlan_hdd_monitor_wext_set_freq')
    callback = function(main, 'hdd_monitor_wext_siwfreq')
    handlers = main[main.index('static const iw_handler hdd_monitor_wext_handlers[]'):
                    main.index('static const struct iw_handler_def hdd_monitor_wext_handler_def')]
    assert re.search(r'\[IW_IOCTL_IDX\(SIOCSIWFREQ\)\]\s*=\s*hdd_monitor_wext_siwfreq',
                     handlers), 'WEXT setter is not registered in the monitor handler table'
    assert 'wlan_hdd_monitor_wext_set_freq' in header, 'Bridge declaration missing'
    assert '__wlan_hdd_cfg80211_set_mon_ch' in bridge, 'Bridge must reuse the validated monitor setter'
    assert 'wlan_hdd_set_mon_chan(' not in bridge, 'Read-only coexistence helper cannot perform retuning'
    code = (HERE / 'tests/wlan_monitor_wext.c').read_text()
    for marker, body in [('UPDATE', update), ('PARSER', parser), ('GETTER', getter), ('BRIDGE', bridge), ('CALLBACK', callback)]:
        code = code.replace('/* INSERT_' + marker + ' */', body)
    with tempfile.TemporaryDirectory(prefix='onyx-monitor-wext-') as directory:
        path = Path(directory)
        source, binary = path / 'wext.c', path / 'wext'
        source.write_text(code)
        subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                        '-Werror', '-Wno-unused-parameter', '-Wno-unused-function',
                        '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                        '-fno-pie', '-no-pie', str(source), '-o', str(binary)], check=True)
        result = subprocess.run([str(binary)], capture_output=True, text=True,
                                timeout=20)
        if result.returncode:
            raise AssertionError(result.stderr[-8000:])
        cases = int(result.stdout.strip())
    return {'status': 'PASS', 'cases': cases, 'sanitizers': 'ASan+UBSan',
            'source_sha256': {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                              for name in (CFG, MAIN, HEADER)},
            'limits': ['The production frequency parser, current-channel helper, WEXT callback and bridge execute in this harness.',
                       'Channel programming, driver recovery, lock primitives and firmware completion are mocked.',
                       'Module compilation and live WEXT/channel-readback tests are required for hardware qualification.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('modules', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.modules), indent=2))
