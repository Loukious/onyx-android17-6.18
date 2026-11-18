#!/usr/bin/env python3
"""Verify the Android-local raw probe offline and link an AArch64 artifact.

Only instrumented host fixtures and explicit dry-run invocations execute.
The linked Android artifact is retained, never executed or deployed.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess

HERE = Path(__file__).resolve().parent
NDK_BIN = Path('/home/loukious/Android/Sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin')
ANDROID_CC = NDK_BIN / 'aarch64-linux-android35-clang'


def identity(path):
    data = path.read_bytes()
    return {'path': str(path.resolve()), 'size': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def invoke(output, name, argv, *, env=None, required=True):
    result = subprocess.run(list(map(str, argv)), capture_output=True,
                            timeout=120, env=env, cwd=output)
    stdout, stderr = output / (name + '.stdout.txt'), output / (name + '.stderr.txt')
    stdout.write_bytes(result.stdout)
    stderr.write_bytes(result.stderr)
    record = {'argv': list(map(str, argv)), 'returncode': result.returncode,
              'stdout': identity(stdout), 'stderr': identity(stderr)}
    if required and result.returncode:
        raise RuntimeError(f'{name} failed; see {stderr}')
    return record, result.stdout, result.stderr


def android_elf_contract(path):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01':
        raise RuntimeError('Expected a little-endian ELF64 binary')
    elf_type, machine = struct.unpack_from('<HH', data, 16)
    if elf_type != 3 or machine != 183:
        raise RuntimeError('Expected an AArch64 ET_DYN executable')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    if size != 56 or offset + size * count > len(data):
        raise RuntimeError('Malformed ELF program-header table')
    loads, interpreter = [], None
    for index in range(count):
        kind, flags, file_offset, virtual, _, file_size, _, alignment = struct.unpack_from(
            '<IIQQQQQQ', data, offset + index * size)
        if kind == 1:
            if alignment != 16384 or virtual % alignment != file_offset % alignment:
                raise RuntimeError('PT_LOAD must satisfy 16 KiB alignment and congruence')
            loads.append({'flags': flags, 'alignment': alignment,
                          'file_offset': file_offset, 'virtual_address': virtual})
        elif kind == 3:
            if file_offset + file_size > len(data):
                raise RuntimeError('Malformed ELF interpreter range')
            interpreter = data[file_offset:file_offset + file_size].rstrip(b'\0').decode()
    if not loads or interpreter != '/system/bin/linker64':
        raise RuntimeError('Expected LOAD segments and the Android linker64 interpreter')
    return {'class': 'ELF64', 'endianness': 'little', 'machine': 'AArch64',
            'type': 'ET_DYN', 'load_segments': loads, 'interpreter': interpreter}


def wire_attributes(data):
    attributes = {}
    while data:
        if len(data) < 4:
            raise RuntimeError('Truncated dry-run netlink attribute')
        size, kind = struct.unpack_from('<HH', data)
        step = (size + 3) & ~3
        if size < 4 or step > len(data) or kind in attributes:
            raise RuntimeError('Malformed dry-run netlink attribute')
        attributes[kind] = data[4:size]
        if any(data[size:step]):
            raise RuntimeError('Nonzero dry-run netlink alignment bytes')
        data = data[step:]
    return attributes


def dry_run_contract(stdout, *, data_frame, count, nonce, frequency):
    records = [json.loads(line) for line in stdout.splitlines()]
    if len(records) != count + 1:
        raise RuntimeError('Unexpected standalone dry-run record count')
    header, *packets = records
    expected = {'event': 'dry_run', 'rf_verified': False, 'device_state_read': False,
        'sockets_opened': False, 'control_interface': 'wonder0', 'raw_interface': 'wondertap0',
        'frequency_mhz': frequency, 'rate_mbps': 6, 'bandwidth_mhz': 20,
        'frame': 'data' if data_frame else 'action',
        'placeholders': {'family_id': 0, 'ifindex': 0, 'netlink_pid': 0}}
    if any(header.get(key) != value for key, value in expected.items()):
        raise RuntimeError('Standalone dry-run metadata contract failed')
    query = bytes.fromhex(header['family_query_hex'])
    vendor = bytes.fromhex(header['vendor_request_hex'])
    if struct.unpack_from('<IHHIIBBH', query) != (32, 16, 5, 1, 0, 3, 1, 0):
        raise RuntimeError('Standalone family query header differs from exact ABI')
    if wire_attributes(query[20:]) != {2: b'nl80211\0'}:
        raise RuntimeError('Standalone family query has incorrect family name')
    if struct.unpack_from('<IHHIIBBH', vendor) != (64, 0, 5, 2, 0, 103, 1, 0):
        raise RuntimeError('Standalone vendor request header differs from exact ABI')
    attrs = wire_attributes(vendor[20:])
    if attrs != {3: struct.pack('<I', 0), 195: struct.pack('<I', 0x001a11),
                 196: struct.pack('<I', 1), 197: struct.pack('<HHIHHHxx', 8, 1, frequency, 6, 2, 0)}:
        raise RuntimeError('Standalone vendor OUI/subcommand/frequency/u16 bandwidth differs from ABI')
    radiotap = struct.pack('<BBHIBxHH', 0, 0, 14, 12, 12, frequency,
                          0x00c0 if frequency < 4900 else 0x0140)
    addresses = bytes.fromhex('021122334455023344556677022233445566')
    prefix = bytes.fromhex('aaaa0300000088b5' if data_frame else '7f001a1157')
    for index, packet in enumerate(packets):
        expected_packet = radiotap + struct.pack('<HH', 0x0008 if data_frame else 0x00d0, 0) + \
            addresses + struct.pack('<H', index << 4) + prefix + struct.pack('<II', nonce, index) + \
            b'WONDER-OFFCHAN-PROBE'
        if packet.get('event') != 'dry_run_packet' or packet.get('index') != index or \
                packet.get('nonce') != nonce or packet.get('rf_verified') is not False or \
                bytes.fromhex(packet['packet_hex']) != expected_packet:
            raise RuntimeError(f'Standalone packet {index} differs from exact wire contract')
    return {'records': len(records), 'packet_count': count, 'frame': expected['frame'],
            'frequency_mhz': frequency, 'nonce': nonce, 'wire_contract': 'PASS'}


NEGATIVE_CONTROLS = [
    ('radiotap_tx_flags', 'put_le32(out + 4, 0x0c);', 'put_le32(out + 4, 0x800c);',
     'radiotap_exact_no_tx_options: !memcmp(packet, expected, sizeof(expected))'),
    ('bandwidth_width', 'uint16_t width = 0;', 'uint32_t width = 0;',
     'netlink_exact_frequency_bandwidth: !memcmp(payload, expected_vendor, sizeof(expected_vendor))'),
    ('bandwidth_enum', 'uint16_t width = 0;', 'uint16_t width = 1;',
     'netlink_exact_frequency_bandwidth: !memcmp(payload, expected_vendor, sizeof(expected_vendor))'),
    ('stats_complete_schema', 'seen != (1U << (sizeof(fields) / sizeof(fields[0]))) - 1 ||', '',
     'stats_complete_strict_readiness: parse_probe_stats("generation=7\\n", &value) < 0'),
    ('stats_duplicate_field', '(seen & (1U << i)) ||', '',
     'stats_complete_strict_readiness: parse_probe_stats(text, &value) < 0'),
    ('stale_entry', 'current->entry_host_ns >= attempt_ns &&', '',
     'stats_complete_strict_readiness: !probe_ready(&changed, &baseline, 1000000000, 2437, 1000000002)'),
    ('second_lease_identity', '!same_lease(&first, &second) ||', '',
     'changed_second_tuple_denies_send: execute(&m, 1) < 0 && !m.send_calls'),
    ('second_read_expiry',
     '!same_lease(&first, &second) ||\n                !probe_ready(&second, &baseline, attempt_ns, options->frequency,\n                             io->now_ns(io->context))',
     '!same_lease(&first, &second)',
     'expiry_on_final_read_denies_send: m->now < m->attempt + 32000000'),
    ('scan_retirement', 'retired->phase == 0 && retired->firmware_ref == 0', 'true',
     'busy_baseline_denies_new_control: execute(&m, 1) < 0 && !m.set_calls && !m.send_calls'),
    ('eagain_abort',
     'if (result) {\n            emit(io, "set_frequency_failed_no_retry", result, &baseline, i); goto out;',
     'if (result && result != -EAGAIN) {\n            emit(io, "set_frequency_failed_no_retry", result, &baseline, i); goto out;',
     'failed_set_frequency_is_not_retried: execute(&m, 2) < 0 && m.set_calls == 1 && !m.send_calls'),
    ('resolver_ack_drain', 'while (!ack || (resolve && !reply))', 'while (resolve ? !reply : !ack)',
     'resolver_consumes_reply_and_ack: transact(true) == 0 && network.next == 2'),
    ('kernel_sender', 'sender.nl_pid != 0 ||', '',
     'netlink_current_kernel_ack_only: transact(false) == -EBADMSG'),
    ('short_send', 'sent != length ? -EIO : 0', '0',
     'short_send_is_not_success: execute(&m, 2) < 0 && m.set_calls == 1 && m.send_calls == 1 && m.retirement_seen'),
    ('dry_run_state_read', 'static int dry_run(const struct probe_options *options)\n{',
     'static int dry_run(const struct probe_options *options)\n{\n    FILE *test_file = fopen(PARAM_DIR "wonder_enabled", "r");\n    if (test_file) fclose(test_file);',
     'dry_run_has_no_radio_or_sysfs_io: result == 0 && forbidden_calls == 0 && length > 0'),
    ('family_attributes_trailing', 'found = true;\n        }\n        data += step; length -= step;',
     'return 0;\n        }\n        data += step; length -= step;',
     'family_attributes_require_complete_stream: parse_family_attrs(attributes, 16, &family) == -EBADMSG'),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=HERE.parent)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    source = repo / 'port/validation/wonder_offchan_probe.c'
    harness = repo / 'port/tests/wonder_offchan_probe.c'
    host_cc = shutil.which('cc') or shutil.which('clang')
    if not host_cc or not ANDROID_CC.is_file():
        raise RuntimeError('An installed host compiler and the existing NDK28.2/API35 compiler are required')
    pinned_inputs = [source, harness, Path(__file__),
        repo / 'port/validation/wonder_offchan_probe.md',
        repo / 'modules/wonder/nl80211_ven_cmd.c',
        repo / 'modules/wonder/wonder_ven_cmd.h',
        repo / 'modules/qcacld-3.0/core/hdd/src/wlan_hdd_wonder.c',
        repo / 'modules/qcacld-3.0/core/hdd/src/wlan_hdd_wonder_coex.c',
        repo / 'modules/qcacld-3.0/core/hdd/inc/wlan_hdd_wonder_dwell.h',
        repo / 'modules/qcacld-3.0/core/hdd/src/wlan_hdd_tx_rx.c',
        repo / 'modules/qcacld-3.0/core/wma/src/wma_data.c']
    report = {'status': 'BUILDING', 'started_utc': datetime.now(timezone.utc).isoformat(),
        'scope': 'Instrumented host wire/control fixtures and dry-run only; Android artifact linked but never executed or deployed',
        'inputs': [identity(path) for path in pinned_inputs],
        'tools': [identity(Path(host_cc)), identity(ANDROID_CC),
                  identity(NDK_BIN / 'clang'), identity(NDK_BIN / 'ld.lld'),
                  identity(NDK_BIN / 'llvm-readelf')],
        'commands': {}, 'artifacts': {}, 'negative_controls': {},
        'limits': [
            'Host mocks verify userspace ordering and wire encoding, not nl80211/WMI acceptance on an Android target.',
            'Android uses installed NDK28.2/API35 compatibility headers and libraries; this is not a full ROM product build.',
            'No radio socket, Android target binary, device command, firmware patch, deployment, APK, or RF transmission is executed.',
            'Socket acceptance remains submission evidence; RF behavior and receiver correlation require later authorized device tests.',
        ]}
    receipt = output / 'raw-probe-validation.json'
    receipt.write_text(json.dumps(report, indent=2) + '\n')
    def run(name, argv, *, env=None, required=True):
        record, stdout, stderr = invoke(output, name, argv, env=env, required=False)
        report['commands'][name] = record
        if required and record['returncode']:
            raise RuntimeError(f'{name} failed; see {output / (name + ".stderr.txt")}')
        return record, stdout, stderr
    try:
        snapshots = output / 'inputs'
        for path in pinned_inputs:
            destination = snapshots / path.relative_to(repo)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            if identity(destination)['sha256'] != identity(path)['sha256']:
                raise RuntimeError('Input snapshot differs from its pinned source')
        report['input_snapshots'] = [identity(path) for path in sorted(snapshots.rglob('*')) if path.is_file()]
        for name, tool in [('host-compiler', Path(host_cc)), ('android-compiler', ANDROID_CC)]:
            run(name, [tool, '--version'])
        common = [host_cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
                  '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                  '-fno-omit-frame-pointer', '-fno-pie', '-no-pie']
        host_fixture = output / 'raw-probe-harness'
        run('host-fixture-build', common + [
            f'-DPROBE_SOURCE_PATH="{source}"', str(harness), '-o', str(host_fixture)])
        sanitizer_env = {**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1:abort_on_error=1',
                         'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'}
        _, stdout, _ = run('host-fixture-run', [host_fixture], env=sanitizer_env)
        report['host_validation'] = {**json.loads(stdout), 'sanitizers': ['ASan', 'UBSan']}
        report['artifacts']['host_fixture'] = identity(host_fixture)
        standalone = output / 'raw-probe-host'
        run('standalone-host-build', common + [str(source), '-o', str(standalone)])
        report['artifacts']['standalone_host'] = identity(standalone)
        report['standalone_dry_runs'] = {}
        base = [standalone, '--receiver', '02:11:22:33:44:55', '--bssid', '02:22:33:44:55:66',
                '--source', '02:33:44:55:66:77']
        for frame, frequency, nonce, count in [('action', 2437, 0x574f4e44, 1),
                                              ('data', 5180, 0xffffffff, 4)]:
            argv = base + ['--frequency', str(frequency), '--nonce', str(nonce), '--count', str(count)]
            if frame == 'data': argv += ['--data']
            _, stdout, _ = run('standalone-' + frame, argv, env=sanitizer_env)
            report['standalone_dry_runs'][frame] = dry_run_contract(stdout, data_frame=frame == 'data',
                frequency=frequency, nonce=nonce, count=count)
        report['standalone_invalid_cli'] = {}
        for name, argv in [('missing', [standalone]),
                           ('frequency', base + ['--frequency', '2437x']),
                           ('receiver', base + ['--frequency', '2437', '--receiver', 'ff:ff:ff:ff:ff:ff']),
                           ('execute_source', base + ['--frequency', '2437', '--execute'])]:
            record, stdout, stderr = run('standalone-invalid-' + name, argv,
                                         env=sanitizer_env, required=False)
            if record['returncode'] != 2 or stdout or b'Usage:' not in stderr:
                raise RuntimeError(f'Malformed standalone CLI {name} was not rejected before execution')
            report['standalone_invalid_cli'][name] = {'expected_returncode': 2, 'status': 'PASS'}
        original = source.read_text()
        for name, anchor, replacement, witness in NEGATIVE_CONTROLS:
            if original.count(anchor) != 1:
                raise RuntimeError(f'Negative control {name} requires one exact source anchor')
            mutant = output / ('negative-' + name + '.c')
            mutant.write_text(original.replace(anchor, replacement, 1))
            binary = output / ('negative-' + name)
            run('negative-' + name + '-build', common + [
                f'-DPROBE_SOURCE_PATH="{mutant}"', str(harness), '-o', str(binary)])
            record, _, stderr = run('negative-' + name + '-run', [binary],
                                     env=sanitizer_env, required=False)
            if record['returncode'] != -signal.SIGABRT or witness.encode() not in stderr:
                raise RuntimeError(f'Negative control {name} did not trigger the expected fixture witness')
            report['negative_controls'][name] = {'status': 'PASS', 'anchor': anchor,
                'replacement': replacement, 'expected_witness': witness,
                'mutation': identity(mutant), 'host_fixture': identity(binary),
                'observed_returncode': record['returncode']}
        android = output / 'wonder_offchan_probe'
        argv = [ANDROID_CC, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O2',
                '-fPIE', '-pie', '-Wl,-z,max-page-size=16384', '-Wl,--no-undefined',
                str(source), '-o', str(android)]
        run('android-build', argv)
        report['artifacts']['android_probe'] = {**identity(android), **android_elf_contract(android)}
        run('android-elf', [NDK_BIN / 'llvm-readelf',
            '-h', '-l', '-d', '--dyn-syms', android])
        report['changed_inputs'] = [record['path'] for record in report['inputs']
                                   if identity(Path(record['path']))['sha256'] != record['sha256']]
        if report['changed_inputs']:
            raise RuntimeError('Source inputs changed during validation')
        report['status'] = 'PASS'
    except Exception as error:
        report['status'], report['error'] = 'FAIL', str(error)
        raise
    finally:
        receipt.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'host_validation': report['host_validation'],
                      'negative_controls': len(report['negative_controls']),
                      'android_probe': report['artifacts']['android_probe'],
                      'receipt_sha256': identity(receipt)['sha256']}, indent=2))


if __name__ == '__main__':
    main()
