#!/usr/bin/env python3
"""Collect read-only native Mosey evidence with Windows adb.exe.

Use --dry-run to inspect the capture plan without contacting a device or writing
files. Actual collection creates a new directory and retains every command's
unmodified stdout/stderr bytes, including failures and partial timeout output.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import time


ARTIFACTS = (
    '/system_ext/bin/mosey_server',
    '/system_ext/bin/onyx_mosey_launcher',
    '/system_ext/lib64/libmosey_daemon_ffi.so',
    '/system_ext/lib64/libmosey_onyx_config.so',
    '/system_ext/etc/init/mosey.rc',
    '/system_ext/etc/init/onyx-mosey.rc',
    '/system_ext/etc/vintf/manifest/manifest_mosey.xml',
)
BASE_COMMANDS = {
    'boot_id': 'cat /proc/sys/kernel/random/boot_id',
    'kernel_release': 'uname -r',
    'android_release': 'getprop ro.build.version.release',
    'android_sdk': 'getprop ro.build.version.sdk',
    'build_fingerprint': 'getprop ro.build.fingerprint',
    'device_serial': 'getprop ro.serialno',
    'selinux_enforcing': 'cat /sys/fs/selinux/enforce',
    'service_state': 'getprop init.svc.mosey_server',
    'service_pid': 'pidof mosey_server',
    'netdevs': 'ls -l /sys/class/net',
    'loaded_modules': 'cat /proc/modules',
    'wonder_coex_stats': 'cat /sys/module/qca_cld3_wcn7750/parameters/wonder_coex_stats',
    'wonder_offchan_probe_enabled': 'cat /sys/module/qca_cld3_wcn7750/parameters/wonder_sta_offchan_probe',
    'wonder_offchan_stats': 'cat /sys/module/qca_cld3_wcn7750/parameters/wonder_offchan_stats',
    'wonder_injection_stats': 'cat /sys/module/qca_cld3_wcn7750/parameters/injection_stats',
    'wonder_auxiliary_devices': 'ls -l /sys/bus/auxiliary/devices',
    'adapter_log': 'logcat -b all -d -v epoch -s MoseyOnyx:D',
}
def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def windows_adb(requested=None):
    candidate = requested or shutil.which('adb.exe') or '/mnt/d/platform-tools/adb.exe'
    path = Path(candidate)
    if path.name.lower() != 'adb.exe' or not path.is_file():
        raise ValueError('A Windows adb.exe executable is required')
    with path.open('rb') as stream:
        if stream.read(2) != b'MZ':
            raise ValueError('The selected adb.exe must be a Windows executable')
    return str(path.resolve())


def process_commands(pid):
    if not isinstance(pid, int) or not 0 < pid < 2**31:
        raise ValueError('Invalid Android process ID')
    proc = f'/proc/{pid}'
    return {
        'stat_before': f'cat {proc}/stat',
        'exe': f'readlink {proc}/exe',
        'selinux_domain': f'cat {proc}/attr/current',
        'status': f'cat {proc}/status',
        # Filter on the device so unrelated environment values are not retained.
        'config_env': (f"mosey_environment=$(tr '\\000' '\\n' < {proc}/environ) || exit $?; "
                       "printf '%s\\n' \"$mosey_environment\" | "
                       "sed -n '/^LD_PRELOAD=/p; /^KONOHA_MOSEY_WONDER=/p'"),
        'maps': f'cat {proc}/maps',
        'auxv': f'cat {proc}/auxv',
        'stat_after': f'cat {proc}/stat',
    }


def parse_pids(data):
    tokens = data.decode('ascii', errors='strict').split()
    if any(not re.fullmatch(r'[0-9]+', token) or not 0 < int(token) < 2**31
           for token in tokens):
        raise ValueError('pidof returned non-numeric or invalid process IDs')
    return sorted({int(token) for token in tokens})


def parse_start_ticks(data):
    # comm is parenthesized and can contain whitespace or closing parentheses.
    text = data.decode('utf-8', errors='replace').strip()
    close = text.rfind(')')
    fields = text[close + 1:].split() if close >= 0 else []
    if len(fields) < 20 or not fields[19].isdigit():
        raise ValueError('Incomplete /proc/PID/stat start time')
    return int(fields[19])  # Field22; fields[0] is field3 (state).


def parse_auxv(data):
    if len(data) % 16:
        raise ValueError('Expected complete little-endian 64-bit auxiliary vector')
    values = {}
    terminated = False
    for offset in range(0, len(data), 16):
        tag, value = struct.unpack_from('<QQ', data, offset)
        if tag == 0:
            terminated = True
            break
        values[tag] = value
    if not terminated:
        raise ValueError('Auxiliary vector lacks AT_NULL terminator')
    return {'format': 'linux-arm64-le', 'entry_count': len(values),
            'at_secure': values.get(23)}


def bytes_value(value):
    if value is None:
        return b''
    if isinstance(value, bytes):
        return value
    return value.encode('utf-8', errors='replace')


def capture_command(directory, name, remote_command, adb, serial, root=False,
                    timeout=15, runner=subprocess.run, journal=None):
    adb = windows_adb(adb)
    if not re.fullmatch(r'[A-Za-z0-9_-]+', name):
        raise ValueError('Invalid capture record name')
    command = f'su -c {shlex.quote(remote_command)}' if root else remote_command
    argv = [adb, '-s', serial, 'exec-out', command]
    started = time.monotonic()
    record = {'command': remote_command, 'argv': argv, 'started_utc': utc_now(),
              'timeout_seconds': timeout, 'root': root, 'outcome': 'running'}
    for stream in ('stdout', 'stderr'):
        record[stream] = {'path': f'{name}.{stream}.bin', 'size': None,
                          'sha256': None, 'capture_complete': False}
    if journal:
        journal(record)
    interrupted = False
    try:
        result = runner(argv, capture_output=True, timeout=timeout)
        stdout, stderr = bytes_value(result.stdout), bytes_value(result.stderr)
        record.update(returncode=result.returncode,
                      outcome='ok' if result.returncode == 0 else 'command_failed')
    except subprocess.TimeoutExpired as error:
        stdout, stderr = bytes_value(error.stdout), bytes_value(error.stderr)
        record.update(returncode=None, outcome='timeout')
    except OSError as error:
        stdout, stderr = b'', b''
        record.update(returncode=None, outcome='launch_failed', error=str(error),
                      errno=error.errno)
    except KeyboardInterrupt:
        stdout, stderr = b'', b''
        interrupted = True
        record.update(returncode=None, outcome='interrupted',
                      output_capture_complete=False,
                      qualification='subprocess.run did not return buffered output before interruption')
    record['elapsed_seconds'] = round(time.monotonic() - started, 6)
    for stream, data in (('stdout', stdout), ('stderr', stderr)):
        path = directory / record[stream]['path']
        with path.open('xb') as output:
            output.write(data)
        record[stream] = {'path': path.name, 'size': len(data), 'sha256': sha256(data),
                          'capture_complete': not interrupted}
        if journal:
            journal(record)
    if interrupted:
        raise KeyboardInterrupt
    return record, stdout


def artifact_hashes(data):
    found = {}
    for line in data.decode('utf-8', errors='replace').splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]{64})\s+\*?(.+)', line)
        if match and match[2] in ARTIFACTS:
            found[match[2]] = match[1].lower()
    return found


def expected_artifacts(path):
    if path is None:
        return {}
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or any(
        name not in ARTIFACTS or not isinstance(digest, str) or
        not re.fullmatch(r'[0-9a-fA-F]{64}', digest)
        for name, digest in value.items()
    ):
        raise ValueError('Expected artifact JSON must map known native paths to SHA256 values')
    return {name: digest.lower() for name, digest in value.items()}


def process_summary(records, outputs):
    result = {'command_outcomes': {name: record['outcome'] for name, record in records.items()}}
    for name in ('stat_before', 'stat_after'):
        if records[name]['outcome'] != 'ok':
            continue
        try:
            result[name + '_start_ticks'] = parse_start_ticks(outputs[name])
        except ValueError as error:
            result[name + '_parse_error'] = str(error)
    before, after = result.get('stat_before_start_ticks'), result.get('stat_after_start_ticks')
    result['same_process_during_capture'] = before == after if before is not None and after is not None else None
    result['executable'] = (outputs['exe'].decode('utf-8', errors='replace').strip()
                            if records['exe']['outcome'] == 'ok' else None)
    result['selinux_domain'] = (outputs['selinux_domain'].decode('utf-8', errors='replace').strip('\x00\n\r ')
                                if records['selinux_domain']['outcome'] == 'ok' else None)
    result['config_environment'] = {} if records['config_env']['outcome'] == 'ok' else None
    if result['config_environment'] is not None:
        for line in outputs['config_env'].decode('utf-8', errors='replace').splitlines():
            name, separator, value = line.partition('=')
            if separator and name in ('LD_PRELOAD', 'KONOHA_MOSEY_WONDER'):
                result['config_environment'][name] = value
    mapped = [line.split()[-1] for line in outputs['maps'].decode('utf-8', errors='replace').splitlines()
              if len(line.split()) >= 6]
    result['observed_config_library_mapping'] = ('/system_ext/lib64/libmosey_onyx_config.so' in mapped
                                                 if records['maps']['outcome'] == 'ok' else None)
    result['observed_ffi_library_mapping'] = ('/system_ext/lib64/libmosey_daemon_ffi.so' in mapped
                                              if records['maps']['outcome'] == 'ok' else None)
    result['process_status'] = None
    if records['status']['outcome'] == 'ok':
        selected = {'Name', 'Uid', 'Gid', 'Groups', 'CapInh', 'CapPrm', 'CapEff',
                    'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp'}
        result['process_status'] = {}
        for line in outputs['status'].decode('utf-8', errors='replace').splitlines():
            name, separator, value = line.partition(':')
            if separator and name in selected:
                result['process_status'][name] = value.strip()
    if records['auxv']['outcome'] == 'ok':
        try:
            result['auxiliary_vector'] = parse_auxv(outputs['auxv'])
        except ValueError as error:
            result['auxiliary_vector_parse_error'] = str(error)
    result['qualification'] = ('Independent snapshots of a process; successful command results and '
                               'matching start ticks are needed to associate observations reliably. '
                               'A library mapping or environment variable does not prove RF operation.')
    return result


def capture_snapshot(output, index, adb, serial, root, timeout, expected,
                     runner=subprocess.run, progress=None, snapshot=None, journal=None):
    directory = output / f'snapshot-{index:04d}'
    directory.mkdir()
    if snapshot is None:
        snapshot = {}
    snapshot.update(directory=directory.name, started_utc=utc_now(),
                    commands={}, processes=[], outcome='collecting')
    if journal:
        journal()

    def save_command(target, name, record):
        target[name] = record
        if journal:
            journal()
    outputs = {}
    commands = {**BASE_COMMANDS,
                'native_artifact_metadata': 'ls -lZ ' + ' '.join(map(shlex.quote, ARTIFACTS)),
                'native_artifact_hashes': 'sha256sum ' + ' '.join(map(shlex.quote, ARTIFACTS))}
    for name, command in commands.items():
        if progress:
            progress(f'{directory.name}: {name}')
        record, data = capture_command(directory, name, command, adb, serial, root, timeout, runner,
            journal=lambda value: save_command(snapshot['commands'], name, value))
        snapshot['commands'][name], outputs[name] = record, data
    observed = artifact_hashes(outputs['native_artifact_hashes'])
    snapshot['artifact_identity'] = {name: {'expected_sha256': digest,
        'observed_sha256': observed.get(name),
        'match': observed[name] == digest if name in observed else None}
        for name, digest in expected.items()}
    snapshot['observed_artifact_sha256'] = observed
    if snapshot['commands']['service_pid']['outcome'] == 'ok':
        try:
            pids = parse_pids(outputs['service_pid'])
        except (ValueError, UnicodeError) as error:
            snapshot['pid_parse_error'] = str(error)
            pids = []
        for pid in pids:
            process = {'pid': pid, 'commands': {}}
            snapshot['processes'].append(process)
            if journal:
                journal()
            data = {}
            for name, command in process_commands(pid).items():
                if progress:
                    progress(f'{directory.name}: pid{pid} {name}')
                record, value = capture_command(directory, f'pid-{pid}-{name}', command,
                    adb, serial, root, timeout, runner,
                    journal=lambda value: save_command(process['commands'], name, value))
                process['commands'][name], data[name] = record, value
            process['observations'] = process_summary(process['commands'], data)
    snapshot['completed_utc'] = utc_now()
    snapshot['outcome'] = 'complete'
    return snapshot


def write_report(output, report):
    temporary = output / 'capture.json.tmp'
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.replace(output / 'capture.json')


def collect(output, adb, serial, root=False, timeout=15, duration=0, interval=10,
            expected=None, runner=subprocess.run, progress=None):
    adb = windows_adb(adb)
    # Fail before any command if the requested evidence directory already exists.
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema_version': 1, 'started_utc': utc_now(), 'serial': serial,
              'adb': {'path': adb, 'sha256': sha256(Path(adb).read_bytes())},
              'collector': {'path': str(Path(__file__).resolve()), 'sha256': sha256(Path(__file__).read_bytes())},
              'scope': 'Read-only native Mosey process and artifact observations; no service, network, radio or transfer change is requested',
              'root': root, 'duration_seconds': duration, 'snapshots': [],
              'limits': ['Collection requires prior user authorization for device reads.',
                         'Permission denied, absent service/files and timeouts remain explicit raw failure records.',
                         'Process maps/configuration and AT_SECURE are observations, not proof of discovery, channel dwell or transfer.',
                         'Only the two Mosey configuration environment variables are captured.'],
              'outcome': 'collecting'}
    write_report(output, report)
    started = time.monotonic()
    index = 0
    try:
        while True:
            snapshot = {}
            report['snapshots'].append(snapshot)
            capture_snapshot(output, index, adb, serial, root, timeout, expected or {},
                runner, progress, snapshot, journal=lambda: write_report(output, report))
            write_report(output, report)
            elapsed = time.monotonic() - started
            if elapsed >= duration:
                break
            # Keep the wait bounded and allow a prompt Ctrl-C between snapshots.
            deadline = time.monotonic() + min(interval, duration - elapsed)
            while time.monotonic() < deadline:
                time.sleep(min(1, max(0, deadline - time.monotonic())))
            index += 1
        report['outcome'] = 'complete'
    except KeyboardInterrupt:
        report['outcome'] = 'interrupted'
        for snapshot in report['snapshots']:
            if snapshot.get('outcome') != 'complete':
                snapshot['outcome'] = 'interrupted'
                snapshot['completed_utc'] = utc_now()
                records = list(snapshot.get('commands', {}).values())
                records += [record for process in snapshot.get('processes', [])
                            for record in process['commands'].values()]
                for record in records:
                    if record['outcome'] == 'running':
                        record['outcome'] = 'interrupted'
                        record['returncode'] = None
                    for stream in ('stdout', 'stderr'):
                        path = output / snapshot['directory'] / record[stream]['path']
                        if path.is_file() and record[stream]['sha256'] is None:
                            data = path.read_bytes()
                            record[stream].update(size=len(data), sha256=sha256(data))
    except Exception as error:
        report['outcome'] = 'failed'
        report['error'] = str(error)
        raise
    finally:
        report['completed_utc'] = utc_now()
        write_report(output, report)
    return report


def plan():
    return {'scope': 'Read-only capture plan; no device contact and no output files',
            'android_tool_requirement': 'Windows adb.exe with MZ header; never bare adb or Linux adb',
            'base_commands': BASE_COMMANDS, 'artifact_paths': ARTIFACTS,
            'process_commands': process_commands(1234),
            'root_option': 'Wraps the same read commands with su -c; no changes',
            'output': 'New directory with capture.json and per-command raw byte streams/SHA256 values'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--serial', help='Exact Android serial; required for collection')
    parser.add_argument('--adb', type=Path)
    parser.add_argument('--output', type=Path, help='New capture directory; must not already exist')
    parser.add_argument('--root', action='store_true', help='Read protected process files through su -c')
    parser.add_argument('--timeout', type=float, default=15, help='Per-command timeout in seconds (0..60)')
    parser.add_argument('--duration', type=float, default=0, help='Repeat snapshots for this many seconds (0..3600)')
    parser.add_argument('--interval', type=float, default=10, help='Delay between snapshots in seconds (0..60)')
    parser.add_argument('--expected-artifacts', type=Path, help='JSON mapping native artifact paths to expected SHA256')
    args = parser.parse_args(argv)
    if args.dry_run:
        print(json.dumps(plan(), indent=2))
        return 0
    if not args.serial or not args.output:
        parser.error('--serial and --output are required for collection')
    if not 0 < args.timeout <= 60 or not 0 <= args.duration <= 3600 or not 0 < args.interval <= 60:
        parser.error('Invalid timeout, duration or interval')
    try:
        adb = windows_adb(args.adb)
        expected = expected_artifacts(args.expected_artifacts)
        report = collect(args.output, adb, args.serial, args.root, args.timeout,
            args.duration, args.interval, expected,
            progress=lambda value: print(value, file=sys.stderr, flush=True))
    except (ValueError, OSError) as error:
        parser.exit(2, f'{error}\n')
    print(args.output / 'capture.json')
    return 130 if report['outcome'] == 'interrupted' else 0


if __name__ == '__main__':
    raise SystemExit(main())
