#!/usr/bin/env python3
"""Collect read-only Wonder bring-up evidence using Windows adb.exe."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess


def windows_adb(requested=None):
    candidate = requested or shutil.which('adb.exe') or '/mnt/d/platform-tools/adb.exe'
    path = Path(candidate)
    if path.name.lower() != 'adb.exe' or not path.is_file():
        raise ValueError('A Windows adb.exe executable is required')
    with path.open('rb') as stream:
        if stream.read(2) != b'MZ':
            raise ValueError('The selected adb.exe must be a Windows executable')
    return str(path.resolve())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--adb', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    adb = windows_adb(args.adb)
    commands = {
        'kernel_release': 'uname -r',
        'android_release': 'getprop ro.build.version.release',
        'native_service': 'ls -l /system_ext/bin/mosey_server /system_ext/lib64/libmosey_daemon_ffi.so',
        'native_service_state': 'getprop init.svc.mosey_server',
        'netdevs': 'ls /sys/class/net',
        'auxiliary_devices': 'ls /sys/bus/auxiliary/devices',
        'provider_enabled': 'cat /sys/module/qca_cld3_wcn7750/parameters/wonder_enabled',
        'injection_stats': 'cat /sys/module/qca_cld3_wcn7750/parameters/injection_stats',
    }
    results = {}
    for name, command in commands.items():
        completed = subprocess.run([adb, '-s', args.serial, 'shell', command],
                                   capture_output=True, text=True, timeout=30)
        results[name] = {'command': command, 'returncode': completed.returncode,
                         'stdout': completed.stdout.strip(), 'stderr': completed.stderr.strip()}
    report = {'collected_utc': datetime.now(timezone.utc).isoformat(),
              'adb': adb, 'serial': args.serial,
              'scope': 'Read-only observations; no radio or transfer test was performed',
              'observations': results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(args.output)


if __name__ == '__main__':
    main()
