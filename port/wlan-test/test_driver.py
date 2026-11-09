#!/usr/bin/env python3
"""Exercise the temporary swap script with isolated files and mocked commands."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent


def main():
    results = []
    for case in ('check', 'wrong-kernel', 'unknown-driver', 'busy',
                 'remove-failed', 'insert-failed', 'probe-failed',
                 'swap-and-restore', 'reclaim-swap', 'wifi-disabled'):
        with tempfile.TemporaryDirectory(prefix='onyx-wlan-swap-') as directory:
            root = Path(directory)
            kit, bin_dir = root / 'kit', root / 'bin'
            kit.mkdir(); bin_dir.mkdir()
            for name, data in [('original', b'original'), ('candidate', b'candidate')]:
                (kit / name).mkdir()
                (kit / name / 'qca_cld3_wcn7750.ko').write_bytes(data)
                (kit / name / 'build-id').write_bytes(data + b'-id')
            vendor = root / 'vendor_dlkm/lib/modules'
            vendor.mkdir(parents=True)
            shutil.copyfile(kit / 'original/qca_cld3_wcn7750.ko', vendor / 'qca_cld3_wcn7750.ko')
            (vendor / 'cfg80211.ko').write_bytes(b'cfg')
            module = root / 'sys/module/qca_cld3_wcn7750'
            (module / 'notes').mkdir(parents=True)
            (module / 'notes/.note.gnu.build-id').write_bytes(
                b'unknown' if case == 'unknown-driver' else b'original-id')
            (module / 'refcnt').write_text('1' if case == 'busy' else '0')
            (root / 'sys/class/net/wlan0').mkdir(parents=True)
            memory = root / 'proc/sys/vm'
            memory.mkdir(parents=True)
            for name in ('compact_memory', 'drop_caches'):
                (memory / name).write_text('')
            script = (HERE / 'driver.sh').read_text()
            for prefix in ('/sys/module/', '/sys/class/', '/vendor_dlkm/', '/proc/sys/vm/'):
                script = script.replace(prefix, str(root) + prefix)
            (kit / 'driver.sh').write_text(script)
            digest = lambda data: hashlib.sha256(data).hexdigest()
            (kit / 'identity.conf').write_text(
                'KERNEL_RELEASE=test-kernel\n'
                f'ORIGINAL_SHA256={digest(b"original")}\n'
                f'CFG80211_SHA256={digest(b"cfg")}\n')
            files = [p for p in kit.rglob('*') if p.is_file()]
            (kit / 'SHA256SUMS').write_text(''.join(
                digest(p.read_bytes()) + '  ' + str(p.relative_to(kit)) + '\n'
                for p in sorted(files)))
            mock = bin_dir / 'mock'
            mock.write_text('''#!/usr/bin/python3
import os, sys, pathlib, shutil
root = pathlib.Path(os.environ['WLAN_TEST_ROOT'])
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
case = os.environ['WLAN_TEST_CASE']
module = root / 'sys/module/qca_cld3_wcn7750'
with (root / 'calls').open('a') as log:
    log.write(name + ' ' + ' '.join(args) + '\\n')
if name == 'id': print(0)
elif name == 'uname': print('wrong' if case == 'wrong-kernel' else 'test-kernel')
elif name == 'getprop': print('onyx')
elif name == 'settings': print(0 if case == 'wifi-disabled' else 1)
elif name == 'pidof': sys.exit(1)
elif name == 'rmmod':
    if case == 'remove-failed': sys.exit(1)
    shutil.rmtree(module)
    shutil.rmtree(root / 'sys/class/net/wlan0', ignore_errors=True)
elif name == 'insmod':
    path = pathlib.Path(args[0])
    assert path.is_relative_to(root / 'kit')
    if case == 'insert-failed' and path.parent.name == 'candidate': sys.exit(1)
    (module / 'notes').mkdir(parents=True)
    shutil.copyfile(path.parent / 'build-id', module / 'notes/.note.gnu.build-id')
    (module / 'refcnt').write_text('0')
    if not (case == 'probe-failed' and path.parent.name == 'candidate') and case != 'wifi-disabled':
        (root / 'sys/class/net/wlan0').mkdir(parents=True)
elif name not in ('svc', 'sleep', 'ip'): raise AssertionError(name)
''')
            mock.chmod(0o755)
            for name in ('id', 'uname', 'getprop', 'settings', 'pidof',
                         'rmmod', 'insmod', 'svc', 'sleep', 'ip'):
                (bin_dir / name).symlink_to('mock')
            env = dict(os.environ, PATH=str(bin_dir) + ':/usr/bin:/bin',
                       WLAN_TEST_ROOT=str(root), WLAN_TEST_CASE=case,
                       WLAN_TEST_RECLAIM='1' if case == 'reclaim-swap' else '0')
            mode = 'check' if case in ('check', 'wrong-kernel', 'unknown-driver') else 'load'
            result = subprocess.run(['sh', str(kit / 'driver.sh'), mode],
                                    capture_output=True, text=True, env=env, timeout=15)
            expected_success = case in ('check', 'swap-and-restore', 'reclaim-swap', 'wifi-disabled')
            assert (result.returncode == 0) == expected_success, (case, result.stderr, result.stdout)
            calls = (root / 'calls').read_text()
            note = module / 'notes/.note.gnu.build-id'
            if case in ('swap-and-restore', 'reclaim-swap', 'wifi-disabled'):
                assert note.read_bytes() == b'candidate-id'
                restored = subprocess.run(['sh', str(kit / 'driver.sh'), 'restore'],
                                          capture_output=True, text=True, env=env, timeout=15)
                assert restored.returncode == 0, restored.stderr
                assert note.read_bytes() == b'original-id'
            elif case != 'unknown-driver':
                assert note.read_bytes() == b'original-id'
            if case in ('check', 'wrong-kernel', 'unknown-driver'):
                assert '\nrmmod ' not in '\n' + calls and '\ninsmod ' not in '\n' + calls
                assert '\nsvc ' not in '\n' + calls
            if case in ('insert-failed', 'probe-failed'):
                assert calls.count('insmod ') == 2 and 'svc wifi enable' in calls
                assert (root / 'sys/class/net/wlan0').is_dir()
            if case == 'probe-failed':
                assert calls.count('rmmod ') == 2
                assert 'probe did not finish' in result.stderr
            if case == 'wifi-disabled':
                assert 'svc wifi enable' not in calls
            if case == 'reclaim-swap':
                assert (memory / 'drop_caches').read_text() == '1\n'
            else:
                assert (memory / 'drop_caches').read_text() == ''
            if case in ('remove-failed', 'busy'):
                assert 'insmod ' not in calls and 'svc wifi enable' in calls
            results.append(case)
    print(json.dumps({'status': 'PASS', 'cases': results,
                      'limits': 'Module loading and Android services are mocked; all filesystem changes are temporary.'}, indent=2))


if __name__ == '__main__':
    main()
