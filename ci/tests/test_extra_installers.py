import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import installer_assets as installers
import test_installers

FIRMWARE = ('ath9k_htc/htc_7010-1.4.0.fw', 'ath9k_htc/htc_9271-1.4.0.fw', 'rt2870.bin',
            'rtlwifi/rtl8188eufw.bin', 'rtlwifi/rtl8188fufw.bin', 'rtlwifi/rtl8192cufw_A.bin',
            'rtlwifi/rtl8192cufw_B.bin', 'rtlwifi/rtl8192cufw_TMSC.bin', 'rtlwifi/rtl8192eu_nic.bin',
            'rtlwifi/rtl8192fufw.bin', 'rtlwifi/rtl8710bufw_SMIC.bin', 'rtlwifi/rtl8710bufw_UMC.bin',
            'rtlwifi/rtl8723aufw_A.bin', 'rtlwifi/rtl8723aufw_B.bin', 'rtlwifi/rtl8723aufw_B_NoBT.bin',
            'rtlwifi/rtl8723bu_nic.bin')


def native_module(release, depends=''):
    names = b'\0.shstrtab\0.modinfo\0__versions\0'
    sections = {'.shstrtab': names, '.modinfo': f'vermagic={release} SMP modversions aarch64\0depends={depends}\0'.encode(),
                '__versions': struct.pack('<Q', 0x12345678) + b'symbol\0' + bytes(49)}
    data, headers = bytearray(64), [bytes(64)]
    for name, contents in sections.items():
        headers.append(struct.pack('<IIQQQQIIQQ', names.index(name.encode()), 1, 0, 0, len(data), len(contents), 0, 0, 1, 0))
        data.extend(contents)
    offset = len(data)
    data.extend(b''.join(headers))
    data[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHI', data, 16, 1, 183, 1)
    struct.pack_into('<Q', data, 40, offset)
    struct.pack_into('<HHHH', data, 52, 64, 0, 0, 64)
    struct.pack_into('<HH', data, 60, len(headers), 1)
    return bytes(data)


def enrich_fixture(artifact, report, source=None):
    """Supply real ELF metadata and complete firmware to ordinary bundle fixtures."""
    deps = {'cfg80211': 'rfkill', 'mac80211': 'cfg80211,libarc4', 'rtl8xxxu': 'cfg80211,mac80211',
            'rt2x00lib': 'cfg80211,mac80211', 'rt2x00usb': 'rt2x00lib,mac80211',
            'rt2800lib': 'rt2x00lib,mac80211,crc_ccitt', 'rt2800usb': 'rt2800lib,rt2x00usb,mac80211',
            'ath': 'cfg80211', 'ath9k_hw': 'ath', 'ath9k_common': 'ath,ath9k_hw,cfg80211',
            'ath9k_htc': 'ath,ath9k_hw,ath9k_common,cfg80211,mac80211'}
    for name, dependencies in deps.items():
        data = native_module(report['kernel_release'], dependencies)
        filename = name + '.ko'
        (artifact / 'platform' / filename).write_bytes(data)
        report['module_verification'].append({'module': filename, 'sha256': installers.sha(data),
            'vermagic': report['kernel_release'] + ' SMP modversions aarch64', 'depends': dependencies, 'imports_checked': 1})
    with tarfile.open(artifact / 'gki/modules_staging_dir.tar.gz', 'w:gz') as archive:
        for name in ('rfkill', 'libarc4', 'crc_ccitt'):
            data = native_module(report['kernel_release'])
            member = tarfile.TarInfo('lib/modules/' + report['kernel_release'] + '/kernel/' + name + '.ko')
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    (artifact / 'gki/modules.builtin').write_text('')
    firmware = artifact / 'firmware'
    (firmware / 'licenses').mkdir(parents=True)
    (firmware / 'licenses/NOTICE').write_text('Firmware redistribution notice\n')
    (firmware / 'sources').mkdir()
    matching_source = b'corresponding source'
    (firmware / 'sources/matching.tar.gz').write_bytes(matching_source)
    manifest = {'blobs': []}
    for index, name in enumerate(FIRMWARE):
        data = bytes([index]) * (index + 1)
        path = firmware / 'firmware' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        manifest['blobs'].append({'path': name, 'sha256': installers.sha(data), 'bytes': len(data), 'license': 'licenses/NOTICE'})
    (firmware / 'manifest.json').write_text(json.dumps(manifest))
    (artifact / 'inputs').mkdir(exist_ok=True)
    (artifact / 'inputs/nethunter-native-modules.json').write_text(json.dumps({
        'wireless_firmware': FIRMWARE,
        'firmware_source_archives': [{'path': 'sources/matching.tar.gz', 'sha256': installers.sha(matching_source)}]}))
    if source is not None:
        catalog = [{'output': p.name} for p in sorted((artifact / 'platform').glob('*.ko'))]
        for path in (source / 'port/modules.json', artifact / 'inputs/modules.json'):
            path.write_text(json.dumps(catalog))
    report['sha256'] = {p.relative_to(artifact).as_posix(): installers.sha(p.read_bytes())
                        for p in artifact.rglob('*') if p.is_file() and p != artifact / 'report.json'}
    (artifact / 'report.json').write_text(json.dumps(report))


class ExtraPackageTests(unittest.TestCase):
    def fixture(self, root):
        identity = test_installers.PackageTests().fixture(root)
        report = json.loads((root / 'report.json').read_text())
        enrich_fixture(root, report)
        identity['asset_format'] = 2
        return identity

    def test_complete_dependency_order_firmware_and_notices_are_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = self.fixture(root)
            products = installers.build(root, identity)
            self.assertEqual(products, installers.build(root, identity))
            self.assertEqual(len(products), 4)
            with zipfile.ZipFile(io.BytesIO(products[installers.names(identity['kernel_release'], 2)[2]])) as archive:
                order = archive.read('modules.load').decode().splitlines()
                self.assertEqual(len(order), 14)
                self.assertLess(order.index('rfkill'), order.index('cfg80211'))
                self.assertLess(order.index('libarc4'), order.index('mac80211'))
                self.assertLess(order.index('crc_ccitt'), order.index('rt2800lib'))
                self.assertLess(order.index('mac80211'), order.index('rtl8xxxu'))
                self.assertEqual(set(archive.read('firmware.paths').decode().splitlines()), set(FIRMWARE))
                self.assertEqual(archive.read('firmware-notices/sources/matching.tar.gz'), b'corresponding source')
                self.assertIn('firmware-notices/licenses/NOTICE', archive.namelist())
                for script in ('service.sh', 'uninstall.sh', 'firmware-overlay.sh', 'module-abi'):
                    self.assertTrue(archive.getinfo(script).external_attr >> 16 & 0o111)
                self.assertNotIn(b'rmmod', archive.read('service.sh'))
                self.assertNotIn(identity['kernel_release'].encode(), archive.read('module.prop'))
                self.assertNotIn(b'@RELEASE@', archive.read('service.sh'))

    def test_missing_dependency_wrong_native_kernel_and_firmware_tampering_rejected(self):
        for failure in ('dependency', 'native-release', 'firmware', 'source'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                identity = self.fixture(root)
                report = json.loads((root / 'report.json').read_text())
                if failure == 'dependency':
                    for entry in report['module_verification']:
                        if entry['module'] == 'rtl8xxxu.ko':
                            entry['depends'] += ',missing_provider'
                    (root / 'report.json').write_text(json.dumps(report))
                    expected = 'Missing USB WLAN module dependency'
                elif failure == 'native-release':
                    with tarfile.open(root / 'gki/modules_staging_dir.tar.gz', 'w:gz') as archive:
                        for name in ('rfkill', 'libarc4', 'crc_ccitt'):
                            data = native_module('6.6.143')
                            member = tarfile.TarInfo(name + '.ko'); member.size = len(data)
                            archive.addfile(member, io.BytesIO(data))
                    report['sha256']['gki/modules_staging_dir.tar.gz'] = installers.sha((root / 'gki/modules_staging_dir.tar.gz').read_bytes())
                    (root / 'report.json').write_text(json.dumps(report))
                    expected = 'different kernel release'
                else:
                    path = root / ('firmware/firmware/rt2870.bin' if failure == 'firmware' else 'firmware/sources/matching.tar.gz')
                    path.write_bytes(b'changed')
                    expected = 'Unverified installer input'
                with self.assertRaisesRegex(ValueError, expected):
                    installers.build(root, identity)

    def test_new_shell_scripts_parse(self):
        for name in ('extra-service.sh', 'extra-customize.sh', 'extra-firmware.sh', 'extra-uninstall.sh'):
            subprocess.run(['sh', '-n', str(installers.HERE / name)], check=True)


def executable(path, body):
    path.write_text('#!/bin/sh\n' + body + '\n')
    path.chmod(0o755)


class ExtraServiceTests(unittest.TestCase):
    def run_service(self, *, loaded=(), kernel='test-release', insert='0', abi='0', firmware='0', tamper=False, missing=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in ('bin', 'drivers', 'dev', 'sys/module'):
                (root / directory).mkdir(parents=True)
            names = ('cfg80211', 'mac80211', 'rtl8xxxu')
            for name in names:
                (root / 'drivers' / (name + '.ko')).write_bytes(name.encode())
            for name in loaded:
                (root / 'sys/module' / name).mkdir()
            (root / 'modules.load').write_text('\n'.join(names) + '\n')
            (root / 'modules.dep').write_text('rtl8xxxu:missing_provider\n' if missing else 'cfg80211:\nmac80211:cfg80211\nrtl8xxxu:cfg80211 mac80211\n')
            executable(root / 'module-abi', 'echo abi >> "$EVENTS"; exit "$TEST_ABI"')
            (root / 'firmware-overlay.sh').write_text('fw_prepare() { echo firmware >> "$EVENTS"; return "$TEST_FIRMWARE"; }\n')
            (root / 'kernel-abi.tsv').write_text('12345678 symbol\n')
            hashed = ['modules.load', 'modules.dep', 'module-abi', 'firmware-overlay.sh', 'kernel-abi.tsv'] + ['drivers/' + n + '.ko' for n in names]
            (root / 'payload.sha256').write_text(''.join(installers.sha((root / n).read_bytes()) + '  ' + n + '\n' for n in hashed))
            if tamper:
                (root / 'drivers/rtl8xxxu.ko').write_bytes(b'changed')
            script = (installers.HERE / 'extra-service.sh').read_text().replace('@RELEASE@', 'test-release')
            script = script.replace('/sys/module', str(root / 'sys/module')).replace('/dev/onyx-', str(root / 'dev/onyx-'))
            (root / 'service.sh').write_text(script)
            executable(root / 'bin/uname', 'echo "$TEST_KERNEL"')
            executable(root / 'bin/log', ':')
            executable(root / 'bin/rmmod', 'echo forbidden-unload >> "$EVENTS"; exit 99')
            executable(root / 'bin/insmod', '''name=$(basename "$1" .ko)
echo "insmod $name" >> "$EVENTS"
[ "$TEST_INSERT" = 0 ] || exit "$TEST_INSERT"
mkdir -p "$TEST_ROOT/sys/module/$name"''')
            events = root / 'events'
            env = dict(os.environ, PATH=str(root / 'bin') + ':' + os.environ['PATH'], TEST_ROOT=str(root),
                       EVENTS=str(events), TEST_KERNEL=kernel, TEST_INSERT=insert, TEST_ABI=abi, TEST_FIRMWARE=firmware)
            result = subprocess.run(['sh', str(root / 'service.sh')], env=env, capture_output=True, timeout=5)
            self.assertFalse((root / 'dev/onyx-nethunter-external-wifi-loader.lock').exists())
            return result.returncode, events.read_text().splitlines() if events.exists() else []

    def test_only_missing_modules_load_in_dependency_order(self):
        self.assertEqual(self.run_service(loaded=('cfg80211',)),
                         (0, ['abi', 'abi', 'abi', 'firmware', 'insmod mac80211', 'insmod rtl8xxxu']))

    def test_already_loaded_drivers_are_never_replaced(self):
        self.assertEqual(self.run_service(loaded=('cfg80211', 'mac80211', 'rtl8xxxu')),
                         (0, ['abi', 'abi', 'abi', 'firmware']))

    def test_wrong_kernel_tampered_payload_or_abi_fail_before_mount_or_load(self):
        self.assertEqual(self.run_service(kernel='wrong'), (1, []))
        self.assertEqual(self.run_service(tamper=True), (1, []))
        self.assertEqual(self.run_service(abi='1'), (1, ['abi']))

    def test_firmware_missing_dependency_and_insert_failures_stop_loading(self):
        self.assertEqual(self.run_service(firmware='1'), (1, ['abi', 'abi', 'abi', 'firmware']))
        self.assertEqual(self.run_service(missing=True), (1, ['abi', 'abi', 'abi', 'firmware']))
        self.assertEqual(self.run_service(insert='1'), (1, ['abi', 'abi', 'abi', 'firmware', 'insmod cfg80211']))


class FirmwareOverlayTests(unittest.TestCase):
    def exercise(self, *, conflict=False, symlink=False, label_fail=False, mount_fail=False,
                 remount_fail=False, marker_fail=False, rerun=False, unrelated=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mod = root / 'module'
            rom = root / 'odm/firmware/o10u'
            for directory in (mod / 'firmware/rtlwifi', mod / 'firmware/ath9k_htc', rom / 'nested/deep', root / 'bin', root / 'sys/module/firmware_class/parameters'):
                directory.mkdir(parents=True)
            (rom / 'nested/deep/vendor.bin').write_bytes(b'unchanged original')
            (rom / 'nested/deep/vendor.bin').chmod(0o600)
            (rom / '.hidden').write_bytes(b'hidden')
            (rom / 'link').symlink_to('nested/deep/vendor.bin')
            (rom / 'broken').symlink_to('does-not-exist')
            names = ('rtlwifi/test.bin', 'ath9k_htc/test.fw', 'rt2870.bin')
            for name in names:
                (mod / 'firmware' / name).write_bytes(name.encode())
            (mod / 'firmware.paths').write_text('\n'.join(names) + '\n')
            if conflict:
                (rom / 'rt2870.bin').write_bytes(b'ROM version must stay unchanged')
            if symlink:
                (root / 'outside').mkdir()
                (rom / 'rtlwifi').symlink_to(root / 'outside', target_is_directory=True)
            if marker_fail:
                (mod / 'firmware-mount-target').mkdir()
            (root / 'sys/module/firmware_class/parameters/path').write_text(str(rom))
            helper = (installers.HERE / 'extra-firmware.sh').read_text()
            helper = helper.replace('/sys/module/firmware_class', str(root / 'sys/module/firmware_class'))
            for prefix in ('/odm/firmware', '/vendor/firmware', '/lib/firmware'):
                helper = helper.replace(prefix, str(root) + prefix)
            (mod / 'firmware-overlay.sh').write_text(helper)
            executable(root / 'bin/ls', 'echo "u:object_r:vendor_file:s0 $2"')
            executable(root / 'bin/chcon', 'echo "context $*" >> "$EVENTS"; exit "$TEST_LABEL_FAIL"')
            executable(root / 'bin/chown', ':')
            executable(root / 'bin/stat', 'exec /usr/bin/stat -L "$@"')
            executable(root / 'bin/mount', '''echo "mount $*" >> "$EVENTS"
if [ "$2" = bind ]; then
  [ "$TEST_MOUNT_FAIL" = 0 ] || exit 1
  mv "$4" "$TEST_ROOT/rom.original"
  ln -s "$3" "$4"
else
  [ "$TEST_REMOUNT_FAIL" = 0 ] || exit 1
fi''')
            executable(root / 'bin/umount', '''echo umount >> "$EVENTS"
rm "$1"
mv "$TEST_ROOT/rom.original" "$1"''')
            script = '''MODDIR=$TEST_ROOT/module
logmsg() { :; }
. "$MODDIR/firmware-overlay.sh"
fw_prepare || exit 1
if [ "$TEST_RERUN" = 1 ]; then
  rm "$MODDIR/firmware-mount-target"
  fw_prepare || exit 1
fi
if [ "$TEST_UNRELATED" = 1 ]; then
  rm "$FW_TARGET"
  mkdir "$FW_TARGET"
fi
fw_release
'''
            (root / 'run.sh').write_text(script)
            events = root / 'events'
            env = dict(os.environ, PATH=str(root / 'bin') + ':' + os.environ['PATH'], TEST_ROOT=str(root), EVENTS=str(events),
                       TEST_LABEL_FAIL=str(int(label_fail)), TEST_MOUNT_FAIL=str(int(mount_fail)), TEST_REMOUNT_FAIL=str(int(remount_fail)),
                       TEST_RERUN=str(int(rerun)), TEST_UNRELATED=str(int(unrelated)))
            result = subprocess.run(['sh', str(root / 'run.sh')], env=env, capture_output=True, timeout=10)
            logs = events.read_text().splitlines() if events.exists() else []
            preserved = root / 'rom.original' if (root / 'rom.original').exists() else rom
            self.assertEqual((preserved / 'nested/deep/vendor.bin').read_bytes(), b'unchanged original')
            self.assertEqual(stat.S_IMODE((preserved / 'nested/deep/vendor.bin').stat().st_mode), 0o600)
            self.assertEqual((preserved / '.hidden').read_bytes(), b'hidden')
            self.assertEqual(os.readlink(preserved / 'link'), 'nested/deep/vendor.bin')
            self.assertEqual(os.readlink(preserved / 'broken'), 'does-not-exist')
            if symlink:
                self.assertFalse((root / 'outside/test.bin').exists())
            if result.returncode == 0:
                overlay = mod / 'firmware-overlay'
                self.assertEqual((overlay / 'nested/deep/vendor.bin').read_bytes(), b'unchanged original')
                for name in names:
                    self.assertEqual((overlay / name).read_bytes(), name.encode())
                    self.assertEqual(stat.S_IMODE((overlay / name).stat().st_mode), 0o644)
                for directory in ('rtlwifi', 'ath9k_htc'):
                    self.assertEqual(stat.S_IMODE((overlay / directory).stat().st_mode), 0o755)
            return result.returncode, logs

    def test_nested_hidden_files_symlinks_and_modes_survive_overlay_and_uninstall(self):
        code, logs = self.exercise()
        self.assertEqual(code, 0)
        self.assertEqual(sum(line.startswith('mount -o bind') for line in logs), 1)
        self.assertEqual(logs.count('umount'), 1)

    def test_rerun_repairs_tracking_without_stacking_mounts(self):
        code, logs = self.exercise(rerun=True)
        self.assertEqual(code, 0)
        self.assertEqual(sum(line.startswith('mount -o bind') for line in logs), 1)
        self.assertEqual(logs.count('umount'), 1)

    def test_uninstaller_never_unmounts_an_unrelated_source(self):
        code, logs = self.exercise(unrelated=True)
        self.assertEqual(code, 0)
        self.assertNotIn('umount', logs)

    def test_conflicts_symlink_escape_context_failure_and_tracking_failure_prevent_mount(self):
        for kwargs in ({'conflict': True}, {'symlink': True}, {'label_fail': True}, {'marker_fail': True}):
            with self.subTest(kwargs=kwargs):
                code, logs = self.exercise(**kwargs)
                self.assertEqual(code, 1)
                self.assertFalse(any(line.startswith('mount ') for line in logs))

    def test_bind_and_readonly_remount_failures_leave_original_tree_available(self):
        code, logs = self.exercise(mount_fail=True)
        self.assertEqual(code, 1)
        self.assertNotIn('umount', logs)
        code, logs = self.exercise(remount_fail=True)
        self.assertEqual(code, 1)
        self.assertIn('umount', logs)


if __name__ == '__main__':
    unittest.main()
