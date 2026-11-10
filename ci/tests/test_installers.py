import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import installer_assets as installers


def elf_module(crc=0x12345678, extended=False):
    sections = {'.shstrtab': b'\0.shstrtab\0__versions\0__version_ext_names\0__version_ext_crcs\0'}
    if extended:
        sections.update(__version_ext_names=b'symbol\0', __version_ext_crcs=struct.pack('<I', crc))
    else:
        sections['__versions'] = struct.pack('<Q', crc)+b'symbol\0'+bytes(49)
    data = bytearray(64)
    headers = [bytes(64)]
    for name, payload in sections.items():
        headers.append(struct.pack('<IIQQQQIIQQ', sections['.shstrtab'].index(name.encode()), 1, 0, 0, len(data), len(payload), 0, 0, 1, 0))
        data.extend(payload)
    data.extend(b'hdd_monitor_mode_tx_inject\0')
    shoff = len(data)
    data.extend(b''.join(headers))
    data[:16] = b'\x7fELF\x02\x01\x01'+bytes(9)
    struct.pack_into('<HHI', data, 16, 1, 183, 1)
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<HHHH', data, 52, 64, 0, 0, 64)
    struct.pack_into('<HH', data, 60, len(headers), 1)
    return bytes(data)


class AbiGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.binary = cls.root/'module-abi'
        subprocess.run(['cc', '-nostdlib', '-static', '-no-pie', '-ffreestanding', '-fno-builtin',
            '-fno-stack-protector', '-O2', str(installers.HERE/'module-abi.c'), '-o', str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_guard(self, module, table='12345678 symbol\n'):
        (self.root/'abi').write_text(table)
        (self.root/'test.ko').write_bytes(module)
        return subprocess.run([str(self.binary), str(self.root/'abi'), str(self.root/'test.ko')], capture_output=True).returncode

    def test_classic_and_extended_imports(self):
        for extended in (False, True):
            self.assertEqual(self.run_guard(elf_module(extended=extended)), 0)
            self.assertEqual(self.run_guard(elf_module(0xdeadbeef, extended=extended)), 1)

    def test_missing_symbol_malformed_table_and_truncated_elf(self):
        self.assertEqual(self.run_guard(elf_module(), '12345678 other\n'), 1)
        self.assertEqual(self.run_guard(elf_module(), 'garbage\n'), 1)
        self.assertEqual(self.run_guard(elf_module()[:-8]), 1)
        self.assertEqual(self.run_guard(b'not a module'), 1)

    def test_invalid_section_offset_is_rejected(self):
        module = bytearray(elf_module())
        struct.pack_into('<Q', module, 40, 0xffffffffffffffff)
        self.assertEqual(self.run_guard(module), 1)


class PackageTests(unittest.TestCase):
    def fixture(self, root):
        (root/'gki').mkdir(); (root/'platform').mkdir()
        image = bytearray(64); image[56:60] = b'ARM\x64'
        (root/'gki/Image').write_bytes(image)
        (root/'gki/kernel_aarch64_Module.symvers').write_text('0x12345678 symbol vmlinux EXPORT_SYMBOL\n')
        module = elf_module()
        (root/'platform'/installers.WLAN).write_bytes(module)
        release = '6.18.38-android17-6-maybe-dirty-4k'
        (root/'report.json').write_text(json.dumps({'kernel_release':release, 'module_verification':[
            {'module':installers.WLAN,'sha256':installers.sha(module),'imports_checked':1,'depends':'cfg80211,icnss2'}]}))
        return {'kernel_release':release,'source_revision':'a'*40,'common_revision':'b'*40,
                'kernelsu_revision':'c'*40,'run_id':'42221490452','artifact_root':'20261106T130718948179Z'}

    def test_archives_contain_exact_payloads_and_executable_installers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); identity=self.fixture(root); products=installers.build(root,identity)
            self.assertEqual(products, installers.build(root,identity))
            ak,wlan=installers.names(identity['kernel_release'])
            with zipfile.ZipFile(io.BytesIO(products[ak])) as z:
                self.assertEqual(z.read('Image'),(root/'gki/Image').read_bytes())
                self.assertIn(b'module-abi',z.read('anykernel.sh'))
                self.assertIn(b'flash_boot',z.read('anykernel.sh'))
                self.assertTrue(z.getinfo('tools/module-abi').external_attr>>16 & 0o111)
                for name in ('tools/busybox', 'tools/magiskboot', 'tools/module-abi'):
                    self.assertEqual(z.read(name)[18:20], b'\xb7\x00')
            with zipfile.ZipFile(io.BytesIO(products[wlan])) as z:
                self.assertEqual(z.read('wlan/'+installers.WLAN),elf_module())
                self.assertIn(b'rmmod "$NAME" ||',z.read('service.sh'))
                self.assertIn(b'cfg80211 icnss2',z.read('service.sh'))
                self.assertIn(b'skip_mount', '\n'.join(z.namelist()).encode())
                self.assertNotIn(b'@RELEASE@',z.read('customize.sh'))
                code=int([x for x in z.read('module.prop').decode().splitlines() if x.startswith('versionCode=')][0].split('=')[1])
                self.assertLess(code,2**31)

    def test_missing_injection_marker_or_invalid_image_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); identity=self.fixture(root)
            (root/'platform'/installers.WLAN).write_bytes(b'missing injection')
            with self.assertRaisesRegex(ValueError,'injection'): installers.build(root,identity)
            (root/'gki/Image').write_bytes(b'not an Image')
            with self.assertRaisesRegex(ValueError,'Image'): installers.build(root,identity)

    def test_shell_syntax(self):
        for name in ('anykernel.sh','wlan-service.sh','wlan-customize.sh','wlan-update-binary.sh'):
            subprocess.run(['sh','-n',str(installers.HERE/name)],check=True)


class WlanServiceTests(unittest.TestCase):
    def run_service(self, *, wifi='1', scan='1', refcnt='0', unload='0', insert='0',
                    abi='0', dependency=True, framework_busy=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for directory in ('bin', 'wlan', 'proc', 'sys/module/qca_cld3_wcn7750', 'vendor_dlkm/lib/modules'):
                (root/directory).mkdir(parents=True)
            if dependency:
                (root/'sys/module/cfg80211').mkdir()
            (root/'sys/module/qca_cld3_wcn7750/refcnt').write_text(refcnt)
            (root/'proc/uptime').write_text('100.00 0.00\n')
            (root/'wifi').write_text(wifi)
            (root/'scan').write_text(scan)
            (root/'dumps').write_text('0')
            (root/'vendor_dlkm/lib/modules'/installers.WLAN).write_bytes(b'original')
            (root/'wlan'/installers.WLAN).write_bytes(b'candidate')
            (root/'payload.sha256').write_text(installers.sha(b'candidate')+'  wlan/'+installers.WLAN+'\n')
            script = (installers.HERE/'wlan-service.sh').read_text().replace('@RELEASE@', 'test-release').replace('@DEPS@', 'cfg80211')
            # Relocate only the filesystem paths; execute the actual service logic.
            for prefix in ('/sys/module', '/vendor_dlkm/lib/modules', '/vendor/lib/modules', '/proc/uptime'):
                script = script.replace(prefix, str(root)+prefix)
            script = script.replace('/system/bin/svc', str(root/'bin/android-svc'))
            (root/'service.sh').write_text(script)
            mocks = {
                'uname': 'echo test-release', 'log': ':', 'getprop': 'echo 1', 'pidof': 'exit 1',
                'sleep': 't=$(cut -d. -f1 "$TEST_ROOT/proc/uptime"); echo "$((t + $1)).00 0.00" > "$TEST_ROOT/proc/uptime"',
                'settings': 'case "$3" in wifi_on) cat "$TEST_ROOT/wifi";; wifi_scan_always_enabled) cat "$TEST_ROOT/scan";; *) exit 1;; esac',
                # Standalone BusyBox resolves the unqualified name to its runsv applet.
                'svc': 'echo "unexpected BusyBox svc" >&2; exit 1',
                'android-svc': '''echo "svc $*" >> "$EVENTS"
case "$2" in enable) echo 1 > "$TEST_ROOT/wifi";; disable) echo 0 > "$TEST_ROOT/wifi";; *) exit 1;; esac''',
                'cmd': '''[ "$1 $2" = 'wifi set-scan-always-available' ] || exit 1
case "$3" in enabled) echo 1 > "$TEST_ROOT/scan";; disabled) echo 0 > "$TEST_ROOT/scan";; *) exit 1;; esac''',
                'dumpsys': '''n=$(cat "$TEST_ROOT/dumps"); echo "$((n + 1))" > "$TEST_ROOT/dumps"
echo 'Dump of WifiActiveModeWarden'
if [ "$TEST_FRAMEWORK_BUSY" = 0 ] && [ "$(cat "$TEST_ROOT/wifi")" = 0 ] && [ "$(cat "$TEST_ROOT/scan")" = 0 ]; then
    echo 'Current wifi mode: DisabledState'; echo 'NumActiveModeManagers: 0'
else
    echo 'Current wifi mode: EnabledState'; echo 'NumActiveModeManagers: 1'
fi
echo 'WifiController:'
# Historical lines must not override the current controller state.
echo 'Current wifi mode: DisabledState'; echo 'NumActiveModeManagers: 0' ''',
                'rmmod': '''echo rmmod >> "$EVENTS"
[ "$TEST_UNLOAD" = 0 ] || exit "$TEST_UNLOAD"
[ "$(cat "$TEST_ROOT/wifi")" = 0 ] && [ "$(cat "$TEST_ROOT/scan")" = 0 ] || exit 90
[ "$TEST_FRAMEWORK_BUSY" = 0 ] && [ "$(cat "$TEST_ROOT/dumps")" -ge 2 ] || exit 91
rm -rf "$TEST_ROOT/sys/module/qca_cld3_wcn7750"''',
                'insmod': '''case "$1" in */wlan/*) echo candidate >> "$EVENTS"; [ "$TEST_INSERT" = 0 ] || exit "$TEST_INSERT";; *) echo rollback >> "$EVENTS";; esac
mkdir -p "$TEST_ROOT/sys/module/qca_cld3_wcn7750"
echo 0 > "$TEST_ROOT/sys/module/qca_cld3_wcn7750/refcnt"''',
            }
            for name, body in mocks.items():
                path = root/'bin'/name
                path.write_text('#!/bin/sh\n'+body+'\n'); path.chmod(0o755)
            (root/'module-abi').write_text('#!/bin/sh\necho abi >> "$EVENTS"\nexit "$TEST_ABI"\n')
            (root/'module-abi').chmod(0o755)
            events = root/'events'
            env = dict(os.environ, PATH=str(root/'bin')+':'+os.environ['PATH'], EVENTS=str(events),
                       TEST_ROOT=str(root), TEST_UNLOAD=unload, TEST_INSERT=insert, TEST_ABI=abi,
                       TEST_FRAMEWORK_BUSY=str(int(framework_busy)))
            result = subprocess.run(['sh', str(root/'service.sh')], env=env, capture_output=True, timeout=5)
            self.assertEqual(((root/'wifi').read_text().strip(), (root/'scan').read_text().strip()), (wifi, scan))
            return result.returncode, events.read_text().splitlines() if events.exists() else []

    def test_success_preserves_wifi_and_independent_scan_setting(self):
        for wifi in ('0', '1'):
            for scan in ('0', '1'):
                with self.subTest(wifi=wifi, scan=scan):
                    restore = 'svc wifi enable' if wifi == '1' else 'svc wifi disable'
                    self.assertEqual(self.run_service(wifi=wifi, scan=scan),
                                     (0, ['abi', 'abi', 'svc wifi disable', 'rmmod', 'candidate', restore]))

    def test_unload_failure_does_not_insert_and_restores_wifi(self):
        self.assertEqual(self.run_service(unload='1'), (1, ['abi', 'abi', 'svc wifi disable', 'rmmod', 'svc wifi enable']))

    def test_insert_failure_reloads_original_and_restores_wifi(self):
        self.assertEqual(self.run_service(insert='1'), (1, ['abi', 'abi', 'svc wifi disable', 'rmmod', 'candidate', 'rollback', 'svc wifi enable']))

    def test_busy_driver_is_never_forcibly_unloaded(self):
        self.assertEqual(self.run_service(refcnt='1'), (1, ['abi', 'abi', 'svc wifi disable', 'svc wifi enable']))

    def test_active_framework_is_not_unloaded_even_with_zero_refcount(self):
        self.assertEqual(self.run_service(framework_busy=True), (1, ['abi', 'abi', 'svc wifi disable', 'svc wifi enable']))

    def test_missing_dependencies_or_wrong_rollback_abi_preserve_driver(self):
        self.assertEqual(self.run_service(dependency=False), (1, []))
        self.assertEqual(self.run_service(abi='1'), (1, ['abi']))


class EnrichedBundleTests(unittest.TestCase):
    def test_round_trip_and_rehashed_installer_tampering(self):
        import test_release as release_tests
        import export_artifacts
        import publish_release
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, workspace, artifact, report = release_tests.fixture(root)
            renamed = artifact.with_name('20261106T130718948179Z')
            artifact.rename(renamed); artifact = renamed
            (artifact/'platform/one.ko').unlink()
            module = elf_module()
            (artifact/'platform'/installers.WLAN).write_bytes(module)
            image = bytearray(64); image[56:60] = b'ARM\x64'
            (artifact/'gki/Image').write_bytes(image)
            catalog = [{'output': installers.WLAN}, {'output': 'two.ko'}]
            for path in (source/'port/modules.json', artifact/'inputs/modules.json'):
                release_tests.write_json(path, catalog)
            report['module_verification'][0].update(module=installers.WLAN, sha256=installers.sha(module), depends='cfg80211')
            report['sha256'] = {p.relative_to(artifact).as_posix(): installers.sha(p.read_bytes())
                               for p in artifact.rglob('*') if p.is_file() and p.name != 'report.json'}
            # Include the nested device-tree report, excluding only the top-level report.
            report['sha256']['devicetrees/report.json'] = installers.sha((artifact/'devicetrees/report.json').read_bytes())
            release_tests.write_json(artifact/'report.json', report)
            bundle = root/'bundle'
            export_artifacts.export(workspace, bundle, source, release_tests.SOURCE, '123', '1')
            identity = installers.add_to_bundle(bundle, source)
            self.assertEqual(len(identity['installers']), 3)
            self.assertEqual(installers.add_to_bundle(bundle, source), identity)
            filename = installers.names(identity['kernel_release'])[1]
            (bundle/filename).write_bytes(b'altered installer')
            identity['sha256'][filename] = installers.sha((bundle/filename).read_bytes())
            release_tests.write_json(bundle/'release.json', identity)
            (bundle/'SHA256SUMS').write_text(''.join(
                installers.sha(p.read_bytes())+'  '+p.relative_to(bundle).as_posix()+'\n'
                for p in sorted(bundle.rglob('*')) if p.is_file() and p.name != 'SHA256SUMS'))
            with self.assertRaisesRegex(ValueError, 'Installer differs'):
                publish_release.validate_bundle(bundle, source, release_tests.SOURCE,
                    release_tests.KERNEL, release_tests.KSU, '123', '1')


if __name__ == '__main__': unittest.main()
