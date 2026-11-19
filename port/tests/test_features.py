"""Adversarial feature replay and built-in SUSFS artifact verification."""
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

PORT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PORT))
import features


PATCH = b'''diff --git a/kernel/a.c b/kernel/a.c
--- a/kernel/a.c
+++ b/kernel/a.c
@@ -1 +1 @@
-old a
+new a
diff --git a/kernel/b.c b/kernel/b.c
--- a/kernel/b.c
+++ b/kernel/b.c
@@ -1 +1 @@
-old b
+new b
'''


class FeatureReplayTests(unittest.TestCase):
    def fixture(self, root):
        common = root / 'common'
        (common / 'kernel').mkdir(parents=True)
        for name, mode in [('a.c', 0o755), ('b.c', 0o640)]:
            path = common / 'kernel' / name
            path.write_text('old ' + name[0] + '\n')
            path.chmod(mode)
        return common

    def snapshot(self, common):
        return {path.relative_to(common).as_posix(): (path.read_bytes(), path.stat().st_mode & 0o7777)
                for path in common.rglob('*') if path.is_file()}

    def replay(self):
        return patch.object(features, 'patches', return_value=[
            (Path('fixture.patch'), PATCH, ['kernel/a.c', 'kernel/b.c'])])

    def imports(self):
        return patch.object(features, 'nomount_files', return_value={'drivers/nomount/test.c': b'nomount\n'})

    def test_body_failure_restores_every_owned_byte_mode_and_added_file(self):
        with tempfile.TemporaryDirectory() as temporary, self.replay(), self.imports():
            root = Path(temporary)
            common = self.fixture(root)
            before = self.snapshot(common)
            with self.assertRaisesRegex(RuntimeError, 'build failed'):
                with features.applied(common, root / 'receipt'):
                    self.assertEqual((common / 'kernel/a.c').read_bytes(), b'new a\n')
                    self.assertEqual((common / 'kernel/a.c').stat().st_mode & 0o7777, 0o755)
                    self.assertTrue((common / 'drivers/nomount/test.c').is_file())
                    raise RuntimeError('build failed')
            self.assertEqual(self.snapshot(common), before)
            self.assertFalse((common / 'drivers').exists())

    def test_mid_application_failure_restores_prior_successful_writes(self):
        with tempfile.TemporaryDirectory() as temporary, self.replay(), self.imports():
            root = Path(temporary)
            common = self.fixture(root)
            before = self.snapshot(common)
            real = features._replace_bytes
            def fail_second(path, data, mode):
                if path == common / 'kernel/b.c' and data == b'new b\n':
                    raise OSError('disk write failed')
                return real(path, data, mode)
            with patch.object(features, '_replace_bytes', side_effect=fail_second), \
                    self.assertRaisesRegex(OSError, 'disk write failed'):
                with features.applied(common, root / 'receipt'):
                    self.fail('A partial replay cannot start a build')
            self.assertEqual(self.snapshot(common), before)

    def test_receipt_write_failure_still_restores_entire_replay(self):
        with tempfile.TemporaryDirectory() as temporary, self.replay(), self.imports():
            root = Path(temporary)
            common = self.fixture(root)
            before = self.snapshot(common)
            original = Path.write_text
            def fail_receipt(path, *args, **kwargs):
                if path == root / 'receipt/receipt.json':
                    raise OSError('receipt write failed')
                return original(path, *args, **kwargs)
            with patch.object(Path, 'write_text', fail_receipt), \
                    self.assertRaisesRegex(OSError, 'receipt write failed'):
                with features.applied(common, root / 'receipt'):
                    self.fail('A replay without evidence cannot start a build')
            self.assertEqual(self.snapshot(common), before)

    def test_concurrent_edit_is_preserved_while_other_owned_files_are_restored(self):
        with tempfile.TemporaryDirectory() as temporary, self.replay(), self.imports():
            root = Path(temporary)
            common = self.fixture(root)
            before = self.snapshot(common)
            with self.assertRaisesRegex(ValueError, 'kernel/a.c'):
                with features.applied(common, root / 'receipt'):
                    (common / 'kernel/a.c').write_bytes(b'user edit\n')
            self.assertEqual((common / 'kernel/a.c').read_bytes(), b'user edit\n')
            self.assertEqual(self.snapshot(common)['kernel/b.c'], before['kernel/b.c'])
            self.assertFalse((common / 'drivers/nomount/test.c').exists())

    def test_concurrent_mode_or_type_change_is_preserved(self):
        for changed in ('mode', 'symlink', 'deleted'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary, self.replay(), self.imports():
                root = Path(temporary)
                common = self.fixture(root)
                target = common / 'kernel/a.c'
                external = root / 'external'
                external.write_bytes(b'external data')
                with self.assertRaisesRegex(ValueError, 'kernel/a.c'):
                    with features.applied(common, root / 'receipt'):
                        if changed == 'mode':
                            target.chmod(0o600)
                        else:
                            target.unlink()
                            if changed == 'symlink':
                                target.symlink_to(external)
                if changed == 'mode':
                    self.assertEqual(target.stat().st_mode & 0o7777, 0o600)
                elif changed == 'symlink':
                    self.assertTrue(target.is_symlink())
                    self.assertEqual(external.read_bytes(), b'external data')
                else:
                    self.assertFalse(target.exists())
                self.assertEqual((common / 'kernel/b.c').read_bytes(), b'old b\n')

    def test_late_patch_conflict_rejects_before_any_live_tree_mutation(self):
        bad = PATCH.replace(b'-old b', b'-different b')
        with tempfile.TemporaryDirectory() as temporary, self.imports(), \
                patch.object(features, 'patches', return_value=[(Path('bad.patch'), bad, ['kernel/a.c', 'kernel/b.c'])]):
            root = Path(temporary)
            common = self.fixture(root)
            before = self.snapshot(common)
            with self.assertRaises(Exception):
                with features.applied(common, root / 'receipt'):
                    self.fail('A conflicting feature patch cannot start a build')
            self.assertEqual(self.snapshot(common), before)
            self.assertFalse((root / 'receipt').exists())


RELEASE = '6.18.63-android17-6-maybe-dirty-4k-onyx-balanced'


def core_elf(release=RELEASE, crc=0x12345678, broken_symbols=False,
              linked_kernel=False, core_protected=False):
    """A small ELF fixture for actual vendor-to-core export admission."""
    strings = b'\0ordinary\0hidden_symbol\0'
    symbols = bytes(24) + b''.join(struct.pack('<IBBHQQ', strings.index(name), 0x10, 0, 0, 0, 0)
                                  for name in (b'ordinary', b'hidden_symbol'))
    sections = {'.modinfo': ('vermagic=' + release + ' SMP modversions aarch64\0').encode(),
                '.notes': b'fixture linker notes',
                '__versions': struct.pack('<Q', crc) + b'ordinary\0' + bytes(47),
                '.strtab': strings, '.symtab': symbols + (b'x' if broken_symbols else b'')}
    addresses = {}
    if linked_kernel:
        sections.update(__ksymtab=struct.pack('<iii', 0, 0x4000 - 0x1004, 0),
                        __kcrctab=struct.pack('<I', crc),
                        __kflagstab=bytes([2 if core_protected else 0]),
                        __ksymtab_strings=b'ordinary\0')
        addresses = {'__ksymtab': 0x1000, '__kcrctab': 0x2000,
                     '__kflagstab': 0x3000, '__ksymtab_strings': 0x4000}
    names = b'\0.shstrtab\0' + b''.join(name.encode() + b'\0' for name in sections)
    sections = {'.shstrtab': names, **sections}
    data, headers = bytearray(64), [bytes(64)]
    for name, contents in sections.items():
        headers.append(struct.pack('<IIQQQQIIQQ', names.index(name.encode()), 1, 0, addresses.get(name, 0), len(data),
                                   len(contents), 0, 0, 1, 0))
        data.extend(contents)
    offset = len(data)
    data.extend(b''.join(headers))
    data[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHI', data, 16, 3 if linked_kernel else 1, 183, 1)
    struct.pack_into('<Q', data, 40, offset)
    struct.pack_into('<HHHHHH', data, 52, 64, 0, 0, 64, len(headers), 1)
    return bytes(data)


BUILTIN_SYMBOLS = ('susfs_init', 'susfs_add_sus_path', 'susfs_add_sus_kstat',
                   'susfs_add_sus_map', 'susfs_get_enabled_features')


class FeatureArtifactTests(unittest.TestCase):
    def fixture(self, root, variant='balanced'):
        artifact = root / 'artifact'
        (artifact / 'gki').mkdir(parents=True)
        (artifact / 'inputs').mkdir()
        source_inputs = root / 'locked-features'
        shutil.copytree(features.INPUTS, source_inputs, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        shutil.copytree(source_inputs, artifact / 'inputs/features')
        shutil.copyfile(Path(features.__file__), artifact / 'inputs/features.py')
        shutil.copyfile(features.HERE / 'verify_modules.py', artifact / 'inputs/verify_modules.py')
        pin = json.loads((features.HERE / 'kernelsu-lock.json').read_text())
        (artifact / 'inputs/kernelsu-next').mkdir()
        (artifact / 'inputs/kernelsu-next/source.json').write_text(json.dumps(pin))
        (artifact / 'inputs/kernelsu-lock.json').write_text(json.dumps(pin))
        (artifact / 'gki/Image').write_bytes(b'fixture kernel')
        (artifact / 'gki/vmlinux').write_bytes(core_elf(linked_kernel=True))
        (artifact / 'platform').mkdir()
        from test_core_import_admission import vendor
        from verify_modules import verify_vendor_core_imports
        vendor(artifact / 'platform/vendor.ko', [('ordinary', 0x12345678)])
        (artifact / 'gki/kernel_aarch64_Module.symvers').write_text('0x12345678 ordinary vmlinux EXPORT_SYMBOL\n')
        symbols = ('ordinary', 'hidden_symbol', '__ksu_is_allow_uid_for_current') + BUILTIN_SYMBOLS
        (artifact / 'gki/System.map').write_text(''.join(
            '%016x T %s\n' % (index, name) for index, name in enumerate(symbols, 1)))
        with patch.object(features, 'INPUTS', source_inputs):
            (artifact / 'gki/kernel_aarch64_dot_config').write_text(''.join(
                name + '=' + value + '\n' for name, value in
                {'CONFIG_KSU': 'y', **features.required_config(variant)}.items()))
            selected = features.profile(variant)
            receipt = features.verify_builtin(artifact / 'gki')
        report = {'variant': selected, 'kernel_release': RELEASE.replace('balanced', variant),
                  'kernelsu_next': pin,
                  'core_import_admission_validation': verify_vendor_core_imports(
                      [artifact / 'platform/vendor.ko'], artifact / 'gki/vmlinux'),
                  'platform_addon_verification': [], 'susfs': receipt}
        return artifact, report, source_inputs

    def verify(self, artifact, report, inputs):
        with patch.object(features, 'INPUTS', inputs):
            return features.verify_artifact(artifact, report)

    def test_both_profiles_verify_builtin_provenance_without_an_addon_or_runtime_claim(self):
        for variant in ('balanced', 'performance'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                artifact, report, inputs = self.fixture(Path(temporary), variant)
                lock = json.loads((inputs / 'lock.json').read_text())['susfs']
                receipt = report['susfs']
                self.assertEqual(receipt['implementation'], 'wildkernels-builtin')
                self.assertIs(receipt['built_in'], True)
                self.assertEqual(receipt['source_revision'], lock['revision'])
                self.assertEqual(receipt['version'], 'v2.4.0')
                contents = b''.join(name.encode() + b'\0' + (inputs / name).read_bytes()
                                    for name in sorted(lock['files']))
                self.assertEqual(receipt['source_sha256'], features.sha(contents))
                self.assertIs(receipt['runtime_verified'], False)
                self.assertEqual(report['platform_addon_verification'], [])
                self.assertFalse((artifact / 'platform-addon').exists())
                result = self.verify(artifact, report, inputs)
                self.assertEqual(result['status'], 'PASS')
                self.assertFalse(result['runtime_verified'])

    def test_each_required_builtin_symbol_must_exist_in_the_linked_kernel(self):
        for missing in BUILTIN_SYMBOLS:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                artifact, _, inputs = self.fixture(Path(temporary))
                mapping = artifact / 'gki/System.map'
                mapping.write_text(''.join(line + '\n' for line in mapping.read_text().splitlines()
                                           if line.split()[-1] != missing))
                with patch.object(features, 'INPUTS', inputs), self.assertRaises(ValueError):
                    features.verify_builtin(artifact / 'gki')

    def test_module_disabled_or_missing_susfs_config_cannot_claim_builtin_capability(self):
        for value in ('m', 'n', None):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                artifact, _, inputs = self.fixture(Path(temporary))
                config = artifact / 'gki/kernel_aarch64_dot_config'
                lines = [line for line in config.read_text().splitlines() if not line.startswith('CONFIG_KSU_SUSFS=')]
                if value is not None:
                    lines.append('CONFIG_KSU_SUSFS=' + value)
                config.write_text('\n'.join(lines) + '\n')
                with patch.object(features, 'INPUTS', inputs), self.assertRaises(ValueError):
                    features.verify_builtin(artifact / 'gki')

    def test_general_and_profile_configs_are_still_required(self):
        for changed in ('CONFIG_NTSYNC', 'CONFIG_DEFAULT_TCP_CONG', 'CONFIG_LOCALVERSION'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                artifact, report, inputs = self.fixture(Path(temporary))
                path = artifact / 'gki/kernel_aarch64_dot_config'
                path.write_text(''.join(line + '\n' for line in path.read_text().splitlines()
                                        if not line.startswith(changed + '=')))
                with self.assertRaises(ValueError):
                    self.verify(artifact, report, inputs)

    def test_each_enabled_susfs_hook_and_kernelsu_are_required(self):
        configs = {'CONFIG_KSU': 'y', **{name: value for name, value in features.manifest()['configs'].items()
                   if name.startswith('CONFIG_KSU_SUSFS') and value == 'y'}}
        for missing in configs:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                artifact, _, inputs = self.fixture(Path(temporary))
                config = artifact / 'gki/kernel_aarch64_dot_config'
                config.write_text(config.read_text().replace(missing + '=y\n', missing + '=n\n'))
                with patch.object(features, 'INPUTS', inputs), self.assertRaises(ValueError):
                    features.verify_builtin(artifact / 'gki')

    def test_vendor_source_bytes_and_locked_vendor_hash_must_agree(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact, _, inputs = self.fixture(Path(temporary))
            lock = json.loads((inputs / 'lock.json').read_text())['susfs']
            name = next(iter(lock['files']))
            source = inputs / name
            source.write_bytes(source.read_bytes() + b'\n/* changed vendor source */\n')
            with patch.object(features, 'INPUTS', inputs), self.assertRaises(ValueError):
                features.verify_builtin(artifact / 'gki')

    def test_invalid_source_provenance_hash_or_incomplete_vendor_inventory_reject(self):
        for changed in ('implementation', 'revision', 'version', 'hash', 'inventory'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                artifact, _, inputs = self.fixture(Path(temporary))
                lock_path = inputs / 'lock.json'
                lock = json.loads(lock_path.read_text())
                pin = lock['susfs']
                if changed == 'implementation':
                    pin['implementation'] = 'official-next-dev-lkm'
                elif changed == 'revision':
                    pin['revision'] = 'unresolved-branch'
                elif changed == 'version':
                    pin['version'] = 'v2.3.0'
                elif changed == 'hash':
                    pin['files'][next(iter(pin['files']))] = 'f' * 64
                else:
                    del pin['files']['vendor/susfs/fs/susfs.c']
                lock_path.write_text(json.dumps(lock))
                with patch.object(features, 'INPUTS', inputs), self.assertRaises(ValueError):
                    features.verify_builtin(artifact / 'gki')

    def test_forged_builtin_source_or_capability_receipts_reject(self):
        for field, value in (('implementation', 'official-next-dev-lkm'), ('built_in', False),
                             ('source_revision', 'f' * 40), ('source_sha256', 'f' * 64),
                             ('version', 'v2.3.0'), ('runtime_verified', True)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                artifact, report, inputs = self.fixture(Path(temporary))
                report['susfs'][field] = value
                with self.assertRaises(ValueError):
                    self.verify(artifact, report, inputs)

    def test_changed_source_inputs_verifiers_and_kernelsu_pins_reject(self):
        for changed in ('manifest', 'vendor', 'feature-verifier', 'core-verifier', 'revision',
                        'upstream-revision', 'kernelsu-sha256'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                artifact, report, inputs = self.fixture(Path(temporary))
                if changed == 'manifest':
                    (artifact / 'inputs/features/manifest.json').write_text('{}\n')
                elif changed == 'vendor':
                    lock = json.loads((inputs / 'lock.json').read_text())['susfs']
                    name = next(iter(lock['files']))
                    (artifact / 'inputs/features' / name).write_bytes(b'altered vendor source')
                elif changed == 'feature-verifier':
                    (artifact / 'inputs/features.py').write_text('# altered feature verifier\n')
                elif changed == 'core-verifier':
                    (artifact / 'inputs/verify_modules.py').write_text('# altered verifier\n')
                else:
                    field = {'revision': 'revision', 'upstream-revision': 'upstream_revision',
                             'kernelsu-sha256': 'sha256'}[changed]
                    report['kernelsu_next'][field] = 'f' * (64 if field == 'sha256' else 40)
                with self.assertRaises(ValueError):
                    self.verify(artifact, report, inputs)

    def test_stale_addon_inventory_module_or_loader_reject(self):
        for changed in ('inventory', 'module', 'loader'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                artifact, report, inputs = self.fixture(Path(temporary))
                if changed == 'inventory':
                    report['platform_addon_verification'] = [{'module': 'susfs_guard_lkm.ko'}]
                else:
                    (artifact / 'platform-addon').mkdir()
                    name = 'susfs_guard_lkm.ko' if changed == 'module' else 'post-fs-data.sh'
                    (artifact / 'platform-addon' / name).write_bytes(b'stale LKM addon')
                with self.assertRaises(ValueError):
                    self.verify(artifact, report, inputs)

    def test_recorded_success_cannot_admit_newly_protected_actual_core_exports(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact, report, inputs = self.fixture(Path(temporary))
            (artifact / 'gki/vmlinux').write_bytes(core_elf(linked_kernel=True, core_protected=True))
            with self.assertRaisesRegex(ValueError, 'protected core export'):
                self.verify(artifact, report, inputs)

    def test_forged_core_admission_receipt_rejects(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact, report, inputs = self.fixture(Path(temporary))
            report['core_import_admission_validation']['core_imports_checked'] = 0
            with self.assertRaises(ValueError):
                self.verify(artifact, report, inputs)

    def test_kernel_note_hash_remains_independent_of_addon_packaging(self):
        with tempfile.TemporaryDirectory() as temporary:
            kernel = Path(temporary) / 'vmlinux'
            kernel.write_bytes(core_elf(linked_kernel=True))
            self.assertEqual(features.kernel_notes_hash(kernel), features.sha(b'fixture linker notes'))


if __name__ == '__main__':
    unittest.main()
