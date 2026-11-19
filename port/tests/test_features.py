"""Adversarial feature replay transactions and owned-file restoration."""
import io
import json
from pathlib import Path
import shutil
import struct
import sys
import tarfile
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


def addon_elf(release=RELEASE, crc=0x12345678, broken_symbols=False):
    """A small ELF fixture with exported and special-loader-only imports."""
    strings = b'\0ordinary\0hidden_symbol\0'
    symbols = bytes(24) + b''.join(struct.pack('<IBBHQQ', strings.index(name), 0x10, 0, 0, 0, 0)
                                  for name in (b'ordinary', b'hidden_symbol'))
    sections = {'.modinfo': ('vermagic=' + release + ' SMP modversions aarch64\0').encode(),
                '.notes': b'fixture linker notes',
                '__versions': struct.pack('<Q', crc) + b'ordinary\0' + bytes(47),
                '.strtab': strings, '.symtab': symbols + (b'x' if broken_symbols else b'')}
    names = b'\0.shstrtab\0' + b''.join(name.encode() + b'\0' for name in sections)
    sections = {'.shstrtab': names, **sections}
    data, headers = bytearray(64), [bytes(64)]
    for name, contents in sections.items():
        headers.append(struct.pack('<IIQQQQIIQQ', names.index(name.encode()), 1, 0, 0, len(data),
                                   len(contents), 0, 0, 1, 0))
        data.extend(contents)
    offset = len(data)
    data.extend(b''.join(headers))
    data[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHI', data, 16, 1, 183, 1)
    struct.pack_into('<Q', data, 40, offset)
    struct.pack_into('<HHHHHH', data, 52, 64, 0, 0, 64, len(headers), 1)
    return bytes(data)


class FeatureArtifactTests(unittest.TestCase):
    def fixture(self, root):
        artifact = root / 'artifact'
        (artifact / 'gki').mkdir(parents=True)
        (artifact / 'platform-addon').mkdir()
        (artifact / 'inputs').mkdir()
        source_inputs = root / 'locked-features'
        shutil.copytree(features.INPUTS, source_inputs, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        shutil.copytree(source_inputs, artifact / 'inputs/features')
        shutil.copyfile(Path(features.__file__), artifact / 'inputs/features.py')
        (artifact / 'gki/Image').write_bytes(b'fixture kernel')
        (artifact / 'gki/vmlinux').write_bytes(addon_elf())
        notes = features.kernel_notes_hash(artifact / 'gki/vmlinux')
        (artifact / 'platform-addon/kernel.notes.sha256').write_text(notes + '\n')
        (artifact / 'gki/kernel_aarch64_Module.symvers').write_text('0x12345678 ordinary vmlinux EXPORT_SYMBOL\n')
        (artifact / 'gki/System.map').write_text('0000000000000001 T ordinary\n0000000000000002 T hidden_symbol\n'
                                               '0000000000000003 T __ksu_is_allow_uid_for_current\n')
        module = artifact / 'platform-addon/susfs_guard_lkm.ko'
        module.write_bytes(addon_elf())
        with patch.object(features, 'INPUTS', source_inputs):
            (artifact / 'gki/kernel_aarch64_dot_config').write_text(''.join(
                name + '=' + value + '\n' for name, value in features.required_config('balanced').items()))
            for name in ('post-fs-data.sh', 'verify-runtime.sh', 'module.prop'):
                (artifact / 'platform-addon' / name).write_bytes(features.addon_file(name, 'balanced'))
            variant = features.profile('balanced')
        (artifact / 'platform-addon/kernel.release').write_text(RELEASE + '\n')
        (artifact / 'inputs/kernelsu-next').mkdir()
        source_archive = artifact / 'inputs/kernelsu-next/source.tar'
        with tarfile.open(source_archive, 'w') as archive:
            data = b'official source fixture'
            member = tarfile.TarInfo('kernel/susfs/susfs.c')
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
            data = b'static const char *symbols[] = { "__ksu_is_allow_uid_for_current", "ksu_is_allow_uid_for_current" };'
            member = tarfile.TarInfo('kernel/susfs/ksu_allow_gate.c')
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        source = {'kernelsu_revision': 'a' * 40,
                  'kernel_notes_sha256': notes,
                  'kernel_sha256': features.sha((artifact / 'gki/Image').read_bytes()),
                  'susfs_source_sha256': features.susfs_source_hash(source_archive)}
        (artifact / 'platform-addon/source.json').write_text(json.dumps(source))
        report = {'variant': variant, 'kernel_release': RELEASE,
                  'kernelsu_next': {'revision': 'a' * 40},
                  'platform_addon_verification': [features.verify_addon(module, artifact / 'gki', RELEASE)]}
        return artifact, report, source_inputs

    def test_real_elf_checks_export_crc_and_special_loader_symbol_availability(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact, report, inputs = self.fixture(Path(temporary))
            row = report['platform_addon_verification'][0]
            self.assertEqual(row['imports_checked'], 2)
            self.assertEqual(row['versioned_imports_checked'], 1)
            with patch.object(features, 'INPUTS', inputs):
                result = features.verify_artifact(artifact, report)
            self.assertEqual(result['status'], 'PASS')
            self.assertFalse(result['runtime_verified'])

    def test_module_crc_missing_private_import_vermagic_and_malformed_symbols_reject(self):
        for changed in ('crc', 'private-import', 'vermagic', 'symbols'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                artifact, _, _ = self.fixture(Path(temporary))
                module = artifact / 'platform-addon/susfs_guard_lkm.ko'
                if changed == 'crc':
                    module.write_bytes(addon_elf(crc=0x87654321))
                elif changed == 'vermagic':
                    module.write_bytes(addon_elf(release=RELEASE.replace('balanced', 'performance')))
                elif changed == 'symbols':
                    module.write_bytes(addon_elf(broken_symbols=True))
                else:
                    (artifact / 'gki/System.map').write_text('0000000000000001 T ordinary\n')
                with self.assertRaises(ValueError):
                    features.verify_addon(module, artifact / 'gki', RELEASE)

    def test_capability_source_loader_kernel_and_revision_tampering_reject(self):
        for changed in ('config', 'source', 'loader', 'kernel', 'revision', 'allow-predicate', 'kernel-notes'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                artifact, report, inputs = self.fixture(Path(temporary))
                if changed == 'config':
                    path = artifact / 'gki/kernel_aarch64_dot_config'
                    path.write_text(path.read_text().replace('CONFIG_NTSYNC=y\n', ''))
                elif changed == 'source':
                    (artifact / 'inputs/features/manifest.json').write_text('{}\n')
                elif changed == 'loader':
                    (artifact / 'platform-addon/post-fs-data.sh').write_text('# altered loader\n')
                elif changed == 'kernel':
                    (artifact / 'gki/Image').write_bytes(b'other kernel')
                elif changed == 'revision':
                    report['kernelsu_next']['revision'] = 'b' * 40
                elif changed == 'allow-predicate':
                    path = artifact / 'gki/System.map'
                    path.write_text(path.read_text().replace('0000000000000003 T __ksu_is_allow_uid_for_current\n', ''))
                else:
                    (artifact / 'platform-addon/kernel.notes.sha256').write_text('0' * 64 + '\n')
                with patch.object(features, 'INPUTS', inputs), self.assertRaises(ValueError):
                    features.verify_artifact(artifact, report)


if __name__ == '__main__':
    unittest.main()
