import copy
from contextlib import nullcontext
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import export_artifacts
import installer_assets
import publish_release
import recover_release
import release_naming
import variant_assets
import verify_artifacts
import test_release
import test_extra_installers
import test_automation
import refresh_recipe
import snapshot_common


def rehash(artifact, report):
    report['sha256'] = {path.relative_to(artifact).as_posix(): verify_artifacts.digest(path)
                        for path in artifact.rglob('*') if path.is_file() and path != artifact / 'report.json'}
    test_release.write_json(artifact / 'report.json', report)


def fixture(root):
    source, workspace, first, report = test_release.fixture(root)
    feature_root = source / 'port/features'
    feature_root.mkdir()
    (feature_root / 'manifest.json').write_text('{"format":1}\n')
    helper = source / 'port/features.py'
    helper.write_text('def verify_artifact(artifact, report):\n'
                      '    if "CONFIG_NTSYNC=y" not in (artifact / "gki/kernel_aarch64_dot_config").read_text().splitlines():\n'
                      '        raise ValueError("NTSync build feature is missing")\n')
    template = root / 'template'
    shutil.copytree(first, template)
    shutil.rmtree(first)
    builds = {}
    for identifier in release_naming.VARIANTS:
        artifact = workspace / 'artifacts' / ('20261119T120000-' + identifier)
        shutil.copytree(template, artifact)
        value = copy.deepcopy(report)
        release = test_release.RELEASE + '-onyx-' + identifier
        value.update(kernel_release=release, variant={'id': identifier, 'label': identifier.title(),
                     'features': ['ntsync', 'susfs'], 'profile': {'tuning': identifier}})
        value['automation_revision'] = 'e' * 40
        for record in value['module_verification']:
            record['vermagic'] = release + ' SMP modversions aarch64'
        (artifact / 'gki/kernel.release').write_text(release + '\n')
        with (artifact / 'gki/kernel_aarch64_dot_config').open('a') as stream:
            stream.write('CONFIG_NTSYNC=y\n')
        shutil.copytree(feature_root, artifact / 'inputs/features')
        shutil.copyfile(helper, artifact / 'inputs/features.py')
        (artifact / 'platform-addon').mkdir()
        (artifact / 'platform-addon/susfs_guard_lkm.ko').write_bytes(identifier.encode() + b' addon module')
        value['platform_addon_verification'] = [{'module': 'susfs_guard_lkm.ko',
             'sha256': verify_artifacts.digest(artifact / 'platform-addon/susfs_guard_lkm.ko'),
             'vermagic': release + ' SMP modversions aarch64', 'imports_checked': 4}]
        rehash(artifact, value)
        builds[identifier] = artifact, value
    return source, workspace, builds


class VariantReleaseTests(unittest.TestCase):
    def export(self, root):
        source, workspace, builds = fixture(root)
        bundle = root / 'bundle'
        identity = export_artifacts.export(workspace, bundle, source, test_release.SOURCE, '123', '1')
        return source, workspace, builds, bundle, identity

    def verify(self, bundle, source):
        return publish_release.validate_bundle(bundle, source, test_release.SOURCE,
                                              test_release.KERNEL, test_release.KSU, '123', '1')

    def test_both_variant_archives_roundtrip_with_unique_downloads_and_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, _, _, bundle, identity = self.export(Path(temporary))
            self.assertEqual(self.verify(bundle, source), identity)
            self.assertEqual(identity['asset_format'], 3)
            self.assertEqual([row['id'] for row in identity['variants']], ['balanced', 'performance'])
            self.assertEqual(identity['artifact_name'], 'Onyx-GKI-Variants-123-1')
            files = publish_release.bundle_files(identity)
            self.assertEqual(len(files), 12)
            self.assertEqual(len({Path(name).name for name in files}), len(files))
            self.assertEqual(set(identity['sha256']), files)
            notes = publish_release.release_notes('owner/repo', identity)
            self.assertIn('| Balanced |', notes)
            self.assertIn('| Performance |', notes)
            self.assertIn('variants array', notes)

    def test_missing_or_duplicate_variant_fails_before_creating_bundle(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, workspace, builds = fixture(root)
                artifact, report = builds['performance']
                if duplicate:
                    report['variant'] = copy.deepcopy(builds['balanced'][1]['variant'])
                    report['kernel_release'] = builds['balanced'][1]['kernel_release']
                    (artifact / 'gki/kernel.release').write_text(report['kernel_release'] + '\n')
                    for row in report['module_verification'] + report['platform_addon_verification']:
                        row['vermagic'] = report['kernel_release'] + ' SMP modversions aarch64'
                    rehash(artifact, report)
                else:
                    shutil.rmtree(artifact)
                with self.assertRaises(ValueError):
                    export_artifacts.export(workspace, root / 'bundle', source, test_release.SOURCE, '123', '1')
                self.assertFalse((root / 'bundle').exists())

    def test_different_ksu_sources_or_automation_revisions_reject_before_export(self):
        for changed in ('ksu', 'automation'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, workspace, builds = fixture(root)
                artifact, report = builds['performance']
                if changed == 'ksu':
                    report['kernelsu_next']['revision'] = 'd' * 40
                    test_release.write_json(artifact / 'inputs/kernelsu-next/source.json', report['kernelsu_next'])
                else:
                    report['automation_revision'] = 'd' * 40
                rehash(artifact, report)
                with self.assertRaisesRegex(ValueError, 'different immutable'):
                    export_artifacts.export(workspace, root / 'bundle', source, test_release.SOURCE, '123', '1')
                self.assertFalse((root / 'bundle').exists())

    def test_recorded_feature_success_does_not_replace_config_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, workspace, builds = fixture(root)
            artifact, report = builds['performance']
            report['feature_validation'] = {'ntsync': 'passed', 'smoke_load': 'passed'}
            (artifact / 'gki/kernel_aarch64_dot_config').write_text('CONFIG_KSU=y\nCONFIG_MODVERSIONS=y\n')
            rehash(artifact, report)
            with self.assertRaisesRegex(ValueError, 'NTSync build feature is missing'):
                export_artifacts.export(workspace, root / 'bundle', source, test_release.SOURCE, '123', '1')

    def test_rehashed_cross_variant_archive_swap_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, _, _, bundle, identity = self.export(Path(temporary))
            balanced, performance = identity['variants']
            left, right = (bundle / row['downloads']['rom_integration'] for row in (balanced, performance))
            shutil.copyfile(left, right)
            performance['sha256'][right.name] = verify_artifacts.digest(right)
            identity['sha256'][right.name] = performance['sha256'][right.name]
            test_release.write_json(bundle / 'release.json', identity)
            release_naming.write_checksums(bundle)
            with self.assertRaisesRegex(ValueError, 'variant archive member'):
                self.verify(bundle, source)

    def test_profile_and_download_metadata_cannot_be_relabelled_after_build(self):
        for changed in ('profile', 'downloads', 'revision'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                source, _, _, bundle, identity = self.export(Path(temporary))
                row = identity['variants'][1]
                if changed == 'profile':
                    row['profile'] = {'tuning': 'balanced'}
                elif changed == 'downloads':
                    row['downloads']['rom_integration'] = identity['variants'][0]['downloads']['rom_integration']
                else:
                    row['kernelsu_revision'] = 'd' * 40
                test_release.write_json(bundle / 'release.json', identity)
                release_naming.write_checksums(bundle)
                with self.assertRaises(ValueError):
                    self.verify(bundle, source)

    def test_addon_module_from_other_kernel_is_rejected_even_with_valid_file_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, workspace, builds = fixture(root)
            artifact, report = builds['performance']
            report['platform_addon_verification'][0]['vermagic'] = builds['balanced'][1]['kernel_release'] + ' SMP modversions aarch64'
            rehash(artifact, report)
            with self.assertRaisesRegex(ValueError, 'SUSFS addon'):
                export_artifacts.export(workspace, root / 'bundle', source, test_release.SOURCE, '123', '1')

    def test_builtin_susfs_exports_without_a_loader_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, workspace, builds = fixture(root)
            for artifact, report in builds.values():
                report['variant']['features'] = ['ntsync', 'susfs-next-builtin']
                report['platform_addon_verification'] = []
                report['susfs'] = {'implementation': 'wildkernels-builtin', 'built_in': True,
                    'source_revision': 'a' * 40, 'source_sha256': 'b' * 64,
                    'version': 'v2.4.0', 'runtime_verified': False}
                shutil.rmtree(artifact / 'platform-addon')
                rehash(artifact, report)
            bundle = root / 'bundle'
            identity = export_artifacts.export(workspace, bundle, source, test_release.SOURCE, '123', '1')
            self.assertEqual(self.verify(bundle, source), identity)
            for row in identity['variants']:
                row['installers'] = ['fixture-installer']
                downloads = variant_assets.download_map(row)
                self.assertNotIn('susfs_module', downloads)
                self.assertIn('internal_wifi', downloads)
                self.assertIn('external_wifi', downloads)
            notes = publish_release.release_notes('owner/repo', identity)
            self.assertIn('SUSFS is built into both kernels', notes)
            self.assertNotIn('SUSFS-KSU-Module.zip', notes)

    def test_builtin_installer_inventory_accepts_three_archives_and_rejects_incomplete_or_stale_sets(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, _, identity = self.export(Path(temporary))
            for row in identity['variants']:
                row['features'] = ['ntsync', 'susfs-next-builtin']
                names = installer_assets.names(row['kernel_release'], 3, row['id'], row['asset_timestamp'])
                row['installers'] = list(names[:3]) + [variant_assets.installer_metadata_name(row['id'], row['asset_timestamp'])]
                row['sha256'].update({name: installer_assets.sha(name.encode()) for name in row['installers']})
                row['downloads'] = variant_assets.download_map(row)
            identity['sha256'] = {name: value for row in identity['variants']
                                  for name, value in row['sha256'].items()}
            files = publish_release.bundle_files(identity)
            self.assertTrue(all(set(row['installers']) <= files for row in identity['variants']))
            self.assertFalse(any('SUSFS-KSU-Module' in name for name in files))
            for change in ('missing_wifi', 'stale_susfs', 'duplicate'):
                malformed = copy.deepcopy(identity)
                row = malformed['variants'][0]
                if change == 'missing_wifi':
                    row['installers'].remove(installer_assets.names(row['kernel_release'], 3, row['id'], row['asset_timestamp'])[2])
                elif change == 'stale_susfs':
                    row['installers'].append(installer_assets.names(row['kernel_release'], 3, row['id'], row['asset_timestamp'])[3])
                else:
                    row['installers'].append(row['installers'][0])
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'installer asset inventory'):
                    publish_release.bundle_files(malformed)

    def test_builtin_susfs_rejects_stale_addon_and_missing_provenance(self):
        for stale in (True, False):
            with self.subTest(stale=stale), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, workspace, builds = fixture(root)
                for artifact, report in builds.values():
                    report['variant']['features'] = ['ntsync', 'susfs-next-builtin']
                    if not stale:
                        report['platform_addon_verification'] = []
                        shutil.rmtree(artifact / 'platform-addon')
                    rehash(artifact, report)
                with self.assertRaisesRegex(ValueError, 'loadable addon payload' if stale else 'provenance'):
                    export_artifacts.export(workspace, root / 'bundle', source, test_release.SOURCE, '123', '1')
                self.assertFalse((root / 'bundle').exists())

    def test_publication_requires_both_complete_installer_sets_before_draft_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, _, _, bundle, _ = self.export(Path(temporary))
            with patch.object(publish_release, 'api', side_effect=[
                    {'head_branch': 'ci', 'path': '.github/workflows/build.yml', 'head_sha': 'e' * 40},
                    {'jobs': [{'name': 'build', 'conclusion': 'success'}]}]) as api:
                with self.assertRaisesRegex(ValueError, 'Both variants require'):
                    publish_release.publish('owner/repo', bundle, source, test_release.SOURCE,
                                            test_release.KERNEL, test_release.KSU, '123', '1')
            self.assertEqual(api.call_count, 2)

    def test_consistently_spoofed_ci_revision_cannot_publish_from_other_authenticated_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, _, _, bundle, identity = self.export(Path(temporary))
            self.assertTrue(all(row['automation_revision'] == identity['automation_revision'] for row in identity['variants']))
            with patch.object(publish_release, 'api', return_value={
                    'head_branch': 'ci', 'path': '.github/workflows/build.yml', 'head_sha': 'f' * 40}) as api, \
                    self.assertRaisesRegex(ValueError, 'authenticated build attempt'):
                publish_release.publish('owner/repo', bundle, source, test_release.SOURCE,
                                        test_release.KERNEL, test_release.KSU, '123', '1')
            self.assertEqual(api.call_count, 1)

    def test_recovery_binds_variant_metadata_to_selected_authenticated_ci_revision(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, _, _, bundle, identity = self.export(Path(temporary))
            self.assertEqual(recover_release.inputs(bundle, '123', '1', 'e' * 40)['source_revision'], test_release.SOURCE)
            for expected in (None, 'f' * 40, 'ci', ''):
                with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, 'selected authenticated build'):
                    recover_release.inputs(bundle, '123', '1', expected)

    def test_format3_cannot_omit_ci_revision_from_both_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, workspace, builds = fixture(root)
            for artifact, report in builds.values():
                report.pop('automation_revision')
                rehash(artifact, report)
            with self.assertRaisesRegex(ValueError, 'exact CI automation revision'):
                export_artifacts.export(workspace, root / 'bundle', source, test_release.SOURCE, '123', '1')
            self.assertFalse((root / 'bundle').exists())


class VariantInstallerTests(unittest.TestCase):
    def test_builtin_susfs_omits_addon_zip_and_preserves_wifi_installers(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary)
            identity = test_extra_installers.ExtraPackageTests().fixture(artifact)
            identity.update(asset_format=3, id='balanced', label='Balanced',
                            features=['susfs-next-builtin'], profile={})
            report = json.loads((artifact / 'report.json').read_text())
            report['platform_addon_verification'] = []
            (artifact / 'inputs/modules.json').write_text('[]')
            rehash(artifact, report)
            products = installer_assets.build(artifact, identity)
            ak, internal, external, susfs = installer_assets.names(identity['kernel_release'], 3, 'balanced')
            self.assertEqual(set(products), {ak, internal, external, 'Onyx-Balanced-installers.json'})
            with zipfile.ZipFile(io.BytesIO(products[internal])) as archive:
                self.assertIn('wlan/' + installer_assets.WLAN, archive.namelist())
            with zipfile.ZipFile(io.BytesIO(products[external])) as archive:
                self.assertTrue(any(name.endswith('rtl8xxxu.ko') for name in archive.namelist()))
            self.assertNotIn(susfs, products)

    def test_builtin_susfs_rejects_stale_addon_file_even_without_an_inventory_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary)
            identity = test_extra_installers.ExtraPackageTests().fixture(artifact)
            identity.update(asset_format=3, id='balanced', label='Balanced',
                            features=['susfs-next-builtin'], profile={})
            report = json.loads((artifact / 'report.json').read_text())
            report['platform_addon_verification'] = []
            addon = artifact / 'platform-addon'
            addon.mkdir()
            (addon / 'susfs_guard_lkm.ko').write_bytes(b'stale addon')
            rehash(artifact, report)
            with self.assertRaisesRegex(ValueError, 'loadable addon payload'):
                installer_assets.build(artifact, identity)

    def test_susfs_zip_keeps_reviewed_special_loader_and_matched_module(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary)
            identity = test_extra_installers.ExtraPackageTests().fixture(artifact)
            identity.update(asset_format=3, id='balanced', label='Balanced', features=['susfs'], profile={})
            report = json.loads((artifact / 'report.json').read_text())
            addon = artifact / 'platform-addon'
            addon.mkdir()
            loader = b'#!/system/bin/sh\n/data/adb/ksud insmod "$MODDIR/susfs_guard_lkm.ko"\n'
            (addon / 'post-fs-data.sh').write_bytes(loader)
            (addon / 'post-fs-data.sh').chmod(0o755)
            (addon / 'module.prop').write_text('id=onyx-susfs\nname=Onyx SUSFS\nversion=1\nversionCode=1\n')
            (addon / 'susfs_guard_lkm.ko').write_bytes(b'matched SUSFS ELF')
            report['platform_addon_verification'] = [{'module': 'susfs_guard_lkm.ko'}]
            (artifact / 'inputs/modules.json').write_text('[]')
            rehash(artifact, report)
            products = installer_assets.build(artifact, identity)
            filename = installer_assets.names(identity['kernel_release'], 3, 'balanced')[3]
            with zipfile.ZipFile(io.BytesIO(products[filename])) as archive:
                self.assertEqual(archive.read('post-fs-data.sh'), loader)
                self.assertEqual(archive.read('susfs_guard_lkm.ko'), b'matched SUSFS ELF')
                self.assertTrue(archive.getinfo('post-fs-data.sh').external_attr >> 16 & 0o111)
                self.assertNotIn('modules.load', archive.namelist())
                self.assertIn('payload.sha256', archive.namelist())
            self.assertIn('Onyx-Balanced-installers.json', products)
            ak_name = installer_assets.names(identity['kernel_release'], 3, 'balanced')[0]
            with zipfile.ZipFile(io.BytesIO(products[ak_name])) as archive:
                self.assertIn('tools/variant-module-guard.sh', archive.namelist())
                self.assertIn('matched-module-payload.sha256', archive.namelist())
                self.assertIn(b'.original-name', archive.read('anykernel.sh'))
                self.assertNotIn(b'@VARIANT_', archive.read('anykernel.sh'))

    def guard_fixture(self, root, expected_module):
        script = root / 'guard.sh'
        script.write_text((installer_assets.HERE / 'variant-module-guard.sh').read_text().replace('@VARIANT@', 'balanced'))
        table = root / 'matched-module-payload.sha256'
        table.write_text(installer_assets.sha(expected_module) + '  feature.ko\n')
        modules = root / 'installed-modules.list'
        return script, table, modules

    def run_guard(self, script, table, modules, release):
        return subprocess.run(['sh', str(script), release, str(modules), str(table)], text=True, capture_output=True)

    def test_identical_import_crcs_cannot_hide_different_installed_module_feature_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = test_extra_installers.native_module('6.18.63-android17-6-maybe-dirty-4k-onyx-balanced')
            expected, installed = base + b'FEATURE_CONFIG=new', base + b'FEATURE_CONFIG=old'
            # Both modules still satisfy the old CRC-only guard.
            binary = root / 'module-abi'
            subprocess.run(['cc', '-nostdlib', '-static', '-no-pie', '-ffreestanding', '-fno-builtin',
                            '-fno-stack-protector', '-O2', str(installer_assets.HERE / 'module-abi.c'), '-o', str(binary)],
                           env={**os.environ, 'TMPDIR': str(root)}, check=True)
            abi = root / 'kernel-abi.tsv'
            abi.write_text('12345678 symbol\n')
            module = root / 'feature.ko'
            for data in (expected, installed):
                module.write_bytes(data)
                self.assertEqual(subprocess.run([str(binary), str(abi), str(module)], capture_output=True).returncode, 0)
            script, table, modules = self.guard_fixture(root, expected)
            modules.write_text(str(module) + '\n')
            release = '6.18.63-android17-6-maybe-dirty-4k-onyx-balanced'
            rejected = self.run_guard(script, table, modules, release)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('differs from the target', rejected.stderr)
            module.write_bytes(expected)
            self.assertEqual(self.run_guard(script, table, modules, release).returncode, 0)

    def test_early_module_names_duplicates_profile_switch_and_safe_patchlevel_upgrade(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = b'target module bytes'
            script, table, modules = self.guard_fixture(root, expected)
            dlkm, early = root / 'feature.ko', root / '1.ko'
            dlkm.write_bytes(expected)
            early.write_bytes(expected)
            (root / '1.ko.original-name').write_text('feature.ko\n')
            modules.write_text(str(dlkm) + '\n' + str(early) + '\n')
            balanced = '6.18.62-android17-6-maybe-dirty-4k-onyx-balanced'
            self.assertEqual(self.run_guard(script, table, modules, balanced).returncode, 0)
            for release in (balanced.replace('balanced', 'performance'), balanced.removesuffix('-onyx-balanced')):
                with self.subTest(release=release):
                    self.assertNotEqual(self.run_guard(script, table, modules, release).returncode, 0)
            early.write_bytes(b'old early module bytes')
            self.assertNotEqual(self.run_guard(script, table, modules, balanced).returncode, 0)

    def test_module_hash_table_keeps_only_reviewed_platform_override(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in ('platform', 'platform-addon', 'gki', 'inputs'):
                (root / directory).mkdir()
            (root / 'platform/feature.ko').write_bytes(b'authoritative port')
            release = '6.18.63-android17-6-maybe-dirty-4k-onyx-balanced'
            (root / 'inputs/modules.json').write_text(json.dumps([
                {'output': 'feature.ko', 'replaces_gki': 'kernel/feature.ko'}]))
            with tarfile.open(root / 'gki/modules_staging_dir.tar.gz', 'w:gz') as archive:
                member = tarfile.TarInfo('lib/modules/' + release + '/kernel/feature.ko')
                data = b'old upstream provider'
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            report = {'kernel_release': release, 'sha256': {path.relative_to(root).as_posix(): installer_assets.sha(path.read_bytes())
                      for path in root.rglob('*') if path.is_file()}}
            self.assertEqual(installer_assets.matched_module_hashes(root, report),
                             {'feature.ko': installer_assets.sha(b'authoritative port')})


class FeatureReplayTests(unittest.TestCase):
    def feature_rebase(self, root, upstream):
        from contextlib import nullcontext
        port, common = test_automation.RebaseTests().setup_fixture(root)
        snapshot = root / 'common'
        candidate = root / 'upstream'
        common.rename(candidate)
        snapshot.mkdir()
        path = candidate / 'memory.c'
        base = 'before\n\tcall_old(\n\t\targument);\n\nafter\n'
        patched = base.replace('\t\targument);', '\targument);\n\tcheck_result();')
        path.write_text(upstream(base))
        (snapshot / path.name).write_text(patched)
        feature_dir = port / 'features'
        feature_dir.mkdir()
        feature_patch = feature_dir / 'memory.patch'
        feature_patch.write_bytes(
            b'diff --git a/memory.c b/memory.c\n--- a/memory.c\n+++ b/memory.c\n'
            b'@@ -1,5 +1,6 @@\n before\n \tcall_old(\n-\t\targument);\n'
            b'+\targument);\n+\tcheck_result();\n \n after\n')
        data = {'patch_series': [{'path': feature_patch.name, 'sha256': refresh_recipe.sha(feature_patch.read_bytes())}]}
        manifest = feature_dir / 'manifest.json'
        manifest.write_text(json.dumps(data))
        (port / 'common-source-hashes.json').write_text(json.dumps({path.name: {
            'sha256': refresh_recipe.sha(patched.encode()), 'executable': False}}))
        def verify(tree):
            self.assertTrue(refresh_recipe.replay(tree, feature_patch.read_bytes()))
        features = SimpleNamespace(
            manifest=lambda: json.loads(manifest.read_text()), nomount_files=dict,
            patches=lambda: [(feature_patch, feature_patch.read_bytes(), [path.name])], refresh_common=verify)
        return port, candidate, snapshot, feature_patch, manifest, {
            'features': features, 'common_fixes': SimpleNamespace(applied=lambda *args: nullcontext())}

    def test_rebase_preserves_upstream_call_and_relocks_patch(self):
        with tempfile.TemporaryDirectory() as temporary:
            port, common, _, feature_patch, manifest, modules = self.feature_rebase(
                Path(temporary), lambda base: base.replace('call_old', 'call_upstream'))
            before = (common / 'memory.c').read_bytes()
            self.assertFalse(refresh_recipe.replay(common, feature_patch.read_bytes()))
            with patch.object(refresh_recipe, 'PORT', port), patch.dict(sys.modules, modules):
                result = refresh_recipe.refresh(common, rebase_features=True)
            self.assertEqual(result['rebased_feature_patches'], [feature_patch.name])
            data = feature_patch.read_bytes()
            self.assertEqual(json.loads(manifest.read_text())['patch_series'][0]['sha256'], refresh_recipe.sha(data))
            self.assertEqual((common / 'memory.c').read_bytes(), before)
            refresh_recipe.apply(common, data)
            self.assertEqual((common / 'memory.c').read_bytes(),
                             before.replace(b'argument);\n', b'argument);\n\tcheck_result();\n'))

    def test_rebase_rejects_overlapping_code_and_unsafe_whitespace_merges(self):
        cases = (
            (lambda base: base.replace('argument);', 'different_argument);\n\tupstream_check();'),
             'Feature patch conflicts with upstream'),
            (lambda base: base.replace('call_old', 'call_upstream').replace('argument);', 'argument );'),
             '(?:Feature patch conflicts with upstream|Whitespace merge changed code edits)'),
        )
        for upstream, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                port, common, _, _, _, modules = self.feature_rebase(root, upstream)
                before = test_automation.RebaseTests().snapshot(root)
                with patch.object(refresh_recipe, 'PORT', port), patch.dict(sys.modules, modules), \
                        self.assertRaisesRegex(ValueError, message + r': memory.patch: memory.c'):
                    refresh_recipe.refresh(common, rebase_features=True)
                self.assertEqual(test_automation.RebaseTests().snapshot(root), before)

    def test_rebase_rejects_modified_accepted_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            port, common, snapshot, _, _, modules = self.feature_rebase(
                root, lambda base: base.replace('call_old', 'call_upstream'))
            (snapshot / 'memory.c').write_text('changed accepted source\n')
            before = test_automation.RebaseTests().snapshot(root)
            with patch.object(refresh_recipe, 'PORT', port), patch.dict(sys.modules, modules), \
                    self.assertRaisesRegex(ValueError, 'Accepted feature snapshot differs from its inventory'):
                refresh_recipe.refresh(common, rebase_features=True)
            self.assertEqual(test_automation.RebaseTests().snapshot(root), before)

    def test_feature_conflict_restores_all_legacy_recipe_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = test_automation.RebaseTests()
            port, common = cases.setup_fixture(root)
            (port / 'features').mkdir()
            (port / 'features/manifest.json').write_text('{"format":1}\n')
            before = cases.snapshot(root)
            def reject(candidate):
                self.assertEqual(candidate, common)
                self.assertTrue((port / 'common-patches/effective.patch').is_file())
                raise ValueError('Feature patch conflicts with new upstream')
            with patch.object(refresh_recipe, 'PORT', port), \
                    patch.dict(sys.modules, {'features': SimpleNamespace(refresh_common=reject)}), \
                    self.assertRaisesRegex(ValueError, 'Feature patch conflicts'):
                refresh_recipe.refresh(common)
            self.assertEqual(before, cases.snapshot(root))

    def test_streamed_git_archive_preserves_snapshot_bytes_modes_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / 'workspace'
            common = workspace / 'common'
            common.mkdir(parents=True)
            def git(*args):
                return subprocess.check_output(['git', '-C', str(common), *args], text=True).strip()
            git('init', '-q')
            git('config', 'user.name', 'Snapshot fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            (common / 'runner.sh').write_text('#!/bin/sh\nexit 0\n')
            (common / 'runner.sh').chmod(0o755)
            (common / 'link').symlink_to('runner.sh')
            git('add', 'runner.sh', 'link')
            git('commit', '-qm', 'source fixture')
            revision = git('rev-parse', 'HEAD')
            source = root / 'source'
            (source / 'port').mkdir(parents=True)
            shutil.copytree(common, source / 'common', symlinks=True, ignore=shutil.ignore_patterns('.git'))
            test_release.write_json(source / 'port/sources.json', {'common': {'revision': revision}})
            test_release.write_json(source / 'port/common-source-hashes.json', snapshot_common.hashes(source / 'common'))
            with patch.object(snapshot_common, 'ROOT', source), \
                    patch.dict(sys.modules, {'common_fixes': SimpleNamespace(applied=lambda *args: nullcontext())}):
                result = snapshot_common.snapshot(workspace)
            self.assertEqual(result['gki_files_verified'], 2)
            self.assertEqual((source / 'common/runner.sh').stat().st_mode & 0o777, 0o755)
            self.assertTrue((source / 'common/link').is_symlink())


if __name__ == '__main__':
    unittest.main()
