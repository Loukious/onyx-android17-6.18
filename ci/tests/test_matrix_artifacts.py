import copy
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_inputs
import export_artifacts
import matrix_artifacts
import publish_release
import test_release
import test_variant_releases


CONTEXT = {'source_revision': test_release.SOURCE, 'automation_revision': 'e' * 40,
           'kernelsu_revision': test_release.KSU, 'run_id': '123', 'run_attempt': '1'}


def fixture(root):
    source, _, builds = test_variant_releases.fixture(root)
    inputs = root / 'compiler-inputs'
    inputs.mkdir()
    for variant, (artifact, report) in builds.items():
        # Each compiler starts with its own workspace and produces just one build.
        workspace = root / ('runner-' + variant)
        target = workspace / 'artifacts' / artifact.name
        shutil.copytree(artifact, target)
        (target / 'mode-check.sh').write_text('#!/bin/sh\nexit 0\n')
        (target / 'mode-check.sh').chmod(0o755)
        test_variant_releases.rehash(target, report)
        output = inputs / matrix_artifacts.name(variant, CONTEXT)
        matrix_artifacts.pack(workspace, output, source, variant, CONTEXT)
    return source, inputs


class MatrixArtifactTests(unittest.TestCase):
    def test_two_runner_roundtrip_preserves_modes_and_existing_release_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, inputs = fixture(root)
            workspace = root / 'combined'
            matrix_artifacts.collect(inputs, workspace, source, CONTEXT)
            for artifact in (workspace / 'artifacts').iterdir():
                self.assertEqual((artifact / 'mode-check.sh').stat().st_mode & 0o777, 0o755)
            identity = export_artifacts.export(workspace, root / 'bundle', source,
                                               test_release.SOURCE, '123', '1')
            self.assertEqual([row['id'] for row in identity['variants']], ['balanced', 'performance'])
            self.assertEqual(publish_release.validate_bundle(root / 'bundle', source, test_release.SOURCE,
                             test_release.KERNEL, test_release.KSU, '123', '1'), identity)

    def test_missing_runner_and_unexpected_artifact_reject_before_output(self):
        for missing in (True, False):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, inputs = fixture(root)
                if missing:
                    shutil.rmtree(inputs / matrix_artifacts.name('performance', CONTEXT))
                else:
                    (inputs / 'unrelated-artifact').mkdir()
                with self.assertRaisesRegex(ValueError, 'both current-run'):
                    matrix_artifacts.collect(inputs, root / 'combined', source, CONTEXT)
                self.assertFalse((root / 'combined').exists())

    def test_different_source_ci_ksu_run_attempt_or_variant_is_rejected_before_output(self):
        for key in (*matrix_artifacts.SHARED, 'variant'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, inputs = fixture(root)
                path = inputs / matrix_artifacts.name('performance', CONTEXT) / 'input.json'
                identity = json.loads(path.read_text())
                identity[key] = 'balanced' if key == 'variant' else '2' if key.startswith('run_') else 'f' * 40
                path.write_text(json.dumps(identity))
                with self.assertRaisesRegex(ValueError, 'different variant, commit, run or attempt'):
                    matrix_artifacts.collect(inputs, root / 'combined', source, CONTEXT)
                self.assertFalse((root / 'combined').exists())

    def test_payload_corruption_and_duplicate_roots_are_rejected_before_output(self):
        for bad in ('payload', 'root', 'common'):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, inputs = fixture(root)
                performance = inputs / matrix_artifacts.name('performance', CONTEXT)
                identity = json.loads((performance / 'input.json').read_text())
                if bad == 'payload':
                    with (performance / 'payload.tar.gz').open('ab') as stream:
                        stream.write(b'corrupted bytes')
                elif bad == 'root':
                    other = inputs / matrix_artifacts.name('balanced', CONTEXT) / 'input.json'
                    identity['artifact_root'] = json.loads(other.read_text())['artifact_root']
                else:
                    identity['common_revision'] = 'f' * 40
                (performance / 'input.json').write_text(json.dumps(identity))
                with self.assertRaises(ValueError):
                    matrix_artifacts.collect(inputs, root / 'combined', source, CONTEXT)
                self.assertFalse((root / 'combined').exists())

    def test_archive_links_traversal_and_duplicate_members_cannot_be_extracted(self):
        for bad in ('symlink', 'hardlink', 'traversal', 'duplicate'):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, inputs = fixture(root)
                folder = inputs / matrix_artifacts.name('performance', CONTEXT)
                identity = json.loads((folder / 'input.json').read_text())
                payload = folder / 'payload.tar.gz'
                with tarfile.open(payload, 'w:gz') as archive:
                    member = tarfile.TarInfo(identity['artifact_root'] + '/escape')
                    if bad in ('symlink', 'hardlink'):
                        member.type = tarfile.SYMTYPE if bad == 'symlink' else tarfile.LNKTYPE
                        member.linkname = str(root / 'outside')
                    elif bad == 'traversal':
                        member.name = '../outside'
                    archive.addfile(member, io.BytesIO())
                    if bad == 'duplicate':
                        archive.addfile(member, io.BytesIO())
                identity['payload_sha256'] = matrix_artifacts.digest(payload)
                (folder / 'input.json').write_text(json.dumps(identity))
                with self.assertRaisesRegex(ValueError, 'Unsafe|unsafe|duplicated'):
                    matrix_artifacts.collect(inputs, root / 'combined', source, CONTEXT)
                self.assertFalse((root / 'outside').exists())
                self.assertFalse((root / 'combined/artifacts').exists())

    def test_rehashed_transfer_still_requires_built_features(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, inputs = fixture(root)
            folder = inputs / matrix_artifacts.name('performance', CONTEXT)
            identity = json.loads((folder / 'input.json').read_text())
            extracted = root / 'extracted'
            with tarfile.open(folder / 'payload.tar.gz', 'r:gz') as archive:
                archive.extractall(extracted, filter='data')
            artifact = extracted / identity['artifact_root']
            report = json.loads((artifact / 'report.json').read_text())
            (artifact / 'gki/kernel_aarch64_dot_config').write_text('CONFIG_KSU=y\nCONFIG_MODVERSIONS=y\n')
            test_variant_releases.rehash(artifact, report)
            with tarfile.open(folder / 'payload.tar.gz', 'w:gz') as archive:
                archive.add(artifact, arcname=identity['artifact_root'])
            identity.update(payload_sha256=matrix_artifacts.digest(folder / 'payload.tar.gz'),
                            report_sha256=matrix_artifacts.digest(artifact / 'report.json'))
            (folder / 'input.json').write_text(json.dumps(identity))
            with self.assertRaisesRegex(ValueError, 'NTSync build feature is missing'):
                matrix_artifacts.collect(inputs, root / 'combined', source, CONTEXT)
            self.assertFalse((root / 'combined/artifacts').exists())

    def test_runner_with_multiple_builds_cannot_pack_one_arbitrarily(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, workspace, _ = test_variant_releases.fixture(root)
            with self.assertRaisesRegex(ValueError, 'exactly one complete'):
                matrix_artifacts.pack(workspace, root / 'output', source, 'balanced', CONTEXT)
            self.assertFalse((root / 'output').exists())

    def test_wrong_variant_or_automation_is_rejected_before_transfer_creation(self):
        for changed in ('variant', 'automation'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, _ = fixture(root)
                context = copy.deepcopy(CONTEXT)
                if changed == 'automation':
                    context['automation_revision'] = 'f' * 40
                with self.assertRaisesRegex(ValueError, 'resolved variant or build inputs'):
                    matrix_artifacts.pack(root / 'runner-balanced', root / 'output', source,
                                          'performance' if changed == 'variant' else 'balanced', context)
                self.assertFalse((root / 'output').exists())


class BuildInputTests(unittest.TestCase):
    def test_resolution_uses_the_committed_lock_and_complete_checkout_revisions(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / 'port/features').mkdir(parents=True)
            (source / 'port/features/manifest.json').write_text('{}')
            with patch.object(build_inputs.kernelsu_lock, 'check', return_value={'revision': 'c' * 40}), \
                    patch.object(build_inputs.subprocess, 'check_output', side_effect=['a' * 40, 'e' * 40]):
                result = build_inputs.resolve(source, Path('/automation'))
            self.assertEqual(result, {'source_revision': 'a' * 40, 'automation_revision': 'e' * 40,
                                      'kernelsu_revision': 'c' * 40, 'feature_variants': 'true'})

    def test_features_without_a_locked_ksu_revision_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / 'port/features').mkdir(parents=True)
            (source / 'port/features/manifest.json').write_text('{}')
            with patch.object(build_inputs.kernelsu_lock, 'check', return_value={'revision': ''}), \
                    self.assertRaisesRegex(ValueError, 'committed KernelSU'):
                build_inputs.resolve(source, Path('/automation'))


if __name__ == '__main__':
    unittest.main()
