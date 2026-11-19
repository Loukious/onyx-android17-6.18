"""Frozen fork metadata and safe official-to-built-in source migration."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PORT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PORT))
import integrate_kernelsu as kernelsu
import prepare


class KernelSuPinTests(unittest.TestCase):
    def test_fork_lock_requires_official_anchor_and_matching_branch(self):
        pin = kernelsu.locked_pin()
        self.assertEqual(kernelsu.SUSFS_UPSTREAM, pin['repository'])
        self.assertEqual('dev-susfs', pin['branch'])
        for mutation in ({'branch': 'dev'}, {'upstream_revision': 'latest'},
                         {'version': pin['version'] + 14}):
            with self.subTest(mutation=mutation):
                invalid = dict(pin, **mutation)
                with self.assertRaises(ValueError):
                    kernelsu.validate_pin(invalid)
        del pin['upstream_revision']
        with self.assertRaises(ValueError):
            kernelsu.validate_pin(pin)

    def test_old_official_lock_remains_verifiable_during_migration(self):
        pin = kernelsu.locked_pin()
        pin['repository'] = kernelsu.UPSTREAM
        pin['branch'] = 'dev'
        pin['revision'] = pin.pop('upstream_revision')
        self.assertEqual(pin, kernelsu.validate_pin(pin))


class KernelSuRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / 'upstream'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'KernelSU source test')
        (self.repo / 'kernel').mkdir()
        (self.repo / 'uapi').mkdir()
        (self.repo / 'kernel/Kbuild').write_text(
            'obj-$(CONFIG_KSU) += kernelsu.o\nLPATH := old-version-discovery\n'
            'git-version := must-not-run\nKSU_NEW_DCACHE_FLUSH := unchanged\n')
        (self.repo / 'kernel/Kconfig').write_text('config KSU\n\ttristate "KernelSU"\n')
        (self.repo / 'uapi/ksu.h').write_text('/* Shared UAPI. */\n')
        (self.repo / 'LICENSE').write_text('fixture license\n')
        self.commit('official dev')
        self.base = self.git('rev-parse', 'HEAD')
        self.git('tag', 'v3.4.2')
        (self.repo / 'kernel/Kconfig').write_text(
            'config KSU\n\ttristate "KernelSU"\nconfig KSU_SUSFS\n\tbool "SUSFS"\n')
        self.commit('built-in SUSFS support')
        self.revision = self.git('rev-parse', 'HEAD')
        self.pin = {
            'repository': kernelsu.SUSFS_UPSTREAM, 'branch': 'dev-susfs',
            'revision': self.revision, 'upstream_revision': self.base,
            'tag': 'v3.4.2', 'git_commit_count': 1, 'version': 30001,
            'sha256': hashlib.sha256(self.archive(self.revision)).hexdigest(),
        }

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], text=True).strip()

    def commit(self, message):
        self.git('add', '.')
        self.git('commit', '-q', '-m', message)

    def archive(self, revision):
        return subprocess.check_output([
            'git', '-C', str(self.repo), 'archive', '--format=tar', revision,
            'kernel', 'uapi', 'LICENSE'])

    def common(self):
        common = self.root / 'workspace/common'
        (common / 'drivers').mkdir(parents=True)
        for name in ('Makefile', 'Kconfig'):
            (common / 'drivers' / name).write_text('original drivers ' + name + '\n')
        subprocess.run(['git', '-C', str(common), 'init', '-q'], check=True)
        subprocess.run(['git', '-C', str(common), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(common), '-c', 'user.name=test',
                        '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'common'],
                       check=True)
        revision = subprocess.check_output([
            'git', '-C', str(common), 'rev-parse', 'HEAD'], text=True).strip()
        self.enterContext(patch.object(kernelsu, 'COMMON_REVISION', revision))
        return common

    def test_fork_metadata_uses_official_count_and_tag(self):
        self.assertEqual('2', self.git('rev-list', '--count', self.revision))
        kernelsu.verify_repository_pin(self.repo, self.pin)
        for mutation in ({'git_commit_count': 2, 'version': 30002}, {'tag': 'v3.4.3'}):
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(ValueError, 'version metadata'):
                    kernelsu.verify_repository_pin(self.repo, dict(self.pin, **mutation))

    def test_fork_that_omits_official_revision_is_rejected(self):
        self.git('checkout', '-q', self.base)
        (self.repo / 'kernel/sibling.c').write_text('/* divergent official update */\n')
        self.commit('new official revision not included by fork')
        missing = self.git('rev-parse', 'HEAD')
        with self.assertRaisesRegex(ValueError, 'does not include'):
            kernelsu.verify_repository_pin(self.repo, dict(self.pin, upstream_revision=missing))

    def test_migrate_verified_official_tree_without_resetting_source(self):
        common = self.common()
        source = common.parent / '.kernelsu-next'
        source.mkdir()
        official = copy.deepcopy(self.pin)
        official['repository'] = kernelsu.UPSTREAM
        official['branch'] = 'dev'
        official['revision'] = official.pop('upstream_revision')
        original_archive = self.archive(self.base)
        official['sha256'] = hashlib.sha256(original_archive).hexdigest()
        (source / 'source.tar').write_bytes(original_archive)
        (source / 'source.json').write_text(json.dumps(official))
        files, _ = kernelsu.expected(common, require_lock=False)
        for name, data in files.items():
            target = common / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        self.assertIn(
            f'# Upstream dev {self.base}; see artifact inputs/kernelsu-next.\n',
            (common / 'drivers/kernelsu/Kbuild').read_text())

        subprocess.run(['git', 'clone', '-q', '--bare', str(self.repo), str(source / 'repo')],
                       check=True)
        subprocess.run(['git', '-C', str(source / 'repo'), 'remote', 'set-url',
                        'origin', kernelsu.UPSTREAM], check=True)
        prepared_inputs = self.root / 'prepare-inputs'
        prepared_inputs.mkdir()
        (prepared_inputs / 'sources.json').write_text(json.dumps({
            'common': {'revision': kernelsu.COMMON_REVISION}, 'baseline': [],
            'manifest': {'url': 'https://example.invalid/manifest', 'revision': 'f' * 40},
        }))
        for name in ('dependency-lock.xml', 'onyx-port.xml'):
            (prepared_inputs / name).write_text('<manifest />\n')
        (common.parent / '.repo/manifests.git').mkdir(parents=True)

        def prepared_git(path, *args):
            if path == common.parent / '.repo/manifests':
                return ('https://example.invalid/manifest' if args[0] == 'remote' else 'f' * 40)
            return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()

        with patch.object(kernelsu, 'locked_pin', return_value=self.pin):
            with patch.object(prepare, 'HERE', prepared_inputs), \
                    patch.object(prepare, 'git', side_effect=prepared_git), \
                    patch.object(sys, 'argv', ['prepare.py', str(common.parent), '--verify-only']):
                prepare.main()
            kernelsu.integrate(common)
            kernelsu.verify(common)

        kbuild = (common / 'drivers/kernelsu/Kbuild').read_text()
        self.assertIn('-DKSU_VERSION=30001', kbuild)
        self.assertIn(self.base, kbuild)
        self.assertNotIn('old-version-discovery', kbuild)
        self.assertNotIn('must-not-run', kbuild)
        self.assertIn('config KSU_SUSFS', (common / 'drivers/kernelsu/Kconfig').read_text())
        self.assertEqual(self.pin, json.loads((source / 'source.json').read_text()))

        (common / 'drivers/kernelsu/Kconfig').write_text('preserve user edit\n')
        with patch.object(kernelsu, 'locked_pin', return_value=self.pin):
            with self.assertRaisesRegex(ValueError, 'integration differs'):
                kernelsu.integrate(common)
        self.assertEqual('preserve user edit\n',
                         (common / 'drivers/kernelsu/Kconfig').read_text())


if __name__ == '__main__':
    unittest.main()
