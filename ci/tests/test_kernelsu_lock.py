import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ci'))
import build_inputs
import kernelsu_lock
import track_upstream


class GitFixture(unittest.TestCase):
    def git(self, repo, *args):
        return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()

    def create(self, root, name, branch):
        repo = root / name
        repo.mkdir()
        self.git(repo, 'init', '-q', '-b', branch)
        self.git(repo, 'config', 'user.name', 'CI fixture')
        self.git(repo, 'config', 'user.email', 'ci@example.invalid')
        self.commit(repo, 'fixture.txt', 'initial')
        return repo

    def commit(self, repo, path, text):
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        self.git(repo, 'add', '.')
        self.git(repo, 'commit', '-qm', text)
        return self.git(repo, 'rev-parse', 'HEAD')

    def kernelsu(self, root):
        repo = self.create(root, 'kernelsu', 'dev')
        for path in ('kernel/Kbuild', 'uapi/ksu.h', 'LICENSE'):
            self.commit(repo, path, path)
        official = self.git(repo, 'rev-parse', 'HEAD')
        self.git(repo, 'tag', 'v3.4.2')
        self.git(repo, 'remote', 'add', 'origin', kernelsu_lock.REPOSITORY)
        return repo, official


class KernelSULockTests(GitFixture):
    def test_tracker_workflow_freezes_selected_repository_and_official_ancestor(self):
        workflow = (ROOT / '.github/workflows/upstream.yml').read_text()
        step = workflow.split('- name: Freeze detected KernelSU revision into the source candidate', 1)[1]
        step = step.split('- name:', 1)[0]
        self.assertIn('KERNELSU_REPOSITORY: ${{ steps.detect.outputs.latest_kernelsu_repository }}', step)
        self.assertIn('UPSTREAM_REVISION: ${{ steps.detect.outputs.latest_kernelsu_upstream_revision }}', step)
        self.assertIn('remote add origin "$KERNELSU_REPOSITORY"', step)
        self.assertIn('--upstream-revision "$UPSTREAM_REVISION"', step)

    def test_official_legacy_lock_and_fork_lock_use_selected_archive_and_official_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, official = self.kernelsu(root)
            legacy = kernelsu_lock.freeze(repo, official)
            self.assertEqual(set(legacy), kernelsu_lock.FIELDS)
            self.git(repo, 'remote', 'set-url', 'origin', kernelsu_lock.SUSFS_REPOSITORY)
            fork = self.commit(repo, 'kernel/susfs.c', 'builtin SUSFS')
            pin = kernelsu_lock.freeze(repo, fork, official)
            self.assertEqual(pin['upstream_revision'], official)
            self.assertEqual(pin['version'], legacy['version'])
            self.assertEqual(pin['git_commit_count'], legacy['git_commit_count'])
            self.assertLess(pin['git_commit_count'], int(self.git(repo, 'rev-list', '--count', fork)))
            archive = subprocess.check_output(['git', '-C', str(repo), 'archive', '--format=tar',
                                               fork, 'kernel', 'uapi', 'LICENSE'])
            self.assertEqual(pin['sha256'], hashlib.sha256(archive).hexdigest())
            self.assertNotEqual(pin['sha256'], legacy['sha256'])

    def test_fork_without_official_ancestor_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, official = self.kernelsu(Path(temporary))
            self.git(repo, 'remote', 'set-url', 'origin', kernelsu_lock.SUSFS_REPOSITORY)
            self.git(repo, 'checkout', '-q', '--orphan', 'unrelated')
            fork = self.commit(repo, 'kernel/fork.c', 'unrelated fork')
            with self.assertRaisesRegex(ValueError, 'contain the detected official'):
                kernelsu_lock.freeze(repo, fork, official)

    def test_builtin_lock_cannot_be_updated_to_plain_official_lkm(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, official = self.kernelsu(root)
            self.git(repo, 'remote', 'set-url', 'origin', kernelsu_lock.SUSFS_REPOSITORY)
            fork = self.commit(repo, 'kernel/susfs.c', 'builtin SUSFS')
            port = root / 'port'
            port.mkdir()
            lock = port / 'kernelsu-lock.json'
            lock.write_text(json.dumps(kernelsu_lock.freeze(repo, fork, official)))
            before = lock.read_bytes()
            with self.assertRaisesRegex(ValueError, 'pinned official dev ancestor'):
                kernelsu_lock.update(port, repo, official)
            self.assertEqual(lock.read_bytes(), before)

    def test_resolver_accepts_exact_fork_pin_and_rejects_official_revision(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, official = self.kernelsu(root)
            self.git(repo, 'remote', 'set-url', 'origin', kernelsu_lock.SUSFS_REPOSITORY)
            fork = self.commit(repo, 'kernel/susfs.c', 'builtin SUSFS')
            source = self.create(root, 'source', 'android17-6.18-lts')
            port = source / 'port'
            port.mkdir()
            (port / 'kernelsu-lock.json').write_text(json.dumps(kernelsu_lock.freeze(repo, fork, official)))
            self.assertEqual(build_inputs.resolve(source, source, fork)['kernelsu_revision'], fork)
            with self.assertRaisesRegex(ValueError, 'differs from the committed'):
                build_inputs.resolve(source, source, official)

    def test_fork_schema_requires_official_ancestor_and_selected_branch(self):
        pin = {'repository': kernelsu_lock.SUSFS_REPOSITORY, 'branch': kernelsu_lock.SUSFS_BRANCH,
               'revision': 'a' * 40, 'upstream_revision': 'b' * 40,
               'tag': 'v3.4.2', 'git_commit_count': 3554, 'version': 33554, 'sha256': 'c' * 64}
        self.assertEqual(kernelsu_lock.validate(pin), pin)
        for mutation in ({'upstream_revision': 'bad'}, {'branch': 'dev'},
                         {'repository': kernelsu_lock.REPOSITORY}):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                kernelsu_lock.validate(dict(pin, **mutation))


class BuiltinTrackingTests(GitFixture):
    def exercise(self, scenario):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            official, upstream = self.kernelsu(root)
            self.git(official, 'remote', 'set-url', 'origin', kernelsu_lock.SUSFS_REPOSITORY)
            self.git(official, 'checkout', '-qb', 'dev-susfs')
            locked = self.commit(official, 'kernel/susfs.c', 'builtin SUSFS')
            pin = kernelsu_lock.freeze(official, locked, upstream)
            source = self.create(root, 'source', 'android17-6.18-lts')
            kernel = self.create(root, 'kernel', 'android17-6.18-lts')
            current = self.git(kernel, 'rev-parse', 'HEAD')
            port = source / 'port'
            port.mkdir()
            (port / 'sources.json').write_text(json.dumps({'common': {'revision': current}}))
            (port / 'kernelsu-lock.json').write_text(json.dumps(pin))
            (port / 'components.json').write_text('{}')
            accepted = self.commit(source, 'accepted.txt', 'accepted fork lock')
            (root / 'ci').mkdir()
            (root / 'ci/last-built.json').write_text(json.dumps({
                'common_revision': current, 'kernelsu_revision': locked,
                'source_revision': accepted, 'release_tag': 'previous-release'}))
            before = (port / 'kernelsu-lock.json').read_bytes()
            if scenario in ('official-behind', 'official-merged', 'kernel-while-waiting'):
                self.git(official, 'checkout', '-q', 'dev')
                upstream = self.commit(official, 'kernel/official.c', 'official dev update')
                self.git(official, 'checkout', '-q', 'dev-susfs')
                if scenario == 'official-merged':
                    self.git(official, 'merge', '--quiet', '--no-edit', 'dev')
            if scenario == 'fork-only':
                self.commit(official, 'kernel/susfs.c', 'SUSFS update')
            if scenario == 'kernel-while-waiting':
                self.commit(kernel, 'Makefile', 'kernel update')
            tracking = {'repository': str(kernel), 'branch': 'android17-6.18-lts',
                        'kernelsu_repository': str(official), 'kernelsu_branch': 'dev',
                        'kernelsu_susfs_repository': str(official), 'kernelsu_susfs_branch': 'dev-susfs'}
            with patch.object(track_upstream, 'ROOT', root), patch.object(track_upstream, 'PORT', port), \
                    patch.object(track_upstream, 'TRACK', tracking), patch.dict(os.environ, {}, clear=True):
                result = track_upstream.detect()
            self.assertEqual((port / 'kernelsu-lock.json').read_bytes(), before)
            self.assertEqual(result['latest_official_kernelsu'], upstream)
            return result, locked

    def test_unchanged_builtin_inputs_do_not_make_candidate(self):
        result, _ = self.exercise('unchanged')
        self.assertFalse(result['candidate_needed'])
        self.assertFalse(result['kernelsu_upstream_waiting'])

    def test_fork_only_updates_make_candidate_without_losing_official_base(self):
        result, locked = self.exercise('fork-only')
        self.assertTrue(result['kernelsu_update_needed'])
        self.assertNotEqual(result['latest_kernelsu'], locked)
        self.assertEqual(result['latest_kernelsu_upstream_revision'], result['latest_official_kernelsu'])

    def test_new_official_dev_waits_for_fork_ancestry(self):
        result, locked = self.exercise('official-behind')
        self.assertTrue(result['kernelsu_upstream_waiting'])
        self.assertFalse(result['kernelsu_update_needed'])
        self.assertFalse(result['candidate_needed'])
        self.assertEqual(result['latest_kernelsu'], locked)

    def test_merged_official_dev_creates_exact_fork_candidate(self):
        result, locked = self.exercise('official-merged')
        self.assertFalse(result['kernelsu_upstream_waiting'])
        self.assertTrue(result['kernelsu_update_needed'])
        self.assertNotEqual(result['latest_kernelsu'], locked)
        self.assertEqual(result['latest_kernelsu_upstream_revision'], result['latest_official_kernelsu'])

    def test_kernel_updates_continue_with_current_builtin_pin_while_fork_lags(self):
        result, locked = self.exercise('kernel-while-waiting')
        self.assertTrue(result['kernelsu_upstream_waiting'])
        self.assertTrue(result['candidate_needed'])
        self.assertTrue(result['kernel_changed'])
        self.assertFalse(result['kernelsu_update_needed'])
        self.assertEqual(result['latest_kernelsu'], locked)


if __name__ == '__main__':
    unittest.main()
