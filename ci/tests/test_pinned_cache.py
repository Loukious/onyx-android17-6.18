"""Restore real shallow Git objects without fetching, and reject corrupt caches."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pinned_cache
import bounded_cache


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def fixture(root):
    origin = root / 'upstream'
    origin.mkdir()
    git(origin, 'init', '-q')
    git(origin, 'config', 'user.name', 'Pin tests')
    git(origin, 'config', 'user.email', 'pins@example.invalid')
    (origin / 'first.c').write_text('int first;\n')
    git(origin, 'add', '.')
    git(origin, 'commit', '-qm', 'first')
    (origin / 'first.c').write_text('int first=2;\n')
    git(origin, 'commit', '-qam', 'second')
    revision = git(origin, 'rev-parse', 'HEAD')
    source, workspace = root / 'source', root / 'workspace'
    (source / 'port').mkdir(parents=True)
    objects = workspace / '.repo/project-objects/kernel/common.git'
    objects.parent.mkdir(parents=True)
    subprocess.run(['git', 'clone', '--bare', '--quiet', '--depth=1', origin.as_uri(), str(objects)], check=True)
    common = workspace / 'common'
    subprocess.run(['git', 'clone', '--quiet', '--shared', str(objects), str(common)], check=True)
    # Git clone --shared disallows shallow alternates; replicate repo's layout
    # using a worktree checkout of the shallow object repository.
    git(common, 'checkout', '--detach', revision)
    if (objects / 'shallow').exists():
        shutil.copyfile(objects / 'shallow', common / '.git/shallow')
    (source / 'port/sources.json').write_text(json.dumps({'common': {'revision': revision}, 'baseline': [],
                                                        'manifest': {'url': origin.as_uri()}}))
    (source / 'port/onyx-port.xml').write_text('<manifest/>')
    (source / 'port/dependency-lock.xml').write_text('<manifest/>')
    return source, workspace, revision


class PinnedTests(unittest.TestCase):
    def test_shallow_cache_restores_pinned_tree_without_upstream_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, workspace, revision = fixture(root)
            cache = root / 'cache'
            result = pinned_cache.save(cache, workspace, source, 'sources')
            shutil.rmtree(root / 'upstream')
            reference = root / 'reference'
            report = pinned_cache.restore(cache, reference, source, 'sources', result['key'])
            self.assertIn('kernel/common', report['repositories'])
            self.assertEqual(git(reference / 'kernel/common.git', 'show', revision + ':first.c'), 'int first=2;')
            checkout = root / 'new-checkout'
            subprocess.run(['git', 'clone', '--quiet', str(reference / 'kernel/common.git'), str(checkout)], check=True)
            self.assertEqual(git(checkout, 'rev-parse', 'HEAD'), revision)
            self.assertFalse((cache / 'kernel/common.git/objects/info/alternates').exists())

    def test_entire_repository_is_omitted_if_it_exceeds_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, workspace, _ = fixture(root)
            with patch.object(pinned_cache, 'budgets', return_value={'sources': 1024**2, 'toolchains': 1024**2}):
                report = pinned_cache.save(root / 'cache', workspace, source, 'sources')
            self.assertEqual(report['omitted'][0]['name'], 'kernel/common')
            self.assertLess(report['bytes'], 1024**2)
            self.assertFalse((root / 'cache/kernel/common.git').exists())

    def test_changed_lock_corrupt_objects_links_and_extra_files_rejected(self):
        for change in ('lock', 'object', 'link', 'extra'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source, workspace, _ = fixture(root)
                cache = root / 'cache'
                result = pinned_cache.save(cache, workspace, source, 'sources')
                if change == 'lock':
                    pins = json.loads((source / 'port/sources.json').read_text())
                    pins['common']['revision'] = 'a' * 40
                    (source / 'port/sources.json').write_text(json.dumps(pins))
                elif change == 'object':
                    pack = next((cache / 'kernel/common.git/objects/pack').glob('*.pack'))
                    pack.unlink()
                    pack.write_bytes(b'corrupt')
                elif change == 'link':
                    (cache / 'escape').symlink_to('/etc/passwd')
                else:
                    (cache / 'extra').write_text('unexpected')
                with self.assertRaises(ValueError):
                    pinned_cache.restore(cache, root / 'reference', source, 'sources', result['key'])

    def test_toolchain_keys_ignore_common_source_updates_and_reject_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, _, _ = fixture(Path(tmp))
            source_before = pinned_cache.identity(source, 'sources')[1]
            tools_before = pinned_cache.identity(source, 'toolchains')[1]
            pins = json.loads((source / 'port/sources.json').read_text())
            pins['common']['revision'] = 'b' * 40
            (source / 'port/sources.json').write_text(json.dumps(pins))
            self.assertNotEqual(source_before, pinned_cache.identity(source, 'sources')[1])
            self.assertEqual(tools_before, pinned_cache.identity(source, 'toolchains')[1])
            (source / 'port/dependency-lock.xml').write_text('<manifest><project name="../../escape" path="escape" revision="' + 'c' * 40 + '"/></manifest>')
            with self.assertRaises(ValueError):
                pinned_cache.projects(source)


if __name__ == '__main__':
    unittest.main()
