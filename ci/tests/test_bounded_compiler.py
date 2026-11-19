"""Real compilation proves cache reuse and content/flag invalidation."""
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
import bounded_cache
import compiler_cache
import cache_retention


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def fixture(root):
    source, workspace = root / 'source', root / 'workspace'
    port = source / 'port'
    (port / 'features').mkdir(parents=True)
    (port / 'platform_defconfig').write_text('CONFIG_MODULES=y\n')
    (port / 'features/manifest.json').write_text('{"format":1}\n')
    original = workspace / 'prebuilts/clang/host/linux-x86/clang-r123'
    (original / 'bin').mkdir(parents=True)
    (original / 'AndroidVersion.txt').write_text('test compiler\nbased on r123\n')
    pinned = os.environ.get('ONYX_TEST_CLANG_DIR')
    if pinned:
        (original / 'lib').symlink_to(Path(pinned) / 'lib', target_is_directory=True)
    cc = str(Path(pinned) / 'bin/clang') if pinned else shutil.which('clang') or shutil.which('gcc')
    cxx = str(Path(pinned) / 'bin/clang++') if pinned else shutil.which('clang++') or shutil.which('g++')
    cc_real = str(Path(pinned) / 'bin/clang-real') if pinned else cc
    cxx_real = str(Path(pinned) / 'bin/clang++-real') if pinned else cxx
    for name, target in (('clang', cc), ('clang-real', cc_real), ('clang++', cxx), ('clang++-real', cxx_real)):
        (original / 'bin' / name).symlink_to(target)
    git(original.parent, 'init', '-q')
    git(original.parent, 'config', 'user.name', 'Cache tests')
    git(original.parent, 'config', 'user.email', 'cache@example.invalid')
    git(original.parent, 'add', '.')
    git(original.parent, 'commit', '-qm', 'pinned compiler')
    revision = git(original.parent, 'rev-parse', 'HEAD')
    (port / 'sources.json').write_text(json.dumps({'common': {'revision': 'a' * 40, 'clang': 'r123'},
                                               'baseline': [], 'manifest': {'url': 'https://example.invalid'}}))
    (port / 'onyx-port.xml').write_text('<manifest/>')
    (port / 'dependency-lock.xml').write_text(f'<manifest><extend-project name="platform/prebuilts/clang/host/linux-x86" '
                                             f'path="prebuilts/clang/host/linux-x86" revision="{revision}"/></manifest>')
    rc = workspace / 'build/kernel/kleaf/common.bazelrc'
    rc.parent.mkdir(parents=True)
    rc.write_text('try-import %workspace%/user.bazelrc\n')
    return source, workspace


class CompilerTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('ccache'), 'ccache required for actual reuse test')
    def test_real_compile_warm_hit_source_header_flags_and_profile_invalidation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, workspace = fixture(root)
            state = compiler_cache.setup(workspace, source, root / 'cache', root / 'control', 'balanced')
            if not os.environ.get('ONYX_TEST_CLANG_DIR') and not shutil.which('clang'):
                with Path(state['config']).open('a') as stream:
                    stream.write('compiler_type = gcc\n')
            binary = Path(state['toolchain']) / 'bin/clang'
            (workspace / 'value.h').write_text('#define VALUE 1\n')
            (workspace / 'sample.c').write_text('#include <stddef.h>\n#include <stdbool.h>\n#include "value.h"\nint answer(void) {return VALUE;}\n')
            output = workspace / 'sample.o'
            command = [str(binary), '-c', '-O2', '-I.', 'sample.c', '-o', 'sample.o']
            def compile():
                output.unlink(missing_ok=True)
                subprocess.run(command, cwd=workspace, check=True, capture_output=True)
                return output.read_bytes(), compiler_cache.stats(state['config'])
            cold, counts = compile()
            self.assertEqual(counts['cache_miss'], 1)
            warm, counts = compile()
            self.assertEqual(cold, warm)
            self.assertEqual(counts['direct_cache_hit'] + counts['preprocessed_cache_hit'], 1)
            (workspace / 'value.h').write_text('#define VALUE 2\n')
            changed, counts = compile()
            self.assertNotEqual(cold, changed)
            self.assertEqual(counts['cache_miss'], 2)
            (workspace / 'sample.c').write_text('int answer(void) {return 3;}\n')
            _, counts = compile()
            self.assertEqual(counts['cache_miss'], 3)
            command[2] = '-O0'
            _, counts = compile()
            self.assertEqual(counts['cache_miss'], 4)
            left = compiler_cache.compatibility(source, 'balanced')[1]
            self.assertNotEqual(left, compiler_cache.compatibility(source, 'performance')[1])
            self.assertNotEqual(left, compiler_cache.compatibility(source, 'balanced', True)[1])
            (source / 'port/platform_defconfig').write_text('CONFIG_MODULES=n\n')
            self.assertNotEqual(left, compiler_cache.compatibility(source, 'balanced')[1])

    @unittest.skipUnless(shutil.which('ccache'), 'ccache required for sandbox relocation test')
    def test_kleaf_prefix_maps_reuse_objects_across_sandbox_locations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, workspace = fixture(root)
            state = compiler_cache.setup(workspace, source, root / 'cache', root / 'control', 'balanced')
            if not os.environ.get('ONYX_TEST_CLANG_DIR') and not shutil.which('clang'):
                with Path(state['config']).open('a') as stream:
                    stream.write('compiler_type = gcc\n')
            objects = []
            for name in ('sandbox-1', 'sandbox-2'):
                sandbox = workspace / name
                sandbox.mkdir()
                (sandbox / 'sample.c').write_text('int value(void) {return 42;}\n')
                subprocess.run([str(Path(state['toolchain']) / 'bin/clang'), '-c', '-g', '-O2',
                                f'-ffile-prefix-map={sandbox}=/proc/self/cwd', 'sample.c', '-o', 'sample.o'],
                               cwd=sandbox, check=True, capture_output=True)
                objects.append((sandbox / 'sample.o').read_bytes())
            self.assertEqual(objects[0], objects[1])
            counts = compiler_cache.stats(state['config'])
            self.assertEqual(counts['cache_miss'], 1)
            self.assertEqual(counts['direct_cache_hit'] + counts['preprocessed_cache_hit'], 1)

    def test_compiler_key_reuses_ordinary_source_edits_and_rejects_different_engine(self):
        if not shutil.which('ccache'):
            self.skipTest('ccache not installed')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, _ = fixture(root)
            left = compiler_cache.compatibility(source, 'balanced')[1]
            (source / 'ordinary-driver.c').write_text('changed source\n')
            self.assertEqual(left, compiler_cache.compatibility(source, 'balanced')[1])
            engine = root / 'other-engine'
            engine.write_text('#!/bin/sh\necho "ccache other version"\n')
            engine.chmod(0o755)
            self.assertNotEqual(left, compiler_cache.compatibility(source, 'balanced', ccache=engine)[1])


class BoundTests(unittest.TestCase):
    def test_default_and_increased_limits_validate_both_variants_and_budget(self):
        self.assertEqual(bounded_cache.budgets({})['compiler'], 3 * 1024**3)
        with self.assertRaisesRegex(ValueError, 'fit the declared'):
            bounded_cache.budgets({'ONYX_COMPILER_CACHE_MIB': '8192'})
        self.assertEqual(bounded_cache.budgets({'ONYX_COMPILER_CACHE_MIB': '8192',
                                               'ONYX_BUDGET_CACHE_MIB': '32768'})['compiler'], 8 * 1024**3)
        for value in ('-1', '1.5', 'NaN', '0', '65537'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bounded_cache.budgets({'ONYX_COMPILER_CACHE_MIB': value})

    def test_stopped_cache_evicts_old_results_without_removing_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'a/b').mkdir(parents=True)
            metadata = root / 'identity.json'
            metadata.write_text('{}')
            for index in range(3):
                p = root / 'a/b' / (str(index) + 'R')
                p.write_bytes(b'x' * 4096)
                os.utime(p, ns=(index + 1, index + 1))
            result = bounded_cache.trim_compiler(root, 2 * 4096)
            self.assertLessEqual(bounded_cache.size(root), 8192)
            self.assertFalse((root / 'a/b/0R').exists())
            self.assertTrue(metadata.exists())
            self.assertGreater(result['evicted_bytes'], 0)

    def test_links_and_special_files_cannot_escape_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'escape').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(ValueError, 'link or special'):
                bounded_cache.size(root)
            with self.assertRaisesRegex(ValueError, 'symlinks'):
                bounded_cache.directory(root / 'escape')

    def test_retention_checks_exact_key_branch_and_positive_size(self):
        key = 'onyx-ccache-v1-Linux-balanced-' + 'a' * 64 + '-123-1'
        with self.assertRaises(ValueError):
            cache_retention.confirm('owner/repo', [key], query=lambda _: {'actions_caches': []}, delay=lambda _: None)
        entry = {'key': key, 'ref': 'refs/heads/ci', 'size_in_bytes': 123}
        self.assertEqual(cache_retention.confirm('owner/repo', [key], query=lambda _: {'actions_caches': [entry]}), [entry])
        with self.assertRaises(ValueError):
            cache_retention.confirm('owner/repo', ['kleaf-v3-old'], query=lambda _: None)


if __name__ == '__main__':
    unittest.main()
