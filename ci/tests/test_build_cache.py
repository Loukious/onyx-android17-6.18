import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_cache


class BuildCache(unittest.TestCase):
    def fixture(self, root):
        temporary, checkout = root / 'temporary', root / 'checkout'
        workspace = temporary / 'konoha-workspace'
        base = workspace / 'out/bazel/output_user_root/hash'
        kept = [temporary / 'kleaf-cache', base / 'action_cache', base / 'execroot/_main/bazel-out', checkout / 'source',
                base.parent / 'install', base.parent / 'cache']
        discarded = [checkout / 'artifacts', workspace / 'artifacts', workspace / '.repo', base / 'sandbox']
        for path in kept + discarded:
            path.mkdir(parents=True)
            (path / 'sentinel').write_text('retained or disposable fixture')
        (checkout / 'artifacts/release.json').write_text(json.dumps({'run_id': '123', 'run_attempt': '1'}))
        environment = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux',
                       'RUNNER_TEMP': str(temporary), 'GITHUB_WORKSPACE': str(checkout),
                       'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}
        return environment, kept, discarded

    def test_uploaded_copies_and_git_metadata_removed_without_touching_cache_or_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            environment, kept, discarded = self.fixture(Path(temporary))
            result = build_cache.prepare(environment)
            self.assertEqual(set(result['removed']), {str(p) for p in discarded})
            self.assertTrue(all((p / 'sentinel').is_file() for p in kept))
            self.assertTrue(all(not p.exists() for p in discarded))

    def test_local_runner_wrong_build_and_symlink_rejected_before_cleanup(self):
        for mode in ('local', 'other_build', 'symlink', 'manifest_symlink'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                environment, kept, discarded = self.fixture(root)
                if mode == 'local':
                    environment['GITHUB_ACTIONS'] = 'false'
                elif mode == 'other_build':
                    environment['GITHUB_RUN_ID'] = '456'
                elif mode == 'symlink':
                    repo = discarded[2]
                    repo.rename(root / 'outside')
                    repo.symlink_to(root / 'outside')
                else:
                    (root / 'outside').write_text('unrelated')
                    (Path(environment['RUNNER_TEMP']) / 'kleaf-cache-links.json').symlink_to(root / 'outside')
                with self.assertRaises(ValueError):
                    build_cache.prepare(environment)
                self.assertTrue(all((p / 'sentinel').is_file() for p in kept + discarded))

    def test_missing_cache_is_rejected_before_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            environment, kept, discarded = self.fixture(Path(temporary))
            (kept[1] / 'sentinel').unlink()
            kept[1].rmdir()
            with self.assertRaisesRegex(ValueError, 'complete stopped'):
                build_cache.prepare(environment)
            self.assertTrue(all((p / 'sentinel').is_file() for p in discarded))

    def test_exact_saved_cache_is_required_and_eventual_listing_is_retried(self):
        key = 'kleaf-v3-Linux-fixture-false-123-1'
        entry = {'id': 7, 'key': key, 'ref': 'refs/heads/ci', 'size_in_bytes': 4096, 'created_at': 'fixture'}
        responses = iter([{'actions_caches': []}, {'actions_caches': [entry]}])
        calls, waits = [], []
        def query(path):
            calls.append(path)
            return next(responses)
        self.assertEqual(build_cache.saved('owner/repo', key, query, waits.append), entry)
        self.assertEqual(len(calls), 2)
        self.assertEqual(waits, [5])
        for bad in ([], [{**entry, 'key': key + '-other'}], [{**entry, 'ref': 'refs/heads/other'}], [{**entry, 'size_in_bytes': 0}]):
            with self.subTest(entries=bad), self.assertRaisesRegex(ValueError, 'did not retain'):
                build_cache.saved('owner/repo', key, lambda _: {'actions_caches': bad}, lambda _: None)

    def test_current_v4_cache_key_is_confirmed_and_unknown_epochs_are_rejected(self):
        key = 'kleaf-v4-Linux-fixture-false-123-1'
        entry = {'id': 7, 'key': key, 'ref': 'refs/heads/ci', 'size_in_bytes': 4096, 'created_at': 'fixture'}
        self.assertEqual(build_cache.saved('owner/repo', key,
                                         lambda _: {'actions_caches': [entry]}), entry)
        for epoch in ('v2', 'v5'):
            with self.subTest(epoch=epoch), self.assertRaisesRegex(ValueError, 'Invalid cache'):
                build_cache.saved('owner/repo', key.replace('v4', epoch),
                                  lambda _: self.fail('Invalid cache keys cannot reach GitHub'))

    def test_workflow_executes_one_profile_per_runner_and_retains_legacy_cache_flags(self):
        workflow = (Path(__file__).resolve().parents[2] / '.github/workflows/build.yml').read_text()
        feature = workflow.split('      - name: Build the selected matched kernel', 1)[1].split(
            '      - name: Verify and archive the compiler output', 1)[0]
        legacy = workflow.split('      - name: Build legacy kernel and modules', 1)[1].split(
            '      - name: Download both current-run', 1)[0]
        required = 30 * 1024**3
        for variant, supported, diagnostic, available in [
                ('balanced', True, False, required), ('performance', True, True, required * 2),
                ('balanced', True, False, required - 1), ('legacy', True, True, 1),
                ('legacy', False, False, 1)]:
            features = variant != 'legacy'
            section = feature if features else legacy
            script = textwrap.dedent(section.split('        run: |\n', 1)[1])
            with self.subTest(variant=variant, supported=supported, diagnostic=diagnostic), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                port = root / 'source/port'
                port.mkdir(parents=True)
                commands = root / 'commands'
                commands.mkdir()
                (commands / 'df').write_text(
                    '#!/bin/sh\nif [ "$1" = "--output=avail" ]; then\n'
                    'printf "Avail\\n%s\\n" "$FEATURE_TEST_AVAILABLE"\n'
                    'else printf "fixture filesystem\\n"; fi\n')
                (commands / 'df').chmod(0o755)
                records, outputs = root / 'calls.jsonl', root / 'github-output'
                help_text = '--cache-dir' if supported else '--jobs'
                (port / 'build.py').write_text(textwrap.dedent(f'''\
                    import json
                    from pathlib import Path
                    import sys
                    if '--help' in sys.argv:
                        print({help_text!r})
                    else:
                        with Path({str(records)!r}).open('a') as output:
                            output.write(json.dumps(sys.argv[1:]) + '\\n')
                    '''))
                environment = {'PATH': str(commands) + os.pathsep + os.defpath,
                               'FEATURE_TEST_AVAILABLE': str(available), 'VARIANT': variant,
                               'DIAGNOSTIC': str(diagnostic).lower(),
                               'RUNNER_TEMP': str(root / 'temporary'), 'GITHUB_OUTPUT': str(outputs),
                               'KONOHA_BUILD_JOBS': '3', 'KONOHA_BUILD_MEMORY_MB': '8192'}
                result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], cwd=root, env=environment,
                                        capture_output=True, text=True)
                if features and available < required:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('At least 30 GiB', result.stderr)
                    self.assertFalse(records.exists())
                    continue
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = [json.loads(line) for line in records.read_text().splitlines()]
                self.assertEqual(len(calls), 1)
                call = calls[0]
                self.assertEqual(call[call.index('--jobs') + 1], '3')
                self.assertEqual(call[call.index('--memory-mb') + 1], '8192')
                self.assertEqual('--qdss-diagnostic' in call, diagnostic)
                self.assertEqual('--cache-dir' in call, not features and supported)
                recorded = outputs.read_text() if outputs.exists() else ''
                if features:
                    self.assertEqual(call[call.index('--variant') + 1], variant)
                    self.assertIn('--bazel-batch', call)
                    self.assertEqual(recorded, '')
                elif supported:
                    self.assertEqual(call[call.index('--cache-dir') + 1], str(root / 'temporary/kleaf-cache'))
                    self.assertEqual(recorded.strip(), 'cache_enabled=true')
        compiler = workflow.split('  compile:\n', 1)[1].split('  build:\n', 1)[0]
        self.assertNotIn('actions/cache/', compiler)
        for label in ('Restore Kleaf incremental build cache',
                      'Restore independent compiler cache files and timestamps'):
            step = workflow.split('      - name: ' + label, 1)[1].split('      - name:', 1)[0]
            self.assertIn("if: needs.resolve.outputs.feature_variants != 'true'", step)

    def test_cleanup_follows_upload_and_shutdown_and_save_is_confirmed(self):
        workflow = (Path(__file__).resolve().parents[2] / '.github/workflows/build.yml').read_text()
        labels = ['name: Upload build artifacts', 'name: Flush Bazel action cache',
                  'name: Reclaim uploaded copies', 'name: Save verified Kleaf', 'name: Confirm GitHub retained']
        offsets = [workflow.index(label) for label in labels]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn('python3 ci/build_cache.py confirm "$CACHE_KEY"', workflow)
        self.assertLess(workflow.index('python3 ci/build_cache.py restore'), workflow.index('name: Build legacy kernel and modules'))
        self.assertEqual(workflow.count('${{ runner.temp }}/kleaf-cache-links.json'), 2)

    def test_missing_manifest_is_only_allowed_for_a_cold_cache_miss(self):
        with tempfile.TemporaryDirectory() as temporary:
            environment, _, _ = self.fixture(Path(temporary))
            self.assertTrue(build_cache.restore(environment)['cold_build'])
            environment['CACHE_MATCHED_KEY'] = 'kleaf-v3-restored'
            with self.assertRaisesRegex(ValueError, 'missing'):
                build_cache.restore(environment)


if __name__ == '__main__':
    unittest.main()
