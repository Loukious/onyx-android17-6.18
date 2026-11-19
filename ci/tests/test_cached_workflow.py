"""Cache wiring preserves immutable variants and complete artifact admission."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / '.github/workflows/build-cached.yml').read_text()


def job(name):
    return re.search(r'^  ' + name + r':\n(.*?)(?=^  [a-z_]+:\n|\Z)', WORKFLOW, re.M | re.S)[1]


class CachedWorkflowTests(unittest.TestCase):
    def test_new_workflow_is_manual_and_does_not_touch_release_status_or_concurrency(self):
        self.assertIn('workflow_dispatch:', WORKFLOW)
        self.assertNotIn('  push:', WORKFLOW)
        self.assertIn('group: onyx-cached-variants-v1', WORKFLOW)
        self.assertIn('cancel-in-progress: false', WORKFLOW)
        self.assertNotIn('ci/post_status.py', WORKFLOW)
        self.assertNotIn('ci/publish_release.py', WORKFLOW)

    def test_compilers_share_resolved_pins_and_use_two_independent_runners(self):
        compile = job('compile')
        self.assertIn('variant: [balanced, performance]', compile)
        self.assertIn('max-parallel: 2', compile)
        self.assertIn('fail-fast: false', compile)
        self.assertIn('ref: ${{ needs.resolve.outputs.source_revision }}', compile)
        self.assertIn('ref: ${{ needs.resolve.outputs.automation_revision }}', compile)
        self.assertIn('onyx-ccache-${{ matrix.variant }}', compile)
        self.assertIn('restore-keys: ${{ steps.compiler-key.outputs.prefix }}', compile)
        self.assertNotIn('--cache-dir', compile)
        self.assertNotIn('output_user_root', compile)

    def test_dependency_caches_are_exact_and_objects_verified_before_sync(self):
        compile = job('compile')
        source = compile.split('Restore exact pinned source objects', 1)[1].split('Restore exact pinned toolchain objects', 1)[0]
        toolchain = compile.split('Restore exact pinned toolchain objects', 1)[1].split('Verify restored pins', 1)[0]
        self.assertNotIn('restore-keys:', source + toolchain)
        self.assertLess(compile.index('Verify restored pins'), compile.index('Sync locked kernel'))
        self.assertIn('--reference "$RUNNER_TEMP/onyx-reference"', compile)
        self.assertEqual(compile.count("if: matrix.variant == 'balanced'"), 4)

    def test_compiler_cache_saved_only_after_verified_artifact_upload(self):
        compile = job('compile')
        self.assertLess(compile.index('matrix_artifacts.py pack'), compile.index('Upload the verified compiler output'))
        self.assertLess(compile.index('Upload the verified compiler output'), compile.index('Save bounded verified variant compiler results'))
        self.assertIn('cache_retention.py', compile)
        self.assertIn('compiler-cache-report.json', compile)

    def test_both_variants_are_reverified_and_packaged_after_success(self):
        assembly = job('build')
        self.assertIn('needs: [resolve, compile]', assembly)
        self.assertIn("needs.compile.result == 'success'", assembly)
        self.assertNotIn("needs.compile.result == 'skipped'", assembly)
        for script in ('matrix_artifacts.py collect', 'export_artifacts.py', 'installer_assets.py', 'recovery_assets.py'):
            self.assertIn(script, assembly)


if __name__ == '__main__':
    unittest.main()
