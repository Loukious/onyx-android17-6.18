import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest

WORKFLOW = (Path(__file__).resolve().parents[2] / '.github/workflows/build.yml').read_text()


def job(name):
    return re.search(r'^  ' + name + r':\n(.*?)(?=^  [a-z_]+:\n|\Z)', WORKFLOW,
                     re.MULTILINE | re.DOTALL)[1]


class ParallelWorkflowTests(unittest.TestCase):
    def test_runners_share_resolved_commits_and_publication_waits_for_complete_build(self):
        compiler = job('compile')
        self.assertIn('needs: resolve', compiler)
        self.assertIn('variant: [balanced, performance]', compiler)
        self.assertIn('max-parallel: 2', compiler)
        self.assertIn('fail-fast: false', compiler)
        self.assertIn('ref: ${{ needs.resolve.outputs.source_revision }}', compiler)
        self.assertIn('ref: ${{ needs.resolve.outputs.automation_revision }}', compiler)
        self.assertNotIn('ref: ${{ inputs.', compiler)
        self.assertIn('needs: [resolve, compile]', job('build'))
        self.assertIn("needs.compile.result == 'success' || needs.compile.result == 'skipped'", job('build'))
        self.assertIn('merge-multiple: false', job('build'))
        self.assertIn('Onyx-GKI-Input-*-${{ github.run_id }}-${{ github.run_attempt }}', job('build'))
        self.assertIn('needs: build', job('release'))
        self.assertIn("always() && needs.build.result == 'success'", job('release'))

    def test_compiler_failure_cancellation_and_skipped_assembly_cannot_post_success(self):
        section = job('status').split('      - name: Record complete source build result', 1)[1]
        script = textwrap.dedent(section.split('        run: |\n', 1)[1])
        for resolve, compile, build, expected in [
                ('success', 'success', 'success', 'success'),
                ('success', 'skipped', 'success', 'success'),  # Legacy build.
                ('success', 'failure', 'skipped', 'failure'),
                ('failure', 'skipped', 'skipped', 'failure'),
                ('success', 'success', 'failure', 'failure'),
                ('success', 'skipped', 'skipped', 'failure'),
                ('success', 'cancelled', 'skipped', 'cancelled'),
                ('success', 'success', 'cancelled', 'cancelled')]:
            with self.subTest(resolve=resolve, compile=compile, build=build), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / 'ci').mkdir()
                calls = root / 'calls.json'
                (root / 'ci/post_status.py').write_text(
                    'import json, sys\nfrom pathlib import Path\n'
                    f'Path({str(calls)!r}).write_text(json.dumps(sys.argv[1:]))\n')
                result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], cwd=root,
                            env={**os.environ, 'RESOLVE_RESULT': resolve, 'COMPILE_RESULT': compile,
                                 'BUILD_RESULT': build, 'REVISION': 'a' * 40},
                            capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(calls.read_text()), ['a' * 40, expected])


if __name__ == '__main__':
    unittest.main()
