"""Exercise the real QDSS insertion against old and extended private clock structs."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


PATCH = Path(__file__).resolve().parents[1] / 'validation/clock_suspend_resume/common-qdss-diagnostic.patch'


def first_file_hunk(path, name):
    marker = f'diff --git a/{name} b/{name}\n'
    text = path.read_text().split(marker, 1)[1]
    hunks = list(re.finditer(r'(?m)^@@ ', text))
    return marker + text[:hunks[1].start()]


def insertion_patch():
    return first_file_hunk(PATCH, 'drivers/clk/clk.c')


def clock_source(extra=''):
    return ('\n' * 115 + 'struct clk {\n\tstruct hlist_node clks_node;\n' + extra +
            '};\n\n/***           runtime pm          ***/\n'
            'static int clk_pm_runtime_get(struct clk_core *core)\n{\n\treturn 0;\n}\n')


class QDSSReplay(unittest.TestCase):
    def test_real_insertion_preserves_original_and_extended_structs(self):
        patch = insertion_patch()
        additions = ''.join(line[1:] for line in patch.splitlines(keepends=True)
                            if line.startswith('+') and not line.startswith('+++'))
        for extra in ('', '\tbool pinning;\n', '\tbool pinning;\n\tunsigned int future_private_state;\n'):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory(prefix='qdss-replay-') as temp:
                root = Path(temp)
                source = root / 'drivers/clk/clk.c'
                source.parent.mkdir(parents=True)
                before = clock_source(extra)
                source.write_text(before)
                result = subprocess.run(['git', '-C', str(root), 'apply', '-'], input=patch,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                expected = before.replace('/***           runtime pm          ***/',
                                          additions + '/***           runtime pm          ***/', 1)
                self.assertEqual(source.read_text(), expected)

    def test_old_last_member_context_reproduces_the_reported_failure(self):
        patch = insertion_patch().replace('@@ -120,5 +120,26 @@\n };',
                                          '@@ -119,6 +119,27 @@\n \tstruct hlist_node clks_node;\n };')
        with tempfile.TemporaryDirectory(prefix='qdss-replay-negative-') as temp:
            root = Path(temp)
            source = root / 'drivers/clk/clk.c'
            source.parent.mkdir(parents=True)
            before = clock_source('\tbool pinning;\n')
            source.write_text(before)
            result = subprocess.run(['git', '-C', str(root), 'apply', '--check', '-'], input=patch,
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(source.read_text(), before)

    def test_droidspaces_include_preserves_both_upstream_header_layouts(self):
        path = PATCH.parents[2] / 'features/patches/droidspaces-618.patch'
        patch = first_file_hunk(path, 'ipc/shm.c')
        for extra in ('#include <linux/nstree.h>\n', ''):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory(prefix='droidspaces-replay-') as temp:
                root = Path(temp)
                source = root / 'ipc/shm.c'
                source.parent.mkdir(parents=True)
                before = ('\n' * 43 + '#include <linux/nsproxy.h>\n#include <linux/mount.h>\n'
                          '#include <linux/ipc_namespace.h>\n#include <linux/rhashtable.h>\n' + extra +
                          '\n#include <linux/uaccess.h>\n')
                source.write_text(before)
                result = subprocess.run(['git', '-C', str(root), 'apply', '-'], input=patch,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                expected = before.replace('#include <linux/ipc_namespace.h>\n',
                                          '#include <linux/ipc_namespace.h>\n#include <linux/sysv_task.h>\n', 1)
                self.assertEqual(source.read_text(), expected)
