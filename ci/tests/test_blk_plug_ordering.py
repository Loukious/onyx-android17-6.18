import difflib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import blk_plug_ordering as ordering
import refresh_recipe


FLUSH = """void __blk_flush_plug(struct blk_plug *plug, bool from_schedule)
{
	if (!list_empty(&plug->cb_list))
		flush_plug_callbacks(plug, from_schedule);
	blk_mq_flush_plug_list(plug, from_schedule);
	if (unlikely(!rq_list_empty(&plug->cached_rqs)))
		blk_mq_free_plug_rqs(plug);
	plug->cur_ktime = 0;
	current->flags &= ~PF_BLOCK_TS;
}
"""
FINISH = """void blk_finish_plug(struct blk_plug *plug)
{
	if (plug == current->plug) {
		__blk_flush_plug(plug, false);
		current->plug = NULL;
	}
}
"""
FIXED = FINISH.replace(
    '\t\tcurrent->plug = NULL;',
    '\t\t/* Preserve timestamp state until detach. */\n'
    '\t\tbarrier();\n\t\tcurrent->plug = NULL;')
FLUSH_FIXED = FLUSH.replace(
    '\tcurrent->flags &= ~PF_BLOCK_TS;',
    '\tcurrent->flags &= ~PF_BLOCK_TS;\n\tbarrier();')


def source(flush=FLUSH, finish=FINISH):
    return (flush + '\n' + finish).encode()


def barrier_patch(fixed=FIXED):
    return (f'diff --git a/{ordering.SOURCE} b/{ordering.SOURCE}\n' +
            ''.join(difflib.unified_diff(
                FINISH.splitlines(keepends=True), fixed.splitlines(keepends=True),
                fromfile='a/' + ordering.SOURCE, tofile='b/' + ordering.SOURCE))).encode()


class OrderingTests(unittest.TestCase):
    def test_current_unsafe_ordering_needs_patch(self):
        self.assertEqual(ordering.classify(source()), ordering.NEEDS_BARRIER)

    def test_unconditional_barrier_in_either_function_is_recognized(self):
        for flush, finish, expected in [
                (FLUSH, FIXED, 'barrier_in_finish'),
                (FLUSH_FIXED, FINISH, 'barrier_in_flush'),
                (FLUSH_FIXED, FIXED, 'barrier_in_finish')]:
            with self.subTest(expected=expected):
                self.assertEqual(ordering.classify(source(flush, finish)), expected)

    def test_comments_spacing_and_unrelated_functions_do_not_control_detection(self):
        updated = FIXED.replace('/* Preserve timestamp state until detach. */',
                                '// A differently worded upstream comment')
        updated = updated.replace('\t', '    ').replace('barrier();', 'barrier ( );')
        text = source(finish=updated)
        text += b'\nvoid unrelated(void) { barrier(); }\n'
        self.assertEqual(ordering.classify(text), 'barrier_in_finish')
        self.assertEqual(ordering.classify(
            b'/* ' + source(finish=FIXED) + b' */\n' + source()),
            ordering.NEEDS_BARRIER)
        self.assertEqual(ordering.classify(
            b'const char *example = "void blk_finish_plug(struct blk_plug *plug) '
            b'{ barrier(); }";\n' + source()), ordering.NEEDS_BARRIER)

    def test_comments_and_unrelated_barriers_do_not_retire_the_patch(self):
        text = source(finish=FINISH.replace(
            '\t\tcurrent->plug = NULL;',
            '\t\t/* barrier(); */\n\t\tcurrent->plug = NULL;'))
        text += b'\nvoid unrelated(void) { barrier(); }\n'
        self.assertEqual(ordering.classify(text), ordering.NEEDS_BARRIER)

    def test_incorrect_barrier_positions_and_conditional_barriers_require_review(self):
        variants = [
            FINISH.replace('\t\t__blk_flush_plug', '\t\tbarrier();\n\t\t__blk_flush_plug'),
            FINISH.replace('\t\tcurrent->plug = NULL;',
                           '\t\tcurrent->plug = NULL;\n\t\tbarrier();'),
            FIXED.replace('barrier();', 'if (plug->cur_ktime) barrier();'),
            FIXED.replace('barrier();', '#if 0\nbarrier();\n#endif'),
            FIXED.replace('barrier();', 'asm volatile("");'),
        ]
        for finish in variants:
            with self.subTest(finish=finish), self.assertRaisesRegex(ValueError, 'review'):
                ordering.classify(source(finish=finish))

    def test_helper_must_still_clear_the_flag_unconditionally(self):
        variants = [
            FLUSH.replace('current->flags &= ~PF_BLOCK_TS;', ''),
            FLUSH.replace('current->flags &= ~PF_BLOCK_TS;',
                          'if (plug->cur_ktime) current->flags &= ~PF_BLOCK_TS;'),
            FLUSH.replace('plug->cur_ktime = 0;', 'if (from_schedule) return;'),
            FLUSH.replace('~PF_BLOCK_TS', '~PF_OTHER'),
            FLUSH.replace('current->flags &= ~PF_BLOCK_TS;',
                          'barrier(); current->flags &= ~PF_BLOCK_TS;'),
        ]
        for flush in variants:
            with self.subTest(flush=flush), self.assertRaisesRegex(ValueError, 'review'):
                ordering.classify(source(flush=flush, finish=FIXED))

    def test_missing_ambiguous_conditional_and_macro_definitions_require_review(self):
        variants = [
            b'', None,
            source() + FIXED.encode(),
            FLUSH.encode() + b'\n#if 0\n' + FIXED.encode() + b'\n#endif\n',
            b'#define barrier() do {} while (0)\n' + source(finish=FIXED),
            b'#define PF_BLOCK_TS 0\n' + source(finish=FIXED),
        ]
        for text in variants:
            with self.subTest(source=text), self.assertRaisesRegex(ValueError, 'review'):
                ordering.classify(text)

    def test_an_unused_multiline_macro_is_not_a_function_definition(self):
        text = (b'#define example \\\n' +
                FIXED.encode().replace(b'\n', b'\\\n') + b'\n' + source())
        self.assertEqual(ordering.classify(text), ordering.NEEDS_BARRIER)

    def test_only_the_reviewed_barrier_delta_can_be_retired(self):
        ordering.validate_patch(barrier_patch())
        for changed in [FIXED.replace('barrier();', 'barrier(); audit();'),
                        FIXED.replace('current->plug = NULL;', 'other->plug = NULL;'),
                        FIXED.replace('barrier();', 'if (plug) barrier();')]:
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'review'):
                ordering.validate_patch(barrier_patch(changed))


class RefreshOrderingTests(unittest.TestCase):
    def setup_fixture(self, root, block_source=None):
        port, common = root / 'port', root / 'common'
        patches = port / 'common-patches'
        diagnostic = port / 'validation/clock_suspend_resume'
        patches.mkdir(parents=True)
        diagnostic.mkdir(parents=True)
        (common / 'block').mkdir(parents=True)
        (common / 'drivers').mkdir()
        (common / ordering.SOURCE).write_bytes(
            source() if block_source is None else block_source)
        (common / 'drivers/other.c').write_text('old\n')
        (common / 'drivers/diag.c').write_text('original\n')
        replay = (b'--- a/drivers/other.c\n+++ b/drivers/other.c\n'
                  b'@@ -1 +1 @@\n-old\n+fixed\n' + barrier_patch())
        (patches / 'required.patch').write_bytes(replay)
        (patches / 'effective.patch').write_bytes(replay)
        (patches / 'manifest.json').write_text(json.dumps({
            'patch': 'effective.patch',
            'replay_patch': 'required.patch',
            'files': {'drivers/other.c': {}, ordering.SOURCE: {}},
            'upstream_checks': {ordering.SOURCE: ordering.CHECK},
        }))
        (diagnostic / 'common-qdss-diagnostic.patch').write_bytes(
            b'--- a/drivers/diag.c\n+++ b/drivers/diag.c\n'
            b'@@ -1 +1 @@\n-original\n+logged\n')
        (diagnostic / 'source-validation.json').write_text(
            json.dumps({'files': {'drivers/diag.c': {}}}))
        return port, common

    def refresh(self, port, common):
        with patch.object(refresh_recipe, 'PORT', port):
            result = refresh_recipe.refresh(common)
        return result, json.loads((port / 'common-patches/manifest.json').read_text())

    def assert_preserved_on_failure(self, root, port, common):
        def snapshot():
            return {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
        before = snapshot()
        with self.assertRaises(ValueError):
            self.refresh(port, common)
        self.assertEqual(before, snapshot())

    def test_apply_barrier_and_record_exact_build_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            port, common = self.setup_fixture(Path(temporary))
            result, manifest = self.refresh(port, common)
            self.assertEqual(result['active_common_patches'], 2)
            self.assertEqual(manifest['integrated_upstream'], [])
            self.assertEqual(manifest['upstream_check_results'][ordering.SOURCE],
                             {'status': 'applied_locally', 'evidence': 'barrier_in_finish'})
            self.assertEqual(manifest['files'][ordering.SOURCE], {
                'before_sha256': refresh_recipe.sha(source()),
                'candidate_sha256': refresh_recipe.sha(source(finish=FIXED)),
            })
            self.assertEqual((common / ordering.SOURCE).read_bytes(), source())

    def test_exact_and_equivalent_upstream_fixes_are_retired(self):
        for text, evidence in [
                (source(finish=FIXED), 'barrier_in_finish'),
                (source(finish=FIXED.replace(
                    '/* Preserve timestamp state until detach. */',
                    '/* Upstream explanation. */')), 'barrier_in_finish'),
                (source(flush=FLUSH_FIXED), 'barrier_in_flush')]:
            with self.subTest(evidence=evidence), tempfile.TemporaryDirectory() as temporary:
                port, common = self.setup_fixture(Path(temporary), text)
                replay = (port / 'common-patches/required.patch').read_bytes()
                result, manifest = self.refresh(port, common)
                self.assertEqual(result['active_common_patches'], 1)
                self.assertEqual(manifest['integrated_upstream'], [ordering.SOURCE])
                self.assertNotIn(b'blk-core.c', (port / 'common-patches/effective.patch').read_bytes())
                self.assertEqual((port / 'common-patches/required.patch').read_bytes(), replay)
                self.assertEqual((common / ordering.SOURCE).read_bytes(), text)
                self.assertEqual(manifest['files'][ordering.SOURCE], {
                    'before_sha256': refresh_recipe.sha(text),
                    'candidate_sha256': refresh_recipe.sha(text),
                })
                self.assertEqual(manifest['upstream_check_results'][ordering.SOURCE],
                                 {'status': 'integrated_upstream', 'evidence': evidence})

    def test_upstream_helper_barrier_is_detected_even_when_patch_would_apply(self):
        with tempfile.TemporaryDirectory() as temporary:
            port, common = self.setup_fixture(Path(temporary), source(flush=FLUSH_FIXED))
            self.assertTrue(refresh_recipe.replay(common, barrier_patch()))
            result, _ = self.refresh(port, common)
            self.assertEqual(result['already_integrated_upstream'], [ordering.SOURCE])

    def test_a_later_upstream_revert_reenables_the_retained_patch(self):
        with tempfile.TemporaryDirectory() as temporary:
            port, common = self.setup_fixture(Path(temporary), source(finish=FIXED))
            self.refresh(port, common)
            (common / ordering.SOURCE).write_bytes(source())
            result, manifest = self.refresh(port, common)
            self.assertEqual(result['active_common_patches'], 2)
            self.assertEqual(manifest['integrated_upstream'], [])
            self.assertIn(b'barrier();', (port / 'common-patches/effective.patch').read_bytes())

    def test_unrecognized_source_stops_without_changing_recipe_or_common(self):
        variants = [
            source(finish=FIXED.replace('barrier();', 'if (plug) barrier();')),
            source(flush=FLUSH.replace('current->flags &= ~PF_BLOCK_TS;', '')),
            source(finish=FINISH.replace('current->plug = NULL;', 'detach_plug();')),
        ]
        for text in variants:
            with self.subTest(source=text), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                port, common = self.setup_fixture(root, text)
                self.assert_preserved_on_failure(root, port, common)

    def test_unrelated_changes_in_same_file_are_not_silently_retired(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            port, common = self.setup_fixture(root, source(finish=FIXED))
            replay = port / 'common-patches/required.patch'
            replay.write_bytes(replay.read_bytes().replace(
                barrier_patch(), barrier_patch(FIXED.replace('barrier();', 'barrier(); audit();'))))
            self.assert_preserved_on_failure(root, port, common)

    def test_invalid_check_configuration_stops_without_changes(self):
        for checks in [[], {ordering.SOURCE: 'unknown'},
                       {'drivers/other.c': ordering.CHECK},
                       {'missing.c': ordering.CHECK}]:
            with self.subTest(checks=checks), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                port, common = self.setup_fixture(root)
                path = port / 'common-patches/manifest.json'
                manifest = json.loads(path.read_text())
                manifest['upstream_checks'] = checks
                path.write_text(json.dumps(manifest))
                self.assert_preserved_on_failure(root, port, common)


if __name__ == '__main__':
    unittest.main()
