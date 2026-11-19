"""Run actual native/SUSFS lookup functions with cold/warm dentries and magic links."""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

PORT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('_susfs_namei', PORT / 'features/susfs_runtime_fixes.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)

PREFIX = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#define static_assert _Static_assert
#define BIT(bit) (1U << (bit))
#define CONFIG_KSU_SUSFS_SUS_PATH 1
#define likely(value) (value)
#define unlikely(value) (value)
#define ERR_PTR(error) ((void *)(intptr_t)(error))
#define IS_ERR(pointer) ((uintptr_t)(pointer) >= (uintptr_t)-4095)
#define ERR_CAST(pointer) ((void *)(pointer))
#define IS_DEADDIR(inode) ((inode)->dead)
#define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) int name = 0
#define WALK_MORE 1
#define LAST_NORM 0
struct dentry;
struct inode;
struct inode_operations {
    struct dentry *(*lookup)(struct inode *, struct dentry *, unsigned int);
};
struct inode { bool dead, hidden; const struct inode_operations *i_op; };
struct qstr { const char *name; };
struct dentry { struct inode *d_inode; bool in_lookup; };
struct path { void *mnt; struct dentry *dentry; };
struct nameidata {
    struct path path;
    struct qstr last;
    struct inode *inode;
    unsigned int flags, state, depth;
    int last_type;
};
static struct { struct nameidata *nameidata; } task;
#define current (&task)
static struct inode parent_inode, target_inode;
static struct dentry parent_dentry = {&parent_inode, false};
static struct dentry found_dentry = {&target_inode, true};
static struct dentry negative_dentry = {NULL, true};
static struct qstr susfs_fake_qstr_name = {"hidden"};
static bool warm, revalidate, magic, app;
static unsigned int callback_flags;
static int callback_count, path_releases;
static struct dentry *fs_lookup(struct inode *inode, struct dentry *dentry, unsigned int flags) {
    (void)inode; (void)dentry; callback_flags = flags; callback_count++; return NULL;
}
static const struct inode_operations inode_ops = {fs_lookup};
static struct dentry *d_alloc_parallel(struct dentry *parent, const struct qstr *name, int *wait) {
    (void)parent; (void)wait;
    if (name == &susfs_fake_qstr_name) return &negative_dentry;
    found_dentry.in_lookup = !revalidate; return &found_dentry;
}
static bool d_in_lookup(struct dentry *dentry) { return dentry->in_lookup; }
static void d_lookup_done(struct dentry *dentry) { dentry->in_lookup = false; }
static void dput(struct dentry *dentry) { (void)dentry; }
static void d_invalidate(struct dentry *dentry) { (void)dentry; }
static int d_revalidate(struct inode *inode, const struct qstr *name,
                        struct dentry *dentry, unsigned int flags) {
    (void)inode; (void)name; (void)dentry;
    callback_flags = flags; callback_count++; return 1;
}
static bool susfs_is_inode_sus_path(struct inode *inode) { return app && inode->hidden; }
static void inode_lock_shared(struct inode *inode) { (void)inode; }
static void inode_unlock_shared(struct inode *inode) { (void)inode; }
static void path_put(const struct path *path) { (void)path; path_releases++; }
static struct dentry *lookup_fast(struct nameidata *nd) { (void)nd; return warm ? &found_dentry : NULL; }
static void put_link(struct nameidata *nd) { (void)nd; }
static const char *handle_dots(struct nameidata *nd, int type) { (void)nd; (void)type; return NULL; }
'''

STEP = r'''
static const char *step_into(struct nameidata *nd, int flags, struct dentry *dentry) {
    (void)nd; (void)flags;
    if (!dentry->d_inode) return ERR_PTR(-ENOENT);
    if (!magic) return NULL;
    struct path destination = {(void *)1, &found_dentry};
    int error = nd_jump_link(&destination);
    return error ? ERR_PTR(error) : NULL;
}
'''

TESTS = r'''
static int run_case(bool cached, bool cached_slow, bool is_magic, bool hidden,
                     bool application, unsigned int native_flags, unsigned int state) {
    warm = cached; revalidate = cached_slow; magic = is_magic; app = application;
    parent_inode.i_op = &inode_ops; target_inode.hidden = hidden;
    found_dentry.in_lookup = true; negative_dentry.in_lookup = true;
    callback_flags = 0; callback_count = path_releases = 0;
    struct nameidata nd = {.path = {(void *)1, &parent_dentry},
                          .last = {"exe"}, .state = state, .flags = native_flags};
    task.nameidata = &nd;
    const char *result = walk_component(&nd, 0);
    task.nameidata = NULL;
    int error = IS_ERR(result) ? (int)(intptr_t)result : 0;
    if (FIXED) {
        assert(nd.flags == native_flags);
        if (callback_count) assert(callback_flags == native_flags);
    }
    return error;
}
int main(void) {
    int cold = run_case(false, false, true, false, false, LOOKUP_FOLLOW, ND_STATE_LOOKUP_LAST);
    assert(cold == (FIXED ? 0 : -ELOOP));
    if (!FIXED) assert(callback_flags & LOOKUP_NO_MAGICLINKS);
    assert(run_case(true, false, true, false, false, LOOKUP_FOLLOW, ND_STATE_LOOKUP_LAST) == 0);
    assert(run_case(false, true, true, false, false, LOOKUP_FOLLOW, ND_STATE_LOOKUP_LAST)
           == (FIXED ? 0 : -ELOOP));
    /* Preserve restrictions explicitly requested by the caller, cold and warm. */
    assert(run_case(false, false, true, false, false,
                    LOOKUP_FOLLOW | LOOKUP_NO_MAGICLINKS, ND_STATE_LOOKUP_LAST) == -ELOOP);
    assert(run_case(true, false, true, false, false,
                    LOOKUP_FOLLOW | LOOKUP_NO_MAGICLINKS, ND_STATE_LOOKUP_LAST) == -ELOOP);
    /* Ordinary links/files stay usable; SUSFS hiding still consumes the marker. */
    assert(run_case(false, false, false, false, false, LOOKUP_FOLLOW, ND_STATE_LOOKUP_LAST) == 0);
    assert(run_case(false, false, false, true, true, LOOKUP_FOLLOW, ND_STATE_LOOKUP_LAST) == -ENOENT);
    assert(run_case(false, false, false, true, false, LOOKUP_FOLLOW, ND_STATE_LOOKUP_LAST) == 0);
    assert(run_case(false, false, true, false, false, LOOKUP_FOLLOW, 0) == 0);
    printf("PASS %s: cold/warm magic links, native policy, callback isolation, SUSFS hiding\n",
           FIXED ? "fixed" : "buggy negative control");
    return 0;
}
'''


class SusfsNameiFlagsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        baseline = Path(os.environ.get('ONYX_TEST_COMMON_DIR', PORT.parent / 'common'))
        if not all((baseline / name).is_file() for name in ('fs/namei.c', 'include/linux/namei.h')):
            raise unittest.SkipTest('Set ONYX_TEST_COMMON_DIR to pinned native common source')
        cls.compiler = shutil.which('cc')
        if cls.compiler is None:
            raise unittest.SkipTest('Host C compiler required')
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.common = cls.root / 'common'
        for name in ('fs/namei.c', 'include/linux/namei.h'):
            target = cls.common / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(baseline / name, target)
        definitions = cls.common / 'include/linux/susfs_def.h'
        shutil.copyfile(PORT / 'features/vendor/susfs/include/linux/susfs_def.h', definitions)
        source = (cls.common / 'fs/namei.c').read_text()
        if 'CONFIG_KSU_SUSFS' in source:
            raise ValueError('Namei regression requires native source before feature replay')
        # Keep the negative control tied to the exact reviewed upstream hooks,
        # while allowing the canonical patch itself to contain the fixed hooks.
        upstream = (PORT / 'features/vendor/susfs/50_add_susfs_in_gki-android17-6.18.patch').read_text()
        section = next(piece for piece in re.split(r'(?m)(?=^diff --git )', upstream)
                       if piece.startswith('diff --git a/fs/namei.c '))
        patch = cls.root / 'namei.patch'
        patch.write_text(section)
        subprocess.run(['git', 'apply', str(patch)], cwd=cls.common, check=True,
                       capture_output=True, text=True)
        cls.before = {name: (cls.common / name).read_bytes()
                      for name in ('fs/namei.c', 'include/linux/susfs_def.h', 'include/linux/namei.h')}
        # The 6.18 imported fs/susfs.c drops the older idmap argument.
        source = (cls.common / 'fs/namei.c').read_text().replace(
            'susfs_is_inode_sus_path(&nop_mnt_idmap, ', 'susfs_is_inode_sus_path(')
        (cls.common / 'fs/namei.c').write_text(source)
        cls.before['fs/namei.c'] = source.encode()
        cls.native = runtime.flag_definitions((baseline / 'include/linux/namei.h').read_text(), 'LOOKUP_')
        cls.executables = {}
        cls.compile_case('buggy', source, definitions.read_text())
        runtime.adapt_namei(cls.common)
        cls.compile_case('fixed', (cls.common / 'fs/namei.c').read_text(), definitions.read_text())

    @classmethod
    def compile_case(cls, label, source, definitions):
        native_macros = '\n'.join('#define ' + name + ' ' + value
                                  for name, value in cls.native.items()) + '\n'
        private_macros = '\n'.join(line for line in definitions.splitlines()
                                   if line.startswith('#define ND_')) + '\n'
        native_state = runtime.flag_definitions(source, 'ND_')
        native_macros += '\n'.join('#define ' + name + ' ' + value
                                    for name, value in native_state.items()) + '\n'
        guard = ''
        if label == 'fixed':
            begin = source.index('/* SUSFS metadata must never enable native path-resolution restrictions. */')
            guard = source[begin:source.index('#endif', begin)]
        functions = '\n'.join(runtime.function(source, name)
                              for name in ('nd_jump_link', '__lookup_slow', 'lookup_slow'))
        harness = cls.root / (label + '.c')
        harness.write_text(PREFIX + native_macros + private_macros + guard + functions + STEP +
                           runtime.function(source, 'walk_component') +
                           '\n#define FIXED ' + str(int(label == 'fixed')) + '\n' + TESTS)
        executable = cls.root / label
        result = subprocess.run([cls.compiler, '-std=gnu11', '-O1', '-Wall', '-Werror',
                                 str(harness), '-o', str(executable)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)
        cls.executables[label] = executable

    def test_actual_lookup_functions_cold_warm_and_original_negative_control(self):
        for label, executable in self.executables.items():
            with self.subTest(label=label):
                result = subprocess.run([str(executable)], capture_output=True, text=True, check=True)
                self.assertIn('PASS ', result.stdout)

    def test_adaptation_is_idempotent(self):
        before = {name: (self.common / name).read_bytes() for name in self.before}
        runtime.adapt_namei(self.common)
        self.assertEqual(before, {name: (self.common / name).read_bytes() for name in self.before})

    def test_future_native_collision_rejected_before_writes(self):
        for adapted in (False, True):
            with self.subTest(adapted=adapted):
                other = self.root / ('collision-' + str(adapted))
                for name in self.before:
                    target = other / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes((self.common / name).read_bytes() if adapted else self.before[name])
                header = other / 'include/linux/namei.h'
                header.write_text(header.read_text() + '\n#define LOOKUP_FUTURE BIT(11)\n')
                before = {name: (other / name).read_bytes() for name in self.before}
                with self.assertRaisesRegex(ValueError, 'collides with LOOKUP_FUTURE'):
                    runtime.adapt_namei(other)
                self.assertEqual(before, {name: (other / name).read_bytes() for name in before})

    def test_partial_adaptation_and_hook_drift_rejected_before_writes(self):
        for old, new in ((b'nd->flags |= ND_FLAGS_LOOKUP_LAST;', b'nd->flags |= UNEXPECTED_FLAG;'),
                         (b'bool is_nd_flags_lookup_last =', b'bool unexpected_lookup_last =')):
            with self.subTest(anchor=old):
                other = self.root / ('drift-' + str(len(old)))
                for name, data in self.before.items():
                    target = other / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data.replace(old, new, 1))
                before = {name: (other / name).read_bytes() for name in self.before}
                with self.assertRaises(ValueError):
                    runtime.adapt_namei(other)
                self.assertEqual(before, {name: (other / name).read_bytes() for name in before})


if __name__ == '__main__':
    unittest.main()
