"""Compile actual mount lookup/SUS_PATH functions and the original failure controls."""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

PORT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('_susfs_apps', PORT / 'features/susfs_runtime_fixes.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)

MOUNT_PREFIX = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#define CONFIG_KSU_SUSFS_SUS_MOUNT 1
#define DEFAULT_KSU_MNT_ID 2000000000
#define READ_ONCE(value) (value)
#define unlikely(value) (value)
#define DCACHE_MANAGE_TRANSIT 1U
#define DCACHE_NEED_AUTOMOUNT 2U
#define DCACHE_MOUNTED 4U
struct dentry { unsigned int d_flags, d_seq; };
struct vfsmount { struct dentry *mnt_root; };
struct mount {
    struct vfsmount mnt;
    int mnt_id;
    struct mount *mnt_parent, *overmount, *next;
    struct dentry *mnt_mountpoint;
};
struct path { struct vfsmount *mnt; struct dentry *dentry; };
struct hlist_head { struct mount *first; };
static struct hlist_head mounts;
static bool umounted;
#define real_mount(value) ((struct mount *)(value))
#define hlist_for_each_entry_rcu(p, head, field) for ((p) = (head)->first; (p); (p) = (p)->next)
static struct hlist_head *m_hash(struct vfsmount *mnt, struct dentry *dentry) {
    (void)mnt; (void)dentry; return &mounts;
}
static bool susfs_is_current_proc_umounted(void) { return umounted; }
static bool mnt_has_parent(struct mount *mnt) { return mnt->mnt_parent != mnt; }
static unsigned int read_seqcount_begin(unsigned int *seq) { return *seq; }
'''

MOUNT_TESTS = r'''
static struct dentry dev_root, point, hidden_root, low_root, other_point;
static struct mount dev, high, low, fallback;
static void init_mount(struct mount *mnt, int id, struct dentry *root,
                       struct mount *parent, struct dentry *mountpoint) {
    *mnt = (struct mount){.mnt = {root}, .mnt_id = id,
                         .mnt_parent = parent, .mnt_mountpoint = mountpoint};
}
static void setup(void) {
    hidden_root.d_flags = DCACHE_MOUNTED;
    init_mount(&dev, 269, &dev_root, &dev, &dev_root);
    init_mount(&high, DEFAULT_KSU_MNT_ID + 2969, &hidden_root, &dev, &point);
    init_mount(&low, 274, &low_root, &high, &hidden_root);
    init_mount(&fallback, 275, &low_root, &dev, &point);
    high.overmount = &low;
    mounts.first = &high;
    umounted = true;
}
int main(void) {
    setup();
    /* Real captured topology: /dev269 -> hidden2969 -> Binderfs274. */
    assert(__lookup_mnt(&dev.mnt, &point) == (FIXED ? &low : NULL));
    /* Root/unmarked tasks retain exactly the native high mount result. */
    umounted = false; assert(__lookup_mnt(&dev.mnt, &point) == &high);
    setup(); high.overmount = NULL;
    assert(__lookup_mnt(&dev.mnt, &point) == NULL);
    high.next = &fallback;
    assert(__lookup_mnt(&dev.mnt, &point) == &fallback);
    setup(); low.mnt_mountpoint = &other_point;
    assert(__lookup_mnt(&dev.mnt, &point) == NULL);
    setup(); low.mnt_parent = &dev;
    assert(__lookup_mnt(&dev.mnt, &point) == NULL);
    setup(); hidden_root.d_flags = DCACHE_MANAGE_TRANSIT;
    assert(__lookup_mnt(&dev.mnt, &point) == NULL);
    setup(); hidden_root.d_flags = DCACHE_NEED_AUTOMOUNT;
    assert(__lookup_mnt(&dev.mnt, &point) == NULL);
    setup(); high.overmount = &high;
    assert(__lookup_mnt(&dev.mnt, &point) == NULL);
    setup(); low.mnt_id = DEFAULT_KSU_MNT_ID;
    low.overmount = &high; high.mnt_parent = &low; high.mnt_mountpoint = &low_root;
    assert(__lookup_mnt(&low.mnt, &low_root) == NULL);
    setup();
    /* Native dotdot skips root-on-root stack members without exposing them. */
    struct path root = {&dev.mnt, &dev_root}, parent = {0}; unsigned int seq = 0;
    assert(choose_mountpoint_rcu(&low, &root, &parent, &seq));
    assert(parent.mnt == &dev.mnt && parent.dentry == &point);
    root = (struct path){&high.mnt, &hidden_root}; parent = (struct path){0};
    assert(!choose_mountpoint_rcu(&low, &root, &parent, &seq));
    /* A long legitimate stack is not cut off by an arbitrary depth limit. */
    setup(); struct mount chain[256]; struct dentry roots[256] = {{0}};
    for (unsigned int i = 0; i < 256; ++i) {
        struct mount *p = i ? &chain[i-1] : &dev;
        init_mount(&chain[i], DEFAULT_KSU_MNT_ID + (int)i, &roots[i], p,
                   i ? p->mnt.mnt_root : &point);
        if (i) chain[i-1].overmount = &chain[i];
    }
    low.mnt_parent = &chain[255]; low.mnt_mountpoint = &roots[255];
    chain[255].overmount = &low; mounts.first = &chain[0];
    assert(__lookup_mnt(&dev.mnt, &point) == (FIXED ? &low : NULL));
    printf("PASS %s: Binderfs root stack, hidden-only, unrelated points, managed roots, cycles, dotdot\n",
           FIXED ? "fixed" : "original negative control");
    return 0;
}
'''

ABI_PREFIX = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#define FUSE_SUPER_MAGIC 0x65735546
#define AS_FLAGS_SUS_PATH 33
#define likely(value) (value)
#define unlikely(value) (value)
#define SUSFS_LOGE(...) ((void)0)
typedef unsigned int uid_t;
struct address_space { unsigned long flags; };
struct super_block { unsigned long s_magic; };
struct inode { struct address_space *i_mapping; struct super_block *i_sb; };
struct fuse_inode { struct inode inode; };
struct dentry { struct inode *d_inode; };
static unsigned int uid;
static bool allowed;
static struct fuse_inode fuse;
struct uid_value { unsigned int val; };
static struct uid_value current_uid(void) { return (struct uid_value){uid}; }
static bool test_bit(unsigned int bit, unsigned long *flags) { return (*flags & (1UL << bit)) != 0; }
static struct fuse_inode *get_fuse_inode(struct inode *inode) { (void)inode; return &fuse; }
static bool susfs_is_uid_allowed_for_sus_path(unsigned int value) { return allowed || value >= 90000; }
'''


class SusfsAppMountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = Path(os.environ.get('ONYX_TEST_COMMON_DIR', PORT.parent / 'common'))
        if not all((base / n).is_file() for n in ('fs/namespace.c', 'fs/namei.c', 'fs/readdir.c')):
            raise unittest.SkipTest('Set ONYX_TEST_COMMON_DIR to pinned native common')
        cls.cc = shutil.which('cc')
        if cls.cc is None:
            raise unittest.SkipTest('Host C compiler required')
        cls.temp = tempfile.TemporaryDirectory(prefix='onyx-app-mount-tests-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.tree = cls.root / 'common'
        for name in ('fs/namespace.c', 'fs/namei.c', 'fs/readdir.c'):
            p = cls.tree / name; p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(base / name, p)
        patch = (PORT / 'features/patches/susfs-6.18.patch').read_text()
        pieces = re.split(r'(?m)(?=^diff --git )', patch)
        for name in ('fs/namespace.c', 'fs/namei.c', 'fs/readdir.c', 'fs/susfs.c', 'include/linux/susfs.h'):
            section = next(x for x in pieces if x.startswith('diff --git a/' + name + ' '))
            p = cls.root / ('apply-' + Path(name).name + '.patch'); p.write_text(section)
            result = subprocess.run(['git', 'apply', str(p)], cwd=cls.tree, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stderr)
        cls.sources = {n: (cls.tree / n).read_text() for n in
                       ('fs/namespace.c', 'fs/namei.c', 'fs/readdir.c', 'fs/susfs.c', 'include/linux/susfs.h')}

    def compile(self, name, source, success=True):
        src = self.root / (name + '.c'); src.write_text(source)
        exe = self.root / name
        result = subprocess.run([self.cc, '-std=gnu11', '-O1', '-Wall', '-Werror', str(src), '-o', str(exe)],
                                capture_output=True, text=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(exe)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('susfs_is_inode_sus_path', result.stderr)
        return result

    def test_actual_mount_functions_and_original_negative_control(self):
        source = self.sources['fs/namespace.c']
        helper = runtime.function(source, 'susfs_visible_root_mount')
        lookup = runtime.function(source, 'struct mount *__lookup_mnt')
        dotdot = runtime.function(self.sources['fs/namei.c'], 'choose_mountpoint_rcu')
        for fixed in (False, True):
            with self.subTest(fixed=fixed):
                body = lookup if fixed else lookup.replace(runtime.NEW_APP_MOUNT_LOOKUP, runtime.OLD_APP_MOUNT_LOOKUP)
                result = self.compile('mount-' + str(fixed), MOUNT_PREFIX +
                                      (helper if fixed else '') + body + dotdot +
                                      '\n#define FIXED ' + str(int(fixed)) + '\n' + MOUNT_TESTS)
                self.assertIn('PASS ', result.stdout)

    def test_actual_inode_function_and_all_twelve_callers(self):
        namei, readdir = self.sources['fs/namei.c'], self.sources['fs/readdir.c']
        calls = re.findall(r'\bsusfs_is_inode_sus_path\(([^()]*)\)', namei + readdir)
        self.assertEqual(len(calls), 12)
        self.assertTrue(all(',' not in c for c in calls))
        self.assertNotIn('extern bool susfs_is_inode_sus_path', namei + readdir)
        prototype = re.search(r'bool susfs_is_inode_sus_path\(struct inode \*inode\);',
                              self.sources['include/linux/susfs.h']).group()
        function = runtime.function(self.sources['fs/susfs.c'], 'susfs_is_inode_sus_path')
        body = '\nstatic bool all_calls(struct inode *inode) {\n' \
               'struct dentry entry = {inode}; struct dentry *dentry = &entry; bool result = false;\n' \
               + '\n'.join('result |= susfs_is_inode_sus_path(' + c + ');' for c in calls) + '\nreturn result;\n}\n'
        checks = r'''
int main(void) {
    struct address_space mapping = {0}; struct super_block sb = {0};
    struct inode inode = {&mapping, &sb};
    uid = 0; mapping.flags = 1UL << AS_FLAGS_SUS_PATH; assert(!all_calls(&inode));
    uid = 1000; assert(!all_calls(&inode));
    uid = 10417; assert(all_calls(&inode));
    allowed = true; assert(!all_calls(&inode)); allowed = false;
    mapping.flags = 0; assert(!all_calls(&inode));
    mapping.flags = 1UL << AS_FLAGS_SUS_PATH; sb.s_magic = FUSE_SUPER_MAGIC;
    fuse.inode = inode; assert(all_calls(&inode));
    fuse.inode.i_mapping = NULL; assert(!all_calls(&inode));
    sb.s_magic = 0; inode.i_mapping = NULL; assert(!all_calls(&inode));
    puts("PASS actual inode-only ABI: twelve callers, root/app, filter, FUSE, unmapped inode");
    return 0;
}
'''
        result = self.compile('inode-abi', ABI_PREFIX + prototype + function + body + checks)
        self.assertIn('PASS ', result.stdout)
        bad = ABI_PREFIX + prototype + function + '\nint main(void) {\n' \
              'struct inode inode = {0}; return susfs_is_inode_sus_path((void *)0, &inode);\n}\n'
        self.compile('legacy-two-argument-negative-control', bad, success=False)

    def test_native_rcu_ref_and_dotdot_functions_are_unchanged(self):
        base = Path(os.environ.get('ONYX_TEST_COMMON_DIR', PORT.parent / 'common'))
        for file, signature in (('fs/namespace.c', 'struct vfsmount *lookup_mnt'),
                                ('fs/namei.c', 'choose_mountpoint_rcu'),
                                ('fs/namei.c', '__follow_mount_rcu')):
            self.assertEqual(runtime.function(self.sources[file], signature),
                             runtime.function((base / file).read_text(), signature))

    def test_adaptation_idempotent_and_abi_drift_fails_before_writes(self):
        before = {n: (self.tree / n).read_bytes() for n in self.sources}
        runtime.adapt_app_mounts_and_path_api(self.tree)
        self.assertEqual(before, {n: (self.tree / n).read_bytes() for n in before})
        path = self.tree / 'fs/namei.c'
        original = path.read_text()
        path.write_text(original.replace('susfs_is_inode_sus_path(dentry->d_inode)',
                                         'susfs_is_inode_sus_path(NULL, dentry->d_inode)', 1))
        changed = {n: (self.tree / n).read_bytes() for n in self.sources}
        with self.assertRaises(ValueError):
            runtime.adapt_app_mounts_and_path_api(self.tree)
        self.assertEqual(changed, {n: (self.tree / n).read_bytes() for n in changed})
        path.write_text(original)


if __name__ == '__main__':
    unittest.main()
