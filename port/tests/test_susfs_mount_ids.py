"""Compile adapted production mount allocators with an adversarial mock xarray.

ONYX_TEST_COMMON_DIR selects an existing pinned kernel/common source tree.
The test copies its two files and applies the shipped WildKernels namespace
patch when needed; it never modifies that source tree or builds a kernel.
"""
import importlib.util
import contextlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import warnings

PORT = Path(__file__).resolve().parents[1]
VENDOR = PORT / 'features/vendor/susfs'


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


ids = module(PORT / 'features/susfs_mount_ids.py', '_susfs_mount_ids')


HARNESS_PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CONFIG_KSU_SUSFS_SUS_MOUNT 1
#define DEFAULT_KSU_MNT_ID 2000000000
#define VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT 0x80000000U
#define GFP_KERNEL 0
#define GFP_KERNEL_ACCOUNT 0
#define INIT_HLIST_NODE(x) ((void)0)
#define INIT_HLIST_HEAD(x) ((void)0)
#define INIT_LIST_HEAD(x) ((void)0)
#define RB_CLEAR_NODE(x) ((void)0)
typedef uint32_t u32;
typedef uint64_t u64;
struct mnt_pcp { int mnt_count; };
struct mount {
    struct { void *mnt_idmap; unsigned int mnt_flags; } mnt;
    const char *mnt_devname;
    int mnt_count, mnt_writers;
    struct mnt_pcp *mnt_pcp;
IDENTITY_FIELDS
};
struct slot { int id; struct mount *entry; };
struct xarray { pthread_mutex_t mutex; struct slot slots[1024]; };
struct xa_limit { u32 min, max; };
#define XA_LIMIT(minimum, maximum) ((struct xa_limit){minimum, maximum})
static struct xarray mnt_id_xa = { .mutex = PTHREAD_MUTEX_INITIALIZER };
static u64 mnt_id_ctr = 1ULL << 31;
static void *mnt_cache, *nop_mnt_idmap;
static int cache_live, pcp_live, name_live, fail_name, fail_percpu, fail_allocation, high_capacity;
static __thread int xa_depth;
static void xa_lock(struct xarray *xa) {
    pthread_mutex_lock(&xa->mutex);
    assert(xa_depth++ == 0);
}
static void xa_unlock(struct xarray *xa) {
    assert(--xa_depth == 0);
    pthread_mutex_unlock(&xa->mutex);
}
static struct mount *find_slot(struct xarray *xa, int id) {
    for (unsigned int i = 0; i < 1024; i++)
        if (xa->slots[i].entry && xa->slots[i].id == id) return xa->slots[i].entry;
    return NULL;
}
static int __xa_alloc(struct xarray *xa, int *id, struct mount *mnt,
                      struct xa_limit limit, int gfp) {
    (void)gfp;
    assert(xa_depth == 1);
    if (fail_allocation) { fail_allocation = 0; return -ENOMEM; }
    if (high_capacity && limit.min == DEFAULT_KSU_MNT_ID)
        limit.max = limit.min + high_capacity - 1;
    u32 candidate = limit.min;
    while (candidate <= limit.max && find_slot(xa, candidate)) candidate++;
    if (candidate > limit.max) return -ENOSPC;
    for (unsigned int i = 0; i < 1024; i++) {
        if (!xa->slots[i].entry) {
            xa->slots[i] = (struct slot){candidate, mnt};
            *id = candidate;
            return 0;
        }
    }
    return -ENOSPC;
}
static struct mount *xa_load(struct xarray *xa, int id) {
    xa_lock(xa);
    struct mount *entry = find_slot(xa, id);
    xa_unlock(xa);
    return entry;
}
static void xa_erase(struct xarray *xa, int id) {
    xa_lock(xa);
    int found = 0;
    for (unsigned int i = 0; i < 1024; i++) {
        if (xa->slots[i].entry && xa->slots[i].id == id) {
            xa->slots[i].entry = NULL;
            found++;
        }
    }
    /* A free without an owned reservation is an allocator lifetime bug. */
    assert(found == 1);
    xa_unlock(xa);
}
static int slot_count(void) {
    int count = 0;
    xa_lock(&mnt_id_xa);
    for (unsigned int i = 0; i < 1024; i++) count += !!mnt_id_xa.slots[i].entry;
    xa_unlock(&mnt_id_xa);
    return count;
}
static void *kmem_cache_zalloc(void *cache, int flags) {
    (void)cache; (void)flags;
    __atomic_add_fetch(&cache_live, 1, __ATOMIC_RELAXED);
    return calloc(1, sizeof(struct mount));
}
static void kmem_cache_free(void *cache, void *mnt) {
    (void)cache;
    __atomic_sub_fetch(&cache_live, 1, __ATOMIC_RELAXED);
    free(mnt);
}
static const char *kstrdup_const(const char *name, int flags) {
    (void)flags;
    if (fail_name) { fail_name = 0; return NULL; }
    name_live++;
    return strdup(name);
}
static __attribute__((unused)) void kfree_const(const char *name) {
    name_live--; free((void *)name);
}
static __attribute__((unused)) struct mnt_pcp *mock_alloc_percpu(void) {
    if (fail_percpu) { fail_percpu = 0; return NULL; }
    __atomic_add_fetch(&pcp_live, 1, __ATOMIC_RELAXED);
    return calloc(1, sizeof(struct mnt_pcp));
}
static __attribute__((unused)) void free_percpu(struct mnt_pcp *pcp) {
    __atomic_sub_fetch(&pcp_live, 1, __ATOMIC_RELAXED); free(pcp);
}
#define alloc_percpu(type) mock_alloc_percpu()
#define this_cpu_add(variable, value) ((variable) += (value))
'''

HARNESS_TESTS = r'''
static void destroy_mount(struct mount *mnt) {
    mnt_free_id(mnt);
#ifdef CONFIG_SMP
    free_percpu(mnt->mnt_pcp);
#endif
    /* Scenarios use NULL names, so the native factory stores its static "none". */
    kmem_cache_free(mnt_cache, mnt);
}
static void ownership(void) {
    struct mount *original = alloc_vfsmnt(NULL);
    assert(original && original->mnt_id == 0);
    struct mount *clone = susfs_alloc_unshare_ksu_vfsmnt(NULL, original->mnt_id);
    assert(clone && clone->mnt_id == 0);
    assert(clone->mnt_id_allocated >= DEFAULT_KSU_MNT_ID);
    assert(clone->mnt_id_unique != original->mnt_id_unique);
    int clone_raw = clone->mnt_id_allocated;
    clone->mnt.mnt_flags |= VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT;
    destroy_mount(clone);
    assert(!xa_load(&mnt_id_xa, clone_raw));
    assert(xa_load(&mnt_id_xa, original->mnt_id_allocated) == original);
    destroy_mount(original);
}
static void original_freed_first(void) {
    struct mount *original = alloc_vfsmnt(NULL);
    struct mount *clone = susfs_alloc_unshare_ksu_vfsmnt(NULL, original->mnt_id);
    destroy_mount(original);
    struct mount *replacement = alloc_vfsmnt(NULL);
    assert(replacement->mnt_id == clone->mnt_id);
    destroy_mount(clone);
    assert(xa_load(&mnt_id_xa, replacement->mnt_id_allocated) == replacement);
    destroy_mount(replacement);
}
static void reserved_high_ids(void) {
    struct mount *ordinary = alloc_vfsmnt(NULL);
    struct mount *first = susfs_alloc_non_unshare_ksu_vfsmnt(NULL);
    struct mount *second = susfs_alloc_non_unshare_ksu_vfsmnt(NULL);
    assert(first->mnt_id >= DEFAULT_KSU_MNT_ID && second->mnt_id > first->mnt_id);
    assert(first->mnt_id == first->mnt_id_allocated);
    assert(xa_load(&mnt_id_xa, first->mnt_id_allocated) == first);
    assert(xa_load(&mnt_id_xa, second->mnt_id_allocated) == second);
    destroy_mount(first);
    assert(xa_load(&mnt_id_xa, second->mnt_id_allocated) == second);
    assert(xa_load(&mnt_id_xa, ordinary->mnt_id_allocated) == ordinary);
    destroy_mount(second);
    destroy_mount(ordinary);
}
static void allocation_failures(void) {
    struct mount *ordinary = alloc_vfsmnt(NULL);
    int baseline = slot_count();
    fail_allocation = 1;
    assert(!susfs_alloc_non_unshare_ksu_vfsmnt(NULL));
    assert(slot_count() == baseline && cache_live == baseline);
    fail_name = 1;
    assert(!susfs_alloc_unshare_ksu_vfsmnt("name-allocation-fails", 0));
    assert(slot_count() == baseline && cache_live == baseline);
    assert(xa_load(&mnt_id_xa, ordinary->mnt_id_allocated) == ordinary);
#ifdef CONFIG_SMP
    fail_percpu = 1;
    assert(!susfs_alloc_non_unshare_ksu_vfsmnt("percpu-allocation-fails"));
    assert(slot_count() == baseline && cache_live == baseline && name_live == 0);
    assert(pcp_live == baseline);
#endif
    destroy_mount(ordinary);
}
static void high_range_exhaustion(void) {
    high_capacity = 2;
    struct mount *ordinary = alloc_vfsmnt(NULL);
    struct mount *first = susfs_alloc_non_unshare_ksu_vfsmnt(NULL);
    struct mount *second = susfs_alloc_unshare_ksu_vfsmnt(NULL, 0);
    assert(first && second && !susfs_alloc_non_unshare_ksu_vfsmnt(NULL));
    assert(slot_count() == 3 && cache_live == 3);
    assert(xa_load(&mnt_id_xa, ordinary->mnt_id_allocated) == ordinary);
    assert(xa_load(&mnt_id_xa, first->mnt_id_allocated) == first);
    assert(xa_load(&mnt_id_xa, second->mnt_id_allocated) == second);
    destroy_mount(first); destroy_mount(second); destroy_mount(ordinary);
}
#define THREADS 4
#define PER_THREAD 64
static struct mount *thread_mounts[THREADS][PER_THREAD];
static void *allocate_thread(void *argument) {
    unsigned long t = (unsigned long)argument;
    for (int i = 0; i < PER_THREAD; i++) {
        struct mount *mnt = i % 3 == 0 ? alloc_vfsmnt(NULL)
            : i % 3 == 1 ? susfs_alloc_non_unshare_ksu_vfsmnt(NULL)
            : susfs_alloc_unshare_ksu_vfsmnt(NULL, 0);
        assert(mnt && xa_load(&mnt_id_xa, mnt->mnt_id_allocated) == mnt);
        thread_mounts[t][i] = mnt;
    }
    return NULL;
}
static int compare_ids(const void *left, const void *right) {
    u64 a = *(const u64 *)left, b = *(const u64 *)right;
    return a < b ? -1 : a > b;
}
static void concurrent_unique_ids(void) {
    pthread_t threads[THREADS];
    u64 unique[THREADS * PER_THREAD];
    for (unsigned long t = 0; t < THREADS; t++)
        assert(!pthread_create(&threads[t], NULL, allocate_thread, (void *)t));
    for (int t = 0; t < THREADS; t++) assert(!pthread_join(threads[t], NULL));
    int n = 0;
    for (int t = 0; t < THREADS; t++)
        for (int i = 0; i < PER_THREAD; i++) unique[n++] = thread_mounts[t][i]->mnt_id_unique;
    qsort(unique, n, sizeof(*unique), compare_ids);
    for (int i = 0; i < n; i++) assert(unique[i] == (1ULL << 31) + i + 1);
    assert(mnt_id_ctr == (1ULL << 31) + n);
    for (int t = 0; t < THREADS; t++)
        for (int i = 0; i < PER_THREAD; i++) destroy_mount(thread_mounts[t][i]);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    if (!strcmp(argv[1], "ownership")) ownership();
    else if (!strcmp(argv[1], "original-freed-first")) original_freed_first();
    else if (!strcmp(argv[1], "reserved-high")) reserved_high_ids();
    else if (!strcmp(argv[1], "failures")) allocation_failures();
    else if (!strcmp(argv[1], "exhaustion")) high_range_exhaustion();
    else if (!strcmp(argv[1], "concurrent")) concurrent_unique_ids();
    else assert(0);
    assert(slot_count() == 0 && cache_live == 0 && pcp_live == 0 && name_live == 0);
    printf("PASS %s\n", argv[1]);
    return 0;
}
'''


class SusfsMountAllocatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        common = Path(os.environ.get('ONYX_TEST_COMMON_DIR', PORT.parent / 'common'))
        if not all((common / 'fs' / name).is_file() for name in ('namespace.c', 'mount.h')):
            raise unittest.SkipTest('Set ONYX_TEST_COMMON_DIR to the pinned common source tree')
        compiler = shutil.which('cc')
        if compiler is None:
            raise unittest.SkipTest('A host C compiler is required')
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.common = cls.root / 'common'
        (cls.common / 'fs').mkdir(parents=True)
        for name in ('namespace.c', 'mount.h'):
            shutil.copy2(common / 'fs' / name, cls.common / 'fs' / name)
        if 'susfs_alloc_unshare_ksu_vfsmnt' not in (cls.common / 'fs/namespace.c').read_text():
            sections = re.split(r'(?m)(?=^diff --git )',
                (VENDOR / '50_add_susfs_in_gki-android17-6.18.patch').read_text())
            namespace_patch = next(section for section in sections
                if section.startswith('diff --git a/fs/namespace.c '))
            patch_path = cls.root / 'namespace.patch'
            patch_path.write_text(namespace_patch)
            subprocess.run([sys.executable,
                str(VENDOR / 'compat/susfs_618_namespace_mnt_t_flags.py'),
                str(cls.common), str(patch_path)], check=True, capture_output=True)
            subprocess.run(['git', 'apply', str(patch_path)], cwd=cls.common,
                           check=True, capture_output=True)
        if 'alloc_vfsmnt_with_id' not in (cls.common / 'fs/namespace.c').read_text():
            compat = module(VENDOR / 'compat/susfs_618_compile_fixes.py', '_wk_mount_compat')
            with warnings.catch_warnings(), contextlib.redirect_stdout(io.StringIO()):
                warnings.simplefilter('ignore', ResourceWarning)
                compat.rewrite_alloc_helpers(str(cls.common))
        cls.before_namespace = (cls.common / 'fs/namespace.c').read_bytes()
        cls.before_mount = (cls.common / 'fs/mount.h').read_bytes()
        ids.adapt(cls.common)
        source = (cls.common / 'fs/namespace.c').read_text()
        mount = (cls.common / 'fs/mount.h').read_text()
        start = mount.index('\tint mnt_id;')
        end = mount.index('\tu64 mnt_id_unique;', start) + len('\tu64 mnt_id_unique;')
        identity = mount[start:end]
        signatures = [
            'static int mnt_alloc_id(struct mount *mnt, u32 min_id)',
            'static void mnt_free_id(struct mount *mnt)', ids.FACTORY_SIGNATURE,
            'static struct mount *alloc_vfsmnt(const char *name)',
            'static struct mount *susfs_alloc_unshare_ksu_vfsmnt(const char *name, int old_mnt_id)',
            'static struct mount *susfs_alloc_non_unshare_ksu_vfsmnt(const char *name)',
        ]
        actual_functions = '\n\n'.join(ids.function(source, signature) for signature in signatures)
        harness = cls.root / 'mount-allocator.c'
        harness.write_text(HARNESS_PREFIX.replace('IDENTITY_FIELDS', identity)
                           + actual_functions + HARNESS_TESTS)
        cls.executables = []
        for suffix, configuration in [('up', []), ('smp', ['-DCONFIG_SMP=1'])]:
            executable = cls.root / ('mount-allocator-' + suffix)
            compilation = subprocess.run([compiler, '-std=gnu11', '-O1', '-Wall', '-Werror',
                '-pthread', *configuration, str(harness), '-o', str(executable)],
                capture_output=True, text=True)
            if compilation.returncode:
                raise RuntimeError(compilation.stderr)
            cls.executables.append(executable)

    def test_allocator_ownership_lifetimes_and_failures(self):
        for executable in self.executables:
            for scenario in ('ownership', 'original-freed-first', 'reserved-high',
                             'failures', 'exhaustion', 'concurrent'):
                with self.subTest(configuration=executable.name, scenario=scenario):
                    result = subprocess.run([str(executable), scenario], check=True,
                                            capture_output=True, text=True)
                    self.assertEqual('PASS ' + scenario + '\n', result.stdout)

    def test_adaptation_is_idempotent(self):
        before = [(self.common / 'fs' / name).read_bytes() for name in ('namespace.c', 'mount.h')]
        ids.adapt(self.common)
        self.assertEqual(before, [(self.common / 'fs' / name).read_bytes()
                                 for name in ('namespace.c', 'mount.h')])

    def test_drift_does_not_partially_write_either_file(self):
        other = self.root / 'drift'
        (other / 'fs').mkdir(parents=True)
        broken = self.before_namespace.replace(b'xa_limit_31b', b'unexpected_id_range')
        (other / 'fs/namespace.c').write_bytes(broken)
        (other / 'fs/mount.h').write_bytes(self.before_mount)
        with self.assertRaises(ValueError):
            ids.adapt(other)
        self.assertEqual(broken, (other / 'fs/namespace.c').read_bytes())
        self.assertEqual(self.before_mount, (other / 'fs/mount.h').read_bytes())


if __name__ == '__main__':
    unittest.main()
