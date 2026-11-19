"""Compile actual SUSFS lifetime functions and page/stat hook segments with mocks."""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

PORT = Path(__file__).resolve().parents[1]
VENDOR = PORT / 'features/vendor/susfs'
spec = importlib.util.spec_from_file_location('_susfs_runtime', PORT / 'features/susfs_runtime_fixes.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


PREFIX = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define CONFIG_KSU_SUSFS_SUS_MAP 1
#define CONFIG_KSU_SUSFS_SUS_KSTAT 1
#define CONFIG_HAVE_IOREMAP_PROT 1
#define KERNEL_VERSION(a,b,c) (((a)<<16)+((b)<<8)+(c))
#define LINUX_VERSION_CODE KERNEL_VERSION(6,18,63)
#define GFP_KERNEL 0
#define LOOKUP_FOLLOW 0
#define FS_EVENT_ON_CHILD 1
#define FS_ISDIR 2
#define FS_OPEN_PERM 4
#define SUSFS_LOGI(...) ((void)0)
#define SUSFS_LOGE(...) ((void)0)
#define IS_ERR(pointer) ((uintptr_t)(pointer) >= (uintptr_t)-4095)
#define PTR_ERR(pointer) ((long)(pointer))
#define ERR_PTR(error) ((void *)(intptr_t)(error))
#define xchg(pointer, value) ({ __typeof__(*(pointer)) previous = *(pointer); *(pointer) = (value); previous; })
typedef uint32_t u32;
struct inode { bool marked, fuse, hidden; };
struct dentry { struct inode *inode; };
struct vfsmount { int mnt_id; };
struct path { struct vfsmount *mnt; struct dentry *dentry; };
struct work_struct { int unused; };
struct delayed_work { struct work_struct work; };
struct static_key_true { bool enabled; };
#define DEFINE_STATIC_KEY_TRUE(name) struct static_key_true name = {true}
#define INIT_DELAYED_WORK(work, function) ((void)(work))
static bool static_key_enabled(struct static_key_true *key) { return key->enabled; }
static void static_branch_disable(struct static_key_true *key) { key->enabled = false; }
struct fsnotify_mark;
struct qstr;
struct fsnotify_ops {
    void (*free_mark)(struct fsnotify_mark *mark);
    int (*handle_inode_event)(struct fsnotify_mark *, u32, struct inode *, struct inode *,
                             const struct qstr *, u32);
};
struct fsnotify_group {
    const struct fsnotify_ops *ops;
    int refs;
    struct fsnotify_mark *mark;
};
struct fsnotify_mark {
    struct fsnotify_group *group;
    int refs;
    bool attached;
    u32 mask;
};
static int groups_live, marks_live, inode_holds, path_holds, marks_freed;
static int fail_group, fail_path, missing_inode, fail_mark;
static struct inode underlying;
static struct dentry directory = {&underlying};
static struct vfsmount mount = {7};
static void fsnotify_put_group(struct fsnotify_group *group) {
    assert(group && !IS_ERR(group) && group->refs > 0);
    if (!--group->refs) { assert(!group->mark); groups_live--; free(group); }
}
static void *kzalloc(size_t bytes, int flags) {
    (void)flags; marks_live++; return calloc(1, bytes);
}
static void kfree(void *mark) { marks_live--; marks_freed++; free(mark); }
static void fsnotify_init_mark(struct fsnotify_mark *mark, struct fsnotify_group *group) {
    mark->group = group; mark->refs = 1; group->refs++;
}
static void fsnotify_put_mark(struct fsnotify_mark *mark) {
    assert(mark->refs > 0);
    if (!--mark->refs) {
        struct fsnotify_group *group = mark->group;
        if (mark->attached) {
            assert(group->mark == mark); group->mark = NULL; inode_holds--;
        }
        /* Match the real 6.18 unconditional callback contract. */
        group->ops->free_mark(mark);
        fsnotify_put_group(group);
    }
}
static int fsnotify_add_inode_mark(struct fsnotify_mark *mark, struct inode *inode, int flags) {
    (void)inode; (void)flags;
    if (fail_mark) return -ENOMEM;
    mark->attached = true; mark->refs++; mark->group->mark = mark; inode_holds++;
    return 0;
}
static struct fsnotify_group *fsnotify_alloc_group(const struct fsnotify_ops *ops, int flags) {
    (void)flags;
    if (fail_group) return ERR_PTR(-ENOMEM);
    struct fsnotify_group *group = calloc(1, sizeof(*group));
    group->ops = ops; group->refs = 1; groups_live++; return group;
}
static void fsnotify_destroy_group(struct fsnotify_group *group) {
    assert(group && !IS_ERR(group));
    if (group->mark) fsnotify_put_mark(group->mark);
    fsnotify_put_group(group);
}
static void ihold(struct inode *inode) { assert(inode); inode_holds++; }
static void iput(struct inode *inode) { assert(inode && inode_holds > 0); inode_holds--; }
static void path_put(struct path *path) { assert(path->mnt && path_holds > 0); path_holds--; }
static int kern_path(const char *name, int flags, struct path *path) {
    (void)name; (void)flags;
    if (fail_path) return -ENOENT;
    directory.inode = missing_inode ? NULL : &underlying;
    path->mnt = &mount; path->dentry = &directory; path_holds++; return 0;
}
static struct inode *d_backing_inode(struct dentry *dentry) { return dentry->inode; }
struct cred { int unused; };
static struct cred *prepare_creds(void) { return calloc(1, sizeof(struct cred)); }
static void setup_selinux(const char *name, struct cred *cred) { (void)name; (void)cred; }
static void commit_creds(struct cred *cred) { free(cred); }
static bool susfs_is_current_ksu_domain(void) { return true; }
static int susfs_handle_sdcard_inode_event(struct fsnotify_mark *mark, u32 mask,
        struct inode *inode, struct inode *dir, const struct qstr *name, u32 cookie) {
    (void)mark; (void)mask; (void)inode; (void)dir; (void)name; (void)cookie; return 0;
}
struct page { int unused; };
struct file { struct inode *inode; };
struct vm_area_struct;
struct vm_operations_struct {
    int (*access)(struct vm_area_struct *, unsigned long, void *, int, int);
};
struct vm_area_struct { struct file *vm_file; const struct vm_operations_struct *vm_ops; };
struct mm_struct { int unused; };
static struct page remote_page;
static struct file remote_file = {&underlying};
static int page_pins, page_puts, gup_error, fallback_calls;
static int remote_access(struct vm_area_struct *vma, unsigned long addr, void *buf,
                         int len, int write) {
    (void)vma; (void)addr; (void)buf; (void)write; fallback_calls++; return len;
}
static const struct vm_operations_struct remote_ops = {.access = remote_access};
static struct vm_area_struct remote_vma = {&remote_file, &remote_ops};
static struct vm_area_struct *vma_lookup(struct mm_struct *mm, unsigned long addr) {
    (void)mm; (void)addr; return &remote_vma;
}
static struct vm_area_struct *expand_stack(struct mm_struct *mm, unsigned long addr) {
    (void)mm; (void)addr; return NULL;
}
static struct page *get_user_page_vma_remote(struct mm_struct *mm, unsigned long addr,
        unsigned int flags, struct vm_area_struct **vma) {
    (void)mm; (void)addr; (void)flags;
    if (gup_error) return ERR_PTR(-EFAULT);
    *vma = &remote_vma; page_pins++; return &remote_page;
}
static void put_page(struct page *page) {
    assert(page == &remote_page && page_pins > 0); page_pins--; page_puts++;
}
static struct inode *file_inode(struct file *file) { return file->inode; }
#define SUSFS_IS_INODE_SUS_MAP(inode) ((inode)->hidden)
#define STATX_SUS_KSTAT 0x10000000U
#define STATX_SUS_KSTAT_FUSE 0x20000000U
#define real_mount(mount) (mount)
struct kstat { uint64_t mnt_id; u32 result_mask; };
static bool susfs_is_current_app_uid(void) { return true; }
static bool susfs_is_inode_sus_kstat(struct inode *inode, bool *is_fuse) {
    *is_fuse = inode->fuse; return inode->marked;
}
'''

TESTS = r'''
static void assert_released(void) {
    assert(!groups_live && !marks_live && !inode_holds && !path_holds);
    assert(!g && !g_watch.inode && !g_watch.kpath.mnt && !g_watch.mark);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    if (!strcmp(argv[1], "success")) {
        assert(susfs_sdcard_monitor_fn(NULL) == 0);
        assert(groups_live == 1 && marks_live == 1 && inode_holds == 2 && path_holds == 1);
        assert(g->mark && g->mark->refs == 1 && !g_watch.mark);
        susfs_sdcard_cleanup_fn(NULL);
        assert(marks_freed == 1);
    } else if (!strcmp(argv[1], "group-error")) {
        fail_group = 1; assert(susfs_sdcard_monitor_fn(NULL) == -ENOMEM);
    } else if (!strcmp(argv[1], "path-error")) {
        fail_path = 1; assert(susfs_sdcard_monitor_fn(NULL) == -ENOENT);
    } else if (!strcmp(argv[1], "inode-error")) {
        missing_inode = 1; assert(susfs_sdcard_monitor_fn(NULL) == -ENOENT);
    } else if (!strcmp(argv[1], "mark-error")) {
        fail_mark = 1; assert(susfs_sdcard_monitor_fn(NULL) == -EINVAL);
        assert(marks_freed == 1);
    } else if (!strcmp(argv[1], "remote")) {
        underlying.hidden = true;
        assert(probe_remote() == 0 && page_pins == 0 && page_puts == 1);
        underlying.hidden = false;
        assert(probe_remote() == 1 && page_pins == 0 && page_puts == 2);
        gup_error = 1;
        underlying.hidden = true;
        assert(probe_remote() == 0 && page_pins == 0 && page_puts == 2 && fallback_calls == 0);
        underlying.hidden = false;
        assert(probe_remote() == 1 && page_pins == 0 && page_puts == 2 && fallback_calls == 1);
        remote_vma.vm_ops = NULL;
        assert(probe_remote() == 0 && page_pins == 0 && page_puts == 2 && fallback_calls == 1);
        susfs_is_sdcard_android_data_not_decrypted.enabled = false;
    } else if (!strcmp(argv[1], "stat")) {
        directory.inode = &underlying;
        underlying.marked = true; underlying.fuse = false;
        assert(probe_stat() == STATX_SUS_KSTAT);
        underlying.fuse = true; assert(probe_stat() == STATX_SUS_KSTAT_FUSE);
        underlying.marked = false; assert(probe_stat() == 0);
        susfs_is_sdcard_android_data_not_decrypted.enabled = false;
    } else assert(0);
    assert_released();
    assert(!susfs_is_sdcard_android_data_not_decrypted.enabled);
    printf("PASS %s\n", argv[1]);
    return 0;
}
'''


class SusfsRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        baseline = Path(os.environ.get('ONYX_TEST_COMMON_DIR', PORT.parent / 'common'))
        if not all((baseline / name).is_file() for name in ('fs/stat.c', 'mm/memory.c')):
            raise unittest.SkipTest('Set ONYX_TEST_COMMON_DIR to pinned common source')
        compiler = shutil.which('cc')
        if compiler is None:
            raise unittest.SkipTest('Host C compiler required')
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.common = cls.root / 'common'
        for name in ('fs/stat.c', 'mm/memory.c'):
            target = cls.common / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(baseline / name, target)
        shutil.copy2(VENDOR / 'fs/susfs.c', cls.common / 'fs/susfs.c')
        sections = re.split(r'(?m)(?=^diff --git )',
                            (VENDOR / '50_add_susfs_in_gki-android17-6.18.patch').read_text())
        for name in ('fs/stat.c', 'mm/memory.c'):
            if ('CONFIG_KSU_SUSFS' in (cls.common / name).read_text()):
                continue
            section = next(piece for piece in sections if piece.startswith('diff --git a/' + name + ' '))
            patch_path = cls.root / (Path(name).stem + '.patch')
            patch_path.write_text(section)
            if name == 'fs/stat.c':
                context_spec = importlib.util.spec_from_file_location(
                    '_susfs_test_context', PORT / 'features/rebuild_susfs.py')
                context_adapter = importlib.util.module_from_spec(context_spec)
                context_spec.loader.exec_module(context_adapter)
                context_adapter.adapt_stat_context(cls.common, patch_path)
            applied = subprocess.run(['git', 'apply', str(patch_path)], cwd=cls.common,
                                     capture_output=True, text=True)
            if applied.returncode:
                raise RuntimeError(applied.stderr)
        cls.before = {name: (cls.common / name).read_bytes()
                      for name in ('fs/susfs.c', 'fs/stat.c', 'mm/memory.c')}
        runtime.adapt(cls.common)
        fs = (cls.common / 'fs/susfs.c').read_text()
        declarations = fs[fs.index('#define SDCARD_ANDROID_PATH '):
                          fs.index('static int add_mark_on_inode(')]
        declarations += '\nstatic struct delayed_work sdcard_cleanup_dwork;\n'
        ops = re.search(r'static const struct fsnotify_ops fsnotify_ops = \{[\s\S]*?\n\};', fs).group()
        functions = '\n\n'.join(runtime.function(fs, name) for name in
            ('susfs_free_sdcard_mark', 'add_mark_on_inode', 'watch_one_dir',
             'susfs_sdcard_cleanup_fn', 'susfs_sdcard_monitor_fn'))
        # The actual ops initializer is needed before the mark-creation function.
        free_mark = runtime.function(fs, 'susfs_free_sdcard_mark')
        functions = functions[len(free_mark):]
        memory = runtime.function((cls.common / 'mm/memory.c').read_text(), '__access_remote_vm')
        segment = memory[memory.index('\t\tstruct vm_area_struct *vma = NULL;'):
                         memory.index('\n\t\tif (IS_ERR(page))')]
        error_start = memory.index('\t\tif (IS_ERR(page))')
        error_end = memory.index('{', error_start) + 1
        depth = 1
        while depth:
            if memory[error_end] == '{':
                depth += 1
            elif memory[error_end] == '}':
                depth -= 1
            error_end += 1
        error_segment = memory[error_start:error_end]
        remote = ('\nstatic int probe_remote(void) {\n'
                  '\tstruct mm_struct state = {0}; struct mm_struct *mm = &state;\n'
                  '\tunsigned long addr = 0; unsigned int gup_flags = 0;\n'
                  '\tchar buffer[1]; void *buf = buffer, *old_buf = buf; int len = 1, write = 0;\n'
                  '\twhile (1) {\n\t\tint bytes = 0;\n' + segment + '\n'
                  + error_segment + ' else {\n\t\t\tput_page(page); return 1;\n\t\t}\n'
                  '\t\treturn bytes;\n'
                  '\t}\n\treturn 0;\n}\n')
        stat = runtime.function((cls.common / 'fs/stat.c').read_text(), 'vfs_getattr_nosec')
        begin = stat.index('\tif (susfs_is_current_app_uid()) {')
        end = stat.index('#endif // #ifdef CONFIG_KSU_SUSFS_SUS_KSTAT', begin)
        stat_segment = stat[begin:end]
        stat_probe = ('\nstatic u32 probe_stat(void) {\n'
                      '\tstruct path state = {&mount, &directory}; struct path *path = &state;\n'
                      '\tstruct kstat result = {0}; struct kstat *stat = &result;\n'
                      + stat_segment + '\tassert(stat->mnt_id == (underlying.marked ? 7 : 0));\n'
                      '\treturn stat->result_mask;\n}\n')
        harness = cls.root / 'susfs-runtime.c'
        harness.write_text(PREFIX + declarations + free_mark + '\n' + ops + functions
                           + remote + stat_probe + TESTS)
        cls.executable = cls.root / 'susfs-runtime'
        compiled = subprocess.run([compiler, '-std=gnu11', '-O1', '-Wall', '-Werror',
                                   str(harness), '-o', str(cls.executable)],
                                  capture_output=True, text=True)
        if compiled.returncode:
            raise RuntimeError(compiled.stderr)

    def test_mark_lifetime_failures_and_page_stat_hooks(self):
        for mode in ('success', 'group-error', 'path-error', 'inode-error', 'mark-error',
                     'remote', 'stat'):
            with self.subTest(mode=mode):
                result = subprocess.run([str(self.executable), mode], check=True,
                                        capture_output=True, text=True)
                self.assertEqual('PASS ' + mode + '\n', result.stdout)

    def test_runtime_adaptation_is_idempotent(self):
        before = {name: (self.common / name).read_bytes() for name in self.before}
        runtime.adapt(self.common)
        self.assertEqual(before, {name: (self.common / name).read_bytes() for name in self.before})

    def test_drift_in_memory_hook_does_not_write_other_sources(self):
        other = self.root / 'drift'
        snapshots = dict(self.before)
        snapshots['mm/memory.c'] = snapshots['mm/memory.c'].replace(
            b'page = get_user_page_vma_remote(mm, addr,', b'page = unexpected_page_api(mm, addr,', 1)
        for name, data in snapshots.items():
            (other / name).parent.mkdir(parents=True, exist_ok=True)
            (other / name).write_bytes(data)
        with self.assertRaises(ValueError):
            runtime.adapt(other)
        self.assertEqual(snapshots, {name: (other / name).read_bytes() for name in snapshots})


if __name__ == '__main__':
    unittest.main()
