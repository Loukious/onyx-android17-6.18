"""Correct 6.18 SUSFS mark lifetime and VMA/stat hook placement before patch generation."""
import ast
from pathlib import Path
import re


def span(source, name):
    matches = list(re.finditer(r'(?m)^[^\n;{}]*\b' + re.escape(name)
                              + r'\([^;{}]*\)\s*\{', source))
    if len(matches) != 1:
        raise ValueError('SUSFS runtime function changed: ' + name)
    start = matches[0].start()
    end = source.index('{', start) + 1
    depth = 1
    while end < len(source) and depth:
        if source[end] == '{':
            depth += 1
        elif source[end] == '}':
            depth -= 1
        end += 1
    if depth:
        raise ValueError('Unterminated SUSFS runtime function: ' + name)
    return start, end


def function(source, name):
    start, end = span(source, name)
    return source[start:end]


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('SUSFS runtime anchor changed: ' + old.splitlines()[0])
    return source.replace(old, new, 1)


def replace_function(source, name, contents):
    start, end = span(source, name)
    return source[:start] + contents + source[end:]


def fix_sdcard(source):
    source = once(source, 'static const struct fsnotify_ops fsnotify_ops = {\n',
        '/* fsnotify always calls free_mark when the last mark reference is dropped. */\n'
        'static void susfs_free_sdcard_mark(struct fsnotify_mark *mark)\n'
        '{\n\tkfree(mark);\n}\n\n'
        'static const struct fsnotify_ops fsnotify_ops = {\n'
        '\t.free_mark = susfs_free_sdcard_mark,\n')
    add_mark = function(source, 'add_mark_on_inode')
    add_mark = once(add_mark, '\t*out = m;\n\treturn 0;',
        '\t/* The group owns the attached mark; do not keep an unowned pointer. */\n'
        '\t*out = NULL;\n'
        '\tfsnotify_put_mark(m);\n'
        '\treturn 0;')
    source = replace_function(source, 'add_mark_on_inode', add_mark)
    watch = function(source, 'watch_one_dir')
    if watch.count('path_put(&wd->kpath);') != 2:
        raise ValueError('SUSFS watch failure cleanup changed')
    watch = watch.replace('path_put(&wd->kpath);',
                          'path_put(&wd->kpath);\n\t\tmemset(&wd->kpath, 0, sizeof(wd->kpath));')
    source = replace_function(source, 'watch_one_dir', watch)
    monitor = function(source, 'susfs_sdcard_monitor_fn')
    monitor = once(monitor, '\tif (IS_ERR(g)) {\n\t\treturn PTR_ERR(g);\n\t}',
        '\tif (IS_ERR(g)) {\n'
        '\t\tret = PTR_ERR(g);\n'
        '\t\tg = NULL;\n'
        '\t\tsusfs_sdcard_cleanup_fn(NULL);\n'
        '\t\treturn ret;\n\t}')
    monitor = once(monitor, '\tret = watch_one_dir(&g_watch);',
        '\tret = watch_one_dir(&g_watch);\n'
        '\tif (ret) {\n'
        '\t\t/* Setup runs outside fsnotify SRCU, so synchronous cleanup is safe. */\n'
        '\t\tsusfs_sdcard_cleanup_fn(NULL);\n'
        '\t\treturn ret;\n\t}')
    return replace_function(source, 'susfs_sdcard_monitor_fn', monitor)


def fix_remote_memory(source):
    body = function(source, '__access_remote_vm')
    old = ('#ifdef CONFIG_KSU_SUSFS_SUS_MAP\n'
           '\t\tstruct page *page = NULL;\n\n'
           '\t\tif (vma && vma->vm_file && SUSFS_IS_INODE_SUS_MAP(file_inode(vma->vm_file)))\n'
           '\t\t\tbreak;\n\n'
           '\t\tpage = get_user_page_vma_remote(mm, addr,\n'
           '\t\t\t\t\t\t\t     gup_flags, &vma);\n'
           '#else\n'
           '\t\tstruct page *page = get_user_page_vma_remote(mm, addr,\n'
           '\t\t\t\t\t\t     gup_flags, &vma);\n'
           '#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MAP')
    new = ('\t\tstruct page *page = get_user_page_vma_remote(mm, addr,\n'
           '\t\t\t\t\t\t     gup_flags, &vma);\n'
           '#ifdef CONFIG_KSU_SUSFS_SUS_MAP\n'
           '\t\t/* GUP supplies the VMA and a page reference before this check. */\n'
           '\t\tif (!IS_ERR(page) && vma && vma->vm_file &&\n'
           '\t\t    SUSFS_IS_INODE_SUS_MAP(file_inode(vma->vm_file))) {\n'
           '\t\t\tput_page(page);\n'
           '\t\t\tbreak;\n'
           '\t\t}\n'
           '#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MAP')
    # Native 6.18 sublevels differ only in the continuation-line indentation here.
    pattern = '\n'.join(
        ''.join(r'[ \t]+' if re.fullmatch(r'[ \t]+', token) else re.escape(token)
                for token in re.split(r'([ \t]+)', line)) if line else r'[ \t]*'
        for line in old.split('\n'))
    matches = list(re.finditer(pattern, body))
    if len(matches) != 1:
        raise ValueError('SUSFS remote-memory GUP hook changed')
    match = matches[0]
    body = body[:match.start()] + new + body[match.end():]
    body = once(body, '\t\t\tvma = vma_lookup(mm, addr);',
        '\t\t\tvma = vma_lookup(mm, addr);\n'
        '#ifdef CONFIG_KSU_SUSFS_SUS_MAP\n'
        '\t\t\t/* A failed GUP can still resolve a VMA for VM_IO access. */\n'
        '\t\t\tif (vma && vma->vm_file &&\n'
        '\t\t\t    SUSFS_IS_INODE_SUS_MAP(file_inode(vma->vm_file)))\n'
        '\t\t\t\tbreak;\n'
        '#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MAP')
    return replace_function(source, '__access_remote_vm', body)


def fix_stat(source):
    body = function(source, 'vfs_getattr_nosec')
    body = once(body,
        '\t\t\t\tstat->result_mask |= STATX_SUS_KSTAT;\n'
        '\t\t\t}\n'
        '\t\t\tstat->mnt_id = real_mount(path->mnt)->mnt_id;\n'
        '\t\t\tstat->result_mask |= STATX_SUS_KSTAT_FUSE;',
        '\t\t\t\tstat->result_mask |= STATX_SUS_KSTAT;\n'
        '\t\t\t} else {\n'
        '\t\t\t\tstat->mnt_id = real_mount(path->mnt)->mnt_id;\n'
        '\t\t\t\tstat->result_mask |= STATX_SUS_KSTAT_FUSE;\n'
        '\t\t\t}')
    return replace_function(source, 'vfs_getattr_nosec', body)


def flag_definitions(source, prefix):
    """Read native flag definitions without evaluating arbitrary source text."""
    source = re.sub(r'/\*[\s\S]*?\*/', '', source.replace('\\\n', ''))
    definitions = {}
    for name, value in re.findall(r'(?m)^#define\s+(' + re.escape(prefix) +
                                  r'\w+)\s+([^\n]+)', source):
        if name in definitions:
            raise ValueError('Duplicate native flag: ' + name)
        definitions[name] = value.strip()
    if not definitions:
        raise ValueError('Missing native flags: ' + prefix)
    return definitions


def flag_value(expression, definitions, seen=()):
    """Evaluate the integer/BIT/OR forms used by the pinned flag headers."""
    def evaluate(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.Name) and node.id in definitions and node.id not in seen:
            return flag_value(definitions[node.id], definitions, seen + (node.id,))
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
                node.func.id == 'BIT' and len(node.args) == 1 and not node.keywords):
            return 1 << evaluate(node.args[0])
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return evaluate(node.left) | evaluate(node.right)
        raise ValueError('Unsupported native flag expression: ' + expression)
    return evaluate(ast.parse(expression, mode='eval').body)


def validate_namei_flags(source, native_lookup):
    native_state = flag_definitions(source, 'ND_')
    lookup_bit = 1 << 11
    for name, value in native_lookup.items():
        if flag_value(value, native_lookup) & lookup_bit:
            raise ValueError('SUSFS private lookup bit collides with ' + name)
    for name, value in native_state.items():
        if flag_value(value, native_state) & (32 | 64):
            raise ValueError('SUSFS private state bits collide with ' + name)
    return native_state


def fix_namei(source, native_lookup):
    native_state = validate_namei_flags(source, native_lookup)
    lookup_mask = ' |\n\t '.join(' | '.join(list(native_lookup)[i:i + 4])
                                 for i in range(0, len(native_lookup), 4))
    state_mask = ' | '.join(native_state)
    guard = ('\n#ifdef CONFIG_KSU_SUSFS_SUS_PATH\n'
             '/* SUSFS metadata must never enable native path-resolution restrictions. */\n'
             'static_assert(!(ND_FLAGS_LOOKUP_LAST &\n\t(' + lookup_mask + ')));\n'
             'static_assert(!((ND_STATE_LOOKUP_LAST | ND_STATE_OPEN_LAST) &\n'
             '\t(' + state_mask + ')));\n'
             'static_assert(!(ND_STATE_LOOKUP_LAST & ND_STATE_OPEN_LAST));\n'
             '#endif\n')
    # Guard exactly the native names seen at generation; new flags are checked
    # before a regenerated patch can be written.
    anchor = re.search(r'(?m)^#define ND_JUMPED[^\n]+\n', source)
    if not anchor:
        raise ValueError('SUSFS native nameidata state anchor changed')
    source = source[:anchor.end()] + guard + source[anchor.end():]
    body = function(source, '__lookup_slow')
    body = once(body,
        '\tbool is_nd_flags_lookup_last = (flags & ND_FLAGS_LOOKUP_LAST);',
        '\tbool is_nd_flags_lookup_last = (flags & ND_FLAGS_LOOKUP_LAST);\n'
        '\n\t/* Consume the private marker before filesystem lookup/revalidation. */\n'
        '\tflags &= ~ND_FLAGS_LOOKUP_LAST;')
    source = replace_function(source, '__lookup_slow', body)
    body = function(source, 'walk_component')
    body = once(body,
        '#ifdef CONFIG_KSU_SUSFS_SUS_PATH\n'
        '\t\tif (nd->state & ND_STATE_LOOKUP_LAST) {\n'
        '\t\t\tnd->flags |= ND_FLAGS_LOOKUP_LAST;\n'
        '\t\t}\n'
        '#endif\n'
        '\t\tdentry = lookup_slow(&nd->last, nd->path.dentry, nd->flags);',
        '#ifdef CONFIG_KSU_SUSFS_SUS_PATH\n'
        '\t\t/* Keep SUSFS metadata out of the persistent pathwalk flags. */\n'
        '\t\tunsigned int lookup_flags = nd->flags;\n'
        '\n\t\tif (nd->state & ND_STATE_LOOKUP_LAST)\n'
        '\t\t\tlookup_flags |= ND_FLAGS_LOOKUP_LAST;\n'
        '\t\tdentry = lookup_slow(&nd->last, nd->path.dentry, lookup_flags);\n'
        '#else\n'
        '\t\tdentry = lookup_slow(&nd->last, nd->path.dentry, nd->flags);\n'
        '#endif')
    return replace_function(source, 'walk_component', body)


def adapt_namei(common: Path):
    """Isolate the upstream SUSFS final-component marker from native lookup flags."""
    common = Path(common)
    namei = common / 'fs/namei.c'
    definitions = common / 'include/linux/susfs_def.h'
    source, flags = namei.read_text(), definitions.read_text()
    native = flag_definitions((common / 'include/linux/namei.h').read_text(), 'LOOKUP_')
    validate_namei_flags(source, native)
    done = [
        '/* SUSFS metadata must never enable native path-resolution restrictions. */' in source,
        '/* Keep SUSFS metadata out of the persistent pathwalk flags. */' in source,
        '\tflags &= ~ND_FLAGS_LOOKUP_LAST;' in function(source, '__lookup_slow'),
        '#define ND_FLAGS_LOOKUP_LAST BIT(11)' in flags,
    ]
    if any(done):
        if not all(done):
            raise ValueError('Incomplete SUSFS namei adaptation')
        return
    source = fix_namei(source, native)
    flags = once(flags, '#define ND_FLAGS_LOOKUP_LAST 0x2000000',
                 '#define ND_FLAGS_LOOKUP_LAST BIT(11) /* consumed by __lookup_slow */')
    # All anchors and bit collisions are checked before either file changes.
    namei.write_text(source)
    definitions.write_text(flags)


VISIBLE_ROOT_MOUNT_HELPER = '''#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
/*
 * A propagated mount can sit beneath a legitimate root overmount. Hiding that
 * parent must not hide the visible filesystem mounted at the very same path.
 * Keep the native mount tree intact: dotdot/root checks and the caller's
 * mount_lock sequence/refcount validation still apply to the returned mount.
 */
static struct mount *susfs_visible_root_mount(struct mount *mnt)
{
	struct mount *slow = mnt;
	bool advance_slow = false;

	while (READ_ONCE(mnt->mnt_id) >= DEFAULT_KSU_MNT_ID) {
		struct dentry *root = READ_ONCE(mnt->mnt.mnt_root);
		struct mount *next;

		/* Do not bypass managed transit or an automount at a skipped root. */
		if (!root || (READ_ONCE(root->d_flags) &
			     (DCACHE_MANAGE_TRANSIT | DCACHE_NEED_AUTOMOUNT)))
			return NULL;
		next = READ_ONCE(mnt->overmount);
		if (!next || next == mnt || READ_ONCE(next->mnt_parent) != mnt ||
		    READ_ONCE(next->mnt_mountpoint) != root)
			return NULL;
		mnt = next;

		/* Fail closed on a corrupt/transient cycle without a depth limit. */
		if (advance_slow) {
			slow = READ_ONCE(slow->overmount);
			if (!slow)
				return NULL;
		}
		advance_slow = !advance_slow;
		if (mnt == slow)
			return NULL;
	}
	return mnt;
}
#endif

'''

OLD_APP_MOUNT_LOOKUP = '''	if (susfs_is_current_proc_umounted()) {
		hlist_for_each_entry_rcu(p, head, mnt_hash)
			if (p->mnt_id < DEFAULT_KSU_MNT_ID && &p->mnt_parent->mnt == mnt && p->mnt_mountpoint == dentry)
				return p;
		return NULL;
	}'''

NEW_APP_MOUNT_LOOKUP = '''	if (susfs_is_current_proc_umounted()) {
		hlist_for_each_entry_rcu(p, head, mnt_hash) {
			struct mount *visible;

			if (READ_ONCE(p->mnt_parent) != real_mount(mnt) ||
			    READ_ONCE(p->mnt_mountpoint) != dentry)
				continue;
			visible = susfs_visible_root_mount(p);
			if (visible)
				return visible;
		}
		return NULL;
	}'''

SUS_PATH_SHARED_ABI = '''/* Share the inode-only SUS_PATH ABI with every lookup caller. */
struct inode;
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
bool susfs_is_inode_sus_path(struct inode *inode);
#endif

'''


def verify_sus_path_calls(source, expected_count):
    calls = re.findall(r'\bsusfs_is_inode_sus_path\(([^()]*)\)', source)
    if len(calls) != expected_count or any(',' in arguments for arguments in calls):
        raise ValueError('SUSFS inode-only lookup ABI/call inventory changed')
    if '#include <linux/susfs.h>' not in source:
        raise ValueError('SUSFS lookup caller lacks the shared ABI header')


def fix_app_mounts_and_path_api(namespace, namei, readdir, header):
    namespace = once(namespace, '/**\n * __lookup_mnt - mount hash lookup\n',
                     VISIBLE_ROOT_MOUNT_HELPER + '/**\n * __lookup_mnt - mount hash lookup\n')
    signature = 'struct mount *__lookup_mnt'
    body = function(namespace, signature)
    body = once(body, OLD_APP_MOUNT_LOOKUP, NEW_APP_MOUNT_LOOKUP)
    namespace = replace_function(namespace, signature, body)
    declaration = 'extern bool susfs_is_inode_sus_path(struct mnt_idmap* idmap, struct inode *inode);\n'
    callers = []
    for source, old_arguments, count in ((namei, '&nop_mnt_idmap, ', 7),
                                         (readdir, 'buf->idmap, ', 5)):
        source = once(source, declaration, '')
        source = once(source, '#include <linux/susfs_def.h>\n',
                      '#include <linux/susfs_def.h>\n#include <linux/susfs.h>\n')
        prefix = 'susfs_is_inode_sus_path(' + old_arguments
        if source.count(prefix) != count:
            raise ValueError('SUSFS older idmap lookup call inventory changed')
        source = source.replace(prefix, 'susfs_is_inode_sus_path(')
        verify_sus_path_calls(source, count)
        callers.append(source)
    header = once(header, '#define SUSFS_VERSION "v2.4.0"\n',
                  SUS_PATH_SHARED_ABI + '#define SUSFS_VERSION "v2.4.0"\n')
    return namespace, *callers, header


def adapt_app_mounts_and_path_api(common: Path):
    """Preserve visible root stacks and enforce the actual inode-only SUS_PATH ABI."""
    common = Path(common)
    names = ('fs/namespace.c', 'fs/namei.c', 'fs/readdir.c', 'include/linux/susfs.h')
    sources = [(common / name).read_text() for name in names]
    # The downloaded >=6.12 implementation is inode-only; do not guess at a new ABI.
    implementation = function((common / 'fs/susfs.c').read_text(), 'susfs_is_inode_sus_path')
    if not re.search(r'\bsusfs_is_inode_sus_path\(struct inode \*inode\)', implementation):
        raise ValueError('SUSFS implementation signature changed; review all callers')
    done = ('static struct mount *susfs_visible_root_mount(' in sources[0],
            '#include <linux/susfs.h>' in sources[1],
            '#include <linux/susfs.h>' in sources[2],
            SUS_PATH_SHARED_ABI in sources[3])
    if any(done):
        if not all(done):
            raise ValueError('Incomplete SUSFS app mount/path ABI adaptation')
        if NEW_APP_MOUNT_LOOKUP not in function(sources[0], 'struct mount *__lookup_mnt'):
            raise ValueError('SUSFS app mount lookup changed after adaptation')
        verify_sus_path_calls(sources[1], 7)
        verify_sus_path_calls(sources[2], 5)
        return
    sources = fix_app_mounts_and_path_api(*sources)
    # Validate all files and anchors before changing any generated source.
    for name, source in zip(names, sources):
        (common / name).write_text(source)


def adapt(common: Path):
    common = Path(common)
    files = {name: (common / name).read_text()
             for name in ('fs/susfs.c', 'mm/memory.c', 'fs/stat.c')}
    done = [
        '.free_mark = susfs_free_sdcard_mark,' in files['fs/susfs.c'],
        ('/* GUP supplies the VMA and a page reference before this check. */' in files['mm/memory.c']
         and '/* A failed GUP can still resolve a VMA for VM_IO access. */' in files['mm/memory.c']),
        '\t\t\t} else {\n\t\t\t\tstat->mnt_id = real_mount(path->mnt)->mnt_id;\n'
        '\t\t\t\tstat->result_mask |= STATX_SUS_KSTAT_FUSE;' in files['fs/stat.c'],
    ]
    if any(done):
        if not all(done):
            raise ValueError('Incomplete SUSFS runtime adaptation')
        return
    files['fs/susfs.c'] = fix_sdcard(files['fs/susfs.c'])
    files['mm/memory.c'] = fix_remote_memory(files['mm/memory.c'])
    files['fs/stat.c'] = fix_stat(files['fs/stat.c'])
    # Drift in any input must fail before any of the three files is changed.
    for name, source in files.items():
        (common / name).write_text(source)
