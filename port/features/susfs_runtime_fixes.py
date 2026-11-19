"""Correct 6.18 SUSFS mark lifetime and VMA/stat hook placement before patch generation."""
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
