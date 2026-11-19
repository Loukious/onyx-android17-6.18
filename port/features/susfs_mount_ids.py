"""Keep SUSFS presentation IDs separate from the 6.18 mount allocator's ownership."""
from pathlib import Path
import re

CONFIG = 'CONFIG_KSU_SUSFS_SUS_MOUNT'
FACTORY_SIGNATURE = ('static struct mount *alloc_vfsmnt_with_id(const char *name, u32 min_id,\n'
                     '\t\t\t\t\t  int visible_id)')
FACTORY_DECLARATION = FACTORY_SIGNATURE + ';\n'


def function_span(source, signature):
    matches = list(re.finditer(re.escape(signature) + r'\s*\n\{', source))
    if len(matches) != 1:
        raise ValueError('Mount allocator definition changed: ' + signature)
    start = matches[0].start()
    brace = source.index('{', matches[0].start())
    depth = 1
    end = brace + 1
    while end < len(source) and depth:
        if source[end] == '{':
            depth += 1
        elif source[end] == '}':
            depth -= 1
        end += 1
    if depth:
        raise ValueError('Unterminated mount allocator: ' + signature)
    return start, end


def function(source, signature):
    start, end = function_span(source, signature)
    return source[start:end]


def replace_function(source, signature, replacement):
    start, end = function_span(source, signature)
    return source[:start] + replacement + source[end:]


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('Mount allocator anchor changed: ' + old.splitlines()[0])
    return source.replace(old, new, 1)


def adapt(common: Path):
    """Run after WildKernels' susfs_618_compile_fixes.py, before generating the patch."""
    namespace_path = Path(common) / 'fs/namespace.c'
    mount_path = Path(common) / 'fs/mount.h'
    namespace = namespace_path.read_text()
    mount = mount_path.read_text()
    if 'mnt_id_allocated' in namespace or 'mnt_id_allocated' in mount:
        if (FACTORY_SIGNATURE not in namespace or 'mnt_id_allocated' not in mount
                or 'XA_LIMIT(min_id, INT_MAX)' not in namespace
                or 'xa_erase(&mnt_id_xa, mnt->mnt_id_allocated)' not in namespace
                or 'sus_mnt_id_ctr' in namespace):
            raise ValueError('Incomplete SUSFS mount allocator adaptation')
        return

    allocator_signature = 'static int mnt_alloc_id(struct mount *mnt)'
    allocator = function(namespace, allocator_signature)
    if 'mnt->mnt_id_unique = ++mnt_id_ctr;' not in allocator:
        raise ValueError('Native mount unique-ID allocator changed')
    allocator = replace_once(allocator, allocator_signature,
                             'static int mnt_alloc_id(struct mount *mnt, u32 min_id)')
    allocator = replace_once(allocator, 'xa_limit_31b', 'XA_LIMIT(min_id, INT_MAX)')
    allocator = replace_once(allocator,
        '\tif (!res)\n\t\tmnt->mnt_id_unique = ++mnt_id_ctr;',
        '\tif (!res) {\n'
        f'#ifdef {CONFIG}\n'
        '\t\t/* This key belongs to this allocation, even when mnt_id is spoofed. */\n'
        '\t\tmnt->mnt_id_allocated = mnt->mnt_id;\n'
        '#endif\n'
        '\t\tmnt->mnt_id_unique = ++mnt_id_ctr;\n'
        '\t}')
    namespace = replace_function(namespace, allocator_signature, allocator)
    namespace = replace_function(namespace, 'static void mnt_free_id(struct mount *mnt)',
        'static void mnt_free_id(struct mount *mnt)\n{\n'
        f'#ifdef {CONFIG}\n'
        '\txa_erase(&mnt_id_xa, mnt->mnt_id_allocated);\n'
        '#else\n'
        '\txa_erase(&mnt_id_xa, mnt->mnt_id);\n'
        '#endif\n}')

    native_signature = 'static struct mount *alloc_vfsmnt(const char *name)'
    factory = function(namespace, native_signature)
    factory = replace_once(factory, native_signature, FACTORY_SIGNATURE)
    factory = replace_once(factory, 'mnt_alloc_id(mnt)', 'mnt_alloc_id(mnt, min_id)')
    factory = replace_once(factory, '\t\tmnt->mnt.mnt_idmap = &nop_mnt_idmap;',
        '\t\tmnt->mnt.mnt_idmap = &nop_mnt_idmap;\n'
        '\t\t/* -1 means expose the allocated ID; zero is a valid presentation ID. */\n'
        '\t\tif (visible_id >= 0)\n'
        '\t\t\tmnt->mnt_id = visible_id;')
    wrapper = '\n\n' + native_signature + '\n{\n' \
              '\treturn alloc_vfsmnt_with_id(name, 0, -1);\n}'
    namespace = replace_function(namespace, native_signature, factory + wrapper)
    namespace = replace_once(namespace, native_signature + ';\n',
                             native_signature + ';\n' + FACTORY_DECLARATION)

    bad_signature = ('static struct mount *susfs_alloc_ksu_vfsmnt(const char *name, '
                     'int forced_mnt_id)')
    bad_helper = function(namespace, bad_signature)
    if 'xa_erase(&mnt_id_xa, mnt->mnt_id)' not in bad_helper:
        raise ValueError('WildKernels mount helper changed before ownership adaptation')
    namespace = replace_function(namespace, bad_signature, '')
    unshare = ('static struct mount *susfs_alloc_unshare_ksu_vfsmnt(const char *name, '
               'int old_mnt_id)')
    namespace = replace_function(namespace, unshare,
        unshare + '\n{\n'
        '\treturn alloc_vfsmnt_with_id(name, DEFAULT_KSU_MNT_ID, old_mnt_id);\n}')
    regular = 'static struct mount *susfs_alloc_non_unshare_ksu_vfsmnt(const char *name)'
    namespace = replace_function(namespace, regular,
        regular + '\n{\n'
        '\treturn alloc_vfsmnt_with_id(name, DEFAULT_KSU_MNT_ID, -1);\n}')
    namespace = replace_once(namespace,
        f'#ifdef {CONFIG}\nstatic atomic64_t sus_mnt_id_ctr = ATOMIC64_INIT(0);\n'
        f'#endif // #ifdef {CONFIG}\n', '')
    if 'sus_mnt_id_ctr' in namespace:
        raise ValueError('Unexpected remaining independent SUSFS mount counter')
    # The imported helper's explanatory comment described the removed unsafe ID swap.
    namespace = re.sub(r'/\* 6\.18 port of the SUSFS mount allocators\.[\s\S]*?\*/',
        '/* SUSFS presentation IDs retain independently reserved native allocator keys. */',
        namespace, count=1)

    identity_field = re.search(r'(?m)^\tint mnt_id;[^\n]*\n', mount)
    if identity_field is None:
        raise ValueError('Native struct mount ID fields changed')
    at = identity_field.end()
    mount = (mount[:at] + f'#ifdef {CONFIG}\n'
             '\tint mnt_id_allocated;\t\t/* owned key in mnt_id_xa */\n'
             '#endif\n' + mount[at:])
    # Complete all validation before writing either source file.
    namespace_path.write_text(namespace)
    mount_path.write_text(mount)
