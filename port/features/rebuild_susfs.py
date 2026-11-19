#!/usr/bin/env python3
"""Rebuild the reviewed WildKernels SUSFS patch against pinned Onyx common sources."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

PORT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PORT))
import features


def run(args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def adapt_stat_context(tree, patch):
    """Retain 6.18.63's verity attribute while adding the SUSFS getattr hooks."""
    if 'STATX_ATTR_VERITY' not in (tree / 'fs/stat.c').read_text():
        return
    text = patch.read_text()
    old = ' \t\t\t\t  STATX_ATTR_DAX);\n'
    new = ' \t\t\t\t  STATX_ATTR_DAX |\n \t\t\t\t  STATX_ATTR_VERITY);\n'
    if text.count(old) != 1:
        raise ValueError('SUSFS stat attribute context changed; review the source port')
    text = text.replace(old, new, 1)
    old_header = '@@ -207,15 +223,42 @@'
    if text.count(old_header) != 1:
        raise ValueError('SUSFS getattr hunk changed; review its context')
    patch.write_text(text.replace(old_header, '@@ -207,16 +223,43 @@', 1))


def build(common, output):
    features.builtin_metadata()  # Verify every downloaded source before executing adapters.
    vendor = features.INPUTS / 'vendor/susfs'
    upstream = vendor / '50_add_susfs_in_gki-android17-6.18.patch'
    series = [(p, data, names) for p, data, names in features.patches()
              if p.name != 'susfs-6.18.patch']
    imported = features.nomount_files()
    names = set(re.findall(r'^\+\+\+ b/([^\n\t]+)', upstream.read_text(), re.M))
    names |= set(imported) | {n for _, _, files in series for n in files}
    names.update(('fs/mount.h', 'include/linux/namei.h'))
    common_manifest = json.loads((PORT / 'common-patches/manifest.json').read_text())
    names.update(common_manifest['files'])
    with tempfile.TemporaryDirectory(prefix='onyx-susfs-rebuild-') as directory:
        tree = Path(directory)
        for name in sorted(names):
            source = common / name
            if source.is_file():
                target = features.safe(tree, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
        for source in (common / 'include/trace/hooks').glob('*.h'):
            target = tree / 'include/trace/hooks' / source.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        common_patch = PORT / 'common-patches' / common_manifest['patch']
        if features.sha(common_patch.read_bytes()) != common_manifest['patch_sha256']:
            raise ValueError('Common fixes changed without a source-lock update')
        for name, expected in common_manifest['files'].items():
            path = tree / name
            actual = features.sha(path.read_bytes()) if path.exists() else None
            if actual != expected['before_sha256']:
                raise ValueError('Changed common source before SUSFS generation: ' + name)
        if common_patch.stat().st_size:
            features.apply_patch(tree, common_patch.read_bytes())
        for name, contents in imported.items():
            target = features.safe(tree, name)
            if target.exists():
                raise ValueError('Existing imported source: ' + name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents)
        for _, data, _ in series:
            features.apply_patch(tree, data)
        run(['git', 'init', '-q', str(tree)])
        run(['git', '-C', str(tree), 'add', '.'])
        adapted = tree / '.susfs-upstream.patch'
        shutil.copyfile(upstream, adapted)
        adapters = vendor / 'compat'
        run([sys.executable, str(adapters / 'susfs_618_namespace_mnt_t_flags.py'),
             str(tree), str(adapted)])
        adapt_stat_context(tree, adapted)
        run([sys.executable, str(adapters / 'susfs_restore_context.py'), str(adapted), str(tree)])
        features.apply_patch(tree, adapted.read_bytes(), check=True)
        features.apply_patch(tree, adapted.read_bytes())
        adapted.unlink()
        for name in ('fs/susfs.c', 'include/linux/susfs.h', 'include/linux/susfs_def.h'):
            target = features.safe(tree, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((vendor / name).read_bytes())
        for script in ('susfs_618_task_mmu.py', 'susfs_618_compile_fixes.py',
                       'susfs_618_prototypes.py'):
            run([sys.executable, str(adapters / script), str(tree)])
        spec = importlib.util.spec_from_file_location('susfs_mount_ids',
                                                      features.INPUTS / 'susfs_mount_ids.py')
        allocator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(allocator)
        allocator.adapt(tree)
        spec = importlib.util.spec_from_file_location('susfs_runtime_fixes',
                                                      features.INPUTS / 'susfs_runtime_fixes.py')
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        runtime.adapt(tree)
        runtime.adapt_namei(tree)
        # Canonicalize whitespace from imported additions while retaining the exact
        # upstream source files in the separately hashed vendor inventory.
        normalized = set(re.findall(r'^\+\+\+ b/([^\n\t]+)', upstream.read_text(), re.M))
        normalized.update(('fs/susfs.c', 'fs/mount.h', 'include/linux/susfs.h',
                           'include/linux/susfs_def.h'))
        for name in normalized:
            target = features.safe(tree, name)
            target.write_text('\n'.join(line.rstrip(' \t')
                                        for line in target.read_text().splitlines()) + '\n')
        run(['git', '-C', str(tree), 'add', '-N', '.'])
        data = subprocess.check_output(['git', '-C', str(tree), 'diff', '--no-color',
                                        '--no-renames', '--binary'])
        if not data or b'fs/susfs.c' not in data or b'mnt_id_allocated' not in data:
            raise ValueError('Incomplete built-in SUSFS source patch')
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
        print('Generated ' + str(output))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('common', type=Path)
    parser.add_argument('--output', type=Path,
                        default=features.INPUTS / 'patches/susfs-6.18.patch')
    args = parser.parse_args()
    build(args.common.resolve(), args.output.resolve())
