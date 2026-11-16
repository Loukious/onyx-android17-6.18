#!/usr/bin/env python3
"""Refresh compiler metadata and reviewed dependency pins with Common updates."""
import copy
import re
import subprocess
import xml.etree.ElementTree as ET


METADATA = {'clang', 'rust', 'kmi_generation'}
CONFIGURATIONS = {
    ('r584948c', '1.91.1.p3', 5),
    ('r596125', '1.91.1.p3', 6),
    ('r596125', '1.91.1.p4', 6),
}
CLANG = '4a7d0a5e443c27d8f68fbd46abfab464e1355a69'
RUST_P3 = 'a04f70c5179f23eff11c58cb480acee4afb1334b'
RUST_P4 = '844e1621bcf67c25ceae15bdd3ddd698cbe8df7c'
# Official LTS superproject cd02f01637ffad386976f463cfed0ebdd2216ec6
# pins Common c29a11a6, this Clang and RUST_P4. The Rust update retains the
# exact p3 directory, so an already upgraded lock must not be downgraded.
COMPILERS = {
    'clang': {
        'name': 'platform/prebuilts/clang/host/linux-x86',
        'path': 'prebuilts/clang/host/linux-x86',
        'revisions': {CLANG},
    },
    'rust': {
        'name': 'platform/prebuilts/rust-toolchain/linux-x86',
        'path': 'prebuilts/rust-toolchain/linux-x86',
        'revisions': {RUST_P3, RUST_P4},
    },
}


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


def constants(repo, revision):
    # build.config.constants is a symlink; read its tracked canonical target,
    # rather than its link text or an unchecked working-tree replacement.
    if git(repo, 'show', revision + ':build.config.constants') != 'bazel/constants.scl':
        raise ValueError('Unsupported Common compiler constants location')
    link = git(repo, 'ls-tree', revision, '--', 'build.config.constants')
    if not re.fullmatch(r'120000 blob [0-9a-f]{40}\tbuild\.config\.constants', link):
        raise ValueError('Common build constants must link to the canonical constants')
    tree = git(repo, 'ls-tree', revision, '--', 'bazel/constants.scl')
    if not re.fullmatch(r'100644 blob [0-9a-f]{40}\tbazel/constants\.scl', tree):
        raise ValueError('Common compiler constants must be a regular tracked file')
    fields = {}
    names = {'BRANCH', 'CLANG_VERSION', 'RUSTC_VERSION', 'KMI_GENERATION'}
    allowed = names | {'AARCH64_NDK_TRIPLE', 'X86_64_NDK_TRIPLE', 'ARM_NDK_TRIPLE'}
    declared = set()
    for line in git(repo, 'show', revision + ':bazel/constants.scl').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'([A-Z][A-Z0-9_]*)\s*=\s*(?:"([A-Za-z0-9_.-]+)"|([0-9]+))', line)
        if not match or match.group(1) not in allowed or match.group(1) in declared:
            raise ValueError('Unsupported or duplicate Common compiler constant: ' + line)
        name = match.group(1)
        declared.add(name)
        if name == 'KMI_GENERATION' and match.group(3) is None:
            raise ValueError('Common KMI generation must be an integer constant')
        if name in names:
            fields[name] = match.group(2) or match.group(3)
    if set(fields) != names or fields['BRANCH'] != 'android17-6.18':
        raise ValueError('Incomplete or unsupported Common compiler constants')
    if not re.fullmatch(r'[0-9]+', fields['KMI_GENERATION']):
        raise ValueError('Common KMI generation must be an integer')
    result = {'clang': fields['CLANG_VERSION'], 'rust': fields['RUSTC_VERSION'],
              'kmi_generation': int(fields['KMI_GENERATION'])}
    if (result['clang'], result['rust'], result['kmi_generation']) not in CONFIGURATIONS:
        raise ValueError('Common compiler/KMI configuration requires reviewed dependency pins')
    return result


def lock_revision(lock, compiler, required):
    root = ET.fromstring(lock)
    if root.tag != 'manifest':
        raise ValueError('Compiler dependency lock must be a manifest')
    selected = [entry for entry in root if entry.get('name') == compiler['name']
                or entry.get('path') == compiler['path']]
    if len(selected) != 1:
        raise ValueError('Expected one locked compiler project: ' + compiler['path'])
    entry = selected[0]
    if (entry.tag != 'extend-project' or entry.get('name') != compiler['name']
            or entry.get('path') != compiler['path']
            or entry.get('upstream') != 'main-kernel-2026'
            or entry.get('revision') not in compiler['revisions']):
        raise ValueError('Unsupported locked compiler provenance: ' + compiler['path'])
    if entry.get('revision') == required:
        return lock
    # Change only this revision literal: unrelated locked projects and their
    # formatting remain byte-identical instead of reserializing the manifest.
    matches = []
    for match in re.finditer(r'<extend-project\b[^>]*>', lock):
        fragment = match.group()
        project = ET.fromstring(fragment)
        if project.get('path') == compiler['path']:
            matches.append(match)
    if len(matches) != 1:
        raise ValueError('Expected one compiler revision literal')
    match = matches[0]
    fragment, count = re.subn(r'(\brevision\s*=\s*)(["\'])([^"\']+)\2',
                             lambda value: value.group(1) + value.group(2)
                             + required + value.group(2), match.group())
    if count != 1:
        raise ValueError('Expected one compiler revision attribute')
    return lock[:match.start()] + fragment + lock[match.end():]


def refresh(repo, revision, common, lock):
    """Return prospective metadata/lock; validate everything before any writes."""
    present = METADATA & common.keys()
    if not present:
        # Minimal recipes without toolchain metadata retain their existing API.
        return common, lock
    if present != METADATA or lock is None:
        raise ValueError('Compiler metadata requires a complete dependency lock')
    updated = copy.deepcopy(common)
    updated.update(constants(repo, revision))
    lock = lock_revision(lock, COMPILERS['clang'], CLANG)
    rust = ET.fromstring(lock).find(
        "extend-project[@path='prebuilts/rust-toolchain/linux-x86']")
    current = rust.get('revision') if rust is not None else None
    required = RUST_P4 if updated['rust'] == '1.91.1.p4' else current
    # p3 works with both reviewed revisions; validate provenance even when the
    # requested compiler is already available and no literal changes are needed.
    lock = lock_revision(lock, COMPILERS['rust'], required)
    return updated, lock
