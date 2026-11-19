#!/usr/bin/env python3
"""Replay locked kernel additions and verify the two release profiles."""
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
INPUTS = HERE / 'features'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe(root, name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or '..' in path.parts or '.git' in path.parts
            or str(path) != name):
        raise ValueError('Unsafe feature path: ' + name)
    result = Path(root)
    for part in path.parts:
        if result.is_symlink():
            raise ValueError('Feature path crosses a symlink')
        result /= part
    if result.is_symlink() or (result.exists() and not result.is_file()):
        raise ValueError('Unexpected feature source type: ' + str(result))
    return result


def manifest():
    data = json.loads((INPUTS / 'manifest.json').read_text())
    if data.get('format') != 1 or [p['id'] for p in data['profiles']] != ['balanced', 'performance']:
        raise ValueError('Invalid kernel feature manifest')
    return data


def profile(name):
    data = manifest()
    selected = next((p for p in data['profiles'] if p['id'] == name), None)
    if selected is None:
        raise ValueError('Unknown kernel variant: ' + name)
    return {'id': name, 'label': selected['label'],
            'features': data['shared_features'] + selected['features'],
            'profile': selected['profile']}


def patches():
    result = []
    for item in manifest()['patch_series']:
        path = safe(INPUTS, item['path'])
        data = path.read_bytes()
        if sha(data) != item['sha256']:
            raise ValueError('Kernel feature patch hash differs: ' + item['path'])
        names = re.findall(rb'^\+\+\+ b/([^\n\t]+)', data, re.M)
        if not names:
            raise ValueError('Feature patch has no source files')
        names = [n.decode() for n in names]
        for name in names:
            safe(Path(tempfile.gettempdir()), name)
        result.append((path, data, names))
    return result


def nomount_files():
    pin = json.loads((INPUTS / 'lock.json').read_text())['nomount']
    data = safe(INPUTS, pin['archive']).read_bytes()
    if sha(data) != pin['sha256']:
        raise ValueError('NoMount source archive hash differs')
    files = {}
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for item in archive:
            safe(Path(tempfile.gettempdir()), item.name.rstrip('/'))
            if item.isdir():
                continue
            if not item.isfile() or item.name in seen:
                raise ValueError('Unexpected NoMount archive member')
            seen.add(item.name)
            contents = archive.extractfile(item).read()
            record = pin['files'].get(item.name)
            if record != {'sha256': sha(contents), 'mode': item.mode}:
                raise ValueError('NoMount source inventory differs')
            if item.name.startswith('kernel/src/'):
                files['drivers/nomount/' + item.name.removeprefix('kernel/src/')] = contents
            elif item.name == 'kernel/LICENSE':
                files['drivers/nomount/LICENSE'] = contents
    if seen != set(pin['files']):
        raise ValueError('Incomplete NoMount source archive')
    return files


def apply_patch(common, data, check=False):
    # git apply inside a wrapper repository otherwise silently skips common/.
    probe = subprocess.run(['git', '-C', str(common), 'rev-parse', '--show-toplevel'],
                           capture_output=True, text=True)
    root = Path(probe.stdout.strip()) if probe.returncode == 0 else common
    prefix = common.resolve().relative_to(root.resolve()).as_posix()
    args = ['git', '-C', str(root), 'apply']
    if prefix != '.':
        args.append('--directory=' + prefix)
    if check:
        args.append('--check')
    subprocess.run(args + ['-'], input=data, check=True)


def _replace_bytes(path, data, mode):
    """Replace one regular source file without exposing a partial write."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.' + path.name + '.onyx-feature-',
                                         delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def applied(common, archive):
    """Apply features after common_fixes and restore only our unchanged files."""
    common, archive = Path(common), Path(archive)
    series = patches()
    imported = nomount_files()
    names = set(imported) | {n for _, _, files in series for n in files}
    before, modes = {}, {}
    for name in sorted(names):
        path = safe(common, name)
        before[name] = path.read_bytes() if path.exists() else None
        modes[name] = path.stat().st_mode & 0o7777 if path.exists() else 0o644
    # Validate the entire sequence in scratch before touching the build tree.
    with tempfile.TemporaryDirectory(prefix='onyx-feature-replay-') as temp:
        trial = Path(temp)
        for name, data in before.items():
            if data is not None:
                path = safe(trial, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        for name, data in imported.items():
            if before[name] is not None:
                raise ValueError('Preserve existing NoMount source: ' + name)
            path = safe(trial, name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for _, data, _ in series:
            apply_patch(trial, data, check=True)
            apply_patch(trial, data)
        candidate = {name: safe(trial, name).read_bytes() for name in names}
    archive.mkdir(parents=True, exist_ok=False)
    receipt = {'format': 1, 'patches': [p.name for p, _, _ in series],
               'source_sha256': {n: sha(d) for n, d in sorted(candidate.items())}}
    touched, created_directories = [], set()
    try:
        for name, data in sorted(candidate.items()):
            path = safe(common, name)
            parent = path.parent
            while not parent.exists():
                created_directories.add(parent)
                parent = parent.parent
            path.parent.mkdir(parents=True, exist_ok=True)
            _replace_bytes(path, data, modes[name])
            touched.append(name)
        (archive / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        yield receipt
    finally:
        conflicts, failures = [], []
        for name in reversed(touched):
            try:
                path = safe(common, name)
                if not path.exists() or path.read_bytes() != candidate[name] or path.stat().st_mode & 0o7777 != modes[name]:
                    conflicts.append(name)
                    continue
                if before[name] is None:
                    path.unlink()
                else:
                    _replace_bytes(path, before[name], modes[name])
            except ValueError:
                conflicts.append(name)  # Preserve a concurrent symlink/type change.
            except OSError as error:
                failures.append((name, error))
        for directory in sorted(created_directories, key=lambda value: len(value.parts), reverse=True):
            try:
                directory.rmdir()
            except OSError:
                pass  # Concurrent content or a remaining failed restoration is retained.
        if failures:
            raise OSError('Kernel feature rollback failed: ' + ', '.join(name for name, _ in failures)) from failures[0][1]
        if conflicts:
            raise ValueError('Concurrent kernel feature edits preserved: ' + ', '.join(sorted(conflicts)))


def refresh_common(common):
    """Require all locked additions to replay on the candidate upstream tree."""
    from common_fixes import applied as common_fixes
    with tempfile.TemporaryDirectory(prefix='onyx-feature-refresh-') as temp:
        root = Path(temp)
        with common_fixes(common, root / 'common'), applied(common, root / 'features') as receipt:
            return receipt


def selections(text):
    result = {}
    for line in text.splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            name, value = line.split('=', 1)
            result[name] = value
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            result[line[2:].removesuffix(' is not set')] = 'n'
    return result


def required_config(variant):
    data = manifest()
    expected = dict(data['configs'])
    expected.update(profile(variant)['profile']['configs'])
    expected.update(selections((INPUTS / 'droidspaces.fragment').read_text()))
    return expected


def stage(workspace, variant):
    """Stage the same Next snapshot's standalone SUSFS module and profile."""
    workspace = Path(workspace)
    from integrate_kernelsu import expected
    files, _ = expected(workspace / 'common')
    sources = {n.removeprefix('drivers/kernelsu/susfs/'): d for n, d in files.items()
               if n.startswith('drivers/kernelsu/susfs/')}
    if not sources or 'Makefile' not in sources:
        raise ValueError('Locked official Next dev snapshot has no SUSFS LKM')
    target = workspace / 'onyx_features'
    wanted = {'susfs/' + name: data for name, data in sources.items()}
    for name, template in [('Kbuild', 'susfs.Kbuild'),
                           ('onyx_gki_namespace.c', 'gki_namespace.c')]:
        if name in sources:
            raise ValueError('Official SUSFS source collides with the GKI build adapter: ' + name)
        wanted['susfs/' + name] = (INPUTS / template).read_bytes()
    wanted['Makefile'] = (INPUTS / 'module.Makefile').read_bytes()
    wanted['Kbuild'] = (INPUTS / 'module.Kbuild').read_bytes()
    wanted['BUILD.bazel'] = (INPUTS / 'module.BUILD.bazel').read_bytes()
    wanted['droidspaces-kmi-symbols'] = (INPUTS / 'droidspaces-kmi-symbols').read_bytes()
    wanted['feature_defconfig'] = ''.join(
        '# ' + n + ' is not set\n' if v == 'n' else n + '=' + v + '\n'
        for n, v in sorted(required_config(variant).items())).encode()
    fingerprint = target / '.source-sha256.json'
    if target.exists():
        old = json.loads(fingerprint.read_text())
        actual = {p.relative_to(target).as_posix(): sha(p.read_bytes())
                  for p in target.rglob('*') if p.is_file() and p != fingerprint}
        if old != actual:
            raise ValueError('Preserve changed standalone feature module sources')
        shutil.rmtree(target)
    target.mkdir()
    for name, data in wanted.items():
        path = safe(target, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    fingerprint.write_text(json.dumps({n: sha(d) for n, d in sorted(wanted.items())}, indent=2) + '\n')
    return profile(variant)


def verify_artifact(artifact, report):
    """Verify build capability; runtime hiding/namespace tests stay separate."""
    artifact = Path(artifact)
    variant = report['variant']['id']
    if report['variant'] != profile(variant):
        raise ValueError('Kernel variant differs from locked feature profile')
    actual = selections((artifact / 'gki/kernel_aarch64_dot_config').read_text())
    for name, value in required_config(variant).items():
        if actual.get(name, 'n') != value:
            raise ValueError('Required kernel feature selection differs: ' + name)
    if not report['kernel_release'].endswith('-4k-onyx-' + variant):
        raise ValueError('Kernel release does not identify the selected variant')
    for path in INPUTS.rglob('*'):
        if path.is_file() and path.suffix != '.pyc' and '__pycache__' not in path.parts:
            archived = artifact / 'inputs/features' / path.relative_to(INPUTS)
            if not archived.is_file() or archived.read_bytes() != path.read_bytes():
                raise ValueError('Archived kernel feature input differs: ' + path.name)
    if (artifact / 'inputs/features.py').read_bytes() != Path(__file__).read_bytes():
        raise ValueError('Kernel feature verifier differs from committed source')
    rows = report['platform_addon_verification']
    if len(rows) != 1 or rows[0]['module'] != 'susfs_guard_lkm.ko' or rows[0].get('imports_checked', 0) < 1:
        raise ValueError('SUSFS matched module verification is absent')
    row = rows[0]
    module = artifact / 'platform-addon/susfs_guard_lkm.ko'
    if row != verify_addon(module, artifact / 'gki', report['kernel_release']):
        raise ValueError('SUSFS module belongs to another kernel build')
    source = json.loads((artifact / 'platform-addon/source.json').read_text())
    if (source['kernelsu_revision'] != report['kernelsu_next']['revision']
            or source['kernel_sha256'] != sha((artifact / 'gki/Image').read_bytes())
            or source['susfs_source_sha256'] != susfs_source_hash(artifact / 'inputs/kernelsu-next/source.tar')):
        raise ValueError('SUSFS and KernelSU Next revisions differ')
    notes = kernel_notes_hash(artifact / 'gki/vmlinux')
    if (source.get('kernel_notes_sha256') != notes
            or (artifact / 'platform-addon/kernel.notes.sha256').read_text().strip() != notes):
        raise ValueError('SUSFS runtime kernel fingerprint differs')
    with tarfile.open(artifact / 'inputs/kernelsu-next/source.tar') as archive:
        gate = archive.getmember('kernel/susfs/ksu_allow_gate.c')
        names = set(re.findall(rb'"((?:__)?ksu_[A-Za-z0-9_]+)"', archive.extractfile(gate).read()))
    kernel_symbols = {f[2].encode() for line in (artifact / 'gki/System.map').read_text().splitlines()
                      if len(f := line.split()) >= 3}
    if not names or not names & kernel_symbols:
        raise ValueError('SUSFS cannot resolve the KernelSU allow predicate in this kernel')
    if (artifact / 'platform-addon/kernel.release').read_text().strip() != report['kernel_release']:
        raise ValueError('SUSFS loader expects another kernel')
    for name in ('post-fs-data.sh', 'verify-runtime.sh', 'module.prop'):
        if (artifact / 'platform-addon' / name).read_bytes() != addon_file(name, variant):
            raise ValueError('SUSFS loader input differs: ' + name)
    return {'status': 'PASS', 'variant': variant, 'configs_verified': len(required_config(variant)),
            'susfs_source_revision': source['kernelsu_revision'],
            'runtime_verified': False}


def addon_file(name, variant):
    data = (INPUTS / 'susfs-module' / name).read_bytes()
    return data.replace(b'@VARIANT@', variant.encode())


def susfs_source_hash(archive):
    files = {}
    with tarfile.open(archive) as tar:
        for entry in tar:
            if entry.isfile() and entry.name.startswith('kernel/susfs/'):
                files[entry.name] = tar.extractfile(entry).read()
    if not files:
        raise ValueError('SUSFS source missing from official Next archive')
    return sha(b''.join(n.encode() + b'\0' + d for n, d in sorted(files.items())))


def kernel_notes_hash(path):
    """Read the exact linker notes exposed by the running /sys/kernel/notes."""
    with path.open('rb') as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:6] != b'\x7fELF\x02\x01':
            raise ValueError('Kernel fingerprint requires ELF64 little-endian vmlinux')
        offset = struct.unpack_from('<Q', header, 40)[0]
        size, count, names_index = struct.unpack_from('<HHH', header, 58)
        if size < 64 or not count or names_index >= count:
            raise ValueError('Invalid vmlinux section table')
        stream.seek(offset + names_index * size)
        names_header = stream.read(64)
        start, length = struct.unpack_from('<QQ', names_header, 24)
        stream.seek(start)
        names = stream.read(length)
        for index in range(count):
            stream.seek(offset + index * size)
            section = stream.read(64)
            name = struct.unpack_from('<I', section)[0]
            if names[name:].split(b'\0', 1)[0] == b'.notes':
                start, length = struct.unpack_from('<QQ', section, 24)
                stream.seek(start)
                data = stream.read(length)
                if not data or len(data) != length:
                    raise ValueError('Missing or truncated kernel linker notes')
                return sha(data)
    raise ValueError('Kernel has no runtime linker-note fingerprint')


def verify_addon(module, kernel_dir, release):
    """Check exports' CRCs and special-loader imports against this exact kernel."""
    from verify_modules import elf_sections, versioned_imports
    sections = elf_sections(module)
    vermagic = next((s.removeprefix(b'vermagic=').decode() for s in sections.get('.modinfo', b'').split(b'\0')
                     if s.startswith(b'vermagic=')), '')
    if not vermagic.startswith(release + ' ') or 'modversions' not in vermagic.split():
        raise ValueError('SUSFS module vermagic mismatch')
    exports = {f[1]: int(f[0], 16) for line in (kernel_dir / 'kernel_aarch64_Module.symvers').read_text().splitlines()
               if len(f := line.split()) >= 3}
    imports = versioned_imports(module)
    if not imports or any(exports.get(n) != crc for n, crc in imports.items()):
        raise ValueError('SUSFS versioned import CRC mismatch')
    strings = sections.get('.strtab', b'')
    symbols = sections.get('.symtab', b'')
    if len(symbols) % 24:
        raise ValueError('SUSFS symbol table is malformed')
    undefined = set()
    for offset in range(0, len(symbols), 24):
        name, info, _, index, _, _ = struct.unpack_from('<IBBHQQ', symbols, offset)
        if index == 0 and info >> 4 in (1, 2) and name:
            end = strings.find(b'\0', name)
            if end < 0:
                raise ValueError('SUSFS import name is malformed')
            undefined.add(strings[name:end].decode())
    kernel_symbols = {f[2] for line in (kernel_dir / 'System.map').read_text().splitlines()
                      if len(f := line.split()) >= 3}
    missing = undefined - kernel_symbols
    if missing:
        raise ValueError('SUSFS imports unavailable in this kernel: ' + ', '.join(sorted(missing)))
    return {'module': module.name, 'sha256': sha(module.read_bytes()), 'vermagic': vermagic,
            'imports_checked': len(undefined), 'versioned_imports_checked': len(imports),
            'loader': 'KernelSU Next ksud insmod'}


def package_addon(module, kernel_dir, artifacts, workspace, variant):
    target = artifacts / 'platform-addon'
    target.mkdir()
    shutil.copyfile(module, target / module.name)
    release = (kernel_dir / 'include/config/kernel.release').read_text().strip()
    for name in ('post-fs-data.sh', 'verify-runtime.sh', 'module.prop'):
        path = target / name
        path.write_bytes(addon_file(name, variant))
        path.chmod(0o755 if name.endswith('.sh') else 0o644)
    (target / 'kernel.release').write_text(release + '\n')
    notes = kernel_notes_hash(kernel_dir / 'vmlinux')
    (target / 'kernel.notes.sha256').write_text(notes + '\n')
    pin = json.loads((workspace / '.kernelsu-next/source.json').read_text())
    (target / 'source.json').write_text(json.dumps({
        'format': 1, 'kernelsu_revision': pin['revision'], 'kernelsu_source_sha256': pin['sha256'],
        'susfs_source_sha256': susfs_source_hash(workspace / '.kernelsu-next/source.tar'),
        'kernel_sha256': sha((kernel_dir / 'Image').read_bytes()), 'variant': variant,
        'kernel_notes_sha256': notes,
        'runtime_verified': False}, indent=2) + '\n')
    return [verify_addon(module, kernel_dir, release)]
