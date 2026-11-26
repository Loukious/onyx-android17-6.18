#!/usr/bin/env python3
"""Replay common fixes, recognizing reviewed upstream equivalents; reject conflicts."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

import blk_plug_ordering

ROOT = Path(__file__).resolve().parents[1]
PORT = Path(os.environ.get('KONOHA_SOURCE_ROOT', ROOT)) / 'port'


def sha(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None


def safe_path(root, name):
    if not isinstance(name, str):
        raise ValueError('Common patch path must be a string')
    relative = PurePosixPath(name)
    if not name or relative.is_absolute() or '..' in relative.parts or '.git' in relative.parts or str(relative) != name:
        raise ValueError('Unsafe common patch path: ' + name)
    path = Path(root)
    for parent in (path, *path.parents):
        if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
            raise ValueError('Unexpected common source parent type: ' + str(parent))
    for component in relative.parts:
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise ValueError('Unexpected common source parent type: ' + str(path))
        path /= component
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('Unexpected common source type: ' + str(path))
    return path


def contents(root, name):
    path = safe_path(root, name)
    return path.read_bytes() if path.exists() else None


def sections(patch):
    """Keep exact git/unified diff bytes, recognizing headers outside hunks."""
    lines = patch.splitlines(keepends=True)
    starts, old_left, new_left, has_header = [], 0, 0, False
    for index, line in enumerate(lines):
        if old_left or new_left:
            if line.startswith(b'\\'):
                continue
            if line[:1] not in (b' ', b'+', b'-'):
                raise ValueError('Malformed common patch hunk')
            old_left -= line[:1] in (b' ', b'-')
            new_left -= line[:1] in (b' ', b'+')
            if min(old_left, new_left) < 0:
                raise ValueError('Malformed common patch hunk counts')
            continue
        if line.startswith(b'diff --git '):
            starts.append(index)
            has_header = False
        elif line.startswith(b'--- ') and index + 1 < len(lines) and lines[index + 1].startswith(b'+++ '):
            if has_header or not starts:
                starts.append(index)
            has_header = True
        elif line.startswith(b'@@ '):
            match = re.match(rb'@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@', line)
            if not match or not has_header:
                raise ValueError('Malformed common patch hunk header')
            old_left, new_left = (int(value) if value is not None else 1 for value in match.groups())
    if old_left or new_left:
        raise ValueError('Truncated common patch hunk')
    if not starts:
        raise ValueError('Common replay patch has no file diffs')
    header = b''.join(lines[:starts[0]])
    diffs = [b''.join(lines[start:end]) for start, end in zip(starts, starts[1:] + [len(lines)])]
    return header, diffs


def file_headers(diff):
    match = re.search(rb'^--- ([^\n]+)\n\+\+\+ ([^\n]+)\n', diff, re.M)
    if not match:
        raise ValueError('Unsupported common patch file header')
    return tuple(value.split(b'\t', 1)[0].decode() for value in match.groups())


def filename(diff):
    old, new = file_headers(diff)
    if not new.startswith('b/') or (old != '/dev/null' and old != 'a/' + new[2:]):
        raise ValueError('Common fixes require same-path regular files or additions')
    if diff.startswith(b'diff --git '):
        git_header = re.match(rb'diff --git a/(\S+) b/(\S+)\n', diff)
        if not git_header or any(value.decode() != new[2:] for value in git_header.groups()):
            raise ValueError('Git and unified common patch paths differ')
    for mode in re.findall(rb'^(?:(?:new file mode|old mode|new mode|deleted file mode) |index \S+\.\.\S+ )(\d+)$', diff, re.M):
        if mode not in (b'100644', b'100755'):
            raise ValueError('Common patch may not create a nonregular file')
    return new[2:]


def replay(repo, patch, reverse=False):
    args = ['git', '-C', str(repo), 'apply', '--check']
    if reverse:
        args.append('--reverse')
    return subprocess.run(args + ['-'], input=patch, capture_output=True).returncode == 0


def apply(repo, patch, *options):
    subprocess.run(['git', '-C', str(repo), 'apply', '--whitespace=nowarn', *options, '-'],
                   input=patch, check=True)


def copy_sources(source, destination, names):
    for name in names:
        data = contents(source, name)
        if data is not None:
            target = safe_path(destination, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(safe_path(source, name).stat().st_mode & 0o777)


def feature_preimages(snapshot, series, directory):
    """Recover each patch's base from the verified, materialized accepted source."""
    names = {name for _, _, files in series for name in files}
    inventory = json.loads(contents(PORT, 'common-source-hashes.json'))
    copy_sources(snapshot, directory, names)
    for name in sorted(names):
        path = safe_path(directory, name)
        if not path.is_file() or inventory.get(name) != {
                'sha256': sha(path.read_bytes()), 'executable': bool(path.stat().st_mode & 0o100)}:
            raise ValueError('Accepted feature snapshot differs from its inventory: ' + name)
    images = {}
    for path, data, names in reversed(series):
        after = {name: contents(directory, name) for name in names}
        if not replay(directory, data, reverse=True):
            raise ValueError('Cannot reverse feature patch on accepted source: ' + path.name)
        apply(directory, data, '--reverse')
        images[path] = {name: (contents(directory, name), after[name]) for name in names}
    return images


def merge_feature_file(repo, path, name, before, upstream, patched):
    label = f'{path.name}: {name}'
    if None in (before, upstream, patched):
        raise ValueError('Feature patch changes a file that was added or removed upstream: ' + label)

    def git(*args, data=None):
        return subprocess.check_output(['git', '-C', str(repo), *args], input=data).strip()

    def tree(data):
        blob = git('hash-object', '-w', '--stdin', data=data)
        return git('mktree', data=b'100644 blob ' + blob + b'\tsource\n').decode()

    def diff(left, right, *options):
        return subprocess.check_output(['git', '-C', str(repo), 'diff', '--no-ext-diff', '--no-textconv',
                                        '--full-index', '--src-prefix=a/', '--dst-prefix=b/',
                                        *options, left, right])

    def code_changes(left, right):
        # Keep whitespace inside lines, which can matter in strings and macros.
        def unindent(data):
            return re.sub(rb'^[ \t]+', b'', data, flags=re.M)

        return [line for hunk in diff(tree(unindent(left)), tree(unindent(right)), '-U0').split(b'\n@@ ')[1:]
                for line in hunk.split(b'\n')[1:] if line.startswith((b'+', b'-', b'\\'))]

    base, incoming, local = map(tree, (before, upstream, patched))
    command = ['git', '-C', str(repo), 'merge-tree', '--write-tree', '--merge-base=' + base]
    result = subprocess.run(command + [incoming, local], capture_output=True)
    if result.returncode == 1 and Path(name).suffix in ('.c', '.h'):
        result = subprocess.run(command + ['-Xignore-space-change', incoming, local], capture_output=True)
        if result.returncode == 0:
            merged_tree = result.stdout.splitlines()[0].decode()
            merged_data = subprocess.check_output(['git', '-C', str(repo), 'show', merged_tree + ':source'])
            if (code_changes(before, patched) != code_changes(upstream, merged_data)
                    or code_changes(before, upstream) != code_changes(patched, merged_data)):
                raise ValueError('Whitespace merge changed code edits: ' + label)
    if result.returncode == 1:
        raise ValueError('Feature patch conflicts with upstream: ' + label)
    result.check_returncode()
    merged = result.stdout.splitlines()[0].decode()
    patch = diff(incoming, merged)
    if not patch:
        raise ValueError('Feature patch became empty and needs review: ' + label)
    encoded = name.encode()
    return (patch.replace(b'diff --git a/source b/source\n', b'diff --git a/' + encoded + b' b/' + encoded + b'\n', 1)
            .replace(b'--- a/source\n', b'--- a/' + encoded + b'\n', 1)
            .replace(b'+++ b/source\n', b'+++ b/' + encoded + b'\n', 1))


def refresh_feature_patches(common, features):
    """Rebase only file diffs that fail exact replay, then relock their patch files."""
    from common_fixes import applied

    series = features.patches()
    manifest = features.manifest()
    outputs = {}
    with tempfile.TemporaryDirectory(prefix='onyx-feature-rebase-') as temporary:
        root = Path(temporary)
        trial, accepted, merge = (root / name for name in ('trial', 'accepted', 'merge'))
        for directory in (trial, accepted, merge):
            directory.mkdir()
        with applied(common, root / 'common-fixes'):
            copy_sources(common, trial, {name for _, _, names in series for name in names})
        for name, data in features.nomount_files().items():
            target = safe_path(trial, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(data)
        images = None
        for (path, data, names), item in zip(series, manifest['patch_series'], strict=True):
            if replay(trial, data):
                apply(trial, data)
                continue
            header, diffs = sections(data)
            if [filename(diff) for diff in diffs] != names or len(set(names)) != len(names):
                raise ValueError('Unexpected feature patch inventory: ' + path.name)
            updated = []
            for name, diff in zip(names, diffs):
                if not replay(trial, diff):
                    if file_headers(diff)[0] == '/dev/null' or re.search(rb'^(old|new) mode ', diff, re.M):
                        raise ValueError(f'Feature patch conflicts with upstream: {path.name}: {name}')
                    if images is None:
                        images = feature_preimages(PORT.parent / 'common', series, accepted)
                        subprocess.run(['git', 'init', '-q', str(merge)], check=True)
                    before, patched = images[path][name]
                    diff = merge_feature_file(merge, path, name, before, contents(trial, name), patched)
                apply(trial, diff)
                updated.append(diff)
            patch = header + b''.join(updated)
            item['sha256'] = sha(patch)
            outputs[safe_path(PORT / 'features', item['path'])] = patch
    if outputs:
        outputs[safe_path(PORT / 'features', 'manifest.json')] = (json.dumps(manifest, indent=2) + '\n').encode()
    return outputs


def refresh(common, *, rebase_features=False):
    patch_dir = PORT / 'common-patches'
    manifest = json.loads(contents(patch_dir, 'manifest.json'))
    original = contents(patch_dir, manifest.get('replay_patch', 'upstream-platform-remove.patch'))
    header, diffs = sections(original)
    names = [filename(diff) for diff in diffs]
    if len(set(names)) != len(names):
        raise ValueError('Duplicate common patch file')
    if 'files' in manifest:
        if not isinstance(manifest['files'], dict):
            raise ValueError('Common patch file inventory must be an object')
        for name in manifest['files']:
            safe_path(common, name)
        if set(names) != set(manifest['files']):
            raise ValueError('Common patch and file inventory differ')
    checks = manifest.get('upstream_checks', {})
    if not isinstance(checks, dict) or set(checks) - set(names):
        raise ValueError('Upstream checks must select files in the replay patch')
    for name, check in checks.items():
        if name != blk_plug_ordering.SOURCE or check != blk_plug_ordering.CHECK:
            raise ValueError('Unknown common patch upstream check: ' + name)
        blk_plug_ordering.validate_patch(diffs[names.index(name)])
    active, integrated, files, check_results = [], [], {}, {}
    feature_outputs = {}
    with tempfile.TemporaryDirectory(prefix='onyx-patch-rebase-') as temporary:
        root = Path(temporary)
        for name, diff in zip(names, diffs):
            source = safe_path(common, name)
            data = contents(common, name)
            if data is None and file_headers(diff)[0] != '/dev/null':
                raise ValueError('Common patch modifies a missing upstream file: ' + name)
            target = safe_path(root, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            if data is not None:
                target.write_bytes(data)
                target.chmod(source.stat().st_mode & 0o777)
            ordering = blk_plug_ordering.classify(data) if name in checks else None
            if ordering is not None and ordering != blk_plug_ordering.NEEDS_BARRIER:
                integrated.append(name)
                check_results[name] = {'status': 'integrated_upstream', 'evidence': ordering}
            elif replay(root, diff):
                subprocess.run(['git', '-C', str(root), 'apply', '-'], input=diff, check=True)
                active.append(diff)
                if ordering is not None:
                    result = blk_plug_ordering.classify(contents(root, name))
                    if result != 'barrier_in_finish':
                        raise ValueError('Plug ordering patch did not establish the reviewed barrier')
                    check_results[name] = {'status': 'applied_locally', 'evidence': result}
            elif ordering is None and replay(root, diff, reverse=True):
                integrated.append(name)
            else:
                raise ValueError(f'Common patch conflicts with upstream: {name}')
            files[name] = {'before_sha256': sha(data), 'candidate_sha256': sha(contents(root, name))}
        patch = header + b''.join(active) if active else b''
        manifest.update(files=files, patch_sha256=sha(patch), integrated_upstream=integrated)
        if checks:
            manifest['upstream_check_results'] = check_results
        # Refresh opt-in diagnostic sources, also requiring exact application.
        evidence = PORT / 'validation/clock_suspend_resume'
        diagnostic = contents(evidence, 'common-qdss-diagnostic.patch')
        receipt = json.loads(contents(evidence, 'source-validation.json'))
        diagnostic_names = [filename(diff) for diff in sections(diagnostic)[1]]
        if len(set(diagnostic_names)) != len(diagnostic_names) or set(diagnostic_names) != set(receipt['files']):
            raise ValueError('Diagnostic patch and file inventory differ')
        diagnostic_before = {}
        for name in receipt['files']:
            target = safe_path(root, name)
            diagnostic_before[name] = contents(common, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            if diagnostic_before[name] is not None:
                target.write_bytes(diagnostic_before[name])
            elif target.exists():
                raise ValueError('Diagnostic patch overlaps a new common file: ' + name)
        if not replay(root, diagnostic):
            raise ValueError('QDSS diagnostic conflicts with upstream; manual port required')
        subprocess.run(['git', '-C', str(root), 'apply', '-'], input=diagnostic, check=True)
        for name in receipt['files']:
            receipt['files'][name] = {'before_sha256': sha(diagnostic_before[name]),
                                    'candidate_sha256': sha(contents(root, name))}
        # Validate every output before changing any recipe file.
        outputs = [(safe_path(patch_dir, manifest['patch']), patch),
                   (safe_path(patch_dir, 'manifest.json'), (json.dumps(manifest, indent=2) + '\n').encode())]
        for name in receipt['files']:
            target = safe_path(evidence / 'candidate', name)
            data = contents(root, name)
            if data is None:
                raise ValueError('Diagnostic candidate file is missing: ' + name)
            outputs.append((target, data))
        outputs.append((safe_path(evidence, 'source-validation.json'),
                        (json.dumps(receipt, indent=2) + '\n').encode()))
        if len({target for target, _ in outputs}) != len(outputs):
            raise ValueError('Recipe output paths overlap')
        # The feature replay reads the refreshed required-patch recipe. Restore
        # every legacy output if that second full replay rejects the candidate.
        previous = [(target, target.read_bytes() if target.exists() else None) for target, _ in outputs]
        try:
            for target, data in outputs:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            if (PORT / 'features/manifest.json').is_file():
                old_path = list(sys.path)
                try:
                    sys.path.insert(0, str(PORT))
                    import features
                    if rebase_features:
                        feature_outputs = refresh_feature_patches(common, features)
                        previous.extend((target, target.read_bytes()) for target in feature_outputs)
                        for target, data in feature_outputs.items():
                            target.write_bytes(data)
                    features.refresh_common(common)
                finally:
                    sys.path[:] = old_path
        except BaseException:
            for target, data in previous:
                if data is None:
                    target.unlink(missing_ok=True)
                else:
                    target.write_bytes(data)
            raise
    result = {'active_common_patches': len(active), 'already_integrated_upstream': integrated}
    if rebase_features:
        result['rebased_feature_patches'] = [target.name for target in feature_outputs if target.suffix == '.patch']
    if checks:
        result['upstream_checks'] = check_results
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('common', type=Path)
    p.add_argument('--rebase-features', action='store_true')
    args = p.parse_args()
    print(json.dumps(refresh(args.common, rebase_features=args.rebase_features), indent=2))
