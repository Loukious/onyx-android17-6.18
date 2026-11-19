#!/usr/bin/env python3
"""Bounded per-variant ccache using Kleaf's supported user Clang toolchain."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import time

from bounded_cache import COMPILER_LIMIT, digest, directory, size, summary, trim_compiler, budgets
from pinned_cache import identity as dependency_identity


def compatibility(source, variant, diagnostic=False, ccache=None):
    if variant not in ('balanced', 'performance'):
        raise ValueError('Unknown compiler cache variant')
    ccache = Path(ccache or shutil.which('ccache')).resolve(strict=True)
    port = source / 'port'
    # Keep ordinary kernel/module source edits out of the key: ccache validates
    # source, included/generated headers and flags by content for every object.
    configs = [source / 'common/arch/arm64/configs/gki_defconfig', port / 'platform_defconfig',
               port / 'features/manifest.json']
    configs += sorted((port / 'features').glob('*.config'))
    configs += sorted((port / 'features').glob('*defconfig*'))
    record = {'schema': 1, 'variant': variant, 'diagnostic': diagnostic,
              'toolchain_key': dependency_identity(source, 'toolchains')[1],
              'ccache_sha256': digest(ccache),
              'ccache_version': subprocess.check_output([str(ccache), '--version'], text=True).splitlines()[0],
              'helper_sha256': digest(Path(__file__)),
              'guards_sha256': digest(Path(__file__).with_name('bounded_cache.py')),
              'configs': {str(p.relative_to(source)): digest(p) for p in configs if p.is_file()}}
    checksum = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
    return record, f'onyx-ccache-v1-Linux-{variant}-{checksum}-'


def setup(workspace, source, cache, control, variant, diagnostic=False):
    workspace = Path(workspace).resolve(strict=True)
    source = Path(source).resolve(strict=True)
    cache = directory(cache)
    control = directory(control)
    if list(control.iterdir()):
        raise ValueError('Compiler control directory must be new')
    record, prefix = compatibility(source, variant, diagnostic)
    limit = budgets()['compiler']
    metadata = cache / 'identity.json'
    if metadata.exists() and json.loads(metadata.read_text()) != record:
        raise ValueError('Restored compiler cache has an incompatible identity')
    if any(cache.iterdir()) and not metadata.exists():
        raise ValueError('Restored compiler cache has no compatibility identity')
    metadata.write_text(json.dumps(record, sort_keys=True) + '\n')
    identity_file = control / 'compiler-identity.json'
    pins = json.loads((source / 'port/sources.json').read_text())
    clang_name = pins['common']['clang']
    if not re.fullmatch(r'r[0-9]+[a-z0-9]*', clang_name):
        raise ValueError('Invalid pinned Clang directory')
    original = workspace / 'prebuilts/clang/host/linux-x86' / ('clang-' + clang_name)
    # The user-toolchain API bypasses Kleaf's version comparison. Explicitly
    # verify the original project pin and version before creating its wrappers.
    from pinned_cache import projects, git
    locked, _ = projects(source)
    clang_project = next(p for p in locked['toolchains'] if p['path'] == 'prebuilts/clang/host/linux-x86')
    if git(original.parent, 'rev-parse', 'HEAD') != clang_project['revision']:
        raise ValueError('Compiler project does not match its exact toolchain pin')
    if git(original.parent, 'status', '--porcelain', '-uno'):
        raise ValueError('Refusing a modified pinned compiler project')
    version = (original / 'AndroidVersion.txt').read_text()
    if 'based on ' + clang_name not in version:
        raise ValueError('Pinned Clang version does not match the source recipe')
    compiler_identity = {**record, 'clang_version': version,
                         'clang_binaries': {name: digest(original / 'bin' / name)
                                            for name in ('clang', 'clang++', 'clang-real', 'clang++-real')}}
    resource_versions = sorted(p.name for p in (original / 'lib/clang').glob('*') if p.is_dir())
    if len(resource_versions) > 1:
        raise ValueError('Pinned Clang has ambiguous builtin resource directories')
    compiler_identity['resource_version'] = resource_versions[0] if resource_versions else None
    identity_file.write_text(json.dumps(compiler_identity, sort_keys=True) + '\n')
    toolchain = control / 'clang'
    toolchain.mkdir()
    for path in original.iterdir():
        if path.name != 'bin':
            (toolchain / path.name).symlink_to(path, target_is_directory=path.is_dir())
    binaries = toolchain / 'bin'
    binaries.mkdir()
    ccache = Path(shutil.which('ccache')).resolve(strict=True)
    config = control / 'ccache.conf'
    config.write_text('\n'.join([
        f'cache_dir = {cache}', f'temporary_dir = {cache / "tmp"}',
        f'base_dir = {workspace}', f'extra_files_to_hash = {identity_file}',
        f'namespace = {prefix}', 'compiler_check = content', 'hash_dir = true',
        'direct_mode = true', 'sloppiness =', 'compression = true',
        'compression_level = 3', f'max_size = {limit // 1024**2 - 256}MiB', 'limit_multiple = 0.8',
        'hard_link = false', 'file_clone = false', 'stats = true', 'remote_storage =', '',
    ]))
    for path in (original / 'bin').iterdir():
        target = binaries / path.name
        if path.name in ('clang', 'clang++'):
            # Absolute compiler invocation changes both builtin C and libc++
            # header discovery. Retain the declared mirror as the install and
            # resource directory so Bazel can validate all dependency paths.
            resource = (' -ccc-install-dir "${BASH_SOURCE[0]%/*}"'
                        ' -resource-dir="${BASH_SOURCE[0]%/*}/../lib/clang/' + resource_versions[0] + '"'
                        if resource_versions else '')
            target.write_text('#!/bin/bash\n'
                              'export CCACHE_CONFIGPATH=' + shlex.quote(str(config)) + '\n'
                              'exec ' + shlex.quote(str(ccache)) + ' ' + shlex.quote(str(path)) + resource + ' "$@"\n')
            target.chmod(0o755)
        else:
            target.symlink_to(path, target_is_directory=path.is_dir())
    rc = workspace / 'user.bazelrc'
    if rc.exists() or rc.is_symlink():
        raise ValueError('Preserve an existing user.bazelrc before enabling compiler caching')
    common_rc = workspace / 'build/kernel/kleaf/common.bazelrc'
    if 'try-import %workspace%/user.bazelrc' not in common_rc.read_text():
        raise ValueError('Pinned Kleaf does not support the expected user RC interface')
    rc.write_text(f'common --repo_env=KLEAF_USER_CLANG_TOOLCHAIN_PATH={shlex.quote(str(toolchain))}\n'
                  f'build --sandbox_writable_path={shlex.quote(str(cache))}\n')
    environment = {**os.environ, 'CCACHE_CONFIGPATH': str(config)}
    subprocess.run([str(ccache), '--zero-stats'], env=environment, check=True)
    trim_compiler(cache, limit)
    summary(f'{variant}: bounded compiler cache configured ({(limit - 256 * 1024**2) / 1024**3:.2f} GiB automatic LRU, '
            f'{limit / 1024**3:.2f} GiB archive ceiling); exact pinned {clang_name}.')
    return {'config': str(config), 'toolchain': str(toolchain), 'cache': str(cache),
            'identity': compiler_identity, 'prefix': prefix, 'limit': limit}


def stats(config):
    result = subprocess.check_output(['ccache', '--print-stats'],
                                    env={**os.environ, 'CCACHE_CONFIGPATH': str(config)}, text=True)
    return {row.split()[0]: int(row.split()[1]) for row in result.splitlines() if row.strip()}


def build(workspace, source, cache, control, variant, jobs, memory, diagnostic=False):
    state = setup(workspace, source, cache, control, variant, diagnostic)
    limit = state['limit']
    started = time.monotonic()
    command = ['python3', str(source / 'port/build.py'), str(workspace), '--variant', variant,
               '--bazel-batch', '--jobs', str(jobs), '--memory-mb', str(memory)]
    if diagnostic:
        command.append('--qdss-diagnostic')
    # Sandbox mode retains no second Kbuild OUT_DIR. Only content-addressed
    # compiler results survive runs; linking, Rust and artifact checks still run.
    process = subprocess.Popen(command, start_new_session=True)
    try:
        while process.poll() is None:
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                if size(cache) > limit:
                    subprocess.run(['ccache', '--cleanup'], check=True,
                                   env={**os.environ, 'CCACHE_CONFIGPATH': state['config']})
                    # Concurrent ccache writes may briefly exceed its soft LRU
                    # quota. Never trim arbitrary files while writers are active.
                    if size(cache) > limit:
                        raise ValueError('Compiler cache exceeded bounded runtime storage')
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        counters = stats(state['config'])
        subprocess.run(['ccache', '--cleanup'], check=True,
                       env={**os.environ, 'CCACHE_CONFIGPATH': state['config']})
        bounds = trim_compiler(cache, limit)
        hits = counters.get('direct_cache_hit', 0) + counters.get('preprocessed_cache_hit', 0)
        misses = counters.get('cache_miss', 0)
        report = {'variant': variant, 'seconds': round(time.monotonic() - started, 2),
                  'exit_code': process.returncode, 'hits': hits, 'misses': misses,
                  'hit_percent': round(100 * hits / (hits + misses), 2) if hits + misses else 0,
                  'counters': counters, 'bounds': bounds, 'compiler_identity': state['identity']}
        (control / 'compiler-cache-report.json').write_text(json.dumps(report, indent=2) + '\n')
        summary(f'{variant}: actual compiler reuse {hits} hits / {misses} misses '
                f'({report["hit_percent"]:.1f}%), compilation {report["seconds"] / 60:.1f} min; '
                f'cache {bounds["bytes_after"] / 1024**3:.2f} GiB. '
                'Rust and final links are rebuilt.')
    if process.returncode:
        raise subprocess.CalledProcessError(process.returncode, command)
    if hits + misses == 0:
        raise ValueError('No compiler cache calls observed: toolchain wiring is not active')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('key', 'build'))
    parser.add_argument('--source', type=Path, default=Path('source'))
    parser.add_argument('--variant', required=True, choices=('balanced', 'performance'))
    parser.add_argument('--diagnostic', action='store_true')
    parser.add_argument('--workspace', type=Path)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--control', type=Path)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--memory-mb', type=int, default=4000)
    args = parser.parse_args()
    if args.command == 'key':
        record, prefix = compatibility(args.source, args.variant, args.diagnostic)
        suffix = os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
        result = {'prefix': prefix, 'key': prefix + suffix, 'identity': record}
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                stream.write('prefix=' + prefix + '\nkey=' + prefix + suffix + '\n')
    else:
        result = build(args.workspace.resolve(), args.source.resolve(), args.cache, args.control,
                       args.variant, args.jobs, args.memory_mb, args.diagnostic)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
