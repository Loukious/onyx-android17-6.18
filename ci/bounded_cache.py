"""Size and path guards shared by the opt-in cached compiler workflow."""
import hashlib
import os
from pathlib import Path
import stat

GIB = 1024 ** 3
COMPILER_LIMIT = 3 * GIB
SOURCE_LIMIT = GIB
TOOLCHAIN_LIMIT = 5 * GIB // 2


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def directory(path):
    path = Path(path).absolute()
    if path.resolve() != path or path.is_symlink():
        raise ValueError('Cache directory must not traverse symlinks: ' + str(path))
    path.mkdir(parents=True, exist_ok=True)
    return path


def files(root):
    root = directory(root)
    result = []
    for parent, directories, names in os.walk(root, followlinks=False):
        for name in directories + names:
            path = Path(parent) / name
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue  # ccache atomically replaces live statistics/temp files.
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('Cache contains a link or special file: ' + str(path))
            result.append((path, info))
    return result


def size(root):
    # Charge every pathname, including hardlinks, to bound the portable archive.
    return sum(max(info.st_size, info.st_blocks * 512) for _, info in files(root))


def trim_compiler(root, limit=COMPILER_LIMIT):
    """Stopped ccache only: evict old disposable result/manifest entries."""
    entries = files(root)
    total = sum(max(info.st_size, info.st_blocks * 512) for _, info in entries)
    before = total
    for path, info in sorted(entries, key=lambda entry: entry[1].st_mtime_ns):
        if total <= limit:
            break
        relative = path.relative_to(root)
        if len(relative.parts) >= 3 and path.name.endswith(('M', 'R')):
            path.unlink()
            total -= max(info.st_size, info.st_blocks * 512)
    if total > limit:
        raise ValueError('Non-entry compiler files exceed cache size limit')
    return {'bytes_before': before, 'bytes_after': total, 'evicted_bytes': before - total,
            'limit_bytes': limit}


def summary(message):
    print(message, flush=True)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
            stream.write(message + '\n')


def budgets(environment=None):
    environment = os.environ if environment is None else environment
    result = {}
    defaults = {'compiler': 3072, 'sources': 1024, 'toolchains': 2560, 'budget': 10240}
    for name, default in defaults.items():
        value = str(environment.get('ONYX_' + name.upper() + '_CACHE_MIB', default))
        if not value.isdigit() or not 256 <= int(value) <= 65536:
            raise ValueError('Cache budgets must be integers between 256 and 65536 MiB')
        result[name] = int(value) * 1024**2
    if 2 * result['compiler'] + result['sources'] + result['toolchains'] > result['budget'] - 512 * 1024**2:
        raise ValueError('Both compiler caches and pinned dependencies must fit the declared repository budget with 512 MiB headroom')
    return result
