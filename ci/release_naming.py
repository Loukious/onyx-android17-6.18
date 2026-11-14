"""Public download names, separate from the exact kernel identity in metadata."""
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re


ASSET_FORMAT = 2


def asset_format(identity):
    version = identity.get('asset_format', 1)
    if type(version) is not int or version not in (1, ASSET_FORMAT):
        raise ValueError('Unsupported release asset format')
    return version


def artifact_name(run_id, attempt, version=ASSET_FORMAT):
    if any(not re.fullmatch(r'[1-9][0-9]*', str(value)) for value in (run_id, attempt)):
        raise ValueError('Artifact requires a positive build run ID and attempt')
    asset_format({'asset_format': version})
    prefix = 'Konoha-Android17-6.18' if version == 1 else 'Onyx-GKI'
    return f'{prefix}-{run_id}-{attempt}'


def archive_name(version=ASSET_FORMAT):
    asset_format({'asset_format': version})
    return ('konoha-gki-and-modules.tar.gz' if version == 1 else
            'Onyx-GKI-6.18-ROM-Integration.tar.gz')


def checksum_paths(names, version):
    """Map public checksum labels back to bundle paths without ambiguities."""
    asset_format({'asset_format': version})
    result = {}
    for name in names:
        label = Path(name).name if version == ASSET_FORMAT else name
        if label in result:
            raise ValueError('Release assets have colliding download filenames: ' + label)
        result[label] = name
    return result


def write_checksums(bundle):
    identity = json.loads((bundle / 'release.json').read_text())
    paths = {path.relative_to(bundle).as_posix(): path for path in bundle.rglob('*')
             if path.is_file() and path.name != 'SHA256SUMS'}
    labels = checksum_paths(paths, asset_format(identity))
    checksums = []
    for label, name in sorted(labels.items()):
        with paths[name].open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        checksums.append(f'{digest}  {label}\n')
    (bundle / 'SHA256SUMS').write_text(''.join(checksums))


def release_title(identity):
    try:
        date = datetime.strptime(identity['artifact_root'][:15], '%Y%m%dT%H%M%S').strftime('%Y-%m-%d')
    except (KeyError, ValueError, TypeError):
        date = f'build {identity["run_id"]}.{identity["run_attempt"]}'
    return 'Onyx GKI 6.18 / KernelSU Next — ' + date
