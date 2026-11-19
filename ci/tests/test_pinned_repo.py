"""Exercise repo's real per-project shallow layout, not git clone substitutes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pinned_cache


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


@unittest.skipUnless(os.environ.get('ONYX_TEST_REPO_SOURCE') and shutil.which('repo'),
                     'set ONYX_TEST_REPO_SOURCE to a local git-repo source checkout')
class RepoReferenceTests(unittest.TestCase):
    def test_shared_project_fetches_both_pins_while_single_project_uses_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upstream = root / 'upstream'
            revisions = {}
            for name in ('kernel/common', 'kernel/common-modules/wonder'):
                path = upstream / name
                path.mkdir(parents=True)
                git(path, 'init', '-q')
                git(path, 'config', 'user.name', 'Repo cache tests')
                git(path, 'config', 'user.email', 'repo-cache@example.invalid')
                (path / 'value').write_text('first\n')
                git(path, 'add', '.')
                git(path, 'commit', '-qm', 'first')
                first = git(path, 'rev-parse', 'HEAD')
                (path / 'value').write_text('second\n')
                git(path, 'commit', '-qam', 'second')
                revisions[name] = (first, git(path, 'rev-parse', 'HEAD'))
            common = revisions['kernel/common'][1]
            wonder_old, wonder_new = revisions['kernel/common-modules/wonder']
            manifest = ET.Element('manifest')
            ET.SubElement(manifest, 'remote', name='local', fetch=upstream.as_uri() + '/')
            ET.SubElement(manifest, 'default', remote='local', revision='master')
            rows = [dict(name='kernel/common', path='common', revision=common),
                    dict(name='kernel/common-modules/wonder', path='common-modules/wonder', revision=wonder_new),
                    dict(name='kernel/common-modules/wonder', path='baseline/kernel/google/wonder', revision=wonder_old)]
            for row in rows:
                ET.SubElement(manifest, 'project', **row)
            manifests = root / 'manifests'
            manifests.mkdir()
            ET.ElementTree(manifest).write(manifests / 'default.xml')
            git(manifests, 'init', '-q')
            git(manifests, 'config', 'user.name', 'Repo cache tests')
            git(manifests, 'config', 'user.email', 'repo-cache@example.invalid')
            git(manifests, 'add', '.')
            git(manifests, 'commit', '-qm', 'pins')
            manifest_pin = git(manifests, 'rev-parse', 'HEAD')
            source = root / 'source'
            (source / 'port').mkdir(parents=True)
            (source / 'port/sources.json').write_text(json.dumps({
                'common': {'revision': common},
                'manifest': {'url': manifests.as_uri()},
                'baseline': [{'repo': rows[2]['name'], 'workspace_path': rows[2]['path'], 'revision': wonder_old}],
            }))
            (source / 'port/onyx-port.xml').write_text('<manifest/>')
            lock = ET.Element('manifest')
            ET.SubElement(lock, 'project', **rows[1])
            ET.ElementTree(lock).write(source / 'port/dependency-lock.xml')
            repo_source = Path(os.environ['ONYX_TEST_REPO_SOURCE']).resolve()
            repo_pin = git(repo_source, 'rev-parse', 'HEAD')
            env = {**os.environ, 'GIT_ALLOW_PROTOCOL': 'file', 'REPO_ALLOW_SHALLOW': '1'}

            def sync(workspace, reference=None):
                workspace.mkdir()
                args = ['repo', 'init', '-q', '-u', manifests.as_uri(), '-b', manifest_pin,
                        '--repo-url=' + repo_source.as_uri(), '--repo-rev=' + repo_pin,
                        '--no-repo-verify', '--depth=1', '--no-clone-bundle']
                if reference:
                    args.append('--reference=' + str(reference))
                subprocess.run(args, cwd=workspace, env=env, check=True, capture_output=True, text=True)
                result = subprocess.run(['repo', 'sync', '-c', '--no-tags', '--no-clone-bundle', '-j2'],
                                        cwd=workspace, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for row in rows:
                    self.assertEqual(git(workspace / row['path'], 'rev-parse', 'HEAD'), row['revision'])

            cold = root / 'cold'
            sync(cold)
            cache, reference = root / 'cache', root / 'reference'
            saved = pinned_cache.save(cache, cold, source, 'sources')
            self.assertIn({'name': 'kernel/common-modules/wonder', 'reason': 'shared-project'}, saved['omitted'])
            self.assertFalse((cache / 'kernel/common-modules/wonder.git').exists())
            pinned_cache.restore(cache, reference, source, 'sources', saved['key'])
            self.assertTrue((reference / 'kernel/common.git').is_dir())
            # repo still negotiates shallow boundaries with the upstream. The
            # cached objects must be used through alternates during that fetch.
            warm = root / 'warm'
            sync(warm, reference)
            alternates = warm / '.repo/project-objects/kernel/common.git/objects/info/alternates'
            self.assertIn(str(reference / 'kernel/common.git/objects'), alternates.read_text())
            self.assertFalse((warm / '.repo/project-objects/kernel/common-modules/wonder.git/objects/info/alternates').exists())


if __name__ == '__main__':
    unittest.main()
