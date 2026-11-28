"""Build time belongs in new download names; old manifests remain usable."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import installer_assets
import publish_release
import recovery_assets
import release_naming
import variant_assets
import test_variant_releases


class ReleaseTimestamps(unittest.TestCase):
    def test_export_binds_downloads_to_real_build_time_and_rejects_relabeling(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, _, _, bundle, identity = test_variant_releases.VariantReleaseTests().export(Path(temporary))
            for row in identity['variants']:
                stamp = row['asset_timestamp']
                self.assertEqual(stamp, release_naming.build_timestamp(row['artifact_root']))
                names = installer_assets.names(row['kernel_release'], 3, row['id'], stamp)
                row['installers'] = list(installer_assets.expected_names(row)) + [variant_assets.installer_metadata_name(row['id'], stamp)]
                row['full_recovery'] = recovery_assets.names(row['kernel_release'], 3, row['id'], stamp)
                downloads = variant_assets.download_map(row)
                marker = stamp[:8] + '-' + stamp[9:15] + 'UTC'
                for key, name in downloads.items():
                    with self.subTest(variant=row['id'], asset=key):
                        extension = '.tar.gz' if name.endswith('.tar.gz') else Path(name).suffix
                        self.assertTrue(name.endswith('-' + marker + extension), name)
                self.assertEqual(downloads['anykernel'], names[0])
                self.assertEqual(downloads['anykernel'], f'Onyx-{row["label"]}-GKI-6.18-AnyKernel3-{marker}.zip')
                self.assertEqual(downloads['kernel_config'], f'Onyx-{row["label"]}-kernel_aarch64_dot_config-{marker}')
            malformed = copy.deepcopy(identity)
            malformed['variants'][0]['asset_timestamp'] = '20261120T120000Z'
            with self.assertRaisesRegex(ValueError, 'timestamp differs'):
                variant_assets.rows(malformed)

    def test_older_manifests_keep_exact_filenames_and_invalid_times_reject(self):
        release = '6.18.64-android17-6-maybe-dirty-4k-onyx-performance'
        row = {'id': 'performance', 'kernel_release': release, 'artifact_root': '20261124T162430-performance'}
        self.assertIsNone(release_naming.asset_timestamp(row))
        self.assertEqual(variant_assets.download_map(row)['rom_integration'],
                         'Onyx-Performance-GKI-6.18-ROM-Integration.tar.gz')
        self.assertEqual(installer_assets.names(release, 3, 'performance')[0],
                         'Onyx-Performance-GKI-6.18-AnyKernel3.zip')
        for root in ('20260230T120000', '20261124T250000', 'bad', None):
            with self.subTest(root=root), self.assertRaises(ValueError):
                release_naming.build_timestamp(root)

    def test_timestamped_prefix_bundles_still_verify(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, _, _, bundle, identity = test_variant_releases.VariantReleaseTests().export(Path(temporary))
            for row in identity['variants']:
                suffix_names = row['downloads']
                del row['timestamp_suffix']
                prefix_names = variant_assets.download_map(row)
                for key, current in suffix_names.items():
                    (bundle / current).rename(bundle / prefix_names[key])
                    row['sha256'][prefix_names[key]] = row['sha256'].pop(current)
                row['downloads'] = prefix_names
            self.assertEqual(identity['variants'][1]['downloads']['rom_integration'],
                             'Onyx-Performance-20261119-120000UTC-GKI-6.18-ROM-Integration.tar.gz')
            identity['sha256'] = {name: digest for row in identity['variants'] for name, digest in row['sha256'].items()}
            (bundle / 'release.json').write_text(json.dumps(identity) + '\n')
            release_naming.write_checksums(bundle)
            self.assertEqual(publish_release.validate_bundle(bundle, source, identity['source_revision'],
                identity['common_revision'], identity['kernelsu_revision'], identity['run_id'], identity['run_attempt']),
                identity)


if __name__ == '__main__':
    unittest.main()
