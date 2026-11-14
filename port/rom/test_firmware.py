#!/usr/bin/env python3
"""Check Android product copies against the immutable wireless firmware package."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
FIRMWARE = HERE.parent / 'firmware'


def product_copies(fragment, vendor='vendor'):
    # Use the actual Android function and GNU make expansion instead of parsing
    # the fragment's text: inherited product file lists must contain real paths.
    rom_functions = Path(os.environ.get('ANDROID_BUILD_TOP', '')) / 'build/make/core/product_config.mk'
    function = r'''define find-copy-subdir-files
$(shell find $(2) -name "$(1)" -type f | $(SED_EXTENDED) "s:($(2)/?(.*)):\\1\\:$(3)/\\2:" | sed "s://:/:g" | sort)
endef
'''
    if rom_functions.is_file():
        text = rom_functions.read_text()
        start = text.index('define find-copy-subdir-files\n')
        end = text.index('\nendef', start) + len('\nendef')
        function = text[start:end] + '\n'
    makefile = ('SED_EXTENDED := sed -E\n' + function + f'TARGET_COPY_OUT_VENDOR := {vendor}\n'
                f'include {fragment}\n'
                '.PHONY: copies\ncopies:\n\t@$(foreach file,$(PRODUCT_COPY_FILES),printf "%s\\n" "$(file)";)\n')
    result = subprocess.run(['make', '--no-print-directory', '-f', '-', 'copies'],
                            input=makefile, text=True, capture_output=True, check=True)
    copies = [line.split(':', 1) for line in result.stdout.splitlines()]
    if len({target for _, target in copies}) != len(copies):
        raise ValueError('Duplicate firmware copy destination')
    return {target: Path(source).resolve() for source, target in copies}


class FirmwareProductTests(unittest.TestCase):
    def test_every_blob_keeps_its_request_name_and_hash(self):
        copies = product_copies(HERE / 'firmware.mk')
        manifest = json.loads((FIRMWARE / 'manifest.json').read_text())
        requirements = json.loads((HERE.parent / 'nethunter-native-modules.json').read_text())
        expected = {f'vendor/firmware/{blob["path"]}': blob for blob in manifest['blobs']}
        self.assertEqual(len(expected), 16)
        self.assertEqual({target for target in copies if target.startswith('vendor/firmware/')}, set(expected))
        self.assertEqual({blob['path'] for blob in expected.values()}, set(requirements['wireless_firmware']))
        for target, blob in expected.items():
            self.assertEqual(copies[target], (FIRMWARE / 'firmware' / blob['path']).resolve())
            self.assertEqual(hashlib.sha256(copies[target].read_bytes()).hexdigest(), blob['sha256'])

    def test_licenses_and_corresponding_source_are_shipped(self):
        copies = product_copies(HERE / 'firmware.mk')
        notice = 'vendor/etc/firmware-notices/onyx-usb-wifi/'
        expected = {'README.md', 'manifest.json'} | {
            path.relative_to(FIRMWARE).as_posix()
            for directory in ('licenses', 'sources')
            for path in (FIRMWARE / directory).rglob('*') if path.is_file()
        }
        self.assertEqual({target.removeprefix(notice) for target in copies if target.startswith(notice)}, expected)
        for relative in expected:
            self.assertEqual(copies[notice + relative], (FIRMWARE / relative).resolve())
        requirements = json.loads((HERE.parent / 'nethunter-native-modules.json').read_text())
        for source in requirements['firmware_source_archives']:
            self.assertEqual(hashlib.sha256(copies[notice + source['path']].read_bytes()).hexdigest(), source['sha256'])

    def test_vendor_output_variable_is_respected(self):
        copies = product_copies(HERE / 'firmware.mk', 'vendor-test')
        self.assertTrue(copies)
        self.assertTrue(all(target.startswith('vendor-test/') for target in copies))


if __name__ == '__main__':
    unittest.main()
