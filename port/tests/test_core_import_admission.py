#!/usr/bin/env python3
"""Reject protected GKI imports even when vendor CRCs match exactly."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_modules import core_export_table, verify_vendor_core_imports


def elf(path, kind, sections):
    names = b'\0' + b''.join(name.encode() + b'\0' for name, _, _, _ in sections) + b'.shstrtab\0'
    entries = [('', 0, 0, b''), *sections, ('.shstrtab', 3, 0, names)]
    payload = bytearray(64 + len(entries) * 64)
    header = bytearray(64)
    header[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', header, 16, kind, 183, 1)
    struct.pack_into('<Q', header, 40, 64)
    struct.pack_into('<HHHHHH', header, 52, 64, 0, 0, 64, len(entries), len(entries) - 1)
    payload[:64] = header
    for index, (name, section_type, address, data) in enumerate(entries):
        start = len(payload)
        payload.extend(data)
        struct.pack_into('<IIQQQQIIQQ', payload, 64 + index * 64,
                         names.find(name.encode() + b'\0'), section_type, 0, address,
                         start, len(data), 0, 0, 1, 0)
    path.write_bytes(payload)


def kernel(path, symbols, kind=3):
    table = bytearray()
    names, flags, crcs = bytearray(), bytearray(), bytearray()
    for index, (name, crc, flag) in enumerate(sorted(symbols)):
        place = 0x1000 + index * 12 + 4
        table.extend(struct.pack('<iii', 0, 0x4000 + len(names) - place, 0))
        names.extend(name.encode() + b'\0')
        flags.append(flag)
        crcs.extend(struct.pack('<I', crc))
    elf(path, kind, [('__ksymtab', 1, 0x1000, table), ('__kcrctab', 1, 0x2000, crcs),
                 ('__kflagstab', 1, 0x3000, flags), ('__ksymtab_strings', 1, 0x4000, names)])


def vendor(path, symbols):
    versions = b''.join(struct.pack('<Q', crc) + name.encode().ljust(56, b'\0')
                        for name, crc in symbols)
    elf(path, 1, [('__versions', 1, 0, versions)])


class CoreAdmission(unittest.TestCase):
    def test_linked_exec_and_pie_kernels_use_the_same_export_layout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for kind in (2, 3):
                kernel(root / 'vmlinux', [('make_kuid', 4, 0)], kind=kind)
                self.assertEqual(core_export_table(root / 'vmlinux'), {'make_kuid': {'crc': 4, 'flags': 0}})

    def test_matching_crc_does_not_admit_a_protected_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kernel(root / 'vmlinux', [('from_kuid_munged', 0x686f57bf, 2)])
            vendor(root / 'msm_sysstats.ko', [('from_kuid_munged', 0x686f57bf)])
            with self.assertRaisesRegex(ValueError, 'msm_sysstats.ko: from_kuid_munged: protected'):
                verify_vendor_core_imports([root / 'msm_sysstats.ko'], root / 'vmlinux')

    def test_public_mapping_exports_pass_and_preserve_dependency_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kernel(root / 'vmlinux', [('make_kgid', 3, 0), ('make_kuid', 4, 0)])
            vendor(root / 'xiaomi_touch.ko', [('make_kuid', 4), ('make_kgid', 3), ('vendor_callback', 5)])
            result = verify_vendor_core_imports([root / 'xiaomi_touch.ko'], root / 'vmlinux')
            self.assertEqual(result['core_imports_checked'], 2)
            self.assertEqual(result['vendor_modules_checked'], 1)
            self.assertEqual(core_export_table(root / 'vmlinux')['make_kuid'], {'crc': 4, 'flags': 0})

    def test_actual_kernel_crc_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kernel(root / 'vmlinux', [('make_kuid', 4, 0)])
            vendor(root / 'xiaomi_touch.ko', [('make_kuid', 9)])
            with self.assertRaisesRegex(ValueError, 'actual core export CRC mismatch'):
                verify_vendor_core_imports([root / 'xiaomi_touch.ko'], root / 'vmlinux')

    def test_multiple_affected_modules_are_reported_together(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kernel(root / 'vmlinux', [('from_kuid', 1, 2), ('make_kuid', 2, 2)])
            vendor(root / 'camera.ko', [('from_kuid', 1)])
            vendor(root / 'touch.ko', [('make_kuid', 2)])
            with self.assertRaises(ValueError) as error:
                verify_vendor_core_imports([root / 'camera.ko', root / 'touch.ko'], root / 'vmlinux')
            self.assertIn('camera.ko: from_kuid', str(error.exception))
            self.assertIn('touch.ko: make_kuid', str(error.exception))

    def test_invalid_flags_and_truncated_kernel_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for flag in (4, 255):
                kernel(root / 'vmlinux', [('make_kuid', 4, flag)])
                with self.assertRaisesRegex(ValueError, 'unknown kernel export flags'):
                    core_export_table(root / 'vmlinux')
            (root / 'vmlinux').write_bytes(b'\x7fELF')
            with self.assertRaisesRegex(ValueError, 'linked ELF64 ARM64'):
                core_export_table(root / 'vmlinux')


if __name__ == '__main__':
    unittest.main()
