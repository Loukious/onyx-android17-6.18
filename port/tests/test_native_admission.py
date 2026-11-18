"""Reproduce the installed Wonder failure using retained production ELFs.

Run with --artifact-dir pointing at a preserved pre-fix source-ROM export.
Positive controls change only the four provider flag bytes in a temporary
copy; no compiled module or source artifact is changed in place.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

PORT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PORT))
from catalog import load_catalog, native_modules
from verify_modules import verify, versioned_imports
from verify_native_abi import (KSYM_FLAG_PROTECTED, export_table,
                               verify_native_exports, verify_native_imports)

REJECTED = (
    "ieee80211_emulate_add_chanctx", "ieee80211_emulate_change_chanctx",
    "ieee80211_emulate_remove_chanctx", "wiphy_to_ieee80211_hw",
)


def section_offset(module, wanted):
    data = module.read_bytes()
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count, strings_index = struct.unpack_from("<HHH", data, 58)
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, offset + index * size)
               for index in range(count)]
    header = headers[strings_index]
    names = data[header[4]:header[4] + header[5]]
    for header in headers:
        name = names[header[0]:].split(b"\0", 1)[0].decode()
        if name == wanted:
            return header[4]
    raise AssertionError("Missing production ELF section: " + wanted)


class NativeAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = ARTIFACT
        cls.wonder = ARTIFACT / "wonder.ko"
        cls.mac = ARTIFACT / "mac80211.ko"
        cls.symvers = ARTIFACT / "Module.symvers"
        receipt = json.loads((ARTIFACT / "onyx-source-build.json").read_text())
        for path in (cls.wonder, cls.mac, cls.symvers):
            if hashlib.sha256(path.read_bytes()).hexdigest() != receipt["sha256"][path.name]:
                raise AssertionError("Retained production fixture changed: " + str(path))
        cls.release = receipt["kernel_release"]
        cls.original_catalog = copy.deepcopy(load_catalog())
        cls.mac_component = next(component for component in cls.original_catalog["components"]
                                 if component["name"] == "mac80211")
        cls.mac_component["required_exports"] = [name for name in
            cls.mac_component["required_exports"] if name not in REJECTED]
        cls.fixed_catalog = copy.deepcopy(cls.original_catalog)
        fixed = next(component for component in cls.fixed_catalog["components"]
                     if component["name"] == "mac80211")
        fixed["required_exports"] = sorted(set(fixed["required_exports"]) | set(REJECTED))
        cls.providers = {entry["output"]: ARTIFACT / Path(entry["output"]).name
                         for entry in native_modules(cls.original_catalog)}
        table, imports = export_table(cls.mac), versioned_imports(cls.wonder)
        protected = {name for name in set(table) & set(imports)
                     if table[name]["flags"] & KSYM_FLAG_PROTECTED}
        if protected != set(REJECTED):
            raise AssertionError("Fixture is not the installed pre-fix failure: " + repr(protected))

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="onyx-native-admission-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.fixed_mac = self.directory / "mac80211.ko"
        data = bytearray(self.mac.read_bytes())
        flags = section_offset(self.mac, "__kflagstab")
        order = list(export_table(self.mac))
        for name in REJECTED:
            data[flags + order.index(name)] &= ~KSYM_FLAG_PROTECTED
        self.fixed_mac.write_bytes(data)
        self.fixed_providers = dict(self.providers,
                                    **{"net/mac80211/mac80211.ko": self.fixed_mac})

    def admission(self, providers=None, symvers=None, catalog=None):
        return verify_native_imports([self.wonder], providers or self.fixed_providers,
                                     [symvers or self.symvers], catalog or self.fixed_catalog)

    def assert_rejected(self, message, **arguments):
        with self.assertRaisesRegex(ValueError, message) as caught:
            self.admission(**arguments)
        return str(caught.exception)

    def test_original_crc_and_declared_export_checks_miss_runtime_failure(self):
        self.assertEqual(verify([self.wonder], [self.symvers], self.release)[0]["module"],
                         "wonder.ko")
        verify_native_exports(self.mac, "net/mac80211/mac80211.ko",
                              [self.symvers], self.original_catalog)
        failure = self.assert_rejected("protected native export", providers=self.providers,
                                       catalog=self.original_catalog)
        for name in REJECTED:
            self.assertIn(name + ": protected native export, undeclared native vendor ABI", failure)

    def test_catalog_declaration_cannot_authorize_protected_provider(self):
        failure = self.assert_rejected("protected native export", providers=self.providers)
        for name in REJECTED:
            self.assertIn(name + ": protected native export", failure)
        self.assertNotIn("undeclared", failure)

    def test_unprotected_declared_production_imports_are_admitted(self):
        result = self.admission()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["vendor_module_count"], 1)
        records = {record["symbol"]: record for record in result["modules"][0]["native_imports"]}
        self.assertTrue(set(REJECTED) <= set(records))
        for name in REJECTED:
            self.assertEqual(records[name]["flags"], 0)
            self.assertEqual(records[name]["provider"], "net/mac80211/mac80211")
        # GPL-only exports are valid; their bit must not be confused with protection.
        self.assertEqual(records["ieee80211_vif_to_wdev"]["flags"], 1)

    def test_unprotected_but_undeclared_imports_are_rejected(self):
        failure = self.assert_rejected("undeclared native vendor ABI", catalog=self.original_catalog)
        for name in REJECTED:
            self.assertIn(name + ": undeclared native vendor ABI", failure)
        self.assertNotIn("protected native export", failure)

    def test_new_protection_on_previously_allowed_import_is_rejected(self):
        name = "ieee80211_alloc_hw_nm"
        data = bytearray(self.fixed_mac.read_bytes())
        data[section_offset(self.fixed_mac, "__kflagstab") +
             list(export_table(self.fixed_mac)).index(name)] |= KSYM_FLAG_PROTECTED
        self.fixed_mac.write_bytes(data)
        self.assert_rejected(name + ": protected native export")

    def rewritten_symvers(self, symbol, *, owner=None, crc=None):
        path = self.directory / "Module.symvers"
        rows, changed = [], 0
        for line in self.symvers.read_text().splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[1] == symbol:
                if owner is not None:
                    fields[2] = owner
                if crc is not None:
                    fields[0] = crc
                line = "\t".join(fields)
                changed += 1
            rows.append(line)
        self.assertEqual(changed, 1)
        path.write_text("\n".join(rows) + "\n")
        return path

    def test_wrong_common_owner_cannot_authorize_native_import(self):
        path = self.rewritten_symvers(REJECTED[0], owner="net/wireless/cfg80211")
        self.assert_rejected("Common provider mismatch", symvers=path)

    def test_wrong_symvers_crc_cannot_authorize_native_import(self):
        path = self.rewritten_symvers(REJECTED[0], crc="0x00000000")
        self.assert_rejected("Common provider mismatch", symvers=path)

    def test_matching_symvers_cannot_hide_actual_import_crc_mismatch(self):
        name = REJECTED[0]
        data = bytearray(self.fixed_mac.read_bytes())
        struct.pack_into("<I", data, section_offset(self.fixed_mac, "__kcrctab") +
                         list(export_table(self.fixed_mac)).index(name) * 4, 0)
        self.fixed_mac.write_bytes(data)
        path = self.rewritten_symvers(name, crc="0x00000000")
        self.assert_rejected(name + ": native export CRC mismatch", symvers=path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    args, remaining = parser.parse_known_args()
    ARTIFACT = args.artifact_dir.resolve()
    unittest.main(argv=[sys.argv[0], *remaining])
