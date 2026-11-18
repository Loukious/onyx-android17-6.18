"""Exercise prefixed imports against real Git blobs and staging checks."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PORT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PORT))
from generate_imports import derive, ordered_lock
from stage import source_bytes


class PrefixedSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="onyx-import-prefix-")
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)
        self.project = self.workspace / "baseline/wonder"
        self.project.mkdir(parents=True)
        self.git("init", "-q")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "user.name", "Source lock fixture")
        (self.project / "main.c").write_text("int upstream_value = 17;\n")
        (self.project / "include").mkdir()
        (self.project / "include/api.h").write_text("extern int upstream_value;\n")
        self.git("add", ".")
        self.git("commit", "-qm", "Pinned source")
        self.revision = self.git("rev-parse", "HEAD")
        self.sources = {"common": {"revision": self.revision}, "baseline": [
            {"workspace_path": "baseline/wonder", "revision": self.revision}]}
        self.catalog = {
            "schema_version": 1, "kernel_build": "//common:kernel_aarch64",
            "shared_attributes": {}, "native_configs": {},
            "components": [{"kind": "vendor_ddk", "rule": "ddk_module",
                "name": "wonder", "attrs": {"out": "wonder.ko",
                    "srcs": {"glob": ["wonder/**/*.c", "wonder/**/*.h"]}}}],
            "source_groups": {"groups": [{"project": "baseline/wonder",
                "prefixes": ["wonder"], "destination_prefix": "wonder",
                "discovery": {"from_recipes": True}}],
                "ownership_overrides": {}, "prerequisites": {},
                "rom_source_checksums": {"baseline/wonder": {"glob": ["wonder/**"]}}},
        }
        self.patches = self.workspace / "patches"
        self.patches.mkdir()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.project), *args],
                                       text=True).strip()

    def records(self, catalog=None):
        return derive(catalog or self.catalog, self.sources, self.workspace, self.patches)[0]

    def test_prefix_replays_exact_upstream_bytes(self):
        records = self.records()
        self.assertEqual({r["path"] for r in records},
                         {"wonder/main.c", "wonder/include/api.h"})
        for source in records:
            self.assertEqual(source["path"], "wonder/" + source["source_path"])
            staged = self.workspace / "staged" / source["path"]
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(source_bytes(self.workspace, source))
            self.assertEqual(staged.read_bytes(), (self.project / source["source_path"]).read_bytes())
            self.assertEqual(len(source["rom_source_sha256"]), 64)
        locked, removed = ordered_lock(records, [])
        self.assertEqual(removed, [])
        self.assertEqual(ordered_lock(records, json.loads(locked))[0], locked)

    def test_unprefixed_source_lock_stays_compatible(self):
        catalog = copy.deepcopy(self.catalog)
        group = catalog["source_groups"]["groups"][0]
        group.pop("destination_prefix")
        group["prefixes"] = ["include"]
        catalog["components"][0]["attrs"]["srcs"] = ["include/api.h"]
        records = self.records(catalog)
        self.assertEqual(len(records), 1)
        self.assertNotIn("source_path", records[0])
        self.assertEqual(source_bytes(self.workspace, records[0]), b"extern int upstream_value;\n")

    def test_wrong_blob_is_rejected_before_staging(self):
        source = next(r for r in self.records() if r["path"] == "wonder/main.c")
        source["blob"] = self.git("rev-parse", "HEAD:include/api.h")
        with self.assertRaisesRegex(ValueError, "unexpected source blob"):
            source_bytes(self.workspace, source)

    def test_wrong_checkout_revision_is_rejected(self):
        source = self.records()[0]
        (self.project / "next.c").write_text("int next;\n")
        self.git("add", ".")
        self.git("commit", "-qm", "Different checkout")
        with self.assertRaisesRegex(ValueError, "unexpected revision"):
            source_bytes(self.workspace, source)

    def test_destination_prefix_cannot_escape_stage(self):
        for prefix in ("../wonder", "/wonder", "wonder/../outside", "wonder\\outside"):
            with self.subTest(prefix=prefix):
                catalog = copy.deepcopy(self.catalog)
                catalog["source_groups"]["groups"][0]["destination_prefix"] = prefix
                with self.assertRaises(ValueError):
                    self.records(catalog)

    def test_owner_prefix_must_stay_inside_destination(self):
        catalog = copy.deepcopy(self.catalog)
        catalog["source_groups"]["groups"][0]["prefixes"] = ["outside"]
        with self.assertRaisesRegex(ValueError, "escape destination prefix"):
            self.records(catalog)

    def test_unrelated_upstream_file_does_not_enter_imports(self):
        (self.project / "README").write_text("Excluded by the build recipe.\n")
        self.git("add", ".")
        self.git("commit", "-qm", "Add unrelated source")
        self.sources["baseline"][0]["revision"] = self.git("rev-parse", "HEAD")
        self.assertEqual({r["path"] for r in self.records()},
                         {"wonder/main.c", "wonder/include/api.h"})


if __name__ == "__main__":
    unittest.main()
