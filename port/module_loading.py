"""Explicit partition and load-list additions, independent of build inventories."""

import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
PARTITIONS = {"vendor_ramdisk", "vendor_dlkm", "system_dlkm"}


def normalize(name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+\.ko", name):
        raise ValueError(f"Invalid module loading policy name: {name!r}")
    return name[:-3].replace("-", "_")


def load_policy(path=HERE / "module-loading.json"):
    policy = json.loads(Path(path).read_text())
    if policy.get("schema_version") != 1 or policy.get("new_modules_default") != "manual":
        raise ValueError("Unsupported module loading policy")
    names = set()
    groups = set()
    for group in policy["groups"]:
        if group["name"] in groups or not group.get("reason"):
            raise ValueError("Module policy groups need unique names and a reason")
        groups.add(group["name"])
        modules = [normalize(name) for name in group["modules"]]
        if len(set(modules)) != len(modules) or names.intersection(modules):
            raise ValueError("Duplicate module loading policy entry")
        names.update(modules)
        partitions = group["ship"]
        if len(set(partitions)) != len(partitions) or not set(partitions) <= PARTITIONS:
            raise ValueError("Unknown or duplicate module shipping partition")
        for partition, files in group["load"].items():
            allowed = {"modules.load"}
            if partition == "vendor_ramdisk":
                allowed.add("modules.load.recovery")
            if (partition not in partitions or len(set(files)) != len(files)
                    or not set(files) <= allowed):
                raise ValueError("Load requests need a shipped partition and a supported load list")
    return policy


def additions(policy, partition, load_list=None):
    """Return filenames selected for shipping, or for one explicit load list."""
    if partition not in PARTITIONS:
        raise ValueError("Unknown module partition")
    return sorted(name for group in policy["groups"]
                  if (partition in group["ship"] if load_list is None
                      else load_list in group["load"].get(partition, []))
                  for name in group["modules"])


def validate_available(policy, available):
    names = {name for group in policy["groups"] for name in group["modules"]}
    missing = {normalize(name) for name in names} - set(available)
    if missing:
        raise ValueError("Loading policy requests unavailable modules: " + ", ".join(sorted(missing)))
