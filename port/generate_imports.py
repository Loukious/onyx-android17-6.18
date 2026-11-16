#!/usr/bin/env python3
"""Derive the staged-source lock from catalog recipes and pinned Git trees.

Source groups choose provenance and bound glob discovery. Explicit recipe files,
reviewed prerequisites and patch preimages remain selected independently. Build
receipts use imports.json as a generated lock, never as an input selection list.
"""

import argparse
from collections import Counter
import fnmatch
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile

import catalog as component_catalog

HERE = Path(__file__).resolve().parent
_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


@lru_cache(None)
def _fixed_prefix(pattern):
    return re.split(r"[*?\[]", pattern, maxsplit=1)[0]


def matches(path, pattern):
    """Match Bazel-style path globs: * stays in one segment, ** crosses dirs."""
    prefix = _fixed_prefix(pattern)
    if prefix and not path.startswith(prefix):
        if not (pattern.endswith("/**") and path == prefix.removesuffix("/")):
            return False
    parts, wanted = tuple(path.split("/")), tuple(pattern.split("/"))

    @lru_cache(None)
    def visit(i, j):
        if j == len(wanted):
            return i == len(parts)
        if wanted[j] == "**":
            return visit(i, j + 1) or (i < len(parts) and visit(i + 1, j))
        return i < len(parts) and fnmatch.fnmatchcase(parts[i], wanted[j]) and visit(i + 1, j + 1)

    return visit(0, 0)


def _selected(path, selector):
    return any(matches(path, pattern) for pattern in selector["glob"]) and not any(
        matches(path, pattern) for pattern in selector.get("exclude", []))


def _selector(value, where):
    if isinstance(value, dict) and value.get("from_recipes") is True:
        if set(value) - {"from_recipes", "exclude"}:
            raise ValueError(f"Invalid recipe discovery scope: {where}")
        if "exclude" in value:
            _selector({"glob": value["exclude"]}, where + ".exclude")
        return value
    if not isinstance(value, dict) or set(value) - {"glob", "exclude"} or "glob" not in value:
        raise ValueError(f"Invalid source selector: {where}")
    for field, patterns in value.items():
        if not isinstance(patterns, list) or any(not isinstance(p, str) for p in patterns):
            raise ValueError(f"Source {where}.{field} must be a string list")
        for pattern in patterns:
            component_catalog._path(pattern, pattern=True)
    return value


def validate_source_groups(value, projects):
    if not isinstance(value, dict) or set(value) != {"groups", "ownership_overrides", "prerequisites", "rom_source_checksums"}:
        raise ValueError("Invalid source_groups schema")
    if not isinstance(value["groups"], list) or not value["groups"]:
        raise ValueError("source_groups.groups must be a nonempty list")
    groups = {}
    for group in value["groups"]:
        if not isinstance(group, dict) or set(group) != {"project", "prefixes", "discovery"}:
            raise ValueError("Invalid source provenance group")
        project = group["project"]
        if project not in projects or project in groups:
            raise ValueError(f"Unpinned or duplicate source project: {project}")
        if not isinstance(group["prefixes"], list):
            raise ValueError(f"Invalid source prefixes for {project}")
        for prefix in group["prefixes"]:
            component_catalog._path(prefix)
        _selector(group["discovery"], project)
        groups[project] = group
    overrides = {}
    for field in ("ownership_overrides", "prerequisites"):
        if not isinstance(value[field], dict):
            raise ValueError(f"source_groups.{field} must be an object")
        for project, names in value[field].items():
            if project not in groups or not isinstance(names, list):
                raise ValueError(f"Unknown source group in {field}: {project}")
            for name in names:
                component_catalog._path(name)
                if field == "ownership_overrides":
                    if name in overrides:
                        raise ValueError(f"Ambiguous source ownership override: {name}")
                    overrides[name] = project
    if not isinstance(value["rom_source_checksums"], dict):
        raise ValueError("rom_source_checksums must be an object")
    for project, selector in value["rom_source_checksums"].items():
        if project not in groups:
            raise ValueError(f"Unknown checksummed source project: {project}")
        _selector(selector, "rom_source_checksums")
        if selector.get("from_recipes"):
            raise ValueError("ROM source checksums require an explicit path selector")
    # Equal prefix ownership is ambiguous even when this checkout has no file.
    prefixes = {}
    for project, group in groups.items():
        for prefix in group["prefixes"]:
            if prefix in prefixes and prefixes[prefix] != project:
                raise ValueError(f"Ambiguous source prefix: {prefix}")
            prefixes[prefix] = project
    return groups, overrides


def pinned_projects(sources):
    result = {"common": sources["common"]["revision"]}
    for project in sources["baseline"]:
        name = project["workspace_path"]
        component_catalog._path(name)
        if name in result:
            raise ValueError(f"Duplicate pinned project: {name}")
        result[name] = project["revision"]
    for name, revision in result.items():
        if not isinstance(revision, str) or not _OBJECT.fullmatch(revision):
            raise ValueError(f"Source project is not commit-pinned: {name}")
    return result


def owner(path, groups, overrides):
    if path in overrides:
        return overrides[path]
    candidates = [(len(prefix), project) for project, group in groups.items()
                  for prefix in group["prefixes"] if path == prefix or path.startswith(prefix + "/")]
    if not candidates:
        raise ValueError(f"No declared source provenance for {path}")
    longest = max(length for length, _ in candidates)
    projects = {project for length, project in candidates if length == longest}
    if len(projects) != 1:
        raise ValueError(f"Ambiguous source provenance for {path}")
    return next(iter(projects))


def _git_tree(workspace, project, revision):
    root = workspace / project
    actual = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", revision + "^{commit}"], text=True).strip()
    if actual != revision:
        raise ValueError(f"Unexpected pinned commit object: {project}")
    data = subprocess.check_output(["git", "-C", str(root), "ls-tree", "-rz", "--full-tree", revision])
    result = {}
    for record in data.split(b"\0"):
        if not record:
            continue
        metadata, name = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode().split()
        path = name.decode()
        component_catalog._path(path)
        result[path] = {"mode": mode, "kind": kind, "blob": object_id}
    return result


def _patch_inputs(directory):
    preimages, created = set(), set()
    for patch in sorted(directory.glob("*.patch")):
        before = None
        for line in patch.read_text().splitlines():
            if line.startswith("--- "):
                name = line[4:].split("\t", 1)[0].split(" ", 1)[0]
                before = None if name == "/dev/null" else name.removeprefix("a/")
                if before is not None:
                    component_catalog._path(before)
                    if before not in created:
                        preimages.add(before)
            elif line.startswith("+++ "):
                name = line[4:].split("\t", 1)[0].split(" ", 1)[0]
                if name == "/dev/null":
                    if before is not None:
                        created.discard(before)
                    continue
                name = name.removeprefix("b/")
                component_catalog._path(name)
                if before is None:
                    created.add(name)
                elif name != before:
                    created.discard(before)
                    created.add(name)
    return preimages, created


def _blob_sha256s(workspace, project, blobs):
    ids = sorted(set(blobs))
    data = subprocess.check_output(["git", "-C", str(workspace / project), "cat-file", "--batch"],
                                   input="".join(blob + "\n" for blob in ids).encode())
    offset, result = 0, {}
    for expected in ids:
        end = data.find(b"\n", offset)
        fields = data[offset:end].decode().split()
        if end < offset or len(fields) != 3 or fields[:2] != [expected, "blob"]:
            raise ValueError(f"Invalid pinned blob checksum input: {project}:{expected}")
        size = int(fields[2])
        start = end + 1
        if size < 0 or start + size >= len(data) or data[start + size] != 10:
            raise ValueError("Truncated pinned blob checksum input")
        result[expected] = hashlib.sha256(data[start:start + size]).hexdigest()
        offset = start + size + 1
    if offset != len(data):
        raise ValueError("Trailing pinned blob checksum data")
    return result


def _glob_selectors(catalog):
    def walk(selector):
        selector = component_catalog._list(selector, catalog)
        if isinstance(selector, list):
            return
        if "concat" in selector:
            for part in selector["concat"]:
                yield from walk(part)
        else:
            yield selector

    for component in catalog["components"]:
        if component["kind"] != "vendor_ddk":
            continue
        for field in ("srcs", "hdrs"):
            if field in component["attrs"]:
                yield from walk(component["attrs"][field])


def derive(catalog, sources, workspace, patches):
    projects = pinned_projects(sources)
    groups, overrides = validate_source_groups(catalog.get("source_groups"), projects)
    trees = {project: _git_tree(workspace, project, projects[project]) for project in groups}
    preimages, created = _patch_inputs(patches)
    local = {"BUILD.bazel", "Kconfig", "kmi-symbols", "scm_defconfig", "platform_defconfig", "relay.fragment"}
    local.update(component_catalog.generated_files(catalog))
    targets = {c["name"] for c in catalog["components"]}
    for component in catalog["components"]:
        if component["kind"] == "vendor_ddk" and component["rule"] == "genrule":
            local.update(component["attrs"]["outs"])
    # Discovery is bounded before glob evaluation; no complete driver tree is
    # copied just because a headers recipe uses a recursive glob.
    available = set()
    recipe_globs = list(_glob_selectors(catalog))
    for project, tree in trees.items():
        for name in tree:
            try:
                declared = owner(name, groups, overrides)
            except ValueError as error:
                if str(error).startswith("No declared"):
                    continue
                raise
            if declared != project:
                continue
            scope = groups[project]["discovery"]
            if scope.get("from_recipes"):
                discovered = any(_selected(name, selector) for selector in recipe_globs) and not any(
                    matches(name, pattern) for pattern in scope.get("exclude", []))
            else:
                discovered = _selected(name, scope) and any(
                    _selected(name, selector) for selector in recipe_globs)
            if discovered:
                available.add(name)
    selected = set(preimages)
    for project, names in catalog["source_groups"]["prerequisites"].items():
        for name in names:
            if owner(name, groups, overrides) != project:
                raise ValueError(f"Prerequisite has a different source owner: {name}")
            selected.add(name)

    def add(selector):
        selector = component_catalog._list(selector, catalog)
        if isinstance(selector, list):
            for name in selector:
                if name.startswith(("//", "@")):
                    continue
                label = name.startswith(":")
                name = name.removeprefix(":")
                if name in local or name in created or (label and name in targets):
                    continue
                selected.add(name)
        elif "concat" in selector:
            for part in selector["concat"]:
                add(part)
        else:
            selected.update(name for name in available if _selected(name, selector))

    for component in catalog["components"]:
        if component["kind"] != "vendor_ddk":
            continue
        for field in ("srcs", "hdrs"):
            if field in component["attrs"]:
                add(component["attrs"][field])
    records = []
    for name in sorted(selected):
        project = owner(name, groups, overrides)
        record = trees[project].get(name)
        if record is None:
            raise ValueError(f"Required source missing from pinned Git tree: {project}:{name}")
        if record["kind"] != "blob" or record["mode"] not in {"100644", "100755"}:
            raise ValueError(f"Required source is not a regular Git blob: {project}:{name}")
        records.append({"project": project, "revision": projects[project], "path": name, "blob": record["blob"]})
    for project, selector in catalog["source_groups"]["rom_source_checksums"].items():
        checksummed = [record for record in records if record["project"] == project and _selected(record["path"], selector)]
        checksums = _blob_sha256s(workspace, project, [record["blob"] for record in checksummed])
        for record in checksummed:
            record["rom_source_sha256"] = checksums[record["blob"]]
    evidence = {"selected": len(records), "discovery_scope": len(available),
                "patch_created": sorted(created), "projects": dict(Counter(r["project"] for r in records))}
    return records, evidence


def ordered_lock(records, previous):
    """Retain stable reviewed lock ordering without using it as source selection."""
    table = {r["path"]: r for r in records}
    if len(table) != len(records):
        raise ValueError("Ambiguous generated source destination")
    if not isinstance(previous, list) or any(not isinstance(r, dict) or "path" not in r for r in previous):
        raise ValueError("Invalid previous source lock")
    order = [r["path"] for r in previous]
    if len(order) != len(set(order)):
        raise ValueError("Duplicate source in previous lock")
    result = [table[name] for name in order if name in table]
    result += [table[name] for name in sorted(table.keys() - set(order))]
    removed = sorted(set(order) - table.keys())
    return json.dumps(result, indent=2) + "\n", removed


def _write(path, contents, before=None):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"Preserve unexpected source-lock destination: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".imports-", delete=False) as output:
        temporary = Path(output.name)
        output.write(contents)
    try:
        if before is not None and (not path.exists() or path.read_text() != before):
            raise ValueError("Previous source lock changed during generation; preserve that edit")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--catalog", type=Path, default=HERE / "components.json")
    parser.add_argument("--sources", type=Path, default=HERE / "sources.json")
    parser.add_argument("--patches", type=Path, default=HERE / "patches")
    parser.add_argument("--previous", type=Path, default=HERE / "imports.json")
    parser.add_argument("--output", type=Path, help="write a fully validated generated lock")
    parser.add_argument("--check", action="store_true", help="require the previous lock to match exactly")
    parser.add_argument("--allow-removals", action="store_true", help="allow reviewed recipe or prerequisite removals")
    args = parser.parse_args()
    try:
        catalog = component_catalog.load_catalog(args.catalog)
        sources = json.loads(args.sources.read_text())
        records, evidence = derive(catalog, sources, args.workspace.resolve(), args.patches)
        before = args.previous.read_text()
        contents, removed = ordered_lock(records, json.loads(before))
        if removed and not args.allow_removals:
            raise ValueError("Source lock would drop required inputs; review removals: " + ", ".join(removed))
        if args.check and contents != before:
            raise ValueError("Generated source lock differs; review the catalog, pins and prerequisites")
        if args.output:
            _write(args.output, contents, before if args.output.resolve() == args.previous.resolve() else None)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
