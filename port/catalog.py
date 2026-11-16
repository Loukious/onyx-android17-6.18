#!/usr/bin/env python3
"""Validate the component catalog and generate its Kleaf build projections.

Recipes are data, with only list concatenation, shared lists and Bazel globs.
Common components declare Kconfig needs and outputs, never copied source lists.
The independent module-loading policy decides which built modules run at boot.
"""

import argparse
import json
from pathlib import Path, PurePosixPath
import re

HERE = Path(__file__).resolve().parent
CATALOG = HERE / "components.json"
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.+-]*\Z")
_CONFIG = re.compile(r"[A-Z][A-Z0-9_]*\Z")
_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_RULE_FIELDS = {
    "ddk_headers": {"hdrs", "includes", "linux_includes", "visibility", "deps"},
    "ddk_module": {"srcs", "hdrs", "out", "kconfig", "defconfig", "deps",
                   "includes", "linux_includes", "visibility", "copts", "local_defines"},
    "ddk_library": {"srcs", "hdrs", "kconfig", "defconfig", "deps", "includes",
                    "linux_includes", "visibility", "copts", "local_defines"},
    "genrule": {"srcs", "outs", "cmd", "visibility"},
}
_LIST_FIELDS = {"srcs", "hdrs", "deps", "includes", "linux_includes", "visibility",
                "copts", "local_defines", "outs"}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate catalog key: {key}")
        result[key] = value
    return result


def _path(value, *, label=False, pattern=False):
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"Invalid catalog path: {value!r}")
    if label and value.startswith(("//", "@")):
        # External labels are passed to Bazel, never used as local paths.
        if ".." in value.split("/") or any(c.isspace() for c in value):
            raise ValueError(f"Invalid external label: {value}")
        return
    name = value.removeprefix(":") if label else value
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or name != path.as_posix():
        raise ValueError(f"Unsafe catalog path: {value}")
    if not pattern and any(c in name for c in "*?["):
        raise ValueError(f"Unexpected catalog path pattern: {value}")


def _list(value, catalog, active=()):
    """Validate and expand shared lists without evaluating Starlark or Python."""
    if isinstance(value, list):
        if any(not isinstance(item, str) for item in value):
            raise ValueError("Catalog lists must contain strings")
        return value
    if not isinstance(value, dict):
        raise ValueError(f"Expected a list selector: {value!r}")
    if set(value) == {"ref"}:
        name = value["ref"]
        if not isinstance(name, str) or name in active:
            raise ValueError(f"Invalid or cyclic shared attribute: {name!r}")
        if name not in catalog["shared_attributes"]:
            raise ValueError(f"Unknown shared attribute: {name}")
        return _list(catalog["shared_attributes"][name], catalog, (*active, name))
    if set(value) == {"concat"}:
        if not isinstance(value["concat"], list) or not value["concat"]:
            raise ValueError("A concatenation must contain list selectors")
        return {"concat": [_list(item, catalog, active) for item in value["concat"]]}
    if "glob" in value and set(value) <= {"glob", "exclude", "allow_empty"}:
        for field in ("glob", "exclude"):
            if field in value:
                items = value[field]
                if not isinstance(items, list) or any(not isinstance(item, str) for item in items):
                    raise ValueError(f"glob {field} must be a string list")
                for item in items:
                    _path(item, pattern=True)
        if not value["glob"] or ("allow_empty" in value and not isinstance(value["allow_empty"], bool)):
            raise ValueError("Invalid glob selector")
        return value
    raise ValueError(f"Unknown catalog list selector: {value!r}")


def _strings(value):
    if isinstance(value, list):
        yield from value
    elif "concat" in value:
        for item in value["concat"]:
            yield from _strings(item)
    else:
        yield from value["glob"]
        yield from value.get("exclude", [])


def _literal_list(value, catalog, field):
    value = _list(value, catalog)
    if isinstance(value, dict) and "concat" in value:
        return [item for part in value["concat"] for item in _literal_list(part, catalog, field)]
    if not isinstance(value, list):
        raise ValueError(f"{field} requires a literal or shared string list")
    return value


def _configs(configs, where):
    if not isinstance(configs, dict):
        raise ValueError(f"Invalid configs in {where}")
    for option, value in configs.items():
        if not _CONFIG.fullmatch(option) or not isinstance(value, str) or value not in {"y", "m", "n"}:
            raise ValueError(f"Invalid config in {where}: {option}={value!r}")


def validate_catalog(catalog):
    required = {"schema_version", "kernel_build", "shared_attributes", "native_configs", "components"}
    if (not isinstance(catalog, dict) or not required <= set(catalog)
            or set(catalog) - required - {"source_groups"} or catalog["schema_version"] != 1):
        raise ValueError("Unsupported component catalog schema")
    if not isinstance(catalog["kernel_build"], str) or not catalog["kernel_build"].startswith("//"):
        raise ValueError("Catalog kernel_build must be an absolute Bazel label")
    if not isinstance(catalog["shared_attributes"], dict):
        raise ValueError("shared_attributes must be an object")
    for name, value in catalog["shared_attributes"].items():
        if not _NAME.fullmatch(name):
            raise ValueError(f"Invalid shared attribute name: {name}")
        _list(value, catalog, (name,))
    _configs(catalog["native_configs"], "native_configs")
    if not isinstance(catalog["components"], list) or not catalog["components"]:
        raise ValueError("Catalog components must be a nonempty list")
    names, outputs, dependencies, exports = {}, {}, {}, {}
    for component in catalog["components"]:
        if not isinstance(component, dict):
            raise ValueError("Each component must be an object")
        name = component.get("name")
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name in names:
            raise ValueError(f"Invalid or duplicate component: {name!r}")
        names[name] = component
        kind = component.get("kind")
        output = None
        if kind == "native_common":
            required_native = {"kind", "name", "output", "configs"}
            if not required_native <= set(component) or set(component) - required_native - {"required_exports"}:
                raise ValueError(f"Native component {name} declares copied sources or unknown fields")
            output = component["output"]
            _path(output)
            _configs(component["configs"], name)
            symbols = component.get("required_exports", [])
            if not isinstance(symbols, list):
                raise ValueError(f"Native required_exports must be a symbol list: {name}")
            for symbol in symbols:
                if not isinstance(symbol, str) or not _SYMBOL.fullmatch(symbol):
                    raise ValueError(f"Invalid required native export {name}: {symbol!r}")
                if symbol in exports:
                    raise ValueError(f"Duplicate required native export {symbol}: {exports[symbol]} and {name}")
                exports[symbol] = name
        elif kind == "vendor_ddk":
            if set(component) - {"kind", "rule", "name", "attrs", "replaces_gki"} or not {"kind", "rule", "name", "attrs"} <= set(component):
                raise ValueError(f"Unknown vendor component field: {name}")
            rule, attrs = component["rule"], component["attrs"]
            if rule not in _RULE_FIELDS or not isinstance(attrs, dict) or set(attrs) - _RULE_FIELDS[rule]:
                raise ValueError(f"Unsupported recipe attributes for {name}")
            required_fields = {"ddk_headers": {"hdrs"}, "ddk_module": {"srcs", "out"},
                               "ddk_library": {"srcs"}, "genrule": {"srcs", "outs", "cmd"}}[rule]
            if required_fields - set(attrs):
                raise ValueError(f"Incomplete recipe: {name}")
            for field, value in attrs.items():
                if field in _LIST_FIELDS:
                    selector = _list(value, catalog)
                    if field not in {"srcs", "hdrs"}:
                        _literal_list(value, catalog, field)
                    if field in {"srcs", "hdrs", "outs", "includes", "linux_includes"}:
                        for item in _strings(selector):
                            _path(item, label=field in {"srcs", "hdrs"}, pattern=field in {"srcs", "hdrs"})
                elif not isinstance(value, str):
                    raise ValueError(f"{name}.{field} must be a string")
                elif field in {"out", "kconfig", "defconfig"}:
                    _path(value)
            if rule == "ddk_module":
                output = attrs["out"]
            if "replaces_gki" in component:
                if rule != "ddk_module":
                    raise ValueError(f"Only module components replace native providers: {name}")
                _path(component["replaces_gki"])
            dependencies[name] = _literal_list(attrs.get("deps", []), catalog, "deps")
        else:
            raise ValueError(f"Unknown component kind for {name}: {kind}")
        if output is not None:
            if not output.endswith(".ko"):
                raise ValueError(f"Component module output must end in .ko: {output}")
            # Linux normalizes hyphens in module identifiers; one provider only.
            module = PurePosixPath(output).name.removesuffix(".ko").replace("-", "_")
            if module in outputs:
                raise ValueError(f"Duplicate module provider {module}: {outputs[module]} and {name}")
            outputs[module] = name
    graph = {}
    for name, labels in dependencies.items():
        graph[name] = []
        for label in labels:
            if label.startswith(":") and "/" not in label:
                target = label[1:]
                if target not in names:
                    raise ValueError(f"Unknown component dependency {name}: {label}")
                if names[target]["kind"] == "vendor_ddk":
                    graph[name].append(target)
            elif not label.startswith(("//", "@")):
                raise ValueError(f"Unsupported component dependency {name}: {label}")
    active, visited = set(), set()

    def visit(name):
        if name in active:
            raise ValueError(f"Cyclic component build dependencies: {name}")
        if name in visited:
            return
        active.add(name)
        for target in graph.get(name, []):
            visit(target)
        active.remove(name)
        visited.add(name)

    for name in graph:
        visit(name)
    native_configs(catalog)
    return catalog


def load_catalog(path=CATALOG):
    return validate_catalog(json.loads(Path(path).read_text(), object_pairs_hook=_unique_object))


def vendor_modules(catalog=None):
    catalog = load_catalog() if catalog is None else catalog
    return [dict({"target": c["name"], "output": c["attrs"]["out"]},
                 **({"replaces_gki": c["replaces_gki"]} if "replaces_gki" in c else {}))
            for c in catalog["components"] if c["kind"] == "vendor_ddk" and c["rule"] == "ddk_module"]


def native_modules(catalog=None):
    catalog = load_catalog() if catalog is None else catalog
    return [{"target": c["name"], "output": c["output"], "configs": dict(c["configs"])}
            for c in catalog["components"] if c["kind"] == "native_common"]


def native_configs(catalog=None):
    catalog = load_catalog() if catalog is None else catalog
    configs = dict(catalog["native_configs"])
    for component in catalog["components"]:
        if component["kind"] != "native_common":
            continue
        for option, value in component["configs"].items():
            if option in configs and configs[option] != value:
                raise ValueError(f"Conflicting native config: {option}")
            configs[option] = value
    return dict(sorted(configs.items()))


def native_required_exports(catalog=None):
    """The explicit native ABI consumed by separately built vendor modules."""
    catalog = load_catalog() if catalog is None else catalog
    return sorted(symbol for component in catalog["components"] if component["kind"] == "native_common"
                  for symbol in component.get("required_exports", []))


def _render_value(value, catalog, indent=4, references=None):
    if isinstance(value, dict):
        if set(value) == {"ref"} and references is not None:
            return references[value["ref"]]
        if set(value) == {"concat"} and references is not None:
            return " + ".join(_render_value(item, catalog, indent, references) for item in value["concat"])
        value = _list(value, catalog)
        if isinstance(value, dict):
            if "concat" in value:
                return " + ".join(_render_value(item, catalog, indent, references) for item in value["concat"])
            arguments = [_render_value(value["glob"], catalog, indent)]
            for field in ("exclude", "allow_empty"):
                if field in value:
                    arguments.append(field + " = " + _render_value(value[field], catalog, indent))
            return "glob(" + ", ".join(arguments) + ")"
    if isinstance(value, list):
        if not value:
            return "[]"
        compact = json.dumps(value)
        if len(compact) + indent <= 108:
            return compact
        pad = " " * indent
        return "[\n" + "".join(pad + "    " + json.dumps(item) + ",\n" for item in value) + pad + "]"
    if isinstance(value, bool):
        return "True" if value else "False"
    return json.dumps(value)


def render_build(catalog=None):
    catalog = load_catalog() if catalog is None else catalog
    native = {c["name"] for c in catalog["components"] if c["kind"] == "native_common"}
    lines = ["# SPDX-License-Identifier: GPL-2.0-only",
             "# Generated by port/catalog.py from components.json; edit the catalog.",
             'load("//build/kernel/kleaf:kernel.bzl", "ddk_headers", "ddk_library", "ddk_module", "kernel_module_group")',
             'load("@rules_pkg//pkg:install.bzl", "pkg_install")',
             'load("@rules_pkg//pkg:mappings.bzl", "pkg_files", "strip_prefix")', "",
             'package(default_visibility = ["//visibility:public"])', ""]
    references, dependency_references = {}, {}
    for index, (name, value) in enumerate(catalog["shared_attributes"].items()):
        symbol = "_SHARED_" + re.sub(r"[^A-Za-z0-9_]", "_", name).upper() + "_" + str(index)
        references[name] = symbol
        lines += [symbol + " = " + _render_value(value, catalog, 0), ""]
        expanded = _list(value, catalog)
        if isinstance(expanded, list):
            filtered = [dep for dep in expanded if not dep.startswith(":") or dep[1:] not in native]
            if filtered != expanded:
                dependency_references[name] = symbol + "_DDK"
                lines += [symbol + "_DDK = " + _render_value(filtered, catalog, 0), ""]
    dependency_references = dict(references, **dependency_references)
    for component in catalog["components"]:
        if component["kind"] == "native_common":
            continue
        attrs = dict(component["attrs"])
        if "deps" in attrs:
            if not isinstance(attrs["deps"], dict) or set(attrs["deps"]) != {"ref"}:
                attrs["deps"] = [dep for dep in _literal_list(attrs["deps"], catalog, "deps")
                                 if dep.removeprefix(":") not in native or not dep.startswith(":")]
        if component["rule"] in {"ddk_module", "ddk_library"}:
            attrs["kernel_build"] = catalog["kernel_build"]
        lines += [component["rule"] + "(", "    name = " + json.dumps(component["name"]) + ","]
        for key, value in attrs.items():
            refs = dependency_references if key == "deps" else references
            lines.append("    " + key + " = " + _render_value(value, catalog, references=refs) + ",")
        lines += [")", ""]
    lines += ['exports_files(["kmi-symbols", "native-kmi-symbols", "native_wireless.fragment"])', "",
              'filegroup(', '    name = "kmi_symbol_lists",',
              '    srcs = ["kmi-symbols", "native-kmi-symbols"],', ')', "",
              'kernel_module_group(', '    name = "platform_modules",',
              '    srcs = ' + _render_value([":" + m["target"] for m in vendor_modules(catalog)], catalog) + ",",
              ')', "", 'pkg_files(', '    name = "platform_files",',
              '    srcs = [":platform_modules"],', '    strip_prefix = strip_prefix.files_only(),',
              ')', "", 'pkg_install(', '    name = "platform_dist",',
              '    srcs = [":platform_files"],', ')', ""]
    return "\n".join(lines)


def generated_files(catalog=None):
    catalog = load_catalog() if catalog is None else catalog
    native = [module["output"] for module in native_modules(catalog)]
    header = "# Generated by port/catalog.py from components.json; edit the catalog.\n"
    module_list = header + "NATIVE_WIRELESS_MODULES = " + _render_value(native, catalog, 0) + "\n"
    fragment = header + "".join(f"# CONFIG_{option} is not set\n" if value == "n" else
                               f"CONFIG_{option}={value}\n"
                               for option, value in native_configs(catalog).items())
    symbols = header + "[abi_symbol_list]\n" + "".join("  " + symbol + "\n"
                                                            for symbol in native_required_exports(catalog))
    return {"BUILD.bazel": render_build(catalog),
            "modules.json": json.dumps(vendor_modules(catalog), indent=2) + "\n",
            "native_modules.bzl": module_list,
            "native_wireless.fragment": fragment,
            "native-kmi-symbols": symbols}


def check_generated(directory=HERE, catalog=None):
    stale = [name for name, contents in generated_files(catalog).items()
             if not (Path(directory) / name).is_file() or (Path(directory) / name).read_text() != contents]
    if stale:
        raise ValueError("Regenerate component projections with port/catalog.py: " + ", ".join(stale))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--output", type=Path, default=HERE)
    parser.add_argument("--check", action="store_true", help="fail if checked-in projections are stale")
    args = parser.parse_args()
    try:
        catalog = load_catalog(args.catalog)
        if args.check:
            check_generated(args.output, catalog)
        else:
            args.output.mkdir(parents=True, exist_ok=True)
            for name, contents in generated_files(catalog).items():
                path = args.output / name
                if path.is_symlink():
                    raise ValueError(f"Preserve generated-file symlink: {path}")
                path.write_text(contents)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(f"Validated {len(vendor_modules(catalog))} vendor and {len(native_modules(catalog))} native modules")


if __name__ == "__main__":
    main()
