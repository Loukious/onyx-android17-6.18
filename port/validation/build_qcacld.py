#!/usr/bin/env python3
"""Compile and link all QCACLD translation units using matching Kleaf inputs.

The generated DDK Kbuild supplies the module's object list and flags. Sources
and WLAN headers are copied into an isolated output tree so adding a field to
hdd_adapter is checked consistently across the complete module. DDK library
objects are rebuilt from their sources with their original specialized flags.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import build_wonder

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catalog import load_catalog


def wonder_provider_objects(repo):
    """Select only explicitly catalogued Wonder HDD/WMA translation units."""
    catalog = load_catalog(repo / "port/components.json")
    component = next(component for component in catalog["components"]
                     if component["name"] == "qca_cld3_wcn7750")
    sources = component["attrs"]["srcs"]
    if not isinstance(sources, list):
        raise ValueError("QCACLD validation requires explicit catalog source paths")
    pattern = re.compile(r"(?:qcacld-3\.0/core/hdd/src/wlan_hdd_wonder"
                         r"|qcacld-3\.0/core/wma/src/wma_wonder)(?:_[a-z0-9]+)*\.c\Z")
    providers = [source for source in sources if pattern.fullmatch(source)]
    if not providers:
        raise ValueError("The QCACLD catalog has no Wonder provider sources")
    for source in providers:
        if not (repo / "modules" / source).is_file():
            raise ValueError("Missing catalogued Wonder provider: " + source)
    return [str(Path(source).with_suffix(".o")) for source in providers]


def write_if_changed(path, value):
    if not path.is_file() or path.read_text() != value:
        path.write_text(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--native-wireless-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path,
                        default=Path("/tmp/onyx-wonder-qcacld-build-20261116"))
    parser.add_argument("--jobs", type=int, default=6)
    args = parser.parse_args()
    workspace, output = args.workspace.resolve(), args.output.resolve()
    repo = build_wonder.REPO
    provider_objects = wonder_provider_objects(repo)
    catalog_sha256 = build_wonder.digest(repo / "port/components.json")
    subprocess.run([sys.executable, str(Path(build_wonder.__file__)),
                    "--workspace", str(workspace), "--output", str(output),
                    "--native-wireless-dir", str(args.native_wireless_dir.resolve()),
                    "--prepare-only"], check=True)
    kernel = output / "kernel"
    module = output / "qcacld"
    module.mkdir(exist_ok=True)
    for directory in ("qcacld-3.0", "qca-wifi-host-cmn", "fw-api", "wonder"):
        shutil.copytree(repo / "modules" / directory, module / directory,
                        dirs_exist_ok=True, ignore=shutil.ignore_patterns(
                            ".git", "*.o", "*.ko", "*.mod*", ".*.cmd", "Module.symvers"))
    source_hashes = {str(path.relative_to(repo / "modules")):
                     build_wonder.digest(module / path.relative_to(repo / "modules"))
                     for directory in ("qcacld-3.0", "qca-wifi-host-cmn", "fw-api", "wonder")
                     for path in sorted((repo / "modules" / directory).rglob("*"))
                     if path.is_file() and path.suffix not in (".o", ".ko", ".cmd")
                     and (directory != "wonder" or
                          (path.suffix == ".h" and "include" in path.relative_to(repo / "modules/wonder").parts))}
    config = workspace / "bazel-bin/onyx/qca_cld3_wcn7750_config/out_dir"
    shutil.copy2(config / ".config", kernel / ".config")
    shutil.copytree(config / "include", kernel / "include", dirs_exist_ok=True)
    auto = kernel / "include/config/auto.conf.cmd"
    auto.write_text(auto.read_text().replace("${ROOT_DIR}", str(workspace)))
    makefiles = workspace / "bazel-bin/onyx/qca_cld3_wcn7750_makefiles/makefiles"

    def relocate(text):
        for directory in ("qcacld-3.0", "qca-wifi-host-cmn", "fw-api", "wonder"):
            text = text.replace("$(ROOT_DIR)/onyx/" + directory,
                                str(module / directory))
        return (text.replace("$(ROOT_DIR)/onyx", str(repo / "modules"))
                .replace("$(ROOT_DIR)/common", str(workspace / "common")))

    def flags(target):
        path = workspace / f"bazel-bin/onyx/{target}_makefiles/makefiles/{target}.cflags_shipped"
        return (relocate(path.read_text()) + "\n-DFEATURE_WLAN_WONDER\n-I" +
                str(module / "wonder/include") + "\n")

    write_if_changed(module / "qca_cld3_wcn7750.cflags", flags("qca_cld3_wcn7750"))
    original_kbuild = (makefiles / "Kbuild").read_text()
    # Replace shipped-object copy rules with compilation of the three actual
    # DDK library sources. Keep the main object list and specialized flags.
    kbuild_lines = []
    for line in original_kbuild.splitlines():
        if (line.startswith("always-y += wlan_main_extra_") or
                line.startswith("$(obj)/wlan_main_extra_") or
                line.strip() == "$(call cmd,copy)"):
            continue
        kbuild_lines.append(line)
    kbuild = relocate("\n".join(kbuild_lines) + "\n")
    extras = {
        "wlan_main_extra_0": ["qca-wifi-host-cmn/wmi/src/wmi_unified_tlv.c",
                              "qcacld-3.0/core/wma/src/wma_dev_if.c"],
        "wlan_main_extra_1": ["qcacld-3.0/components/dp/dispatcher/src/wlan_dp_flow_ucfg_api.c"],
    }
    for target, paths in extras.items():
        write_if_changed(module / (target + ".cflags"), flags(target))
        for relative in paths:
            copied = module / target / relative
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(module / relative, copied)
            obj = str(Path(target) / Path(relative).with_suffix(".o"))
            kbuild += (f"CFLAGS_{obj} += @$(obj)/{target}.cflags\n"
                       f"$(obj)/{obj}: $(obj)/{target}.cflags\n")
    for provider in provider_objects:
        if f"qca_cld3_wcn7750-y += {provider}\n" in kbuild:
            continue
        kbuild += (f"qca_cld3_wcn7750-y += {provider}\n"
                   f"CFLAGS_{provider} += @$(obj)/qca_cld3_wcn7750.cflags\n"
                   f"$(obj)/{provider}: $(obj)/qca_cld3_wcn7750.cflags\n")
    write_if_changed(module / "Kbuild", kbuild)
    shutil.copy2(makefiles / "Makefile", module / "Makefile")
    shutil.copy2(makefiles / "ddk_modinfo.c", module / "ddk_modinfo.c")
    dependencies = re.findall(r"# Include symbol: onyx/([^\n]+)",
                              (makefiles / "Makefile").read_text())
    symvers_dir = output / "dependencies"
    symvers_dir.mkdir(exist_ok=True)
    symvers = []
    for name in dependencies:
        target = name.removesuffix("_Module.symvers")
        source = workspace / f"bazel-bin/onyx/{target}/{name}"
        copied = symvers_dir / name
        shutil.copy2(source, copied)
        symvers.append(copied)
    clang = workspace / "prebuilts/clang/host/linux-x86/clang-r596125/bin"
    tools = workspace / "prebuilts/kernel-build-tools/linux_musl-x86/bin"
    rust = workspace / "bazel-workspace/external/+_repo_rules2+prebuilt_rust/1.91.1.p4/bin"
    env = os.environ.copy()
    env["PATH"] = ":".join(map(str, (clang, tools, rust))) + ":" + env.get("PATH", "")
    env["LIBCLANG_PATH"] = str(clang.parent / "lib")
    env["KBUILD_GENDWARFKSYMS_STABLE"] = "1"
    command = ["make", "-C", str(workspace / "common"), f"O={kernel}", f"M={module}",
               "ARCH=arm64", "LLVM=1",
               "KCONFIG_EXT_PREFIX=../bazel-out/k8-fastbuild/bin/onyx/qca_cld3_wcn7750_config/kconfig_ext/",
               "KBUILD_EXTRA_SYMBOLS=" + " ".join(map(str, symvers)),
               f"-j{args.jobs}", "modules"]
    report = {"status": "BUILDING", "scope": "Complete host QCACLD compilation and linking; no radio validation",
              "source_input_scope": "QCACLD, qca-host, firmware-api sources and public Wonder provider headers",
              "workspace": str(workspace), "kernel_release": build_wonder.EXPECTED_RELEASE,
              "command": command, "source_files": source_hashes,
              "component_catalog_sha256": catalog_sha256,
              "wonder_provider_objects": provider_objects,
              "baseline_kbuild_sha256": build_wonder.digest(makefiles / "Kbuild"),
              "ddk_config_sha256": build_wonder.digest(config / ".config"),
              "dependencies": {path.name: build_wonder.digest(path) for path in symvers},
              "translation_units": sum(line.startswith("qca_cld3_wcn7750-y += ")
                                       for line in kbuild.splitlines())}
    (output / "qcacld-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Building {report['translation_units']} translation units; log: {output / 'qcacld.log'}", flush=True)
    with (output / "qcacld.log").open("w") as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    report["returncode"] = result.returncode
    report["status"] = "PASS" if result.returncode == 0 else "FAIL"
    report["changed_after_snapshot"] = sorted(
        relative for relative, expected in source_hashes.items()
        if build_wonder.digest(repo / "modules" / relative) != expected)
    if report["changed_after_snapshot"]:
        report["status"] = "FAIL"
        report["error"] = "Sources changed after the build snapshot; rerun to validate current sources"
    if build_wonder.digest(repo / "port/components.json") != catalog_sha256:
        report["status"] = "FAIL"
        report["error"] = "The component catalog changed during compilation; rerun with current sources"
    artifact = module / "qca_cld3_wcn7750.ko"
    if result.returncode == 0:
        report["module"] = str(artifact)
        report["sha256"] = build_wonder.digest(artifact)
        report["symvers_sha256"] = build_wonder.digest(module / "Module.symvers")
        previous = workspace / ("bazel-bin/onyx/qca_cld3_wcn7750/"
                                "qca_cld3_wcn7750_Module.symvers")
        old_exports = {row[1]: row[0] for line in previous.read_text().splitlines()
                       if (row := line.split())}
        new_exports = {row[1]: row[0] for line in (module / "Module.symvers").read_text().splitlines()
                       if (row := line.split())}
        report["existing_exports_preserved"] = {
            "count": len(old_exports), "missing": sorted(set(old_exports) - set(new_exports)),
            "changed_crcs": sorted(name for name, crc in old_exports.items()
                                   if name in new_exports and new_exports[name] != crc)}
        sys.path.insert(0, str(repo / "port"))
        from verify_modules import verify
        try:
            report["module_verification"] = verify([artifact], [kernel / "Module.symvers", *symvers],
                                                   build_wonder.EXPECTED_RELEASE)
        except (ValueError, RuntimeError) as error:
            report["status"] = "FAIL"
            report["error"] = str(error)
    (output / "qcacld-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in
                      ("status", "kernel_release", "translation_units", "returncode")}, indent=2))
    if report["status"] != "PASS":
        print((output / "qcacld.log").read_text()[-24000:])
        raise SystemExit(1)


if __name__ == "__main__":
    main()
