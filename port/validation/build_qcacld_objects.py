#!/usr/bin/env python3
"""Type-check changed QCACLD objects with real matching Kleaf/DDK inputs.

This compiles objects only. The complete QCACLD module must still be linked
and checked before using the implementation on a device.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import build_wonder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", type=Path,
                        default=Path("/tmp/onyx-wonder-provider-build-20261116"))
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("sources", nargs="+", type=Path)
    args = parser.parse_args()
    workspace, output = args.workspace.resolve(), args.output.resolve()
    repo = build_wonder.REPO
    subprocess.run([sys.executable, str(Path(build_wonder.__file__)),
                    "--workspace", str(workspace), "--output", str(output),
                    "--prepare-only"], check=True)
    kernel = output / "kernel"
    config = workspace / "bazel-bin/onyx/qca_cld3_wcn7750_config/out_dir"
    shutil.copy2(config / ".config", kernel / ".config")
    shutil.copytree(config / "include", kernel / "include", dirs_exist_ok=True)
    auto = kernel / "include/config/auto.conf.cmd"
    auto.write_text(auto.read_text().replace("${ROOT_DIR}", str(workspace)))
    makefiles = workspace / "bazel-bin/onyx/qca_cld3_wcn7750_makefiles/makefiles"

    def relocate(text):
        return (text.replace("$(ROOT_DIR)/onyx", str(repo / "modules"))
                .replace("$(ROOT_DIR)/common", str(workspace / "common")))

    flags = relocate((makefiles / "qca_cld3_wcn7750.cflags_shipped").read_text())
    flags += "\n-DFEATURE_WLAN_WONDER\n-I" + str(repo / "modules/wonder/include") + "\n"
    kbuild = (makefiles / "Kbuild").read_text()
    common_flags = kbuild[kbuild.index("LINUXINCLUDE :="):kbuild.index("\nCFLAGS_")]
    common_flags = relocate(common_flags)
    module = output / "qcacld"
    module.mkdir(exist_ok=True)
    sources = [path.resolve() for path in args.sources]
    if len({path.name for path in sources}) != len(sources):
        parser.error("Source basenames must be unique")
    objects = [path.with_suffix(".o").name for path in sources]
    # Copied translation units still need their original private sibling
    # headers, which are not all exported through the DDK include list.
    flags += "".join("\n-I" + str(path) for path in sorted({path.parent for path in sources})) + "\n"
    (module / "qcacld.cflags").write_text(flags)
    for path in sources:
        shutil.copy2(path, module / path.name)
    (module / "Makefile").write_text("obj-m += " + " ".join(objects) + "\n" +
                                      common_flags + "\nccflags-y += @$(src)/qcacld.cflags\n")
    clang = workspace / "prebuilts/clang/host/linux-x86/clang-r596125/bin"
    rust = workspace / "bazel-workspace/external/+_repo_rules2+prebuilt_rust/1.91.1.p4/bin"
    env = os.environ.copy()
    env["PATH"] = str(clang) + ":" + str(rust) + ":" + env.get("PATH", "")
    env["LIBCLANG_PATH"] = str(clang.parent / "lib")
    env["KBUILD_GENDWARFKSYMS_STABLE"] = "1"
    command = ["make", "-C", str(workspace / "common"), f"O={kernel}", f"M={module}",
               "ARCH=arm64", "LLVM=1",
               "KCONFIG_EXT_PREFIX=../bazel-out/k8-fastbuild/bin/onyx/qca_cld3_wcn7750_config/kconfig_ext/",
               f"-j{args.jobs}", *objects]
    headers = [repo / "modules/qcacld-3.0/core/hdd/inc/wlan_hdd_main.h",
               repo / "modules/qcacld-3.0/core/hdd/inc/wlan_hdd_wonder.h",
               repo / "modules/qcacld-3.0/core/hdd/inc/wlan_hdd_wonder_coex.h",
               repo / "modules/qcacld-3.0/core/hdd/inc/wlan_hdd_wonder_dwell.h",
               repo / "modules/qcacld-3.0/core/hdd/inc/wlan_hdd_wonder_sched.h",
               repo / "modules/qcacld-3.0/components/mlme/dispatcher/inc/wlan_mlme_sta_mon.h",
               repo / "modules/wonder/include/wondertap.h"]
    headers = [path for path in headers if path.is_file()]
    report = {"status": "BUILDING", "scope": "Object compilation only; complete QCACLD is not linked",
              "workspace": str(workspace), "kernel_release": build_wonder.EXPECTED_RELEASE,
              "command": command,
              "ddk_config_sha256": build_wonder.digest(config / ".config"),
              "ddk_flags_sha256": build_wonder.digest(makefiles / "qca_cld3_wcn7750.cflags_shipped"),
              "sources": {str(path.relative_to(repo)): build_wonder.digest(module / path.name)
                          for path in sources},
              "headers": {str(path.relative_to(repo)): build_wonder.digest(path) for path in headers}}
    with (output / "objects.log").open("w") as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    report["returncode"] = result.returncode
    report["status"] = "PASS" if result.returncode == 0 else "FAIL"
    report["changed_after_copy"] = sorted(
        relative for relative, expected in report["sources"].items()
        if build_wonder.digest(repo / relative) != expected)
    if report["changed_after_copy"]:
        report["status"] = "FAIL"
        report["error"] = "Sources changed after copying; rerun to validate current sources"
    report["changed_headers_after_snapshot"] = sorted(
        relative for relative, expected in report["headers"].items()
        if build_wonder.digest(repo / relative) != expected)
    if report["changed_headers_after_snapshot"]:
        report["status"] = "FAIL"
        report["error"] = "Recorded headers changed during compilation; rerun with current headers"
    report["objects"] = {name: build_wonder.digest(module / name)
                         for name in objects if (module / name).is_file()}
    (output / "objects-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if report["status"] != "PASS":
        print((output / "objects.log").read_text()[-18000:])
        raise SystemExit(result.returncode or 1)


if __name__ == "__main__":
    main()
