#!/usr/bin/env python3
"""Compile Wonder against an existing, matching Kleaf kernel build.

The source checkout and the existing kernel outputs are read-only inputs. A
small modules_prepare tree and a copy of Wonder are built under --output.
This does not build a kernel image or install anything on an Android device.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile


EXPECTED_RELEASE = "6.18.63-android17-6-maybe-dirty-4k"
REPO = Path(__file__).resolve().parents[2]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def extract(archive, destination):
    with tarfile.open(archive, "r:gz") as stream:
        # Kleaf generates these archives locally; still reject unsafe members.
        stream.extractall(destination, filter="data")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", type=Path,
                        default=Path("/tmp/onyx-wonder-build-20261116"))
    parser.add_argument("--module", type=Path, default=REPO / "modules/wonder")
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--native-wireless-dir", type=Path,
                        help="Use verified, rebuilt cfg80211/mac80211 providers")
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    output = args.output.resolve()
    source = args.module.resolve()
    kernel = workspace / "bazel-bin/common/kernel_aarch64"
    release = (kernel / "include/config/kernel.release").read_text().strip()
    if release != EXPECTED_RELEASE:
        parser.error(f"Expected {EXPECTED_RELEASE}, found {release}")
    config = (kernel / "kernel_aarch64_dot_config").read_text()
    for required in ("CONFIG_AUXILIARY_BUS=y", "CONFIG_MAC80211=m",
                     "CONFIG_CFG80211=m", "CONFIG_MODVERSIONS=y"):
        if required not in config.splitlines():
            parser.error(f"Required matching-kernel config is absent: {required}")
    clang_dir = workspace / "prebuilts/clang/host/linux-x86/clang-r596125/bin"
    if not (clang_dir / "clang").is_file():
        parser.error("The kernel's clang-r596125 toolchain is missing")
    output.mkdir(parents=True, exist_ok=True)
    if output == workspace or output == source or workspace.is_relative_to(output):
        parser.error("Output must be separate from the input workspace and sources")
    prepared = output / "kernel"
    prepared.mkdir(exist_ok=True)
    archive = workspace / ("bazel-bin/common/kernel_aarch64_modules_prepare/"
                           "modules_prepare_outdir.tar.gz")
    extract(archive, prepared)
    extract(kernel / "kernel_aarch64_generated_headers_for_module.tar.gz", prepared)
    shutil.copy2(kernel / "kernel_aarch64_dot_config", prepared / ".config")
    shutil.copy2(kernel / "Module.symvers", prepared / "Module.symvers")
    shutil.copy2(kernel / "include/config/kernel.release",
                 prepared / "include/config/kernel.release")
    shutil.copy2(kernel / "System.map", prepared / "System.map")
    vmlinux = prepared / "vmlinux"
    if vmlinux.is_symlink():
        vmlinux.unlink()
    if not vmlinux.exists():
        vmlinux.symlink_to((kernel / "vmlinux").resolve())
    # Kleaf host tools use relinterp and search their runtime libraries through
    # ancestor-relative prebuilts paths. Retain that layout in the small tree.
    prebuilts = prepared / "prebuilts"
    if not prebuilts.exists():
        prebuilts.symlink_to(workspace / "prebuilts", target_is_directory=True)
    # The archive's Makefile contains its original KBUILD_OUTPUT. Kbuild emits
    # the correct wrapper for this O= directory when invoked below.
    (prepared / "Makefile").unlink(missing_ok=True)
    report = {
        "status": "PREPARED",
        "scope": "Host compilation only; no firmware or radio validation",
        "workspace": str(workspace),
        "kernel_release": release,
        "kernel_symvers_sha256": digest(kernel / "Module.symvers"),
        "modules_prepare_sha256": digest(archive),
        "output": str(output),
        "compiler": subprocess.check_output([str(clang_dir / "clang"),
                                             "--version"], text=True).splitlines()[0],
    }
    if args.native_wireless_dir:
        native = args.native_wireless_dir.resolve()
        receipt = json.loads((native / "native-report.json").read_text())
        if (receipt.get("status") != "PASS" or receipt.get("kernel_release") != release
                or receipt.get("baseline_kernel_symvers_sha256") != report["kernel_symvers_sha256"]):
            parser.error("Native providers do not match this verified kernel build")
        rows = [line for line in (prepared / "Module.symvers").read_text().splitlines()
                if line.split()[2] not in ("net/wireless/cfg80211", "net/mac80211/mac80211")]
        for provider in receipt["providers"]:
            artifact = Path(provider["module"])
            if digest(artifact) != provider["sha256"]:
                parser.error(f"Rebuilt provider was changed after verification: {artifact}")
            symbols = Path(provider["symvers"])
            if digest(symbols) != provider.get("symvers_sha256"):
                parser.error(f"Provider symbols were changed after verification: {symbols}")
            rows.extend(symbols.read_text().splitlines())
        (prepared / "Module.symvers").write_text("\n".join(rows) + "\n")
        report["native_wireless_receipt"] = str(native / "native-report.json")
        report["build_symvers_sha256"] = digest(prepared / "Module.symvers")
    if args.prepare_only:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        return
    if not (source / "Makefile").is_file():
        parser.error(f"Wonder has not been imported at {source}")
    module = output / "wonder"
    report["source_files"] = {str(path.relative_to(source)): digest(path)
                              for path in sorted(source.rglob("*"))
                              if path.is_file() and ".git" not in path.relative_to(source).parts}
    shutil.copytree(source, module, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".git", "*.o", "*.ko", "*.mod*",
                                                 ".*.cmd", "Module.symvers", "modules.order"))
    env = os.environ.copy()
    rust_bin = workspace / "bazel-workspace/external/+_repo_rules2+prebuilt_rust/1.91.1.p4/bin"
    env["PATH"] = str(clang_dir) + ":" + str(rust_bin) + ":" + env.get("PATH", "")
    env["KBUILD_GENDWARFKSYMS_STABLE"] = "1"
    env["LIBCLANG_PATH"] = str(clang_dir.parent / "lib")
    command = ["make", "-C", str(workspace / "common"), f"O={prepared}",
               f"M={module}", "ARCH=arm64", "LLVM=1", f"-j{args.jobs}",
               "CONFIG_ANDROID_WONDER=m", "KCFLAGS=-D__ANDROID_COMMON_KERNEL__",
               f"EXTRA_CFLAGS=-I{module / 'include'}", "modules"]
    report["command"] = command
    report["status"] = "BUILDING"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    with (output / "build.log").open("w") as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    report["returncode"] = result.returncode
    report["status"] = "PASS" if result.returncode == 0 else "FAIL"
    report["changed_after_snapshot"] = sorted(
        relative for relative, expected in report["source_files"].items()
        if digest(source / relative) != expected)
    if report["changed_after_snapshot"]:
        report["status"] = "FAIL"
        report["error"] = "Sources changed during compilation; rerun to validate current sources"
    artifact = module / "wonder.ko"
    if result.returncode == 0 and artifact.is_file():
        report["module"] = str(artifact)
        report["module_sha256"] = digest(artifact)
        report["vermagic"] = subprocess.check_output(["modinfo", "-F", "vermagic",
                                                     str(artifact)], text=True).strip()
        report["depends"] = subprocess.check_output(["modinfo", "-F", "depends",
                                                    str(artifact)], text=True).strip()
        if not report["vermagic"].startswith(release + " "):
            report["status"] = "FAIL"
            report["error"] = "Compiled module has an unexpected kernel release"
        else:
            sys.path.insert(0, str(REPO / "port"))
            from verify_modules import verify
            try:
                report["module_verification"] = verify([artifact],
                                                       [prepared / "Module.symvers"], release)
            except (ValueError, RuntimeError) as error:
                report["status"] = "FAIL"
                report["error"] = str(error)
    elif result.returncode == 0:
        report["status"] = "FAIL"
        report["error"] = "Build returned success without producing wonder.ko"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if report["status"] != "PASS":
        print((output / "build.log").read_text()[-16000:])
        raise SystemExit(1)


if __name__ == "__main__":
    main()
