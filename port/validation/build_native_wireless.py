#!/usr/bin/env python3
"""Rebuild real cfg80211/mac80211 providers against an existing 6.18.63 GKI.

External Kbuild retains their exports, including the Wonder exports added to
the source catalog whitelist. No symbol CRCs are synthesized, and baseline
provider rows are omitted only because those providers are rebuilt here.
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
                        default=Path("/tmp/onyx-wonder-native-build-20261116"))
    parser.add_argument("--jobs", type=int, default=6)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    output = args.output.resolve()
    subprocess.run([sys.executable, str(Path(build_wonder.__file__)),
                    "--workspace", str(workspace), "--output", str(output),
                    "--prepare-only"], check=True)
    prepared = output / "kernel"
    base = prepared / "Module.symvers"
    original = base.read_text().splitlines()
    base.write_text("\n".join(line for line in original
                              if line.split()[2] not in
                              ("net/wireless/cfg80211", "net/mac80211/mac80211")) + "\n")
    shutil.copyfile(base, output / "gki_without_wireless.symvers")
    kernel = workspace / "bazel-bin/common/kernel_aarch64"
    clang = workspace / "prebuilts/clang/host/linux-x86/clang-r596125/bin"
    tools = workspace / "prebuilts/kernel-build-tools/linux_musl-x86/bin"
    rust = workspace / "bazel-workspace/external/+_repo_rules2+prebuilt_rust/1.91.1.p4/bin"
    env = os.environ.copy()
    env["PATH"] = ":".join(map(str, (clang, tools, rust))) + ":" + env.get("PATH", "")
    env["LIBCLANG_PATH"] = str(clang.parent / "lib")
    env["KBUILD_GENDWARFKSYMS_STABLE"] = "1"
    report = {"status": "BUILDING", "kernel_release": build_wonder.EXPECTED_RELEASE,
              "workspace": str(workspace), "output": str(output),
              "baseline_kernel_symvers_sha256": build_wonder.digest(kernel / "Module.symvers"),
              "scope": "Host native-provider compilation; radio behavior is unverified",
              "provider_exports": "External Kbuild retains all actual source exports",
              "providers": []}
    (output / "native-report.json").write_text(json.dumps(report, indent=2) + "\n")
    previous_symvers = []
    for name, directory in (("cfg80211", "wireless"), ("mac80211", "mac80211")):
        source = build_wonder.REPO / "common/net" / directory
        destination = output / "net" / directory
        shutil.copytree(source, destination, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("*.o", "*.ko", "*.mod*", ".*.cmd",
                                                     "Module.symvers", "modules.order"))
        command = ["make", "-C", str(workspace / "common"), f"O={prepared}",
                   f"M={destination}", "ARCH=arm64", "LLVM=1", f"-j{args.jobs}",
                   "KCFLAGS=-D__ANDROID_COMMON_KERNEL__", "modules"]
        if previous_symvers:
            command.append("KBUILD_EXTRA_SYMBOLS=" + " ".join(map(str, previous_symvers)))
        entry = {"name": name, "command": command,
                 "source_files": {str(path.relative_to(source)): build_wonder.digest(path)
                                  for path in sorted(source.rglob("*")) if path.is_file()}}
        with (output / (name + ".log")).open("w") as log:
            result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        entry["returncode"] = result.returncode
        report["providers"].append(entry)
        if result.returncode:
            report["status"] = "FAIL"
            (output / "native-report.json").write_text(json.dumps(report, indent=2) + "\n")
            print((output / (name + ".log")).read_text()[-16000:])
            raise SystemExit(result.returncode)
        artifact = destination / (name + ".ko")
        entry["module"] = str(artifact)
        entry["sha256"] = build_wonder.digest(artifact)
        entry["vermagic"] = subprocess.check_output(
            ["modinfo", "-F", "vermagic", str(artifact)], text=True).strip()
        entry["symvers"] = str(destination / "Module.symvers")
        entry["symvers_sha256"] = build_wonder.digest(destination / "Module.symvers")
        previous_symvers.append(destination / "Module.symvers")
    # Check every imported CRC against the unchanged GKI or a real freshly
    # rebuilt provider, then prove the required Wonder symbols were exported.
    sys.path.insert(0, str(build_wonder.REPO / "port"))
    from verify_modules import verify
    report["module_verification"] = verify(
        [Path(entry["module"]) for entry in report["providers"]],
        [base, *previous_symvers], build_wonder.EXPECTED_RELEASE)
    symbols = {line.split()[1] for path in previous_symvers
               for line in path.read_text().splitlines() if line}
    original_exports = {row[1]: row[0] for line in original
                        if (row := line.split()) and row[2] in
                        ("net/wireless/cfg80211", "net/mac80211/mac80211")}
    rebuilt_exports = {row[1]: row[0] for path in previous_symvers
                       for line in path.read_text().splitlines() if (row := line.split())}
    missing = sorted(set(original_exports) - set(rebuilt_exports))
    changed = sorted(name for name, crc in original_exports.items()
                     if name in rebuilt_exports and rebuilt_exports[name] != crc)
    report["existing_exports_preserved"] = {"count": len(original_exports),
                                            "missing": missing, "changed_crcs": changed}
    if missing or changed:
        raise RuntimeError("Rebuilt native providers changed existing exports")
    required = {"get_wiphy_regdom", "ieee80211_txq_schedule_start", "ieee80211_next_txq",
                "__ieee80211_schedule_txq", "ieee80211_tx_dequeue", "ieee80211_vif_to_wdev",
                "ieee80211_txq_get_depth"}
    report["wonder_exports"] = sorted(required & symbols)
    if required - symbols:
        raise RuntimeError("Missing real Wonder exports: " + ", ".join(sorted(required-symbols)))
    report["status"] = "PASS"
    (output / "native-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in
                      ("status", "kernel_release", "output", "wonder_exports")}, indent=2))


if __name__ == "__main__":
    main()
