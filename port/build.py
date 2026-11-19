#!/usr/bin/env python3
"""Build the pinned 6.18 GKI and initial Onyx modules; archive and verify outputs."""

import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tarfile

from catalog import check_generated, load_catalog, native_configs, native_modules, vendor_modules
from verify_native_abi import verify_native_exports, verify_native_imports
from verify_modules import verify, verify_vendor_core_imports

HERE = Path(__file__).resolve().parent


def output_category(path, execution_root):
    """Classify the Bazel target path, ignoring the workspace's directory names."""
    relative = path.relative_to(execution_root)
    return "platform" if "onyx" in relative.parts else "gki"


def verify_native_modules(kernel_dir, symvers, release, vendor_outputs):
    """Verify native Kbuild outputs without adding another shipped source copy."""
    components = load_catalog()
    wanted = {entry["output"] for entry in native_modules(components)}
    selected = {}
    members = {}
    prefix = "lib/modules/" + release + "/kernel/"
    with tempfile.TemporaryDirectory(prefix="onyx-native-modules-") as temporary:
        directory = Path(temporary)
        with tarfile.open(kernel_dir / "modules_staging_dir.tar.gz", "r:gz") as archive:
            for member in archive:
                if not member.name.endswith(".ko"):
                    continue
                name = member.name.removeprefix("./")
                path = Path(name)
                if (not member.isfile() or not name.startswith(prefix)
                        or path.is_absolute() or ".." in path.parts):
                    raise ValueError("Unsafe native module archive member")
                relative = name.removeprefix(prefix)
                if path.name in members or relative in selected:
                    raise ValueError("Duplicate native module output")
                target = directory / path.name
                target.write_bytes(archive.extractfile(member).read())
                selected[relative] = target
                members[path.name] = name
        if not wanted <= set(selected):
            raise ValueError("Native component outputs are missing: " + ", ".join(sorted(wanted-set(selected))))
        verification = verify(list(selected.values()), symvers, release)
        native_abi = [verify_native_exports(selected[output], output, symvers, components)
                      for output in sorted(wanted)]
        native_imports = verify_native_imports(vendor_outputs, selected, symvers, components)
        for entry in verification:
            entry["archive_member"] = members[entry["module"]]
    return verification, native_abi, native_imports


def verify_standalone_provider(verifier, harness, receipt, staged, artifacts):
    """Run a source-based harness without overwriting checked-in receipts."""
    with tempfile.TemporaryDirectory(prefix="onyx-provider-host-") as temporary:
        root = Path(temporary)
        runner = root / "port" / (verifier + ".py")
        runner.parent.mkdir()
        (runner.parent / "tests").mkdir()
        (root / "modules").symlink_to(staged.resolve(), target_is_directory=True)
        shutil.copyfile(HERE / runner.name, runner)
        shutil.copyfile(HERE / "tests" / harness, runner.parent / "tests" / harness)
        result = subprocess.run([sys.executable, str(runner)], capture_output=True,
                                text=True, check=False)
        (artifacts / receipt.replace(".json", ".log")).write_text(
            result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"{verifier} failed; see {receipt.replace('.json', '.log')}")
        report = json.loads((runner.parent / receipt).read_text())
        if report.get("status") != "PASS":
            raise ValueError(f"{verifier} did not produce a passing host receipt")
    (artifacts / receipt).write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--jobs", type=int, default=12)
    parser.add_argument("--memory-mb", type=int, default=20000)
    parser.add_argument("--cache-dir", type=Path,
                        help="Reuse Kleaf's supported incremental OUT_DIR cache")
    parser.add_argument("--qdss-diagnostic", action="store_true",
                        help="temporarily apply reviewed opt-in AMBA/QDSS logging")
    parser.add_argument("--variant", choices=("balanced", "performance"), default="balanced")
    parser.add_argument("--output-root", type=Path, help="Place Bazel outputs on a separate build drive")
    parser.add_argument("--artifact-root", type=Path, help="Place verified build artifacts on a separate drive")
    parser.add_argument("--bazel-batch", action="store_true", help="Use a fresh Bazel process with the compilation cache")
    args = parser.parse_args()
    if args.jobs < 1 or args.memory_mb < 1024:
        parser.error("jobs must be positive and memory-mb at least 1024")
    workspace = args.workspace.resolve()
    check_generated()
    for script in ["prepare.py", "stage.py", "integrate_kernelsu.py"]:
        command = [sys.executable, str(HERE / script), str(workspace)]
        if script == "prepare.py":
            command.append("--verify-only")
        subprocess.run(command, check=True)

    from features import stage as stage_features, applied as feature_fixes, package_addon
    variant = stage_features(workspace, args.variant)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    artifacts = (args.artifact_root.resolve() if args.artifact_root else workspace / "artifacts") / stamp
    artifacts.mkdir(parents=True)
    from verify_mi_thermal import verify as verify_mi_thermal
    thermal_validation = verify_mi_thermal(
        workspace / "onyx/drivers/thermal/xiaomi/mi_thermal_interface.c")
    (artifacts / "mi-thermal-host-validation.json").write_text(
        json.dumps(thermal_validation, indent=2) + "\n")
    charger_thermal_report = artifacts / "charger-thermal-host-validation.json"
    subprocess.run([sys.executable, str(HERE / "verify_charger_thermal.py"),
                    str(workspace), "--output", str(charger_thermal_report)], check=True)
    charger_thermal_validation = json.loads(charger_thermal_report.read_text())
    from verify_device_services import verify as verify_device_services
    services_validation = verify_device_services(workspace / "onyx")
    (artifacts / "device-services-host-validation.json").write_text(
        json.dumps(services_validation, indent=2) + "\n")
    from verify_platform_providers import verify as verify_platform_providers
    platform_validation = verify_platform_providers(workspace / "onyx")
    (artifacts / "platform-providers-host-validation.json").write_text(
        json.dumps(platform_validation, indent=2) + "\n")
    from verify_vbat_ovp import verify as verify_vbat_ovp
    vbat_validation = verify_vbat_ovp(workspace / "onyx")
    (artifacts / "vbat-ovp-host-validation.json").write_text(
        json.dumps(vbat_validation, indent=2) + "\n")
    from verify_qcom_sysfs import verify as verify_qcom_sysfs
    qcom_sysfs_validation = verify_qcom_sysfs(workspace / "onyx")
    (artifacts / "qcom-sysfs-host-validation.json").write_text(
        json.dumps(qcom_sysfs_validation, indent=2) + "\n")
    from verify_coresight_cti import verify as verify_coresight_cti
    cti_validation = verify_coresight_cti(workspace / "onyx")
    (artifacts / "coresight-cti-host-validation.json").write_text(
        json.dumps(cti_validation, indent=2) + "\n")
    from verify_memlat import verify as verify_memlat
    memlat_validation = verify_memlat(workspace / "onyx")
    (artifacts / "memlat-host-validation.json").write_text(
        json.dumps(memlat_validation, indent=2) + "\n")
    from importlib import import_module
    provider_verifiers = {
        "boot_diagnostics": "verify_boot_diagnostics",
        "business_misc": "verify_business_misc",
        "ibat_ocp": "verify_ibat_ocp",
        "scmi_stats": "verify_scmi_stats",
        "coresight_qmi": "verify_coresight_qmi",
        "coresight_tgu": "verify_coresight_tgu",
        "cpucp_log": "verify_cpucp_log",
        "scmi_controls": "verify_scmi_controls",
        "cpucp_fast": "verify_cpucp_fast",
        "coresight_sources": "verify_coresight_sources",
        "glink_pkt": "verify_glink_pkt",
        "wlan_wiphy_lock": "verify_wlan_wiphy_lock",
        "wlan_injection": "verify_wlan_injection",
        "cpuss_v4": "verify_cpuss_v4",
        "cpuss_native": "verify_cpuss_native",
    }
    provider_validations = {}
    for name, verifier in provider_verifiers.items():
        result = import_module(verifier).verify(workspace / "onyx")
        provider_validations[name + "_host_validation"] = result
        (artifacts / (name.replace("_", "-") + "-host-validation.json")).write_text(
            json.dumps(result, indent=2) + "\n")
    standalone_provider_verifiers = {
        "edac": ("verify_edac", "edac_harness.c", "edac-host-validation.json"),
        "cpufreq_debug": ("verify_cpufreq_debug", "cpufreq_debug_harness.c", "cpufreq-debug-host-validation.json"),
        "sysmon_stats": ("verify_sysmon_stats", "sysmon_stats_harness.c", "sysmon-stats-host-validation.json"),
        "sys_pm_vx": ("verify_sys_pm_vx", "sys_pm_vx_harness.c", "sys-pm-vx-host-validation.json"),
        "i2c_pmic": ("verify_i2c_pmic", "i2c_pmic_harness.c", "i2c-pmic-host-validation.json"),
        "regmap_debugfs": ("verify_regmap_debugfs", "regmap_debugfs_harness.c", "regmap-debugfs-host-validation.json"),
        "pmic_glink_address": ("verify_pmic_glink_address", "pmic_glink_address_harness.c", "pmic-glink-address-host-validation.json"),
        "battery_debug": ("verify_battery_debug", "battery_debug_harness.c", "battery-debug-host-validation.json"),
        "hung_task_enh": ("verify_hung_task_enh", "hung_task_enh_harness.c", "hung-task-enh-host-validation.json"),
    }
    for name, inputs in standalone_provider_verifiers.items():
        provider_validations[name + "_host_validation"] = verify_standalone_provider(
            *inputs, workspace / "onyx", artifacts)
    cache_flags = []
    if args.cache_dir:
        cache = args.cache_dir.resolve()
        cache.mkdir(parents=True, exist_ok=True)
        cache_flags = ["--config=local", f"--cache_dir={cache}"]
    bazel = ["tools/bazel"]
    if args.bazel_batch:
        bazel.append("--batch")
    if args.output_root:
        bazel.append("--output_root=" + str(args.output_root.resolve()))
    command = [*bazel, "build", *cache_flags, "--keep_going", f"--jobs={args.jobs}",
               f"--local_resources=memory={args.memory_mb}",
               "--//build/kernel/kleaf:user_kmi_symbol_lists=//onyx_features:kmi_symbol_lists",
               "//common:kernel_aarch64", "//onyx:platform_modules", "//onyx_features:susfs"]
    print(f"Building; log: {artifacts / 'build.log'}", flush=True)
    from qdss_diagnostic import applied
    from common_fixes import applied as common_fixes
    diagnostic = (applied(workspace / 'common', artifacts / 'common-diagnostic')
                  if args.qdss_diagnostic else nullcontext())
    with (artifacts / "build.log").open("w") as log:
        with diagnostic, common_fixes(workspace / 'common', artifacts / 'common-fixes'), feature_fixes(workspace / 'common', artifacts / 'feature-fixes'):
            from verify_cti_assoc import verify as verify_cti_assoc
            cti_assoc_validation = verify_cti_assoc(workspace / "common")
            (artifacts / "cti-assoc-host-validation.json").write_text(
                json.dumps(cti_assoc_validation, indent=2) + "\n")
            subprocess.run(command, cwd=workspace, stdout=log,
                           stderr=subprocess.STDOUT, check=True)
            # Resolve files while the same BUILD fragments are active. Restoring
            # them first would make cquery select a different kernel transition.
            execution_root = Path(subprocess.check_output(
                [*bazel, "info", "execution_root"], cwd=workspace, text=True).strip())
            query = subprocess.check_output([
                *bazel, "cquery", *cache_flags, "--output=files",
                "--//build/kernel/kleaf:user_kmi_symbol_lists=//onyx_features:kmi_symbol_lists",
                "//common:kernel_aarch64 + //onyx:platform_modules + //onyx_features:susfs"
            ], cwd=workspace, text=True)
    (artifacts / "bazel-outputs.txt").write_text(query)
    outputs = [execution_root / line for line in query.splitlines()]
    kernel_dir = next(p.parent for p in outputs if p.name == "Image")
    release = (kernel_dir / "include/config/kernel.release").read_text().strip()
    config = (kernel_dir / "kernel_aarch64_dot_config").read_text()
    if "\nCONFIG_KSU=y\n" not in config:
        raise ValueError("KernelSU Next must be built into the GKI")
    for option in ["KSU_DEBUG", "KSU_DISABLE_MANAGER", "KSU_DISABLE_POLICY"]:
        if f"\nCONFIG_{option}=y\n" in config:
            raise ValueError(f"unexpected KernelSU Next option: {option}")
    modules = [p for p in outputs if p.suffix == ".ko"
               and output_category(p, execution_root) == "platform"]
    catalog = vendor_modules()
    if {p.name for p in modules} != {entry["output"] for entry in catalog}:
        raise ValueError("unexpected platform module set")
    symvers = [p for p in outputs if p.name.endswith("_Module.symvers")]
    verification = verify(modules, symvers, release)
    core_import_admission = verify_vendor_core_imports(modules, kernel_dir / 'vmlinux')
    selections = dict(line.split("=", 1) for line in config.splitlines() if line.startswith("CONFIG_"))
    for option, value in native_configs().items():
        if selections.get("CONFIG_" + option, "n") != value:
            raise ValueError("Native wireless Kconfig selection differs: " + option)
    native_verification, native_abi_validation, native_import_admission = verify_native_modules(
        kernel_dir, symvers, release, modules)

    addon = next(p for p in outputs if p.name == 'susfs_guard_lkm.ko')
    addon_verification = package_addon(addon, kernel_dir, artifacts, workspace, args.variant)

    for path in outputs:
        if 'onyx_features' in path.relative_to(execution_root).parts:
            continue
        category = output_category(path, execution_root)
        target = artifacts / category / path.name
        if path.is_file():
            target.parent.mkdir(exist_ok=True)
            shutil.copyfile(path, target)
    for name in ["modules_staging_dir.tar.gz", "out-dir-kernel-headers.tar.gz"]:
        shutil.copyfile(kernel_dir / name, artifacts / "gki" / name)
    for entry in catalog:
        target = entry["target"]
        config = kernel_dir.parent.parent / "onyx" / (target + "_config") / "out_dir/.config"
        shutil.copyfile(config, artifacts / "platform" / (target + ".config"))
    (artifacts / "gki/kernel.release").write_text(release + "\n")
    shutil.copytree(HERE / "firmware", artifacts / "firmware")
    from verify_nethunter import verify as verify_nethunter
    nethunter_validation = verify_nethunter(artifacts, HERE)
    (artifacts / "nethunter-host-validation.json").write_text(
        json.dumps(nethunter_validation, indent=2) + "\n")
    subprocess.run([sys.executable, str(HERE / "build_devicetrees.py"), str(workspace),
                    "--output", str(artifacts / "devicetrees")], check=True)
    dt_report = json.loads((artifacts / "devicetrees/report.json").read_text())
    inputs = artifacts / "inputs"
    inputs.mkdir()
    for name in ["sources.json", "imports.json", "onyx-port.xml", "dependency-lock.xml",
                 "components.json", "catalog.py", "generate_imports.py", "native_modules.bzl", "native_wireless.fragment", "native-kmi-symbols", "verify_native_abi.py",
                 "kernelsu-lock.json", "module-loading.json", "module_loading.py",
                 "module-source-hashes.json", "common-source-hashes.json",
                 "BUILD.bazel", "Kconfig", "scm_defconfig", "platform_defconfig", "relay.fragment", "modules.json",
                 "build.py", "prepare.py", "stage.py", "integrate_kernelsu.py", "verify_modules.py", "verify_mi_thermal.py", "verify_charger_thermal.py", "verify_device_services.py", "verify_platform_providers.py", "boot-parameters.txt",
                 "qdss_diagnostic.py", "common_fixes.py", "verify_vbat_ovp.py", "verify_cti_assoc.py", "verify_qcom_sysfs.py", "verify_coresight_cti.py", "verify_memlat.py",
                 "build_devicetrees.py", "devicetrees.json", "kmi-symbols",
                 "nethunter-native-modules.json", "verify_nethunter.py"]:
        shutil.copyfile(HERE / name, inputs / name)
    shutil.copytree(HERE / "firmware", inputs / "firmware")
    if (HERE / "recovery").is_dir():
        shutil.copytree(HERE / "recovery", inputs / "recovery",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copytree(HERE / "patches", inputs / "patches")
    shutil.copytree(HERE / "common-patches", inputs / "common-patches")
    shutil.copytree(HERE / "features", inputs / "features",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copyfile(HERE / "features.py", inputs / "features.py")
    shutil.copytree(HERE / "kernelsu", inputs / "kernelsu")
    shutil.copyfile(HERE / "tests/mi_thermal_harness.c", inputs / "mi_thermal_harness.c")
    shutil.copytree(HERE / "tests", inputs / "tests",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for verifier in provider_verifiers.values():
        shutil.copyfile(HERE / (verifier + ".py"), inputs / (verifier + ".py"))
    for verifier, _, _ in standalone_provider_verifiers.values():
        shutil.copyfile(HERE / (verifier + ".py"), inputs / (verifier + ".py"))
    ksu_inputs = inputs / "kernelsu-next"
    ksu_inputs.mkdir()
    for name in ["source.json", "source.tar"]:
        shutil.copyfile(workspace / ".kernelsu-next" / name, ksu_inputs / name)
    shutil.copytree(HERE.parent / "validation/platform_providers", inputs / "platform-providers-tests",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "LOCAL*"))
    if (HERE / "validation").is_dir():
        shutil.copytree(HERE / "validation", inputs / "validation",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copyfile(workspace / "onyx/.staged-files.json", inputs / "staged-files.json")
    hashes = {}
    for path in sorted(artifacts.rglob("*")):
        if path.is_file():
            with path.open("rb") as stream:
                hashes[path.relative_to(artifacts).as_posix()] = hashlib.file_digest(
                    stream, "sha256").hexdigest()
    report = {
        "variant": variant,
        "platform_addon_verification": addon_verification,
        "command": command,
        "automation_revision": os.environ.get("KONOHA_CI_REVISION"),
        "qdss_diagnostic": args.qdss_diagnostic,
        "kernel_release": release,
        "kernelsu_next": {
            **json.loads((workspace / ".kernelsu-next/source.json").read_text()),
            "integration": "built-in CONFIG_KSU=y",
            "hardware_validated": False,
        },
        "module_verification": verification,
        "core_import_admission_validation": core_import_admission,
        "native_module_verification": native_verification,
        "native_abi_validation": native_abi_validation,
        "native_import_admission_validation": native_import_admission,
        "nethunter_host_validation": nethunter_validation,
        "mi_thermal_host_validation": thermal_validation,
        "charger_thermal_host_validation": charger_thermal_validation,
        "device_services_host_validation": services_validation,
        "platform_providers_host_validation": platform_validation,
        "vbat_ovp_host_validation": vbat_validation,
        "cti_assoc_host_validation": cti_assoc_validation,
        "qcom_sysfs_host_validation": qcom_sysfs_validation,
        "coresight_cti_host_validation": cti_validation,
        "memlat_host_validation": memlat_validation,
        **provider_validations,
        "devicetree_verification": {
            "overlay_engines_agree": dt_report["overlay_engines_agree"],
            "bootloader_ids_preserved": dt_report["bootloader_ids_preserved"],
            "dtbo_table_verified": dt_report["dtbo_table_verified"],
            "dtc_warnings": dt_report["dtc_warnings"],
            "report": "devicetrees/report.json",
        },
        "sha256": hashes,
        "limits": [
            "Build and imported-symbol CRC checks only; no device boot or hardware validation.",
            "Build archive only; assemble and verify matched boot and DLKM images before flashing.",
            "Gunyah secure-VM loading, proxy scheduling, memory assignment, and QRTR host transport are compiled together but have not been exercised with device firmware. Guest-power drivers are disabled, matching the Onyx HLOS baseline.",
            "The default Kleaf build uses the maybe-dirty suffix without stamping; input revisions are recorded separately.",
        ],
    }
    from features import verify_artifact as verify_features
    report['feature_validation'] = verify_features(artifacts, report)
    (artifacts / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Build and module CRC checks passed: {artifacts}")


if __name__ == "__main__":
    main()
