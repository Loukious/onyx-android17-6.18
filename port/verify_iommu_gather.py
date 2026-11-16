#!/usr/bin/env python3
"""Run a sanitized host regression against real IOMMU source functions."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
DRIVER = Path("modules/drivers/iommu/arm/arm-smmu/arm-smmu.c")
HEADER = Path("common/include/linux/iommu.h")
CORE = Path("common/drivers/iommu/iommu.c")
HARNESS = Path("port/tests/iommu_gather_harness.c")
NEGATIVE_REVISION = "945bc4499192bd44aa3c44e43529428a843428ba"


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


def mask_literals(text):
    """Preserve offsets while ignoring braces in comments and C literals."""
    pattern = r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(pattern, lambda match: re.sub(r"[^\n]", " ", match[0]),
                  text, flags=re.DOTALL)


def balanced_end(masked, brace):
    depth = 0
    for offset in range(brace, len(masked)):
        if masked[offset] == "{":
            depth += 1
        elif masked[offset] == "}":
            depth -= 1
            if depth == 0:
                return offset + 1
    raise ValueError("Unterminated C definition")


def function(text, name):
    masked = mask_literals(text)
    # Select the first real definition, excluding declarations and call sites.
    match = re.search(rf"\b{re.escape(name)}\s*\([^;{{}}]*\)\s*\{{", masked)
    if not match:
        raise ValueError(f"Function definition not found: {name}")
    start = text.rfind("\n", 0, match.start()) + 1
    end = balanced_end(masked, masked.index("{", match.start()))
    return text[start:end] + "\n"


def gather_type(text):
    masked = mask_literals(text)
    match = re.search(r"\bstruct iommu_iotlb_gather\s*\{", masked)
    if not match:
        raise ValueError("IOMMU gather type not found")
    end = balanced_end(masked, masked.index("{", match.start()))
    if text[end:end + 1] != ";":
        raise ValueError("IOMMU gather type has an unexpected terminator")
    return text[match.start():end + 1] + "\n"


def run_harness(directory, label, code, compiler):
    source = directory / f"{label}.c"
    binary = directory / label
    source.write_text(code)
    command = [*shlex.split(compiler), "-std=gnu11", "-O1", "-g", "-Wall",
               "-Wextra", "-Werror", "-fsanitize=address,undefined",
               "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
               str(source), "-o", str(binary)]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
    try:
        cases = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{label} did not emit a test result:\n{result.stderr}") from error
    return {
        "returncode": result.returncode,
        "result": cases,
        "stderr": result.stderr,
        "compiled_c_sha256": sha256(code),
    }


def verify(compiler):
    driver = (ROOT / DRIVER).read_text()
    header = (ROOT / HEADER).read_text()
    core = (ROOT / CORE).read_text()
    template = (ROOT / HARNESS).read_text()
    original = subprocess.run(
        ["git", "show", f"{NEGATIVE_REVISION}:{DRIVER.as_posix()}"],
        cwd=ROOT, check=True, capture_output=True, text=True).stdout
    fixed_unmap = function(driver, "arm_smmu_unmap_pages")
    old_unmap = function(original, "arm_smmu_unmap_pages")
    common_functions = {
        "iommu_iotlb_gather_init": function(header, "iommu_iotlb_gather_init"),
        "iommu_iotlb_gather_add_range": function(header, "iommu_iotlb_gather_add_range"),
        "iommu_iotlb_sync": function(header, "iommu_iotlb_sync"),
        "__iommu_unmap": function(core, "__iommu_unmap"),
        "iommu_unmap": function(core, "iommu_unmap"),
    }
    collector = gather_type(header)

    def assemble(unmap):
        functions = "\n".join(list(common_functions.values())[:3] + [unmap] +
                              list(common_functions.values())[3:])
        return template.replace("/* ACTUAL_GATHER_TYPE */", collector).replace(
            "/* ACTUAL_FUNCTIONS */", functions)

    with tempfile.TemporaryDirectory(prefix="onyx-iommu-gather-") as temp:
        directory = Path(temp)
        fixed = run_harness(directory, "fixed", assemble(fixed_unmap), compiler)
        negative = run_harness(directory, "negative-945bc", assemble(old_unmap), compiler)

    if fixed["returncode"] or fixed["result"]["failed"]:
        raise RuntimeError(f"Fixed source failed:\n{json.dumps(fixed, indent=2)}")
    failures = {case["name"] for case in negative["result"]["cases"]
                if not case["passed"]}
    expected_failures = {"qcom_success", "qcom_partial", "qcom_batch",
                         "qcom_queued", "qcom_top_iova"}
    if negative["returncode"] != 1 or failures != expected_failures:
        raise RuntimeError(f"Negative control did not isolate the flush regression:\n"
                           f"{json.dumps(negative, indent=2)}")
    witness = "DMA memory reuse occurred without completed TLB sync"
    if negative["stderr"].count(witness) != len(expected_failures):
        raise RuntimeError("Negative control failed without the expected DMA-reuse witness")
    compiler_version = subprocess.run([*shlex.split(compiler), "--version"], check=True,
                                      capture_output=True, text=True).stdout.splitlines()[0]
    return {
        "status": "PASS",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "compiler": compiler_version,
        "sanitizers": ["ASan", "UBSan"],
        "source_revision": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                           check=True, capture_output=True,
                                           text=True).stdout.strip(),
        "source_files_sha256": {str(path): sha256(content) for path, content in
                                [(DRIVER, driver), (HEADER, header), (CORE, core),
                                 (HARNESS, template)]},
        "actual_functions_sha256": {
            **{name: sha256(code) for name, code in common_functions.items()},
            "arm_smmu_unmap_pages_fixed": sha256(fixed_unmap),
            "arm_smmu_unmap_pages_negative": sha256(old_unmap),
        },
        "fixed": fixed,
        "negative_control": {"revision": NEGATIVE_REVISION, **negative,
                             "expected_failures": sorted(expected_failures)},
        "limits": [
            "Real current collector type/functions, vendor unmap wrapper, and core unmap loop run on the host.",
            "Backend PTE removal, private invalidation queue, full-context flush and stale device DMA are modeled.",
            "The mock domain advertises only 4K pages; page-size selection is a host shim.",
            "This establishes the software synchronization contract, not hardware crash causality.",
            "No kernel/device build, flash, common source edit or source-hash metadata write is performed.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="cc", help="Host C compiler command")
    parser.add_argument("--receipt", type=Path, help="Optional JSON result path")
    args = parser.parse_args()
    report = verify(args.cc)
    rendered = json.dumps(report, indent=2) + "\n"
    if args.receipt:
        args.receipt.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
