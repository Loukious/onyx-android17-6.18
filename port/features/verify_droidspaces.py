#!/usr/bin/env python3
"""Check a built Droidspaces configuration and optional complete KMI comparison."""

import argparse
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent


def read_config(path):
    selected = {}
    for line in path.read_text().splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            selected[key] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            selected[line[2:-11]] = "n"
    return selected


def read_symvers(path):
    symbols = {}
    for line in path.read_text().splitlines():
        columns = line.split()
        if len(columns) < 4:
            raise ValueError(f"Invalid symbol version line in {path}")
        crc, name = columns[:2]
        if name in symbols:
            raise ValueError(f"Duplicate symbol {name} in {path}")
        symbols[name] = crc.lower()
    if not symbols:
        raise ValueError(f"No symbol versions in {path}")
    return symbols


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--symvers", type=Path)
    parser.add_argument("--baseline-symvers", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.baseline_symvers and not args.symvers:
        parser.error("--baseline-symvers requires --symvers")
    expected = read_config(HERE / "droidspaces.fragment")
    # These preserve the reserve replacement's versioning/layout contract.
    expected.update({"CONFIG_ANDROID_KABI_RESERVE": "y", "CONFIG_GENDWARFKSYMS": "y"})
    actual = read_config(args.config)
    missing = {key: {"expected": value, "actual": actual.get(key, "n")}
               for key, value in expected.items() if actual.get(key, "n") != value}
    report = {"configuration": str(args.config), "missing_requirements": missing,
              "complete_kmi_checked": False}
    failed = bool(missing)
    if args.symvers:
        current = read_symvers(args.symvers)
        absent = [name for name in ("init_ipc_ns", "put_ipc_ns") if name not in current]
        report["missing_binder_exports"] = absent
        failed |= bool(absent)
        if args.baseline_symvers:
            old = read_symvers(args.baseline_symvers)
            changed = {name: {"baseline": crc, "current": current.get(name)}
                       for name, crc in old.items() if current.get(name) != crc}
            report.update({"complete_kmi_checked": True,
                           "baseline_export_count": len(old),
                           "changed_or_missing_exports": changed})
            failed |= bool(changed)
    report["status"] = "FAIL" if failed else "PASS"
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    print(text, end="")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
