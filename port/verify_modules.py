#!/usr/bin/env python3
"""Check the new modules' imported CRCs and vermagic against their build inputs.

This is a build-artifact check, not proof of hardware or runtime compatibility.
Reads classic and extended CRC sections directly; kmod is used for modinfo only.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import struct


def elf_sections(module):
    """Read sections from the uncompressed ELF64 little-endian ARM64 outputs."""
    data = module.read_bytes()
    if (len(data) < 64 or data[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<H", data, 18)[0] != 183):
        raise ValueError(f"expected ELF64 little-endian ARM64 module: {module}")
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count, strings_index = struct.unpack_from("<HHH", data, 58)
    if size < 64 or not count or strings_index >= count or offset + size * count > len(data):
        raise ValueError(f"invalid/unsupported section table: {module}")
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, offset + i * size)
               for i in range(count)]
    def contents(header):
        start, length = header[4:6]
        if start + length > len(data):
            raise ValueError(f"section exceeds module size: {module}")
        return data[start:start + length]
    names = contents(headers[strings_index])
    result = {}
    for header in headers:
        if header[0] >= len(names):
            raise ValueError(f"invalid section name: {module}")
        end = names.find(b"\0", header[0])
        if end < 0:
            raise ValueError(f"unterminated section name: {module}")
        name = names[header[0]:end].decode()
        if header[1] != 8:  # SHT_NOBITS has no file payload.
            result[name] = contents(header)
    return result


def versioned_imports(module):
    """Merge __versions with all __version_ext_names/__version_ext_crcs pairs."""
    sections = elf_sections(module)
    imports = {}
    def add(name, crc):
        if not name or (name in imports and imports[name] != crc):
            raise ValueError(f"empty/conflicting imported symbol: {module}: {name}")
        imports[name] = crc
    classic = sections.get("__versions", b"")
    if len(classic) % 64:
        raise ValueError(f"invalid classic version section: {module}")
    for offset in range(0, len(classic), 64):
        name = classic[offset + 8:offset + 64]
        if b"\0" not in name:
            raise ValueError(f"unterminated classic symbol: {module}")
        add(name.split(b"\0", 1)[0].decode(), struct.unpack_from("<Q", classic, offset)[0])
    names = sections.get("__version_ext_names")
    crcs = sections.get("__version_ext_crcs")
    if names is not None or crcs is not None:
        if names is None or crcs is None or len(crcs) % 4 or not names.endswith(b"\0"):
            raise ValueError(f"invalid extended version sections: {module}")
        # Linker alignment may append zero padding after the last terminator.
        unpadded = names.rstrip(b"\0")
        symbols = unpadded.split(b"\0") if unpadded else []
        if len(symbols) != len(crcs) // 4:
            raise ValueError(f"extended version count mismatch: {module}")
        for name, (crc,) in zip(symbols, struct.iter_unpack("<I", crcs)):
            add(name.decode(), crc)
    return imports


def core_export_table(vmlinux):
    """Read the linked ARM64 export flags that Module.symvers cannot encode."""
    vmlinux = Path(vmlinux)
    data = vmlinux.read_bytes()
    if (len(data) < 64 or data[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<H", data, 16)[0] not in (2, 3)
            or struct.unpack_from("<H", data, 18)[0] != 183):
        raise ValueError("expected linked ELF64 ARM64 kernel")
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count, strings_index = struct.unpack_from("<HHH", data, 58)
    if size < 64 or not count or strings_index >= count or offset + size * count > len(data):
        raise ValueError("invalid kernel ELF section table")
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, offset + index * size)
               for index in range(count)]

    def contents(header):
        start, length = header[4:6]
        if start + length > len(data):
            raise ValueError("kernel export section exceeds file bounds")
        return data[start:start + length]

    def string(payload, start):
        if not 0 <= start < len(payload):
            raise ValueError("kernel export string offset is out of bounds")
        end = payload.find(b"\0", start)
        if end < 0:
            raise ValueError("unterminated kernel export string")
        return payload[start:end].decode("ascii")

    section_names = contents(headers[strings_index])
    sections = {}
    for header in headers:
        name = string(section_names, header[0])
        if name in sections:
            raise ValueError("duplicate kernel export section name")
        if name in ("__ksymtab", "__kflagstab", "__kcrctab", "__ksymtab_strings"):
            if header[1] != 1:
                raise ValueError("kernel export section is not PROGBITS")
            sections[name] = (header[3], contents(header))
    if set(sections) != {"__ksymtab", "__kflagstab", "__kcrctab", "__ksymtab_strings"}:
        raise ValueError("kernel export flag/CRC sections are missing")
    table_base, table = sections["__ksymtab"]
    _, flags = sections["__kflagstab"]
    _, crcs = sections["__kcrctab"]
    names_base, names = sections["__ksymtab_strings"]
    if not flags or len(table) != len(flags) * 12 or len(crcs) != len(flags) * 4:
        raise ValueError("unsupported linked kernel PREL32 export layout")
    exports = {}
    order = []
    for index, flag in enumerate(flags):
        if flag & ~3:
            raise ValueError("unknown kernel export flags")
        place = table_base + index * 12 + 4
        target = place + struct.unpack_from("<i", table, index * 12 + 4)[0]
        name = string(names, target - names_base)
        if not name or name in exports:
            raise ValueError("empty or duplicate kernel export")
        exports[name] = {"flags": flag, "crc": struct.unpack_from("<I", crcs, index * 4)[0]}
        order.append(name)
    if order != sorted(order):
        raise ValueError("linked kernel export table is not sorted")
    return exports


def verify_vendor_core_imports(modules, vmlinux):
    """Unsigned vendor modules cannot consume GKI-protected core exports."""
    exports = core_export_table(vmlinux)
    violations, hashes, checked = [], {}, 0
    for module in modules:
        module = Path(module)
        if module.name in hashes:
            raise ValueError("duplicate vendor module in core import admission")
        hashes[module.name] = hashlib.sha256(module.read_bytes()).hexdigest()
        for name, crc in versioned_imports(module).items():
            record = exports.get(name)
            if record is None:
                continue  # Non-core providers pass the separate native/vendor gates.
            if record["flags"] & 2:
                violations.append(f"{module.name}: {name}: protected core export")
            elif record["crc"] != crc:
                violations.append(f"{module.name}: {name}: actual core export CRC mismatch")
            else:
                checked += 1
    if violations:
        raise ValueError("Vendor core import admission failed:\n" + "\n".join(violations))
    return {"status": "PASS", "vendor_modules_checked": len(hashes),
            "core_imports_checked": checked,
            "vmlinux_sha256": hashlib.sha256(Path(vmlinux).read_bytes()).hexdigest(),
            "vendor_module_sha256": hashes}


def verify(modules, symvers, release):
    exports = {}
    providers = {}
    for path in symvers:
        for line in path.read_text().splitlines():
            fields = line.split()
            if len(fields) < 3:
                continue
            crc, name = int(fields[0], 16), fields[1]
            if name in exports and exports[name] != crc:
                raise ValueError(f"conflicting provider CRCs for {name}")
            if name in providers and providers[name] != fields[2]:
                raise ValueError(f"duplicate symbol providers for {name}: "
                                 f"{providers[name]} and {fields[2]}")
            exports[name] = crc
            providers[name] = fields[2]

    result = []
    for module in modules:
        version = subprocess.check_output(
            ["modinfo", "-F", "vermagic", str(module)], text=True).strip()
        if not version.startswith(release + " ") or "modversions" not in version.split():
            raise ValueError(f"unexpected vermagic in {module}: {version}")
        imports = versioned_imports(module)
        checked = 0
        for name, crc in imports.items():
            if exports.get(name) != crc:
                raise ValueError(f"missing provider or CRC mismatch: {module.name}: {name}")
            checked += 1
        if not checked:
            raise ValueError(f"no versioned imports read from {module}")
        result.append({
            "module": module.name,
            "sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
            "vermagic": version,
            "imports_checked": checked,
            "depends": subprocess.check_output(
                ["modinfo", "-F", "depends", str(module)], text=True).strip(),
            "aliases": subprocess.check_output(
                ["modinfo", "-F", "alias", str(module)], text=True).splitlines(),
        })
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, action="append", required=True)
    parser.add_argument("--symvers", type=Path, action="append", required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(verify(args.module, args.symvers, args.release), indent=2) + "\n"
    if args.output:
        args.output.write_text(result)
    print(result, end="")


if __name__ == "__main__":
    main()
