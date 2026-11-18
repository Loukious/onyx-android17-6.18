#!/usr/bin/env python3
"""Check native exports and vendor imports against actual ELF flags and CRCs."""

import hashlib
from pathlib import Path
import struct

from catalog import load_catalog, native_modules, native_required_exports
from verify_modules import elf_sections, versioned_imports

KSYM_FLAG_GPL_ONLY = 1
KSYM_FLAG_PROTECTED = 2


def export_table(module):
    """Read ARM64 ET_REL PREL32 exports; reject unsupported or ambiguous layouts."""
    module = Path(module)
    sections = elf_sections(module)
    data = module.read_bytes()
    if struct.unpack_from("<H", data, 16)[0] != 1:
        raise ValueError(f"expected relocatable native module: {module}")
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count, strings_index = struct.unpack_from("<HHH", data, 58)
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, offset + i * size)
               for i in range(count)]
    names_header = headers[strings_index]
    section_names = data[names_header[4]:names_header[4] + names_header[5]]

    def string(payload, start):
        if not 0 <= start < len(payload):
            raise ValueError(f"native ELF string offset is out of bounds: {module}")
        end = payload.find(b"\0", start)
        if end < 0:
            raise ValueError(f"unterminated native ELF string: {module}")
        return payload[start:end].decode("ascii")

    indices = {}
    for index, header in enumerate(headers):
        name = string(section_names, header[0])
        if name in indices:
            raise ValueError(f"duplicate native ELF section {name}: {module}")
        indices[name] = index
    wanted = {"__ksymtab", "__kflagstab", "__kcrctab", "__ksymtab_strings",
              ".symtab", ".rela__ksymtab"}
    if not wanted <= set(sections):
        raise ValueError(f"missing native export sections: {module}")
    flags, crcs, table = (sections[name] for name in
                          ("__kflagstab", "__kcrctab", "__ksymtab"))
    if not flags or len(table) != len(flags) * 12 or len(crcs) != len(flags) * 4:
        raise ValueError(f"unsupported native export table layout: {module}")
    symbols_header = headers[indices[".symtab"]]
    if (symbols_header[1] != 2 or symbols_header[9] != 24
            or len(sections[".symtab"]) % 24 or symbols_header[6] >= count):
        raise ValueError(f"unsupported native ELF symbol table: {module}")
    symbols = list(struct.iter_unpack("<IBBHQQ", sections[".symtab"]))
    rela_header = headers[indices[".rela__ksymtab"]]
    relocations = sections[".rela__ksymtab"]
    if (rela_header[1] != 4 or rela_header[9] != 24
            or rela_header[6] != indices[".symtab"]
            or rela_header[7] != indices["__ksymtab"]
            or len(relocations) != len(flags) * 3 * 24):
        raise ValueError(f"unsupported native export relocations: {module}")
    resolved = {}
    for place, info, addend in struct.iter_unpack("<QQq", relocations):
        symbol_index, kind = info >> 32, info & 0xffffffff
        if (kind != 261 or symbol_index >= len(symbols) or place >= len(table)
                or place % 12 not in (0, 4, 8) or place in resolved):
            raise ValueError(f"invalid native PREL32 export relocation: {module}")
        symbol = symbols[symbol_index]
        if symbol[3] == 0 or symbol[3] >= count:
            raise ValueError(f"undefined native export relocation target: {module}")
        if place % 12 in (4, 8):
            if symbol[3] != indices["__ksymtab_strings"]:
                raise ValueError(f"native export string targets wrong section: {module}")
            resolved[place] = string(sections["__ksymtab_strings"], symbol[4] + addend)
        else:
            resolved[place] = None
    result = {}
    order = []
    for index, flag in enumerate(flags):
        name = resolved[index * 12 + 4]
        if not name or name in result or flag & ~(KSYM_FLAG_GPL_ONLY | KSYM_FLAG_PROTECTED):
            raise ValueError(f"invalid native export name or flags: {module}: {name}")
        order.append(name)
        result[name] = {"flags": flag, "crc": struct.unpack_from("<I", crcs, index * 4)[0]}
    if order != sorted(order):
        raise ValueError(f"unsorted native export table: {module}")
    return result


def verify_native_exports(module, output, symvers, catalog=None):
    """Verify one extracted native catalog output, preserving the Common owner."""
    catalog = load_catalog() if catalog is None else catalog
    if output not in {entry["output"] for entry in native_modules(catalog)}:
        raise ValueError(f"unknown native catalog output: {output}")
    required = sorted(symbol for component in catalog["components"]
                      if component["kind"] == "native_common" and component["output"] == output
                      for symbol in component.get("required_exports", []))
    if not set(required) <= set(native_required_exports(catalog)):
        raise ValueError("inconsistent native export catalog")
    if not required:
        return {"provider": output.removesuffix(".ko"), "required_exports": []}
    exports = export_table(module)
    provider = output.removesuffix(".ko")
    providers = {}
    for path in symvers:
        for line in Path(path).read_text().splitlines():
            fields = line.split()
            if not fields or fields[1:2] == [] or fields[1] not in required:
                continue
            if len(fields) < 4:
                raise ValueError(f"malformed required native symvers row: {path}")
            crc, name, owner = int(fields[0], 16), fields[1], fields[2]
            if not 0 <= crc <= 0xffffffff or name in providers:
                raise ValueError(f"invalid CRC or duplicate native provider: {name}")
            providers[name] = (crc, owner)
    checked = []
    for name in required:
        if name not in exports:
            raise ValueError(f"required native export was trimmed: {output}: {name}")
        record = exports[name]
        if record["flags"] & KSYM_FLAG_PROTECTED:
            raise ValueError(f"required native export is protected: {output}: {name}")
        if providers.get(name) != (record["crc"], provider):
            raise ValueError(f"required native export CRC or Common provider mismatch: {output}: {name}")
        checked.append({"symbol": name, "crc": f"0x{record['crc']:08x}", "flags": record["flags"]})
    return {"provider": provider, "sha256": hashlib.sha256(Path(module).read_bytes()).hexdigest(),
            "required_exports": checked}


def verify_native_imports(modules, native_outputs, symvers, catalog=None):
    """Require every vendor-to-native import to use the declared public ABI.

    A matching Module.symvers CRC does not encode MODULE_SIG_PROTECT. Inspect
    the provider's export flags as well, including imports omitted from the
    catalog's required_exports list. These vendor DDK modules must not depend
    on protected exports that only a trusted signed consumer can resolve.
    """
    catalog = load_catalog() if catalog is None else catalog
    components = {entry["output"]: entry for entry in catalog["components"]
                  if entry["kind"] == "native_common"}
    if not set(components) <= set(native_outputs):
        raise ValueError("Native import admission is missing catalog providers")
    owners = {output.removesuffix(".ko"): output for output in components}
    exports, native_hashes = {}, {}
    for output in sorted(components):
        module = Path(native_outputs[output])
        native_hashes[output] = hashlib.sha256(module.read_bytes()).hexdigest()
        sections = elf_sections(module)
        if "__ksymtab" not in sections:
            if any(name in sections for name in
                   ("__kflagstab", "__kcrctab", ".rela__ksymtab")):
                raise ValueError(f"incomplete native export table: {output}")
            continue
        for name, record in export_table(module).items():
            if name in exports:
                raise ValueError(f"duplicate actual native export: {name}")
            exports[name] = (output, record)

    providers = {}
    for path in symvers:
        for line in Path(path).read_text().splitlines():
            fields = line.split()
            if len(fields) < 3:
                continue
            crc, name, owner = int(fields[0], 16), fields[1], fields[2]
            if name not in exports and owner not in owners:
                continue
            if (not 0 <= crc <= 0xffffffff or
                    (name in providers and providers[name] != (crc, owner))):
                raise ValueError(f"conflicting native import provider: {name}")
            providers[name] = (crc, owner)

    checked, violations = [], []
    for module in modules:
        module = Path(module)
        imports = []
        for name, crc in sorted(versioned_imports(module).items()):
            symvers_record = providers.get(name)
            if name not in exports and symvers_record is None:
                continue
            if name not in exports:
                violations.append(f"{module.name}: {name}: missing actual native export")
                continue
            output, record = exports[name]
            problems = []
            if record["flags"] & KSYM_FLAG_PROTECTED:
                problems.append("protected native export")
            if name not in components[output].get("required_exports", []):
                problems.append("undeclared native vendor ABI")
            if crc != record["crc"]:
                problems.append("native export CRC mismatch")
            if symvers_record != (record["crc"], output.removesuffix(".ko")):
                problems.append("native export CRC or Common provider mismatch")
            if problems:
                violations.append(f"{module.name}: {name}: " + ", ".join(problems))
            else:
                imports.append({"symbol": name, "provider": output.removesuffix(".ko"),
                                "crc": f"0x{crc:08x}", "flags": record["flags"]})
        checked.append({"module": module.name,
                        "sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
                        "native_imports": imports})
    if violations:
        raise ValueError("Vendor native import admission failed:\n" + "\n".join(violations))
    return {"status": "PASS", "native_provider_count": len(components),
            "vendor_module_count": len(checked),
            "native_import_count": sum(len(entry["native_imports"]) for entry in checked),
            "native_provider_sha256": native_hashes, "modules": checked}
