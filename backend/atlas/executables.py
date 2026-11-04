"""Selected, bounded PE/ELF metadata reads. Never load or execute an artifact.

Declared virtual ranges are not runtime permissions. Mapping is conservative:
incomplete or overlapping address tables cannot establish a unique file offset.
"""

import math
import struct
from collections import Counter
from dataclasses import dataclass

LIMITS = {
    "sections": 256, "program_headers": 128, "import_descriptors": 128,
    "libraries": 128, "symbols": 512, "symbol_records": 20000,
    "dynamic_records": 4096, "name_bytes": 512, "entropy_bytes": 64 * 1024 * 1024,
    "findings": 50, "warnings": 64,
}
PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0x1C4: "ARM Thumb-2", 0xAA64: "ARM64"}
ELF_MACHINES = {3: "x86", 62: "x86-64", 40: "ARM", 183: "ARM64", 243: "RISC-V", 8: "MIPS",
                20: "PowerPC", 21: "PowerPC64", 2: "SPARC", 43: "SPARC v9"}
ELF_TYPES = {1: "Relocatable object", 2: "Executable", 3: "Shared object / PIE", 4: "Core dump"}
ELF_SECTIONS = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH",
                6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 11: "DYNSYM", 18: "SYMTAB_SHNDX"}


class _Malformed(ValueError):
    """An expected failure of a declared structure, not a parser exception."""


def _span(offset, size, length):
    return 0 <= offset <= length and 0 <= size <= length - offset


def _name(raw):
    # Keep markup literal and make non-ASCII/control bytes visible, including
    # bidi controls. A displayed name is not a path, URL, or Unicode directive.
    return "".join(chr(byte) if 32 <= byte < 127 else f"\\x{byte:02x}" for byte in raw)


@dataclass
class _Region:
    start: int
    size: int
    offset: int
    file_size: int
    name: str
    header_offset: int
    valid: bool = True


@dataclass
class _ELFSection:
    name_index: int
    kind: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int


@dataclass
class _ELFProgram:
    kind: int
    flags: int
    offset: int
    address: int
    physical_address: int
    file_size: int
    memory_size: int
    alignment: int


class _Inspection:
    def __init__(self, data, format):
        self.data = data
        self.regions = []
        self.address_table_complete = False
        self.entropies = {}
        self.report = {
            "format": format, "status": "invalid", "architecture": "Unknown", "bitness": None,
            "byte_order": None, "kind": "Unknown", "sections_declared": "0",
            "program_headers_declared": "0", "sections": [], "load_segments": [],
            "entry_point": {"address": None, "rva": None, "offset": None, "region": None, "mapping": "unavailable"},
            "imports": {"status": "unavailable", "note": "Executable headers could not be decoded.",
                        "libraries": [], "symbols": []},
            "findings": [], "warnings": [], "limits": {**LIMITS, "reached": []},
            "coverage": {"sections_read": 0, "program_headers_read": 0, "import_descriptors_read": 0,
                         "symbol_records_read": 0, "dynamic_records_read": 0, "entropy_bytes_read": 0},
        }

    def require(self, offset, size, what):
        if not _span(offset, size, len(self.data)):
            raise _Malformed(f"{what} at {hex(offset)} exceeds the available file bytes (declared size {size}).")

    def read(self, fmt, offset, what):
        self.require(offset, struct.calcsize(fmt), what)
        return struct.unpack_from(fmt, self.data, offset)

    def warn(self, message, partial=True):
        if partial and self.report["status"] == "parsed":
            self.report["status"] = "partial"
        warnings = self.report["warnings"]
        if message in warnings:
            return
        if len(warnings) < LIMITS["warnings"]:
            warnings.append(message)
        else:
            if "warnings" not in self.report["limits"]["reached"]:
                self.report["limits"]["reached"].append("warnings")
            warnings[-1] = "The 64-warning retention limit was reached; further decoding warnings were omitted."

    def limit(self, key, message):
        if key not in self.report["limits"]["reached"]:
            self.report["limits"]["reached"].append(key)
            self.warn(message)

    def finding(self, code, label, detail, offset=None):
        if len(self.report["findings"]) < LIMITS["findings"]:
            self.report["findings"].append({"code": code, "label": label, "detail": detail,
                                            "offset": hex(offset) if offset is not None else None})
        else:
            self.limit("findings", "The 50-finding retention limit was reached; further structural observations were omitted.")

    def entropy(self, offset, size):
        if not size:
            return None
        key = offset, size
        if key in self.entropies:
            return self.entropies[key]
        used = self.report["coverage"]["entropy_bytes_read"]
        if size > LIMITS["entropy_bytes"] - used:
            self.limit("entropy_bytes", "The cumulative 64 MiB section-entropy budget was reached; remaining sections have no entropy value.")
            return None
        counts = Counter(memoryview(self.data)[offset:offset + size])
        value = round(-sum((count / size) * math.log2(count / size) for count in counts.values()), 3)
        self.entropies[key] = value
        self.report["coverage"]["entropy_bytes_read"] += size
        return value

    def mapping(self, address, size=1):
        """Return state, byte offset, region name, and remaining file bytes."""
        if not self.address_table_complete:
            return "unavailable", None, None, 0
        hits = [region for region in self.regions
                if region.size and address < region.start + region.size and region.start < address + size]
        if len(hits) > 1:
            return "ambiguous", None, None, 0
        if not hits:
            return "unmapped", None, None, 0
        region = hits[0]
        delta = address - region.start
        if delta < 0 or size > region.size - delta or not region.valid:
            return "unavailable", None, region.name, 0
        if size > region.file_size - delta:
            return "zero_fill", None, region.name, 0
        return "file_backed", region.offset + delta, region.name, region.file_size - delta

    def overlaps(self, rows):
        for index, row in enumerate(rows):
            for other in rows[:index]:
                if row.size and other.size and row.start < other.start + other.size and other.start < row.start + row.size:
                    self.finding("overlapping_virtual_ranges", "Overlapping declared virtual ranges",
                                 f"{other.name} and {row.name} declare overlapping virtual bytes; address mapping may be ambiguous.", row.header_offset)
                    self.warn("Declared virtual ranges overlap; affected addresses are not mapped to arbitrary file bytes.")
                if row.file_size and other.file_size and row.offset < other.offset + other.file_size and other.offset < row.offset + row.file_size:
                    self.finding("overlapping_file_ranges", "Overlapping declared file ranges",
                                 f"{other.name} and {row.name} declare overlapping file ranges.", row.header_offset)
                    self.warn("Declared file ranges overlap; declarations are preserved but are not loader-acceptance proof.")

    def section_observations(self, section):
        if "Write" in section["flags"] and "Execute" in section["flags"]:
            self.finding("writable_executable_section", "Section declares write and execute",
                         f"{section['name']} declares both permissions; this is not proof of malicious behavior or runtime permissions.",
                         int(section["header_offset"], 16))
        if section["entropy"] is not None and section["entropy"] > 7.2:
            self.finding("high_entropy_section", "High-entropy section",
                         f"{section['name']} may contain compressed, encrypted, or packed bytes; entropy alone is not a verdict.",
                         int(section["file_offset"], 16))

    def import_warning(self, message):
        self.report["imports"]["status"] = "partial"
        self.warn(message)

    def import_limit(self, key, message):
        self.report["imports"]["status"] = "partial"
        self.limit(key, message)

    def cstring(self, offset, end, what, allow_empty=False):
        self.require(offset, 1, what)
        stop = min(end, offset + LIMITS["name_bytes"], len(self.data))
        terminator = self.data.find(b"\0", offset, stop)
        if terminator < 0:
            if stop - offset == LIMITS["name_bytes"]:
                self.limit("name_bytes", "The 512-byte terminated-name limit was reached; oversized names were rejected, not truncated.")
            raise _Malformed(f"{what} at {hex(offset)} is not terminated within its file-backed range and 512-byte name limit.")
        if terminator == offset and not allow_empty:
            raise _Malformed(f"{what} at {hex(offset)} is empty.")
        return _name(self.data[offset:terminator]), terminator - offset + 1

    def library(self, name, offset, record_offset):
        if len(self.report["imports"]["libraries"]) >= LIMITS["libraries"]:
            self.import_limit("libraries", "Only the first 128 imported-library records were retained.")
            return
        self.report["imports"]["libraries"].append({"name": name, "offset": hex(offset), "record_offset": hex(record_offset)})

    def symbol(self, name, ordinal, library, offset, name_offset, binding=None):
        if len(self.report["imports"]["symbols"]) >= LIMITS["symbols"]:
            self.import_limit("symbols", "Only the first 512 imported-symbol records were retained; table inspection has a separate 20,000-record budget.")
            return
        self.report["imports"]["symbols"].append({
            "name": name, "ordinal": str(ordinal) if ordinal is not None else None, "library": library,
            "offset": hex(offset), "name_offset": hex(name_offset) if name_offset is not None else None, "binding": binding,
        })


def _pe_name(inspection, rva, what, prefix=0):
    state, offset, _, available = inspection.mapping(rva, prefix + 1)
    if state != "file_backed":
        raise _Malformed(f"{what} RVA {hex(rva)} has {state.replace('_', ' ')} mapping; no name was inferred from unrelated bytes.")
    name, size = inspection.cstring(offset + prefix, offset + available, what)
    state, _, _, _ = inspection.mapping(rva, prefix + size)
    if state != "file_backed":
        raise _Malformed(f"{what} RVA {hex(rva)} crosses an ambiguous or unavailable file-backed range.")
    return name, offset + prefix


def _pe_thunks(inspection, rva, library, bits):
    width, fmt = (8, "<Q") if bits == 64 else (4, "<I")
    ordinal_flag = 1 << (bits - 1)
    index = 0
    while inspection.report["coverage"]["symbol_records_read"] < LIMITS["symbol_records"]:
        address = rva + index * width
        state, offset, _, _ = inspection.mapping(address, width)
        if address + width > 1 << 32 or state != "file_backed":
            inspection.import_warning(f"PE import lookup table for {library} at RVA {hex(rva)} has no terminator within its unambiguous file-backed range ({state.replace('_', ' ')}).")
            return
        value, = inspection.read(fmt, offset, "PE import lookup record")
        inspection.report["coverage"]["symbol_records_read"] += 1
        if not value:
            return
        if value & ordinal_flag:
            if value & ~(ordinal_flag | 0xFFFF):
                inspection.import_warning(f"PE ordinal lookup record at {hex(offset)} sets reserved bits; no ordinal was invented.")
            else:
                inspection.symbol(None, value & 0xFFFF, library, offset, None)
        elif value > 0xFFFFFFFF:
            inspection.import_warning(f"PE named lookup record at {hex(offset)} exceeds a 32-bit RVA; it may contain a resolved IAT address, not an import name.")
        else:
            try:
                name, name_offset = _pe_name(inspection, value, "PE imported symbol name", prefix=2)
                inspection.symbol(name, None, library, offset, name_offset)
            except _Malformed as error:
                inspection.import_warning(str(error))
        index += 1
    inspection.import_limit("symbol_records", "The cumulative 20,000 symbol/thunk-record inspection budget was reached; remaining lookup records were not decoded.")


def _pe_imports(inspection, directories, directory_count, bits):
    imports = inspection.report["imports"]
    imports.update(status="not_present", note="Only normal PE imports are decoded; ordinal names are not resolved.")
    if directory_count > 1 and len(directories) < 2:
        imports.update(status="unavailable", note="The declared normal import directory is missing from the optional header.")
    elif len(directories) > 1 and any(directories[1]):
        imports["status"] = "parsed"
        rva, size = directories[1]
        state, _, _, available = inspection.mapping(rva)
        if not rva or size < 20 or state != "file_backed":
            inspection.import_warning(f"PE normal import directory at RVA {hex(rva)} cannot be decoded (size {size}, {state.replace('_', ' ')} mapping).")
        else:
            if size > available:
                inspection.import_warning(f"PE import directory at RVA {hex(rva)} exceeds its file-backed range; only complete mapped descriptors can be read.")
            count = min(size, available) // 20
            terminated = False
            for index in range(min(count, LIMITS["import_descriptors"])):
                state, offset, _, _ = inspection.mapping(rva + index * 20, 20)
                if state != "file_backed":
                    inspection.import_warning(f"PE import descriptor at RVA {hex(rva + index * 20)} has {state.replace('_', ' ')} mapping.")
                    break
                original, timestamp, forwarder, name_rva, first = inspection.read("<IIIII", offset, "PE import descriptor")
                inspection.report["coverage"]["import_descriptors_read"] += 1
                if not any((original, timestamp, forwarder, name_rva, first)):
                    terminated = True
                    break
                try:
                    if not name_rva:
                        raise _Malformed(f"PE import library name pointer is zero in descriptor at {hex(offset)}.")
                    name, name_offset = _pe_name(inspection, name_rva, "PE import library name")
                    inspection.library(name, name_offset, offset)
                    if not original and timestamp:
                        inspection.import_warning(f"PE descriptor at {hex(offset)} has a bound FirstThunk but no original lookup table; library {name} is retained without guessed symbols.")
                    elif not (original or first):
                        inspection.import_warning(f"PE descriptor at {hex(offset)} for {name} has no import lookup pointer.")
                    else:
                        _pe_thunks(inspection, original or first, name, bits)
                except _Malformed as error:
                    inspection.import_warning(str(error))
            if not terminated:
                if inspection.report["coverage"]["import_descriptors_read"] >= LIMITS["import_descriptors"]:
                    inspection.import_limit("import_descriptors", "Only the first 128 PE import descriptors were inspected; the complete directory was not established.")
                inspection.import_warning(f"PE import descriptor table at RVA {hex(rva)} has no null terminator within its declared, inspected range.")
    if len(directories) > 13 and any(directories[13]):
        inspection.import_warning("PE delay-import descriptors are declared but are not decoded in this report.")


def _pe(inspection):
    report, data = inspection.report, inspection.data
    inspection.require(0, 64, "DOS header")
    pe, = inspection.read("<I", 0x3C, "DOS PE pointer")
    if pe < 64:
        raise _Malformed(f"PE pointer {hex(pe)} overlaps the DOS header.")
    inspection.require(pe, 24, "PE signature and COFF header")
    if data[pe:pe + 4] != b"PE\0\0":
        raise _Malformed(f"No PE signature at the DOS-declared offset {hex(pe)}; DOS-only files are not decoded as PE images.")
    machine, count, _, _, _, optional_size, characteristics = inspection.read("<HHIIIHH", pe + 4, "COFF header")
    report.update(architecture=PE_MACHINES.get(machine, f"Unknown machine ({hex(machine)})"),
                  byte_order="little", sections_declared=str(count),
                  kind="DLL" if characteristics & 0x2000 else "Executable image")
    optional = pe + 24
    inspection.require(optional, optional_size, "PE optional header")
    if optional_size < 2:
        raise _Malformed(f"PE optional header at {hex(optional)} is too short to identify PE32/PE32+.")
    magic, = inspection.read("<H", optional, "PE optional magic")
    if magic not in (0x10B, 0x20B):
        raise _Malformed(f"Unsupported PE optional-header magic {hex(magic)} at {hex(optional)}; only PE32 and PE32+ are decoded.")
    bits = 64 if magic == 0x20B else 32
    minimum = 112 if bits == 64 else 96
    if optional_size < minimum:
        raise _Malformed(f"PE{bits} optional header at {hex(optional)} is shorter than its {minimum}-byte fixed fields.")
    report["bitness"] = bits
    entry, = inspection.read("<I", optional + 16, "PE entry RVA")
    base, = inspection.read("<Q" if bits == 64 else "<I", optional + (24 if bits == 64 else 28), "PE image base")
    headers, = inspection.read("<I", optional + 60, "PE header size")
    directory_count, = inspection.read("<I", optional + minimum - 4, "PE data-directory count")
    available_directories = (optional_size - minimum) // 8
    report["status"] = "parsed"
    if directory_count > available_directories:
        inspection.warn(f"PE declares {directory_count} data directories but its optional header contains only {available_directories} complete entries.")
    directories = [inspection.read("<II", optional + minimum + 8 * index, "PE data directory")
                   for index in range(min(directory_count, available_directories, 16))]
    table = optional + optional_size
    if headers < table + count * 40 or headers > len(data):
        inspection.warn(f"PE SizeOfHeaders {headers} does not cover the declared header tables within this file.")
    valid_header_address = base + headers <= 1 << bits
    if not valid_header_address:
        inspection.warn(f"PE header range overflows its declared {bits}-bit address width (image base {hex(base)}, size {headers}).")
    if count > LIMITS["sections"]:
        inspection.limit("sections", "Only the first 256 PE section headers were inspected; address mapping is unavailable for the incomplete table.")
    available = max(0, (len(data) - table) // 40)
    if available < count:
        inspection.warn(f"PE section table at {hex(table)} is truncated: {count} headers declared, {available} complete headers available.")
    for index in range(min(count, available, LIMITS["sections"])):
        offset = table + index * 40
        name, memory_size, rva, file_size, file_offset, _, _, _, _, flags = inspection.read("<8sIIIIIIHHI", offset, "PE section header")
        name = _name(name.split(b"\0", 1)[0]) or f"Section {index}"
        valid_file = not file_size or _span(file_offset, file_size, len(data))
        extent = max(memory_size, file_size)
        valid_address = rva + extent <= 1 << 32 and base + rva + extent <= 1 << bits
        if not valid_file:
            inspection.warn(f"PE section {index} ({name}) declares file bytes outside the file at {hex(file_offset)} (size {file_size}).")
        if not valid_address:
            inspection.warn(f"PE section {index} ({name}) overflows its declared address width at RVA {hex(rva)}.")
        section = {
            "index": index, "name": name, "header_offset": hex(offset), "address": hex(base + rva), "rva": hex(rva),
            "file_offset": hex(file_offset), "file_size": str(file_size), "memory_size": str(memory_size),
            "type": "Code" if flags & 0x20 else "Uninitialized data" if flags & 0x80 else "Data",
            "flags": [label for mask, label in ((0x40000000, "Read"), (0x80000000, "Write"), (0x20000000, "Execute")) if flags & mask],
            "flags_value": hex(flags), "entropy": inspection.entropy(file_offset, file_size) if valid_file else None,
            "status": "invalid_range" if not valid_file or not valid_address else "file_backed" if file_size else "zero_fill" if memory_size else "empty",
        }
        report["sections"].append(section)
        report["coverage"]["sections_read"] += 1
        inspection.regions.append(_Region(rva, extent, file_offset, file_size, name, offset, valid_file and valid_address))
        inspection.section_observations(section)
    inspection.overlaps(inspection.regions)
    inspection.address_table_complete = len(report["sections"]) == count
    inspection.regions.append(_Region(0, headers, 0, headers, "Headers", optional + 60, headers <= len(data) and valid_header_address))
    if entry:
        state, offset, region, _ = inspection.mapping(entry)
        report["entry_point"] = {"address": hex(base + entry), "rva": hex(entry),
                                 "offset": hex(offset) if offset is not None else None, "region": region, "mapping": state}
        if state != "file_backed":
            inspection.finding("entry_not_file_backed", "Entry point has no proven file byte",
                               f"The entry RVA {hex(entry)} has mapping state {state.replace('_', ' ')}.", optional + 16)
    else:
        report["entry_point"] = {"address": None, "rva": "0x0", "offset": None, "region": None, "mapping": "not_declared"}
    _pe_imports(inspection, directories, directory_count, bits)


def _elf_table(inspection, offset, count, stride, fmt, kind, header_size):
    if not count:
        return [], True
    limit = LIMITS[kind]
    if count > limit:
        inspection.limit(kind, f"Only the first {limit} ELF {kind.replace('_', ' ')} were inspected; declared count {count} exceeds the limit.")
    minimum = struct.calcsize(fmt)
    if offset < header_size or stride < minimum:
        inspection.warn(f"ELF {kind.replace('_', ' ')} table has invalid offset {hex(offset)} or entry size {stride}; at least {minimum} bytes per entry are required.")
        return [], False
    available = max(0, (len(inspection.data) - offset) // stride)
    if count > available:
        inspection.warn(f"ELF {kind.replace('_', ' ')} table at {hex(offset)} is truncated: {count} entries declared, {available} complete entries available.")
    rows = [inspection.read(fmt, offset + index * stride, f"ELF {kind.replace('_', ' ')} header")
            for index in range(min(count, available, limit))]
    inspection.report["coverage"][f"{kind}_read"] = len(rows)
    return rows, len(rows) == count


def _elf_string_table(inspection, sections, index, what):
    if not 0 <= index < len(sections):
        raise _Malformed(f"{what} references unavailable string table section {index}.")
    table = sections[index]
    if table.kind != 3:
        raise _Malformed(f"{what} references section {index}, which is not a string table.")
    if table.flags & 0x800:
        raise _Malformed(f"{what} references compressed string table section {index}; compressed tables are not decompressed.")
    inspection.require(table.offset, table.size, f"{what} string table")
    return table


def _elf_string(inspection, table, index, what, allow_empty=False):
    if not 0 <= index < table.size:
        raise _Malformed(f"{what} name index {index} is outside its declared string table at {hex(table.offset)} (size {table.size}).")
    name, _ = inspection.cstring(table.offset + index, table.offset + table.size, what, allow_empty)
    return name, table.offset + index


def _elf_dynamic_records(inspection, offset, size, stride, endian, bits, linked_strings=None):
    minimum = 16 if bits == 64 else 8
    if stride < minimum:
        inspection.import_warning(f"ELF dynamic table at {hex(offset)} has invalid entry size {stride}.")
        return
    if not _span(offset, size, len(inspection.data)):
        inspection.import_warning(f"ELF dynamic table at {hex(offset)} declares unavailable file bytes (size {size}).")
        return
    if size % stride:
        inspection.import_warning(f"ELF dynamic table at {hex(offset)} has a partial trailing entry.")
    pointers, needed, conflict, terminated = {}, [], False, False
    count = size // stride
    for index in range(count):
        if inspection.report["coverage"]["dynamic_records_read"] >= LIMITS["dynamic_records"]:
            inspection.import_limit("dynamic_records", "The cumulative 4,096 dynamic-record inspection budget was reached; remaining records were not decoded.")
            break
        record_offset = offset + index * stride
        tag, value = inspection.read(endian + ("qQ" if bits == 64 else "iI"), record_offset, "ELF dynamic record")
        inspection.report["coverage"]["dynamic_records_read"] += 1
        if tag == 0:
            terminated = True
            break
        if tag == 1:
            needed.append((value, record_offset))
        elif tag in (5, 10):
            if tag in pointers and pointers[tag] != value:
                conflict = True
            pointers[tag] = value
    if not terminated:
        inspection.import_warning(f"ELF dynamic table at {hex(offset)} has no DT_NULL terminator within its declared, inspected range.")
    if conflict:
        inspection.import_warning(f"ELF dynamic table at {hex(offset)} has conflicting string-table pointers or sizes; no arbitrary library table was selected.")
        return
    if not needed:
        return
    if linked_strings is not None:
        table = linked_strings
        if 10 in pointers and pointers[10] > table.size:
            inspection.import_warning(f"ELF dynamic string size {pointers[10]} exceeds its linked string table at {hex(table.offset)}.")
            return
        table = _ELFSection(0, 3, 0, 0, table.offset, pointers.get(10, table.size), 0, 0, 1, 0)
    else:
        if 5 not in pointers or 10 not in pointers or not pointers[10]:
            inspection.import_warning(f"ELF dynamic table at {hex(offset)} lacks a usable DT_STRTAB/DT_STRSZ pair for needed library names.")
            return
        state, string_offset, _, _ = inspection.mapping(pointers[5], pointers[10])
        if pointers[5] + pointers[10] > 1 << bits or state != "file_backed":
            inspection.import_warning(f"ELF dynamic string table at address {hex(pointers[5])} (size {pointers[10]}) has {state.replace('_', ' ')} mapping.")
            return
        table = _ELFSection(0, 3, 0, pointers[5], string_offset, pointers[10], 0, 0, 1, 0)
    for name_index, record_offset in needed:
        try:
            name, name_offset = _elf_string(inspection, table, name_index, "ELF needed library")
            inspection.library(name, name_offset, record_offset)
        except _Malformed as error:
            inspection.import_warning(str(error))


def _elf_dependencies(inspection, programs, sections, endian, bits):
    dynamic = [program for program in programs if program.kind == 2]
    distinct = {(program.offset, program.file_size, program.address) for program in dynamic}
    if len(distinct) > 1:
        inspection.import_warning("ELF declares multiple distinct PT_DYNAMIC segments; dependency-library decoding is ambiguous and was omitted.")
        return
    if dynamic:
        program = dynamic[0]
        state, offset, _, _ = inspection.mapping(program.address, max(1, program.file_size))
        if state != "file_backed" or offset != program.offset:
            inspection.import_warning(f"ELF PT_DYNAMIC at {hex(program.offset)} does not match an unambiguous file-backed load mapping ({state.replace('_', ' ')}).")
            return
        _elf_dynamic_records(inspection, program.offset, program.file_size, 16 if bits == 64 else 8, endian, bits)
        return
    for section in sections:
        if section.kind != 6:
            continue
        try:
            if section.flags & 0x800:
                raise _Malformed(f"ELF dynamic section at {hex(section.offset)} is compressed and was not decompressed.")
            strings = _elf_string_table(inspection, sections, section.link, "ELF dynamic section")
            _elf_dynamic_records(inspection, section.offset, section.size, section.entry_size, endian, bits, strings)
        except _Malformed as error:
            inspection.import_warning(str(error))


def _elf_symbols(inspection, sections, kind, endian, bits, sections_declared):
    selected = [section for section in sections if section.kind == (2 if kind == 1 else 11)]
    minimum = 24 if bits == 64 else 16
    for section in selected:
        try:
            if section.flags & 0x800:
                raise _Malformed(f"ELF symbol table at {hex(section.offset)} is compressed and was not decompressed.")
            if section.entry_size < minimum:
                raise _Malformed(f"ELF symbol table at {hex(section.offset)} has invalid entry size {section.entry_size}; at least {minimum} bytes are required.")
            inspection.require(section.offset, section.size, "ELF symbol table")
            strings = _elf_string_table(inspection, sections, section.link, "ELF symbol table")
            if section.size % section.entry_size:
                inspection.import_warning(f"ELF symbol table at {hex(section.offset)} has a partial trailing record.")
            for index in range(section.size // section.entry_size):
                if inspection.report["coverage"]["symbol_records_read"] >= LIMITS["symbol_records"]:
                    inspection.import_limit("symbol_records", "The cumulative 20,000 symbol/thunk-record inspection budget was reached; remaining symbols were not decoded.")
                    return selected
                offset = section.offset + index * section.entry_size
                if bits == 64:
                    name_index, info, _, shndx, _, _ = inspection.read(endian + "IBBHQQ", offset, "ELF symbol record")
                else:
                    name_index, _, _, info, _, shndx = inspection.read(endian + "IIIBBH", offset, "ELF symbol record")
                inspection.report["coverage"]["symbol_records_read"] += 1
                if shndx == 0xFFFF:
                    inspection.import_warning(f"ELF symbol at {hex(offset)} uses SHN_XINDEX; section-index symbol recovery is not decoded.")
                elif 0 < shndx < 0xFF00 and shndx >= sections_declared:
                    inspection.import_warning(f"ELF symbol at {hex(offset)} references invalid section index {shndx}.")
                if shndx or info >> 4 not in (1, 2) or not name_index:
                    continue
                try:
                    name, name_offset = _elf_string(inspection, strings, name_index, "ELF undefined symbol")
                    inspection.symbol(name, None, None, offset, name_offset, "GLOBAL" if info >> 4 == 1 else "WEAK")
                except _Malformed as error:
                    inspection.import_warning(str(error))
        except _Malformed as error:
            inspection.import_warning(str(error))
    return selected


def _elf(inspection):
    data, report = inspection.data, inspection.report
    inspection.require(0, 16, "ELF identification")
    if data[4] not in (1, 2) or data[5] not in (1, 2) or data[6] != 1:
        raise _Malformed("ELF identification has an unsupported class, byte order, or version.")
    bits, endian = (64 if data[4] == 2 else 32), ("<" if data[5] == 1 else ">")
    fmt = endian + ("16sHHIQQQIHHHHHH" if bits == 64 else "16sHHIIIIIHHHHHH")
    header_size = struct.calcsize(fmt)
    _, kind, machine, version, entry, phoff, shoff, _, ehsize, phstride, phcount, shstride, shcount, shnames = inspection.read(fmt, 0, "ELF fixed header")
    if version != 1 or ehsize < header_size:
        raise _Malformed(f"ELF fixed header has unsupported version {version} or invalid header size {ehsize}.")
    inspection.require(0, ehsize, "ELF declared header")
    report.update(status="parsed", architecture=ELF_MACHINES.get(machine, f"Unknown machine ({hex(machine)})"),
                  bitness=bits, byte_order="little" if endian == "<" else "big",
                  kind=ELF_TYPES.get(kind, f"Unknown ELF type ({hex(kind)})"),
                  sections_declared=str(shcount), program_headers_declared=str(phcount))
    shfmt = endian + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII")
    phfmt = endian + ("IIQQQQQQ" if bits == 64 else "IIIIIIII")
    sh_usable, ph_usable = True, True
    if (shoff and not shcount) or shnames == 0xFFFF or phcount == 0xFFFF:
        try:
            if shoff < ehsize or shstride < struct.calcsize(shfmt):
                raise _Malformed("ELF extended numbering requires a complete null section header zero.")
            inspection.require(shoff, shstride, "ELF extended-numbering section zero")
            zero = _ELFSection(*inspection.read(shfmt, shoff, "ELF extended-numbering section zero"))
            if zero.kind != 0:
                raise _Malformed("ELF extended numbering references a non-null section header zero.")
            if not shcount:
                shcount = zero.size
            if phcount == 0xFFFF:
                phcount = zero.info
            if shnames == 0xFFFF:
                shnames = zero.link
        except _Malformed as error:
            inspection.warn(str(error))
            sh_usable, ph_usable = False, phcount != 0xFFFF
    report.update(sections_declared=str(shcount), program_headers_declared=str(phcount))
    program_rows, ph_complete = _elf_table(inspection, phoff, phcount, phstride, phfmt, "program_headers", ehsize) if ph_usable else ([], False)
    programs = [_ELFProgram(*row) if bits == 64 else _ELFProgram(row[0], row[6], *row[1:6], row[7]) for row in program_rows]
    for index, program in enumerate(programs):
        if program.kind != 1:
            continue
        valid_file = not program.file_size or _span(program.offset, program.file_size, len(data))
        valid_address = program.address + program.memory_size <= 1 << bits and program.file_size <= program.memory_size
        valid_alignment = program.alignment in (0, 1) or (
            not program.alignment & (program.alignment - 1) and (program.address - program.offset) % program.alignment == 0)
        if not valid_file or not valid_address or not valid_alignment:
            inspection.warn(f"ELF PT_LOAD {index} at {hex(phoff + index * phstride)} has an invalid file/memory range or alignment (file size {program.file_size}, memory size {program.memory_size}).")
        valid = valid_file and valid_address and valid_alignment
        flags = [label for mask, label in ((4, "Read"), (2, "Write"), (1, "Execute")) if program.flags & mask]
        report["load_segments"].append({
            "index": index, "name": f"PT_LOAD {index}", "header_offset": hex(phoff + index * phstride),
            "address": hex(program.address), "file_offset": hex(program.offset),
            "file_size": str(program.file_size), "memory_size": str(program.memory_size),
            "flags": flags, "flags_value": hex(program.flags),
            "status": "invalid_range" if not valid else "file_backed" if program.file_size else "zero_fill" if program.memory_size else "empty",
        })
        inspection.regions.append(_Region(program.address, program.memory_size, program.offset, program.file_size,
                                          f"PT_LOAD {index}", phoff + index * phstride, valid))
        if "Write" in flags and "Execute" in flags:
            inspection.finding("writable_executable_segment", "Load segment declares write and execute",
                               f"PT_LOAD {index} declares both permissions; this is not a runtime or malware verdict.", phoff + index * phstride)
    inspection.overlaps(inspection.regions)
    inspection.address_table_complete = ph_complete
    if entry:
        state, offset, region, _ = inspection.mapping(entry)
        report["entry_point"] = {"address": hex(entry), "rva": None, "offset": hex(offset) if offset is not None else None,
                                 "region": region, "mapping": state}
        if state != "file_backed":
            inspection.finding("entry_not_file_backed", "Entry point has no proven file byte",
                               f"The entry address {hex(entry)} has mapping state {state.replace('_', ' ')}.", 24)
    else:
        report["entry_point"] = {"address": None, "rva": None, "offset": None, "region": None, "mapping": "not_declared"}
    section_rows, sh_complete = _elf_table(inspection, shoff, shcount, shstride, shfmt, "sections", ehsize) if sh_usable else ([], False)
    sections = [_ELFSection(*row) for row in section_rows]
    names = None
    if shnames:
        try:
            names = _elf_string_table(inspection, sections, shnames, "ELF section-name table")
        except _Malformed as error:
            inspection.warn(str(error))
    section_regions = []
    for index, section in enumerate(sections):
        name = f"Section {index}"
        if names is not None:
            try:
                decoded, _ = _elf_string(inspection, names, section.name_index, f"ELF section {index} name", allow_empty=True)
                name = decoded or name
            except _Malformed as error:
                inspection.warn(str(error))
        file_size = 0 if section.kind in (0, 8) else section.size
        memory_size = 0 if section.kind == 0 else section.size
        valid_file = not file_size or _span(section.offset, file_size, len(data))
        valid_address = section.address + memory_size <= 1 << bits
        if not valid_file or not valid_address:
            inspection.warn(f"ELF section {index} ({name}) declares an invalid file/address range at {hex(section.offset)} (size {section.size}).")
        rendered = {
            "index": index, "name": name, "header_offset": hex(shoff + index * shstride), "address": hex(section.address), "rva": None,
            "file_offset": hex(section.offset), "file_size": str(file_size), "memory_size": str(memory_size),
            "type": ELF_SECTIONS.get(section.kind, f"Type {hex(section.kind)}"),
            "flags": [label for mask, label in ((2, "Allocated"), (1, "Write"), (4, "Execute"), (0x10, "Merge"),
                                                (0x20, "Strings"), (0x400, "TLS"), (0x800, "Compressed")) if section.flags & mask],
            "flags_value": hex(section.flags), "entropy": inspection.entropy(section.offset, file_size) if valid_file else None,
            "status": "invalid_range" if not valid_file or not valid_address else "file_backed" if file_size else "zero_fill" if memory_size else "empty",
        }
        report["sections"].append(rendered)
        inspection.section_observations(rendered)
        section_regions.append(_Region(section.address, memory_size if section.flags & 2 and kind != 1 else 0,
                                       section.offset, file_size, name, shoff + index * shstride, valid_file and valid_address))
    inspection.overlaps(section_regions)
    report["imports"].update(status="parsed", note="Undefined symbols are declarations; their library providers are not resolved. Symbols come from section-based dynamic tables, or regular tables in relocatable objects.")
    _elf_dependencies(inspection, programs, sections, endian, bits)
    selected = _elf_symbols(inspection, sections, kind, endian, bits, shcount)
    if not sections or not sh_complete:
        report["imports"]["note"] += " Section headers are absent or incomplete; section-based symbol decoding is unavailable or partial."
        inspection.import_warning("ELF section headers are absent or incomplete; missing section-based symbols were not inferred from printable strings.")
    elif not selected and (any(program.kind == 2 for program in programs) or any(section.kind == 6 for section in sections)):
        report["imports"]["note"] += " No selected symbol table is available."
        inspection.import_warning("ELF has dynamic metadata but no available selected symbol table; symbol names were not inferred from strings.")
    elif not selected and report["imports"]["status"] == "parsed":
        report["imports"]["status"] = "not_present"


def inspect_executable(data: bytes) -> dict | None:
    if data.startswith(b"MZ"):
        inspection = _Inspection(data, "PE")
        parser = _pe
    elif data.startswith(b"\x7fELF"):
        inspection = _Inspection(data, "ELF")
        parser = _elf
    else:
        return None
    try:
        parser(inspection)
    except _Malformed as error:
        inspection.warn(str(error))
    return inspection.report
