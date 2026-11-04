import json
import random
import struct

import pytest
from atlas.analysis import analyze_file
from atlas.executables import inspect_executable
from executable_fixtures import (
    elf_fixture,
    elf_many_dynamic,
    elf_many_symbols,
    pe_fixture,
    pe_import_fixture,
    pe_many_descriptors,
    pe_many_thunks,
    write_elf_program,
    write_elf_section,
    write_elf_symbol,
    write_pe_section,
)


def report_for(data):
    report = analyze_file("fixture.bin", bytes(data)).get("executable")
    assert report is not None, "MZ/ELF inspection must include executable structure, not only strings"
    return report


@pytest.mark.parametrize(("bitness", "architecture", "address"), [
    (32, "x86", "0x401010"),
    (64, "x86-64", "0x140001010"),
])
def test_pe_maps_entry_to_section_bytes_with_exact_architecture(bitness, architecture, address):
    report = report_for(pe_fixture(bitness))
    assert report["format"] == "PE"
    assert report["status"] == "parsed"
    assert report["architecture"] == architecture
    assert report["bitness"] == bitness
    assert report["byte_order"] == "little"
    assert report["kind"] == "Executable image"
    assert report["sections_declared"] == "2"
    assert report["program_headers_declared"] == "0"
    assert report["entry_point"] == {
        "address": address, "rva": "0x1010", "offset": "0x210",
        "region": ".text", "mapping": "file_backed",
    }


def test_pe_reports_section_ranges_permissions_and_entropy_not_runtime_claims():
    data = pe_fixture()
    data[0x200:0x400] = bytes(range(256)) * 2
    report = report_for(data)
    assert report["sections"][0] == {
        "index": 0, "name": ".text", "header_offset": "0x188",
        "address": "0x140001000", "rva": "0x1000", "file_offset": "0x200",
        "file_size": "512", "memory_size": "384", "type": "Code",
        "flags": ["Read", "Execute"], "flags_value": "0x60000020",
        "entropy": 8.0, "status": "file_backed",
    }
    assert report["sections"][1]["flags"] == ["Read", "Write"]
    assert report["coverage"]["entropy_bytes_read"] == 1024
    assert any(item["code"] == "high_entropy_section" and item["offset"] == "0x200"
               for item in report["findings"])


def test_non_executable_and_capture_reports_do_not_gain_fake_executable_structure():
    assert "executable" not in analyze_file("text.py", b"print('hello')\n")
    pcap = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    result = analyze_file("empty.pcap", pcap)
    assert "executable" not in result
    assert result["capture"]["packet_count"] == 0


@pytest.mark.parametrize("length", [2, 0x3F, 0x83, 0x97, 0x100])
def test_truncated_pe_headers_return_invalid_structure_instead_of_crashing(length):
    report = report_for(pe_fixture()[:length])
    assert report["status"] == "invalid"
    assert report["warnings"]
    assert report["sections"] == []
    assert report["entry_point"]["offset"] is None


@pytest.mark.parametrize(("offset", "value", "width"), [
    (0x3C, 0xFFFFFFF0, "I"),  # e_lfanew outside the file
    (0x3C, 0x10, "I"),  # e_lfanew overlaps the DOS header
    (0x94, 1, "H"),  # optional header is too short
    (0x94, 0xFFFF, "H"),  # optional header extends beyond the file
    (0x98, 0x107, "H"),  # ROM optional header is not PE32/PE32+
])
def test_invalid_pe_header_declarations_do_not_invent_sections(offset, value, width):
    data = pe_fixture()
    struct.pack_into("<" + width, data, offset, value)
    report = report_for(data)
    assert report["status"] == "invalid"
    assert report["sections"] == []
    assert report["warnings"]


def test_pe_zero_fill_entry_has_no_file_offset():
    data = pe_fixture()
    write_pe_section(data, 64, 0, b".text", 0x400, 0x1000, 0x200, 0x200, 0x60000020)
    struct.pack_into("<I", data, 0xA8, 0x1250)
    report = report_for(data)
    assert report["entry_point"]["mapping"] == "zero_fill"
    assert report["entry_point"]["offset"] is None
    assert report["entry_point"]["region"] == ".text"
    assert any(item["code"] == "entry_not_file_backed" for item in report["findings"])


def test_pe_overlapping_virtual_sections_do_not_choose_arbitrary_entry_bytes():
    data = pe_fixture()
    write_pe_section(data, 64, 1, b".alias", 0x200, 0x1000, 0x200, 0x400, 0xE0000040)
    report = report_for(data)
    assert report["entry_point"]["mapping"] == "ambiguous"
    assert report["entry_point"]["offset"] is None
    codes = {item["code"] for item in report["findings"]}
    assert {"overlapping_virtual_ranges", "writable_executable_section"} <= codes
    assert report["status"] == "partial"


def test_pe_out_of_file_section_is_reported_without_entropy_or_entry_bytes():
    data = pe_fixture()
    write_pe_section(data, 64, 0, b".text", 0x180, 0x1000, 0x200, 0xFFFFFF00, 0x60000020)
    report = report_for(data)
    section = report["sections"][0]
    assert section["file_offset"] == "0xffffff00"
    assert section["file_size"] == "512"
    assert section["status"] == "invalid_range"
    assert section["entropy"] is None
    assert report["entry_point"]["offset"] is None
    assert report["status"] == "partial"


def test_pe_absent_entry_and_dll_flag_are_not_guessed_as_code():
    data = pe_fixture()
    struct.pack_into("<I", data, 0xA8, 0)
    struct.pack_into("<H", data, 0x96, 0x2022)
    report = report_for(data)
    assert report["kind"] == "DLL"
    assert report["entry_point"] == {
        "address": None, "rva": "0x0", "offset": None,
        "region": None, "mapping": "not_declared",
    }


def test_pe_header_rva_maps_only_within_declared_file_backed_headers():
    data = pe_fixture()
    struct.pack_into("<I", data, 0xA8, 0x100)
    report = report_for(data)
    assert report["entry_point"]["offset"] == "0x100"
    assert report["entry_point"]["region"] == "Headers"


@pytest.mark.parametrize(("bitness", "base", "address", "mapping", "offset"), [
    (32, 0xFFFFFE00, "0xffffff00", "file_backed", "0x100"),
    (32, 0xFFFFFFF0, "0x1000000f0", "unavailable", None),
    (64, 0xFFFFFFFFFFFFFE00, "0xffffffffffffff00", "file_backed", "0x100"),
    (64, 0xFFFFFFFFFFFFFFF0, "0x100000000000000f0", "unavailable", None),
])
def test_pe_header_mapping_checks_address_width_without_wrapping_declared_values(bitness, base, address, mapping, offset):
    data = pe_fixture(bitness)
    struct.pack_into("<H", data, 0x86, 0)  # isolate the header region from section declarations
    struct.pack_into("<I", data, 0xA8, 0x100)
    struct.pack_into("<Q" if bitness == 64 else "<I", data, 0xB0 if bitness == 64 else 0xB4, base)
    report = report_for(data)
    assert report["entry_point"] == {
        "address": address, "rva": "0x100", "offset": offset, "region": "Headers", "mapping": mapping,
    }
    if offset is None:
        assert report["status"] == "partial"
        assert any("header" in warning.lower() and "overflows" in warning.lower() for warning in report["warnings"])
    else:
        assert report["status"] == "parsed"


@pytest.mark.parametrize(("format", "bitness", "header_offset"), [
    ("PE", 32, "0x178"), ("PE", 64, "0x188"),
    ("ELF", 32, "0x628"), ("ELF", 64, "0x640"),
])
def test_section_flag_evidence_locates_the_header_not_unavailable_declared_data(format, bitness, header_offset):
    if format == "PE":
        data = pe_fixture(bitness)
        write_pe_section(data, bitness, 0, b".bad", 0x180, 0x1000, 0x200, 0xFFFFFF00, 0xE0000020)
        section_index = 0
    else:
        data = elf_fixture(bitness)
        write_elf_section(data, bitness, "<", 1, 1, 1, 7, 0x100, 0xFFFFFF00, 32)
        section_index = 1
    report = report_for(data)
    section = report["sections"][section_index]
    assert section["file_offset"] == "0xffffff00"
    assert section["status"] == "invalid_range"
    assert section["entropy"] is None
    finding, = [row for row in report["findings"] if row["code"] == "writable_executable_section"]
    assert finding["offset"] == header_offset


@pytest.mark.parametrize(("format", "header_offset", "data_offset"), [
    ("PE", "0x188", "0x200"), ("ELF", "0x640", "0x100"),
])
def test_section_flags_and_entropy_locate_distinct_header_and_data_evidence(format, header_offset, data_offset):
    if format == "PE":
        data = pe_fixture()
        write_pe_section(data, 64, 0, b".text", 0x200, 0x1000, 0x200, 0x200, 0xE0000020)
        data[0x200:0x400] = bytes(range(256)) * 2
    else:
        data = elf_fixture()
        write_elf_section(data, 64, "<", 1, 1, 1, 7, 0x400100, 0x100, 256)
        data[0x100:0x200] = bytes(range(256))
    report = report_for(data)
    flags, = [row for row in report["findings"] if row["code"] == "writable_executable_section"]
    entropy, = [row for row in report["findings"] if row["code"] == "high_entropy_section"]
    assert flags["offset"] == header_offset
    assert entropy["offset"] == data_offset


@pytest.mark.parametrize(("format", "bitness", "header_offset"), [
    ("PE", 32, "0x1a0"), ("PE", 64, "0x1b0"),
    ("ELF", 32, "0x6c8"), ("ELF", 64, "0x740"),
])
def test_section_overlap_evidence_locates_headers_even_when_declared_file_bytes_are_absent(format, bitness, header_offset):
    if format == "PE":
        data = pe_fixture(bitness)
        for index, rva, offset in [(0, 0x1000, 0xFFFFFF00), (1, 0x1100, 0xFFFFFF80)]:
            write_pe_section(data, bitness, index, b".bad", 0x200, rva, 0x200, offset, 0x60000020)
    else:
        data = elf_fixture(bitness)
        for index, address, offset in [(1, 0x100, 0xFFFFFF00), (5, 0x110, 0xFFFFFF10)]:
            write_elf_section(data, bitness, "<", index, 0, 1, 6, address, offset, 32)
    report = report_for(data)
    overlaps = [row for row in report["findings"] if row["code"].startswith("overlapping_")]
    assert {row["code"] for row in overlaps} == {"overlapping_virtual_ranges", "overlapping_file_ranges"}
    assert {row["offset"] for row in overlaps} == {header_offset}


@pytest.mark.parametrize(("bitness", "header_offset"), [(32, "0x54"), (64, "0x78")])
def test_load_overlap_evidence_locates_program_headers_not_unavailable_data(bitness, header_offset):
    data = elf_fixture(bitness)
    base = 0x400000 if bitness == 64 else 0x8048000
    for index, address, offset in [(0, base, 0xFFFFFF00), (1, base + 0x100, 0xFFFFFF80)]:
        write_elf_program(data, bitness, "<", index, 1, offset, address, 0x500, 0x600, 5, 1)
    report = report_for(data)
    assert report["entry_point"]["mapping"] == "ambiguous"
    assert report["entry_point"]["offset"] is None
    overlaps = [row for row in report["findings"] if row["code"].startswith("overlapping_")]
    assert {row["code"] for row in overlaps} == {"overlapping_virtual_ranges", "overlapping_file_ranges"}
    assert {row["offset"] for row in overlaps} == {header_offset}


def test_pe_truncated_section_table_keeps_complete_headers_but_mapping_is_unavailable():
    data = pe_fixture()[:0x1BC]  # full first header, 12 bytes of second
    report = report_for(data)
    assert len(report["sections"]) == 1
    assert report["sections_declared"] == "2"
    assert report["entry_point"]["mapping"] == "unavailable"
    assert report["entry_point"]["offset"] is None
    assert report["status"] == "partial"


def test_pe_excessive_section_count_stops_at_cap_and_explains_unavailable_mapping():
    data = pe_fixture()
    data.extend(b"\0" * (0x188 + 40 * 257 - len(data)))
    struct.pack_into("<H", data, 0x86, 257)
    report = report_for(data)
    assert len(report["sections"]) == 256
    assert report["sections_declared"] == "257"
    assert report["coverage"]["sections_read"] == 256
    assert "sections" in report["limits"]["reached"]
    assert report["entry_point"]["mapping"] == "unavailable"
    assert report["status"] == "partial"
    assert any("256" in warning and "section" in warning.lower() for warning in report["warnings"])


@pytest.mark.parametrize(("bitness", "ordinal_offset"), [(32, "0x444"), (64, "0x448")])
def test_pe_imports_come_only_from_named_and_ordinal_lookup_records(bitness, ordinal_offset):
    report = report_for(pe_import_fixture(bitness))
    imports = report["imports"]
    assert imports["status"] == "parsed"
    assert imports["libraries"] == [{"name": "KERNEL32.dll", "offset": "0x480", "record_offset": "0x400"}]
    assert imports["symbols"] == [
        {"name": "CreateFileW", "ordinal": None, "library": "KERNEL32.dll", "offset": "0x440",
         "name_offset": "0x4a2", "binding": None},
        {"name": None, "ordinal": "7", "library": "KERNEL32.dll", "offset": ordinal_offset,
         "name_offset": None, "binding": None},
    ]
    assert report["coverage"]["import_descriptors_read"] == 2
    assert report["coverage"]["symbol_records_read"] == 3
    assert report["status"] == "parsed"
    assert "VirtualAllocEx" not in [row["name"] for row in imports["symbols"]]


@pytest.mark.parametrize("bitness", [32, 64])
def test_pe_missing_original_lookup_uses_unbound_first_thunk(bitness):
    data = pe_import_fixture(bitness)
    struct.pack_into("<I", data, 0x400, 0)
    report = report_for(data)
    assert report["imports"]["status"] == "parsed"
    assert report["imports"]["symbols"][0]["offset"] == "0x460"
    assert report["imports"]["symbols"][0]["name"] == "CreateFileW"


def test_pe_bound_first_thunk_without_original_lookup_is_not_guessed_as_import_names():
    data = pe_import_fixture()
    struct.pack_into("<II", data, 0x400, 0, 1)  # nonzero timestamp marks a bound descriptor
    struct.pack_into("<QQQ", data, 0x460, 0x140009000, 0x14000A000, 0)
    report = report_for(data)
    assert report["imports"]["libraries"][0]["name"] == "KERNEL32.dll"
    assert report["imports"]["symbols"] == []
    assert report["imports"]["status"] == "partial"
    assert any("bound" in warning.lower() for warning in report["warnings"])


@pytest.mark.parametrize(("descriptor_field", "value"), [
    (0x40C, 0), (0x40C, 0x2800), (0x40C, 0xFFFFFFFF),
    (0x400, 0x2800), (0x400, 0xFFFFFFFF),
])
def test_pe_unmapped_import_names_or_lookup_tables_remain_partial(descriptor_field, value):
    data = pe_import_fixture()
    struct.pack_into("<I", data, descriptor_field, value)
    report = report_for(data)
    assert report["imports"]["symbols"] == []
    assert report["imports"]["status"] == "partial"
    assert report["warnings"]


def test_pe_imports_do_not_map_through_ambiguous_virtual_sections():
    data = pe_import_fixture()
    write_pe_section(data, 64, 0, b".alias", 0x400, 0x2000, 0x200, 0x200, 0x60000020)
    report = report_for(data)
    assert report["imports"]["libraries"] == []
    assert report["imports"]["symbols"] == []
    assert report["imports"]["status"] == "partial"


def test_pe_descriptor_terminator_must_be_inside_declared_directory():
    data = pe_import_fixture()
    struct.pack_into("<I", data, 0x114, 20)  # excludes the otherwise present null descriptor
    report = report_for(data)
    assert len(report["imports"]["symbols"]) == 2
    assert report["imports"]["status"] == "partial"
    assert any("descriptor" in warning.lower() and "terminat" in warning.lower() for warning in report["warnings"])


def test_pe_lookup_terminator_cannot_be_taken_from_bytes_after_the_section():
    data = pe_import_fixture()
    struct.pack_into("<I", data, 0x400, 0x21F0)
    struct.pack_into("<QQ", data, 0x5F0, (1 << 63) | 1, (1 << 63) | 2)
    report = report_for(data)
    assert [row["ordinal"] for row in report["imports"]["symbols"]] == ["1", "2"]
    assert report["imports"]["status"] == "partial"
    assert any("lookup" in warning.lower() and "terminat" in warning.lower() for warning in report["warnings"])


@pytest.mark.parametrize(("where", "warning"), [(0x480, "library"), (0x4A2, "symbol")])
def test_pe_unterminated_import_names_are_rejected_not_truncated(where, warning):
    data = pe_import_fixture()
    data[where:0x600] = b"X" * (0x600 - where)
    report = report_for(data)
    if where == 0x480:
        assert report["imports"]["libraries"] == []
        assert report["imports"]["symbols"] == []
    else:
        assert [row["ordinal"] for row in report["imports"]["symbols"]] == ["7"]
    assert report["imports"]["status"] == "partial"
    assert any(warning in item.lower() and "terminat" in item.lower() for item in report["warnings"])


@pytest.mark.parametrize(("name_length", "retained"), [(511, True), (512, False)])
def test_pe_name_byte_budget_requires_a_terminator_within_512_bytes(name_length, retained):
    data = pe_import_fixture()
    write_pe_section(data, 64, 1, b".idata", 0x400, 0x2000, 0x400, 0x400, 0xC0000040)
    data[0x480:0x480 + name_length + 1] = b"X" * name_length + b"\0"
    report = report_for(data)
    assert bool(report["imports"]["libraries"]) is retained
    if retained:
        assert report["imports"]["libraries"][0]["name"] == "X" * 511
    else:
        assert "name_bytes" in report["limits"]["reached"]


@pytest.mark.parametrize(("bitness", "thunk"), [
    (32, 0x80010007), (64, 0x8000000000010007), (64, 0x1000020A0),
])
def test_pe_reserved_ordinal_bits_and_wide_name_rvas_do_not_invent_symbols(bitness, thunk):
    data = pe_import_fixture(bitness)
    struct.pack_into("<Q" if bitness == 64 else "<I", data, 0x440, thunk)
    report = report_for(data)
    assert [row["ordinal"] for row in report["imports"]["symbols"]] == ["7"]
    assert report["imports"]["status"] == "partial"


def test_pe_symbol_retention_cap_still_checks_the_terminated_lookup_table():
    report = report_for(pe_many_thunks(600))
    assert len(report["imports"]["symbols"]) == 512
    assert report["imports"]["symbols"][-1]["ordinal"] == "512"
    assert report["coverage"]["symbol_records_read"] == 601
    assert "symbols" in report["limits"]["reached"]
    assert report["imports"]["status"] == "partial"


def test_pe_thunk_work_stops_after_20000_records_without_claiming_complete_imports():
    report = report_for(pe_many_thunks(20001))
    assert len(report["imports"]["symbols"]) == 512
    assert report["coverage"]["symbol_records_read"] == 20000
    assert "symbol_records" in report["limits"]["reached"]
    assert report["imports"]["status"] == "partial"


def test_pe_descriptor_work_and_library_output_stop_at_128_records():
    report = report_for(pe_many_descriptors(129))
    assert len(report["imports"]["libraries"]) == 128
    assert report["imports"]["libraries"][-1]["name"] == "L127.dll"
    assert report["coverage"]["import_descriptors_read"] == 128
    assert "import_descriptors" in report["limits"]["reached"]
    assert report["imports"]["status"] == "partial"


def test_pe_delay_imports_are_explicitly_omitted_not_reported_as_empty_clean_imports():
    data = pe_fixture()
    struct.pack_into("<II", data, 0x170, 0x2000, 32)  # directory index 13
    report = report_for(data)
    assert report["imports"]["status"] == "partial"
    assert any("delay" in warning.lower() and "not decoded" in warning.lower() for warning in report["warnings"])


def test_pe_missing_declared_directory_bytes_are_not_a_proven_absence_of_imports():
    data = pe_fixture()
    headers = data[0x188:0x1D8]
    struct.pack_into("<H", data, 0x94, 112)
    data[0x108:0x158] = headers
    report = report_for(data)
    assert report["imports"]["status"] == "unavailable"
    assert report["imports"]["symbols"] == []


@pytest.mark.parametrize(("bitness", "endian", "architecture", "address", "symbol_offset", "weak_offset"), [
    (32, "<", "x86", "0x8048110", "0x390", "0x3a0"),
    (32, ">", "x86", "0x8048110", "0x390", "0x3a0"),
    (64, "<", "x86-64", "0x400110", "0x398", "0x3b0"),
    (64, ">", "x86-64", "0x400110", "0x398", "0x3b0"),
])
def test_elf_classes_and_byte_orders_decode_loads_dependencies_and_undefined_symbols(
    bitness, endian, architecture, address, symbol_offset, weak_offset,
):
    report = report_for(elf_fixture(bitness, endian))
    assert report["status"] == "parsed"
    assert report["format"] == "ELF"
    assert report["architecture"] == architecture
    assert report["bitness"] == bitness
    assert report["byte_order"] == ("little" if endian == "<" else "big")
    assert report["kind"] == "Shared object / PIE"
    assert report["sections_declared"] == "7"
    assert report["program_headers_declared"] == "2"
    assert report["entry_point"] == {
        "address": address, "rva": None, "offset": "0x110", "region": "PT_LOAD 0", "mapping": "file_backed",
    }
    assert report["load_segments"][0]["flags"] == ["Read", "Execute"]
    assert report["load_segments"][0]["file_size"] == "1280"
    assert report["load_segments"][0]["memory_size"] == "1536"
    assert report["sections"][1]["name"] == ".text"
    assert report["sections"][1]["flags"] == ["Allocated", "Execute"]
    assert report["sections"][1]["file_offset"] == "0x100"
    assert report["imports"]["libraries"] == [{"name": "libfixture.so", "offset": "0x301", "record_offset": "0x200"}]
    assert report["imports"]["symbols"] == [
        {"name": "puts", "ordinal": None, "library": None, "offset": symbol_offset,
         "name_offset": "0x30f", "binding": "GLOBAL"},
        {"name": "optional_hook", "ordinal": None, "library": None, "offset": weak_offset,
         "name_offset": "0x314", "binding": "WEAK"},
    ]
    assert report["coverage"]["symbol_records_read"] == 5
    assert report["coverage"]["dynamic_records_read"] == 4
    assert "provider" in report["imports"]["note"].lower()


def test_elf_nobits_does_not_read_declared_zero_fill_as_file_bytes():
    data = elf_fixture()
    struct.pack_into("<Q", data, 24, 0x400510)
    write_elf_section(data, 64, "<", 5, 32, 8, 3, 0x400500, 0xFFFFFFFFFFFFFFFF, 256, alignment=16)
    report = report_for(data)
    assert report["sections"][5]["type"] == "NOBITS"
    assert report["sections"][5]["file_size"] == "0"
    assert report["sections"][5]["memory_size"] == "256"
    assert report["sections"][5]["entropy"] is None
    assert report["sections"][5]["status"] == "zero_fill"
    assert report["entry_point"]["mapping"] == "zero_fill"
    assert report["entry_point"]["offset"] is None


def test_sectionless_elf_still_decodes_dynamic_libraries_but_explains_missing_symbols():
    data = elf_fixture()
    struct.pack_into("<Q", data, 40, 0)
    struct.pack_into("<HHH", data, 58, 0, 0, 0)
    report = report_for(data)
    assert report["sections"] == []
    assert report["entry_point"]["offset"] == "0x110"
    assert report["imports"]["libraries"][0]["name"] == "libfixture.so"
    assert report["imports"]["symbols"] == []
    assert report["imports"]["status"] == "partial"
    assert "section" in report["imports"]["note"].lower()
    assert report["status"] == "partial"


@pytest.mark.parametrize("bitness", [32, 64])
def test_elf_extended_numbering_uses_null_section_metadata_without_entropy_reads(bitness):
    data = elf_fixture(bitness)
    if bitness == 64:
        struct.pack_into("<H", data, 56, 0xFFFF)
        struct.pack_into("<HH", data, 60, 0, 0xFFFF)
    else:
        struct.pack_into("<H", data, 44, 0xFFFF)
        struct.pack_into("<HH", data, 48, 0, 0xFFFF)
    write_elf_section(data, bitness, "<", 0, 0, 0, 0, 0, 0, 7, link=6, info=2)
    report = report_for(data)
    assert report["status"] == "parsed"
    assert report["sections_declared"] == "7"
    assert report["program_headers_declared"] == "2"
    assert report["sections"][0]["file_size"] == "0"
    assert report["sections"][0]["entropy"] is None
    assert report["sections"][6]["name"] == ".shstrtab"
    assert report["imports"]["symbols"][0]["name"] == "puts"


def test_elf_extended_numbering_rejects_non_null_section_zero():
    data = elf_fixture()
    struct.pack_into("<H", data, 60, 0)
    write_elf_section(data, 64, "<", 0, 0, 1, 0, 0, 0, 7)
    report = report_for(data)
    assert report["status"] == "partial"
    assert report["sections"] == []
    assert any("null" in warning.lower() for warning in report["warnings"])


def test_elf_relocatable_objects_use_regular_undefined_symbols_not_virtual_entry_mapping():
    data = elf_fixture()
    struct.pack_into("<H", data, 16, 1)
    struct.pack_into("<Q", data, 24, 0)
    struct.pack_into("<Q", data, 32, 0)
    struct.pack_into("<H", data, 56, 0)
    write_elf_section(data, 64, "<", 3, 15, 2, 0, 0, 0x380, 120, link=2, info=1, alignment=8, entry_size=24)
    write_elf_section(data, 64, "<", 4, 0, 0, 0, 0, 0, 0)
    report = report_for(data)
    assert report["kind"] == "Relocatable object"
    assert report["entry_point"]["mapping"] == "not_declared"
    assert [row["name"] for row in report["imports"]["symbols"]] == ["puts", "optional_hook"]
    assert all(row["library"] is None for row in report["imports"]["symbols"])
    assert report["imports"]["libraries"] == []


@pytest.mark.parametrize(("offset", "value", "width"), [
    (4, 0, "B"), (5, 0, "B"), (6, 0, "B"), (20, 2, "I"), (52, 1, "H"),
])
def test_invalid_elf_identification_and_fixed_header_sizes_return_invalid_reports(offset, value, width):
    data = elf_fixture()
    struct.pack_into("<" + width, data, offset, value)
    report = report_for(data)
    assert report["status"] == "invalid"
    assert report["sections"] == []
    assert report["warnings"]


@pytest.mark.parametrize("length", [4, 15, 51, 63])
def test_truncated_elf_fixed_headers_do_not_raise_struct_unpack_errors(length):
    report = report_for(elf_fixture()[:length])
    assert report["status"] == "invalid"
    assert report["warnings"]


def test_elf_wide_sizes_offsets_and_extended_counts_remain_exact_decimal_or_hex_strings():
    data = elf_fixture()
    struct.pack_into("<H", data, 60, 0)
    write_elf_section(data, 64, "<", 0, 0, 0, 0, 0, 0, 0x8000000000000007)
    write_elf_section(data, 64, "<", 1, 1, 1, 6, 0x400100, 0xFFFFFFFFFFFFFFF0, 0x8000000000000001)
    report = report_for(data)
    assert report["sections_declared"] == "9223372036854775815"
    assert report["sections"][1]["file_offset"] == "0xfffffffffffffff0"
    assert report["sections"][1]["file_size"] == "9223372036854775809"
    assert report["sections"][1]["entropy"] is None
    assert report["status"] == "partial"
    assert len(report["sections"]) <= 256
    assert "sections" in report["limits"]["reached"]


@pytest.mark.parametrize("link", [1, 99])
def test_elf_symbol_names_require_a_valid_linked_string_table(link):
    data = elf_fixture()
    struct.pack_into("<I", data, 0x6E8, link)  # .dynsym sh_link
    report = report_for(data)
    assert report["imports"]["symbols"] == []
    assert report["imports"]["status"] == "partial"
    assert any("string table" in warning.lower() for warning in report["warnings"])


@pytest.mark.parametrize("entry_size", [0, 8])
def test_elf_symbol_table_entry_sizes_cannot_reinterpret_arbitrary_bytes(entry_size):
    data = elf_fixture()
    struct.pack_into("<Q", data, 0x6F8, entry_size)
    report = report_for(data)
    assert report["imports"]["symbols"] == []
    assert report["imports"]["status"] == "partial"


def test_elf_compressed_linked_strings_are_not_decompressed_or_read_as_symbol_names():
    data = elf_fixture()
    struct.pack_into("<Q", data, 0x688, 0x802)  # .dynstr sh_flags
    report = report_for(data)
    assert report["imports"]["symbols"] == []
    assert report["imports"]["status"] == "partial"
    assert any("compressed" in warning.lower() for warning in report["warnings"])


def test_elf_symbol_name_indices_and_terminators_stay_inside_linked_table():
    data = elf_fixture()
    write_elf_symbol(data, 64, "<", 0x398, 128, 0x12, 0)
    data[0x314:0x380] = b"X" * (0x380 - 0x314)
    report = report_for(data)
    assert report["imports"]["symbols"] == []
    assert report["imports"]["status"] == "partial"
    assert report["warnings"]


def test_elf_overlapping_load_segments_do_not_choose_even_identical_entry_mappings():
    data = elf_fixture()
    write_elf_program(data, 64, "<", 1, 1, 0, 0x400000, 0x500, 0x600, 5, 0x1000)
    report = report_for(data)
    assert report["entry_point"]["mapping"] == "ambiguous"
    assert report["entry_point"]["offset"] is None
    assert any(item["code"] == "overlapping_virtual_ranges" for item in report["findings"])


def test_elf_load_file_size_cannot_exceed_memory_size_for_entry_mapping():
    data = elf_fixture()
    write_elf_program(data, 64, "<", 0, 1, 0, 0x400000, 0x500, 0x100, 5, 0x1000)
    report = report_for(data)
    assert report["load_segments"][0]["status"] == "invalid_range"
    assert report["entry_point"]["offset"] is None
    assert report["status"] == "partial"


@pytest.mark.parametrize(("field", "value", "width"), [(32, 0, "Q"), (54, 8, "H"), (32, 0xFFFFFFFFFFFFFFFF, "Q")])
def test_elf_bad_program_tables_preserve_header_but_do_not_map_entries(field, value, width):
    data = elf_fixture()
    struct.pack_into("<" + width, data, field, value)
    report = report_for(data)
    assert report["status"] == "partial"
    assert report["entry_point"]["mapping"] == "unavailable"
    assert report["entry_point"]["offset"] is None


def test_elf_program_header_cap_prevents_unique_mapping_claims_from_only_a_prefix():
    data = elf_fixture()
    data.extend(b"\0" * (0x40 + 129 * 56 - len(data)))
    struct.pack_into("<H", data, 56, 129)
    report = report_for(data)
    assert report["coverage"]["program_headers_read"] == 128
    assert "program_headers" in report["limits"]["reached"]
    assert report["entry_point"]["mapping"] == "unavailable"


def test_elf_dynamic_termination_is_not_inferred_from_bytes_outside_the_table():
    data = elf_fixture()
    struct.pack_into("<qQ", data, 0x230, 21, 1)
    report = report_for(data)
    assert report["imports"]["libraries"][0]["name"] == "libfixture.so"
    assert report["imports"]["status"] == "partial"
    assert any("dynamic" in warning.lower() and "terminat" in warning.lower() for warning in report["warnings"])


@pytest.mark.parametrize("name_index", [0, 128, 0xFFFFFFFFFFFFFFFF])
def test_elf_needed_offsets_cannot_escape_the_dynamic_string_table(name_index):
    data = elf_fixture()
    struct.pack_into("<Q", data, 0x208, name_index)
    report = report_for(data)
    assert report["imports"]["libraries"] == []
    assert report["imports"]["status"] == "partial"


def test_elf_conflicting_dynamic_string_pointers_do_not_select_an_arbitrary_library():
    data = elf_fixture()
    struct.pack_into("<qQ", data, 0x230, 5, 0x400400)
    report = report_for(data)
    assert report["imports"]["libraries"] == []
    assert report["imports"]["status"] == "partial"
    assert any("conflict" in warning.lower() for warning in report["warnings"])


def test_elf_dynamic_string_declared_size_must_be_file_backed_even_with_a_valid_prefix():
    data = elf_fixture()
    struct.pack_into("<Q", data, 0x228, 0x8000000000000001)
    report = report_for(data)
    assert report["imports"]["libraries"] == []
    assert report["imports"]["status"] == "partial"


def test_elf_multiple_distinct_dynamic_segments_are_explicitly_ambiguous():
    data = elf_fixture()
    struct.pack_into("<H", data, 56, 3)
    write_elf_program(data, 64, "<", 2, 2, 0x240, 0x400240, 64, 64, 6, 8)
    data[0x240:0x280] = data[0x200:0x240]
    report = report_for(data)
    assert report["imports"]["libraries"] == []
    assert report["imports"]["status"] == "partial"
    assert any("dynamic" in warning.lower() and "multiple" in warning.lower() for warning in report["warnings"])


def test_elf_symbol_output_limit_does_not_bypass_record_inspection_budget():
    report = report_for(elf_many_symbols(600))
    assert len(report["imports"]["symbols"]) == 512
    assert report["imports"]["symbols"][-1]["offset"] == "0x4000"
    assert report["coverage"]["symbol_records_read"] == 601
    assert "symbols" in report["limits"]["reached"]


def test_elf_symbol_table_work_stops_at_20000_records_per_file():
    report = report_for(elf_many_symbols(20001))
    assert report["coverage"]["symbol_records_read"] == 20000
    assert len(report["imports"]["symbols"]) == 512
    assert "symbol_records" in report["limits"]["reached"]
    assert report["imports"]["status"] == "partial"


def test_elf_dynamic_work_and_library_retention_are_independently_bounded():
    report = report_for(elf_many_dynamic(4098))
    assert report["coverage"]["dynamic_records_read"] == 4096
    assert len(report["imports"]["libraries"]) == 128
    assert {"libraries", "dynamic_records"} <= set(report["limits"]["reached"])
    assert report["imports"]["status"] == "partial"


@pytest.mark.parametrize(("distinct", "used", "missing"), [(True, 67108864, True), (False, 2097152, False)])
def test_elf_overlapping_entropy_ranges_share_a_cumulative_budget_and_identical_spans_are_reused(distinct, used, missing):
    data = elf_fixture()
    data.extend(b"\0" * (0x1000 + 2097152 + 33 - len(data)))
    struct.pack_into("<HH", data, 60, 34, 0)
    for index in range(1, 34):
        write_elf_section(data, 64, "<", index, 0, 1, 0, 0,
                          0x1000 + (index if distinct else 0), 2097152)
    report = report_for(data)
    assert report["coverage"]["entropy_bytes_read"] == used
    assert (report["sections"][33]["entropy"] is None) is missing
    assert ("entropy_bytes" in report["limits"]["reached"]) is missing


def test_elf_many_malformed_sections_cannot_expand_findings_or_warning_output():
    data = elf_fixture()
    data.extend(b"\0" * (0x600 + 256 * 64 - len(data)))
    struct.pack_into("<HH", data, 60, 256, 0)
    for index in range(1, 256):
        write_elf_section(data, 64, "<", index, 0, 1, 7, 0xFFFFFFFFFFFFFFF0, 0xFFFFFFFFFFFFFFF0, 256)
    report = report_for(data)
    assert len(report["findings"]) == 50
    assert len(report["warnings"]) == 64
    assert {"findings", "warnings"} <= set(report["limits"]["reached"])
    assert all(section["entropy"] is None for section in report["sections"])


@pytest.mark.parametrize("fixture", [pe_fixture(32), pe_import_fixture(), elf_fixture(32), elf_fixture(), elf_fixture(64, ">")],
                         ids=["pe32", "pe64-imports", "elf32", "elf64", "elf64-big-endian"])
def test_truncations_and_deterministic_table_mutations_never_escape_checked_parsing(fixture):
    randomizer = random.Random(0xA71A5)
    candidates = [fixture[:length] for length in range(4, len(fixture), 29)]
    for _ in range(384):
        changed = bytearray(fixture)
        offset = randomizer.randrange(4, len(changed))
        width = randomizer.choice((1, 2, 4, 8))
        changed[offset:min(offset + width, len(changed))] = randomizer.randbytes(min(width, len(changed) - offset))
        candidates.append(changed)
    for candidate in candidates:
        report = inspect_executable(bytes(candidate))
        assert report is not None
        assert report["status"] in ("parsed", "partial", "invalid")
        assert len(report["sections"]) <= 256
        assert len(report["load_segments"]) <= 128
        assert len(report["imports"]["libraries"]) <= 128
        assert len(report["imports"]["symbols"]) <= 512
        assert len(report["findings"]) <= 50
        assert len(report["warnings"]) <= 64
        assert report["coverage"]["entropy_bytes_read"] <= 67108864
        assert report["coverage"]["symbol_records_read"] <= 20000
        assert report["coverage"]["dynamic_records_read"] <= 4096
        assert all(row["offset"] is None or 0 <= int(row["offset"], 16) < len(candidate) for row in report["findings"])
        json.dumps(report, allow_nan=False)
