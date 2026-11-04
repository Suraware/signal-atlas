"""Hand-built benign byte fixtures; none of these files is ever executed.

Offsets below are deliberately independent of the production parser. PE's DOS
pointer is at 0x3c, COFF starts at 0x84, and the optional header at 0x98.
"""

import struct


def pe_fixture(bitness=64):
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    optional_size = 0xF0 if bitness == 64 else 0xE0
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664 if bitness == 64 else 0x14C,
                     2, 0, 0, 0, optional_size, 0x22 if bitness == 64 else 0x102)
    struct.pack_into("<H", data, 0x98, 0x20B if bitness == 64 else 0x10B)
    struct.pack_into("<I", data, 0xA8, 0x1010)  # AddressOfEntryPoint
    if bitness == 64:
        struct.pack_into("<Q", data, 0xB0, 0x140000000)
        struct.pack_into("<I", data, 0x104, 16)  # NumberOfRvaAndSizes
    else:
        struct.pack_into("<I", data, 0xB4, 0x400000)
        struct.pack_into("<I", data, 0xF4, 16)
    struct.pack_into("<II", data, 0xB8, 0x1000, 0x200)
    struct.pack_into("<II", data, 0xD0, 0x3000, 0x200)
    struct.pack_into("<H", data, 0xDC, 3)  # console subsystem
    write_pe_section(data, bitness, 0, b".text", 0x180, 0x1000, 0x200, 0x200, 0x60000020)
    write_pe_section(data, bitness, 1, b".idata", 0x200, 0x2000, 0x200, 0x400, 0xC0000040)
    bait = b"VirtualAllocEx unrelated.dll /bin/sh bait\0"
    data[0x700:0x700 + len(bait)] = bait
    return data


def write_pe_section(data, bitness, index, name, memory_size, rva, file_size, file_offset, flags):
    table = 0x188 if bitness == 64 else 0x178
    struct.pack_into("<8sIIIIIIHHI", data, table + 40 * index, name, memory_size, rva,
                     file_size, file_offset, 0, 0, 0, 0, flags)


def pe_import_fixture(bitness=64):
    data = pe_fixture(bitness)
    directory = 0x110 if bitness == 64 else 0x100
    struct.pack_into("<II", data, directory, 0x2000, 40)
    struct.pack_into("<IIIII", data, 0x400, 0x2040, 0, 0, 0x2080, 0x2060)
    width = "Q" if bitness == 64 else "I"
    thunks = (0x20A0, (1 << (bitness - 1)) | 7, 0)
    struct.pack_into("<" + width * 3, data, 0x440, *thunks)
    struct.pack_into("<" + width * 3, data, 0x460, *thunks)
    data[0x480:0x48D] = b"KERNEL32.dll\0"
    struct.pack_into("<H", data, 0x4A0, 42)
    data[0x4A2:0x4AE] = b"CreateFileW\0"
    return data


def pe_many_thunks(count):
    data = pe_import_fixture()
    data.extend(b"\0" * (0x1000 + (count + 1) * 8 - len(data)))
    struct.pack_into("<IIIII", data, 0x400, 0x2C00, 0, 0, 0x2080, 0x2C00)
    for index in range(count):
        struct.pack_into("<Q", data, 0x1000 + index * 8, (1 << 63) | (index + 1))
    size = len(data) - 0x400
    write_pe_section(data, 64, 1, b".idata", size, 0x2000, size, 0x400, 0xC0000040)
    return data


def pe_many_descriptors(count):
    data = pe_import_fixture()
    data.extend(b"\0" * (0x6200 - len(data)))
    struct.pack_into("<II", data, 0x110, 0x2C00, 20 * (count + 1))
    for index in range(count):
        struct.pack_into("<IIIII", data, 0x1000 + index * 20, 0x7C00, 0, 0,
                         0x5C00 + index * 16, 0x7C00)
        name = f"L{index:03}.dll\0".encode("ascii")
        data[0x4000 + index * 16:0x4000 + index * 16 + len(name)] = name
    struct.pack_into("<QQ", data, 0x6000, (1 << 63) | 1, 0)
    write_pe_section(data, 64, 1, b".idata", 0x5E00, 0x2000, 0x5E00, 0x400, 0xC0000040)
    return data


def elf_fixture(bitness=64, endian="<"):
    data = bytearray(0x800)
    base = 0x400000 if bitness == 64 else 0x8048000
    ident = b"\x7fELF" + bytes((2 if bitness == 64 else 1, 1 if endian == "<" else 2, 1)) + b"\0" * 9
    header = "16sHHIQQQIHHHHHH" if bitness == 64 else "16sHHIIIIIHHHHHH"
    struct.pack_into(endian + header, data, 0, ident, 3, 62 if bitness == 64 else 3, 1,
                     base + 0x110, 0x40 if bitness == 64 else 0x34, 0x600, 0,
                     64 if bitness == 64 else 52, 56 if bitness == 64 else 32, 2,
                     64 if bitness == 64 else 40, 7, 6)
    dynamic_width = 16 if bitness == 64 else 8
    symbol_width = 24 if bitness == 64 else 16
    write_elf_program(data, bitness, endian, 0, 1, 0, base, 0x500, 0x600, 5, 0x1000)
    write_elf_program(data, bitness, endian, 1, 2, 0x200, base + 0x200,
                      4 * dynamic_width, 4 * dynamic_width, 6, dynamic_width // 2)
    strings = b"\0libfixture.so\0puts\0optional_hook\0defined_symbol\0unrelated.so\0VirtualAllocEx\0"
    data[0x300:0x300 + len(strings)] = strings
    section_names = b"\0.text\0.dynstr\0.dynsym\0.dynamic\0.bss\0.shstrtab\0"
    data[0x500:0x500 + len(section_names)] = section_names
    for index, (tag, value) in enumerate(((1, 1), (5, base + 0x300), (10, 128), (0, 0))):
        struct.pack_into(endian + ("qQ" if bitness == 64 else "iI"), data, 0x200 + index * dynamic_width, tag, value)
    for index, (name, info, shndx, value) in enumerate(((0, 0, 0, 0), (15, 0x12, 0, 0),
                                                      (20, 0x20, 0, 0), (34, 0x12, 1, base + 0x110),
                                                      (62, 0x02, 0, 0))):
        write_elf_symbol(data, bitness, endian, 0x380 + index * symbol_width, name, info, shndx, value)
    write_elf_section(data, bitness, endian, 0, 0, 0, 0, 0, 0, 0)
    write_elf_section(data, bitness, endian, 1, 1, 1, 6, base + 0x100, 0x100, 32, alignment=16)
    write_elf_section(data, bitness, endian, 2, 7, 3, 2, base + 0x300, 0x300, 128)
    write_elf_section(data, bitness, endian, 3, 15, 11, 2, base + 0x380, 0x380, 5 * symbol_width,
                      link=2, info=1, alignment=symbol_width // 2, entry_size=symbol_width)
    write_elf_section(data, bitness, endian, 4, 23, 6, 3, base + 0x200, 0x200, 4 * dynamic_width,
                      link=2, alignment=dynamic_width // 2, entry_size=dynamic_width)
    write_elf_section(data, bitness, endian, 5, 32, 8, 3, base + 0x500, 0x500, 256, alignment=16)
    write_elf_section(data, bitness, endian, 6, 37, 3, 0, 0, 0x500, len(section_names))
    return data


def write_elf_program(data, bitness, endian, index, kind, offset, address, file_size, memory_size, flags, alignment):
    if bitness == 64:
        struct.pack_into(endian + "IIQQQQQQ", data, 0x40 + index * 56,
                         kind, flags, offset, address, address, file_size, memory_size, alignment)
    else:
        struct.pack_into(endian + "IIIIIIII", data, 0x34 + index * 32,
                         kind, offset, address, address, file_size, memory_size, flags, alignment)


def write_elf_section(data, bitness, endian, index, name, kind, flags, address, offset, size,
                      link=0, info=0, alignment=1, entry_size=0):
    width, fmt = (64, "IIQQQQIIQQ") if bitness == 64 else (40, "IIIIIIIIII")
    struct.pack_into(endian + fmt, data, 0x600 + index * width,
                     name, kind, flags, address, offset, size, link, info, alignment, entry_size)


def write_elf_symbol(data, bitness, endian, offset, name, info, shndx, value=0):
    if bitness == 64:
        struct.pack_into(endian + "IBBHQQ", data, offset, name, info, 0, shndx, value, 0)
    else:
        struct.pack_into(endian + "IIIBBH", data, offset, name, value, 0, info, 0, shndx)


def elf_many_symbols(count):
    data = elf_fixture()
    data.extend(b"\0" * (0x1000 + (count + 1) * 24 - len(data)))
    for index in range(1, count + 1):
        write_elf_symbol(data, 64, "<", 0x1000 + index * 24, 15, 0x12, 0)
    write_elf_section(data, 64, "<", 3, 15, 11, 2, 0x401000, 0x1000,
                      (count + 1) * 24, link=2, info=1, alignment=8, entry_size=24)
    write_elf_program(data, 64, "<", 0, 1, 0, 0x400000, len(data), len(data), 5, 0x1000)
    return data


def elf_many_dynamic(count):
    data = elf_fixture()
    data.extend(b"\0" * (0x1000 + count * 16 - len(data)))
    for index in range(count):
        tag, value = (5, 0x400300) if index == 0 else (10, 128) if index == 1 else (1, 1) if index < count - 1 else (0, 0)
        struct.pack_into("<qQ", data, 0x1000 + index * 16, tag, value)
    write_elf_program(data, 64, "<", 1, 2, 0x1000, 0x401000, count * 16, count * 16, 6, 8)
    write_elf_program(data, 64, "<", 0, 1, 0, 0x400000, len(data), len(data), 5, 0x1000)
    return data
