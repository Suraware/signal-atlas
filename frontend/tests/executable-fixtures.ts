import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const literalLibrary = `<script>window.EXECUTABLE_NAME_RAN=true</script>${'L'.repeat(180)}_library_tail.dll`;
export const literalSymbol = `<img src=x onerror=window.EXECUTABLE_NAME_RAN=true>${'S'.repeat(180)}_symbol_tail`;

export type ExecutableFixture = 'pe32' | 'pe64' | 'elf32' | 'elf64' | 'elf64-big' | 'sectionless' | 'invalid-pe' | 'invalid-elf' | 'partial-pe' | 'literal-pe' | 'wide-elf' | 'limited-pe' | 'overflow-pe32' | 'overflow-pe64' | 'invalid-range-pe';

// Reuse the hand-built test byte layouts, never production parsing or an
// uploaded file. The test-only Python process generates bytes; it executes no
// artifact. No binary fixture or private research data is stored in the repo.
const root = fileURLToPath(new URL('../../', import.meta.url));
const generator = `
import struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / 'tests'))
from executable_fixtures import pe_fixture, pe_import_fixture, pe_many_thunks, elf_fixture, write_pe_section, write_elf_section
kind = sys.argv[2]
if kind.startswith('pe'):
    data = pe_import_fixture(32 if kind == 'pe32' else 64)
elif kind.startswith('elf'):
    data = elf_fixture(32 if kind == 'elf32' else 64, '>' if kind == 'elf64-big' else '<')
elif kind == 'sectionless':
    data = elf_fixture()
    struct.pack_into('<Q', data, 40, 0)
    struct.pack_into('<HHH', data, 58, 0, 0, 0)
elif kind == 'invalid-pe':
    data = b'MZ'
elif kind == 'invalid-elf':
    data = b'\\x7fELF'
elif kind == 'partial-pe':
    data = pe_import_fixture()
    write_pe_section(data, 64, 0, b'.alias', 0x400, 0x2000, 0x200, 0x200, 0xE0000020)
elif kind in ('overflow-pe32', 'overflow-pe64'):
    bits = 32 if kind == 'overflow-pe32' else 64
    data = pe_fixture(bits)
    struct.pack_into('<H', data, 0x86, 0)
    struct.pack_into('<I', data, 0xA8, 0x100)
    struct.pack_into('<Q' if bits == 64 else '<I', data, 0xB0 if bits == 64 else 0xB4,
                     0xFFFFFFFFFFFFFFF0 if bits == 64 else 0xFFFFFFF0)
elif kind == 'invalid-range-pe':
    data = pe_import_fixture()
    write_pe_section(data, 64, 0, b'.bad', 0x180, 0x1000, 0x200, 0xFFFFFF00, 0xE0000020)
elif kind == 'literal-pe':
    data = pe_import_fixture()
    data.extend(b'\\0' * (0xC00 - len(data)))
    write_pe_section(data, 64, 1, b'.idata', 0x800, 0x2000, 0x800, 0x400, 0xC0000040)
    library, symbol = sys.argv[3].encode('ascii') + b'\\0', sys.argv[4].encode('ascii') + b'\\0'
    data[0x480:0x480 + len(library)] = library
    struct.pack_into('<Q', data, 0x440, 0x24A0)
    struct.pack_into('<H', data, 0x8A0, 42)
    data[0x8A2:0x8A2 + len(symbol)] = symbol
elif kind == 'wide-elf':
    data = elf_fixture()
    struct.pack_into('<H', data, 60, 0)
    write_elf_section(data, 64, '<', 0, 0, 0, 0, 0, 0, 0x8000000000000007)
    write_elf_section(data, 64, '<', 1, 1, 1, 6, 0x400100, 0xFFFFFFFFFFFFFFF0, 0x8000000000000001)
elif kind == 'limited-pe':
    data = pe_many_thunks(600)
else:
    raise ValueError('Unknown test fixture')
sys.stdout.buffer.write(data)
`;

export function executableFixture(kind: ExecutableFixture): Buffer {
  return execFileSync(`${root}/.venv/bin/python`, ['-c', generator, root, kind, literalLibrary, literalSymbol]);
}
