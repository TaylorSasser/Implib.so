from __future__ import annotations
import os
import bisect
import lief

from implib.base import BinaryBackend, MAGIC_ELF, Symbol, SectionInfo, RelocationInfo
from implib.log import error

class ElfBackend(BinaryBackend):
    format_name = "elf"

    @property
    def default_platform(self) -> str:
        return "linux"

    def matches(self) -> bool:
        if self.is_def:
            return True
        return self.magic == MAGIC_ELF

    def collect_symbols(self) -> list[Symbol]:
        if self.binary is None:
            return self._collect_def_symbols()
        elf: lief.ELF.Binary = self.binary

        all_addrs = sorted({sym.value for sym in elf.symbols if sym.value != 0})
        sections = sorted([(s.virtual_address, s.virtual_address + s.size) for s in elf.sections], key=lambda x: x[0])
        sec_starts = [x[0] for x in sections]

        def get_exact_size(sym: lief.ELF.Symbol) -> int:
            if sym.size > 0 or not sym.value: return sym.size
            idx = bisect.bisect_right(all_addrs, sym.value)
            next_sym_addr = all_addrs[idx] if idx < len(all_addrs) else None
            
            sec_end = 0
            s_idx = bisect.bisect_right(sec_starts, sym.value) - 1
            if s_idx >= 0:
                _, end = sections[s_idx]
                if sym.value < end: sec_end = end
            
            limit = next_sym_addr if next_sym_addr and next_sym_addr < sec_end else sec_end
            if limit and limit > sym.value:
                return limit - sym.value
            return 0

        def _get_score(s: Symbol) -> int:
            score = 0
            if s.ndx != "UND": score += 8
            if s.typ != "NOTYPE": score += 4
            if s.size > 0: score += 2
            if s.value != 0: score += 1
            return score

        by_name: dict[str, Symbol] = {}
        order: list[str] = []

        for sym in elf.exported_symbols:
            if not sym.name: continue

            if sym.imported or sym.shndx == 0: ndx = "UND"
            elif sym.shndx == 0xFFF1: ndx = "ABS"
            elif sym.shndx == 0xFFF2: ndx = "COM"
            else: ndx = str(sym.shndx)

            ver_name, default = None, True
            if sym.has_version:
                ver = sym.symbol_version
                if ver:
                    default = not (ver.value & 0x8000)
                    if ver.symbol_version_auxiliary:
                        ver_name = ver.symbol_version_auxiliary.name

            if sym.visibility == lief.ELF.Symbol.VISIBILITY.HIDDEN:
                default = False

            s_obj = Symbol(
                name=sym.name,
                bind=sym.binding.name,
                typ=sym.type.name,
                ndx=ndx,
                value=sym.value,
                size=get_exact_size(sym),
                default=default,
                version=ver_name,
                demangled=sym.demangled_name or sym.name
            )

            if sym.name not in by_name:
                by_name[sym.name] = s_obj
                order.append(sym.name)
            else:
                existing = by_name[sym.name]
                new_score = _get_score(s_obj)
                old_score = _get_score(existing)
                
                if (new_score > old_score) or (existing.version is None and s_obj.version is not None):
                    if s_obj.version is None:
                        s_obj.version, s_obj.default = existing.version, existing.default
                    by_name[sym.name] = s_obj
                elif s_obj.version is not None and existing.version is not None:
                    if s_obj.default and not existing.default:
                        by_name[sym.name] = s_obj

        out = [by_name[n] for n in order]
        if not out: error(f"failed to analyze symbols in {self.path}")
        return out

    def default_load_name(self) -> str:
        if self.binary is None:
            return self._read_def_library_name() or os.path.basename(self.path)

        for entry in self.binary.dynamic_entries:
            if int(entry.tag) == 14:
                return entry.name
        return os.path.basename(self.path)

    def supports_vtables(self) -> bool:
        return True

    def collect_sections(self) -> list[SectionInfo]:
        if not self.binary: return []
        return [
            SectionInfo(s.name, s.virtual_address, s.offset, s.size, "ALLOC")
            for s in self.binary.sections if s.has(lief.ELF.Section.FLAGS.ALLOC)
        ]

    def collect_relocations(self) -> list[RelocationInfo]:
        if not self.binary:
            return []
        elf: lief.ELF.Binary = self.binary

        addr_syms = sorted([(s.value, s.value + max(1, s.size), s.name)
                            for s in elf.symbols if s.name and s.value != 0 and not s.name.startswith(".")],
                           key=lambda t: t[0])
        starts = [t[0] for t in addr_syms]

        def resolve_addr(addr: int) -> tuple[str, int] | None:
            if not addr_syms: return None
            idx = bisect.bisect_right(starts, addr) - 1
            if idx >= 0:
                start, end, name = addr_syms[idx]
                if addr < end or addr - start <= 0x100000:
                    return name, addr - start
            return None

        rels: list[RelocationInfo] = []
        for rel in elf.relocations:
            rel_type_name = f"R_{rel.type.name}"
            if elf.header.machine_type == lief.ELF.ARCH.I386:
                rel_type_name = rel_type_name.replace("R_X86_", "R_386_")
            try:
                target_addr = rel.resolve()
            except Exception:
                target_addr = rel.addend + (rel.symbol.value if rel.has_symbol else 0)

            sym_name = ""
            addend = 0
            
            if rel.has_symbol and rel.symbol.name and not rel.symbol.name.startswith("."):
                sym_name = rel.symbol.name
                addend = target_addr - rel.symbol.value
            else:
                got = resolve_addr(target_addr)
                if got:
                    sym_name, addend = got
                else:
                    addend = target_addr

            rels.append(RelocationInfo(rel.address, rel.info, rel_type_name, (sym_name, addend)))

        return rels

    def byteorder(self) -> str:
        if not self.binary:
            return "little"
        return "little" if self.binary.header.identity_data == lief.ELF.Header.ELF_DATA.LSB else "big"
