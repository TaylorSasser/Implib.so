from __future__ import annotations
import os
import re
from typing import Any

from implib.base import BinaryBackend, BackendError
from implib.model import Symbol, SectionInfo, RelocationInfo
from implib.log import error

class ElfBackend(BinaryBackend):
    format_name = "elf"

    @property
    def default_platform(self) -> str:
        return "linux"

    def matches(self, path: str) -> bool:
        if path.lower().endswith(".def"):
            return True
        try:
            with open(path, "rb") as f:
                sig = f.read(4)
                if sig == b"\x7fELF":
                    return True
                # Check for EXPORTS in first few lines (for .def files)
                f.seek(0)
                for _ in range(10):
                    try:
                        line = f.readline().decode('ascii', errors='ignore').strip().upper()
                        if line == "EXPORTS":
                            return True
                    except Exception:
                        break
        except OSError:
            pass
        return False

    def _parse_lief_binary(self, path: str) -> Any:
        import lief
        bin_ = lief.parse(path)
        if bin_ is None or not isinstance(bin_, lief.ELF.Binary):
            return None
        return bin_

    def _get_section_flags(self, section: Any) -> str:
        # 2 is SHF_ALLOC
        return "ALLOC" if section.flags & 2 else ""

    def _collect_def_symbols(self, path: str) -> list[Symbol]:
        out: list[Symbol] = []
        try:
            with open(path, "r") as f:
                lines = f.readlines()
            exports_found = False
            for line in lines:
                line = line.strip()
                if not line or line.startswith(";"): continue
                if line.upper() == "EXPORTS":
                    exports_found = True
                    continue
                if not exports_found: continue
                m = re.match(r"^([A-Za-z0-9_]+)$", line)
                if m:
                    name = m.group(1)
                    out.append(Symbol(name, "GLOBAL", "FUNC", "1", 0, 0, True, demangled=name))
        except Exception as e:
            error(f"failed to parse .def file '{path}': {e}")
        return out

    def collect_symbols(self, path: str) -> list[Symbol]:
        bin_ = self._get_binary(path)
        if bin_ is None:
            return self._collect_def_symbols(path)

        by_name: dict[str, Symbol] = {}
        order: list[str] = []
        
        sizes = self._calculate_symbol_sizes(bin_, bin_.symbols)

        # Iterate over all symbols to allow internal relocation resolution in generator
        for sym in bin_.symbols:
            name = sym.name
            if not name: continue

            bind = sym.binding.name if hasattr(sym.binding, "name") else "LOCAL"
            typ = sym.type.name if hasattr(sym.type, "name") else "NOTYPE"
            vis = sym.visibility.name if hasattr(sym.visibility, "name") else "DEFAULT"

            shndx = sym.shndx
            if sym.imported or shndx == 0:
                ndx = "UND"
            elif shndx == 0xFFF1: ndx = "ABS"
            elif shndx == 0xFFF2: ndx = "COM"
            else: ndx = str(shndx)

            ver_name, default = None, True
            if sym.has_version:
                sym_ver = sym.symbol_version
                if sym_ver:
                    default = not (sym_ver.value & 0x8000)
                    ver_name = sym_ver.symbol_version_auxiliary.name if sym_ver.symbol_version_auxiliary else None

            if vis == "HIDDEN":
                default = False

            is_exported = sym.exported
            demangled = sym.demangled_name or name
            size = sym.size if sym.size > 0 else sizes.get(sym.value, 0)

            sym_obj = Symbol(name, bind, typ, ndx, sym.value, size, default, is_exported, demangled=demangled)

            if name not in by_name:
                by_name[name] = sym_obj
                order.append(name)
            else:
                existing = by_name[name]
                # Priority: exported > default version > larger size
                if sym_obj.exported and not existing.exported:
                    by_name[name] = sym_obj
                elif sym_obj.exported == existing.exported:
                    if sym_obj.default and not existing.default:
                        by_name[name] = sym_obj
                    elif sym_obj.default == existing.default:
                        if sym_obj.size > existing.size:
                            by_name[name].size = sym_obj.size

        out = [by_name[n] for n in order]
        if not out: error(f"failed to analyze symbols in {path}")
        return out


    def default_load_name(self, path: str) -> str:
        bin_ = self._get_binary(path)
        if bin_ is None:
            return self._read_def_library_name(path) or os.path.basename(path)

        for entry in bin_.dynamic_entries:
            if int(entry.tag) == 14: # DT_SONAME
                return entry.name or os.path.basename(path)
        return os.path.basename(path)

    def _read_def_library_name(self, path: str) -> str | None:
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    m = re.match(r"^(?:LIBRARY|NAME)\s+([A-Za-z0-9_.\-]+)$", line, re.I)
                    if m: return m.group(1)
        except Exception: pass
        return os.path.splitext(os.path.basename(path))[0] + ".so"

    def supports_vtables(self) -> bool:
        return True

    def collect_relocations(self, path: str) -> list[RelocationInfo]:
        bin_ = self._get_binary(path)
        rels: list[RelocationInfo] = []
        if bin_ is None: return []

        addr_syms = sorted(
            [(s.value, s.value + max(1, s.size), s.name)
             for s in bin_.symbols
             if s.name and s.value != 0 and not s.name.startswith(".")],
            key=lambda t: t[0]
        )

        def resolve_addr(addr: int) -> tuple[str, int] | None:
            if not addr_syms: return None
            for start, end, name in addr_syms:
                if start <= addr < end: return name, addr - start
            best = next(( (name, addr - start) for start, _, name in reversed(addr_syms) if start <= addr ), None)
            if best and best[1] <= 0x100000: return best
            return None

        byteorder = self.byteorder(path)
        ptr_size = 8 if int(bin_.header.identity_class) == 2 else 4
        has_rela = any(int(e.tag) == 7 for e in bin_.dynamic_entries)
        m_type = int(bin_.header.machine_type)

        for rel in bin_.relocations:
            rel_type_name = f"R_{rel.type.name}"

            sym_name = rel.symbol.name if rel.has_symbol and rel.symbol.name else ""
            if sym_name.startswith("."): sym_name = ""

            addend = rel.addend
            if addend == 0 and not rel.is_rela and not has_rela:
                try:
                    raw = self.read_data(path, rel.address, ptr_size)
                    if len(raw) == ptr_size:
                        val = int.from_bytes(bytes(raw), byteorder=byteorder, signed=False)
                        if val >= (1 << (ptr_size * 8 - 1)): val -= (1 << (ptr_size * 8))
                        addend = val
                except Exception: pass

            target_address = addend + (rel.symbol.value if rel.has_symbol else 0)
            if not sym_name and target_address != 0:
                got = resolve_addr(target_address)
                if got is not None: sym_name, addend = got

            rels.append(RelocationInfo(rel.address, rel.info, rel_type_name, (sym_name, addend)))
        return rels

    def byteorder(self, path: str) -> str:
        bin_ = self._get_binary(path)
        if bin_ is None: return "little"
        return "little" if int(bin_.header.identity_data) == 1 else "big"
