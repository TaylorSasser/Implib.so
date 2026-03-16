from __future__ import annotations
import os

import re

from implib.base import BinaryBackend, BackendError
from implib.model import Symbol, SectionInfo, RelocationInfo
from implib.log import error

class ElfBackend(BinaryBackend):
    format_name = "elf"

    @property
    def default_platform(self) -> str:
        return "linux"

    def __init__(self):
        super().__init__()
        self._current_path = None
        self._current_bin = None

    def matches(self, path: str) -> bool:
        if path.lower().endswith(".def"):
            return True
        try:
            with open(path, "rb") as f:
                sig = f.read(4)
                if sig == b"\x7fELF":
                    return True
                # Check for EXPORTS in first few lines
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

    def _require_lief(self):
        try:
            import lief  # noqa: F401
        except ImportError as e:
            error(f"LIEF is required for ELF parsing but not installed. Error: {e!r}")

    def _get_binary(self, path: str):
        if self._current_path != path:
            self._require_lief()
            import lief
            try:
                bin_ = lief.parse(path)
                if bin_ is None or not isinstance(bin_, lief.ELF.Binary):
                    bin_ = None
            except Exception:
                bin_ = None

            self._current_bin = bin_
            self._current_path = path

        return self._current_bin

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
                    out.append(Symbol(name, "GLOBAL", "FUNC", "1", 0, 0, True, None, demangled=name))
        except Exception as e:
            error(f"failed to parse .def file '{path}': {e}")
        return out

    def read_data(self, path: str, address: int, size: int) -> bytes:
        bin_ = self._get_binary(path)
        if bin_ is None: return b""
        try:
            return bytes(bin_.get_content_from_virtual_address(address, size))
        except Exception:
            return b""

    def collect_symbols(self, path: str) -> list[Symbol]:
        bin_ = self._get_binary(path)
        if bin_ is None:
            return self._collect_def_symbols(path)

        by_name: dict[str, Symbol] = {}
        order: list[str] = []

        # Get all symbol addresses in sorted order for fast size calculation if missing
        all_addrs = sorted({sym.value for sym in bin_.symbols if sym.value != 0})
        sections = [(sec.virtual_address, sec.virtual_address + sec.size) for sec in bin_.sections]

        import bisect
        def get_exact_size(val: int, current_size: int) -> int:
            if current_size > 0 or not val: return current_size
            idx = bisect.bisect_right(all_addrs, val)
            next_sym_addr = all_addrs[idx] if idx < len(all_addrs) else None
            
            sec_end = 0
            for start, end in sections:
                if start <= val < end:
                    sec_end = end
                    break
            
            if next_sym_addr and next_sym_addr < sec_end:
                return next_sym_addr - val
            return max(0, sec_end - val)

        def _score(sym: Symbol) -> tuple[int, int, int, int]:
            defined = 1 if sym.ndx != "UND" else 0
            typed = 1 if sym.typ != "NOTYPE" else 0
            sized = 1 if sym.size and sym.size > 0 else 0
            valued = 1 if sym.value and sym.value != 0 else 0
            return (defined, typed, sized, valued)

        def _merge(existing: Symbol, new: Symbol, *, new_from_dynsym: bool) -> None:
            if _score(new) > _score(existing):
                existing.bind, existing.typ = new.bind, new.typ
                existing.ndx, existing.value, existing.size = new.ndx, new.value, new.size
            else:
                if existing.typ == "NOTYPE" and new.typ != "NOTYPE": existing.typ = new.typ
                if existing.ndx == "UND" and new.ndx != "UND": existing.ndx = new.ndx
                if existing.size == 0 and new.size: existing.size = new.size
                if existing.value == 0 and new.value: existing.value = new.value
                if existing.bind == "LOCAL" and new.bind != "LOCAL": existing.bind = new.bind

            if new_from_dynsym:
                existing.version, existing.default = new.version, new.default
            elif existing.version is None and new.version is not None:
                existing.version, existing.default = new.version, new.default

        static_syms = getattr(bin_, "static_symbols", [])
        if not static_syms:
            static_syms = getattr(bin_, "symbols", [])
        dynamic_syms = getattr(bin_, "dynamic_symbols", [])

        for is_dyn, syms in [(False, static_syms), (True, dynamic_syms)]:
            for sym in syms:
                name = sym.name
                if not name: continue

                try:
                    bind = sym.binding.name.upper()
                except AttributeError:
                    bv = int(sym.binding) if hasattr(sym.binding, "__int__") else getattr(sym.binding, "value", 0)
                    bind = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}.get(bv, str(sym.binding).split(".")[-1]).upper()

                try:
                    typ = sym.type.name.upper()
                except AttributeError:
                    tv = int(sym.type) if hasattr(sym.type, "__int__") else getattr(sym.type, "value", 0)
                    typ = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 5: "COMMON", 6: "TLS"}.get(tv, str(sym.type).split(".")[-1]).upper()

                try:
                    vis = sym.visibility.name.upper()
                except AttributeError:
                    vv = int(sym.visibility) if hasattr(sym.visibility, "__int__") else getattr(sym.visibility, "value", 0)
                    vis = {0: "DEFAULT", 1: "INTERNAL", 2: "HIDDEN", 3: "PROTECTED"}.get(vv, str(sym.visibility).split(".")[-1]).upper()

                # Use LIEF's section index
                shndx = getattr(sym, "shndx", 0)
                is_imported = getattr(sym, "is_imported", False)
                if is_imported or shndx == 0:
                    ndx = "UND"
                elif shndx == 0xFFF1: # SHN_ABS
                    ndx = "ABS"
                elif shndx == 0xFFF2: # SHN_COMMON
                    ndx = "COM"
                else:
                    ndx = str(shndx)

                ver_name, default = None, True
                if is_dyn and sym.has_version:
                    sym_ver = sym.symbol_version
                    if sym_ver:
                        # MSB (0x8000) is the hidden bit in ELF versioning
                        default = not (sym_ver.value & 0x8000)
                        try:
                            ver_name = sym_ver.symbol_version_auxiliary.name
                        except AttributeError:
                            pass

                if vis == "HIDDEN":
                    default = False

                demangled = getattr(sym, "demangled_name", "") or name
                size = get_exact_size(sym.value, sym.size)

                sym_obj = Symbol(name, bind, typ, ndx, sym.value, size, default, ver_name, demangled=demangled)

                if name not in by_name:
                    by_name[name] = sym_obj
                    order.append(name)
                else:
                    _merge(by_name[name], sym_obj, new_from_dynsym=is_dyn)

        out = [by_name[n] for n in order]
        if not out: error(f"failed to analyze symbols in {path}")
        return out

    def _read_def_library_name(self, path: str) -> str | None:
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    m = re.match(r"^(?:LIBRARY|NAME)\s+([A-Za-z0-9_.\-]+)$", line, re.I)
                    if m: return m.group(1)
        except Exception:
            pass
        return os.path.splitext(os.path.basename(path))[0] + ".so"

    def default_load_name(self, path: str) -> str:
        bin_ = self._get_binary(path)
        if bin_ is None:
            return self._read_def_library_name(path) or os.path.basename(path)

        for entry in bin_.dynamic_entries:
            if getattr(entry, "tag", None) == 14: # 14 is DT_SONAME
                return getattr(entry, "name", os.path.basename(path))
        return os.path.basename(path)

    def supports_vtables(self) -> bool:
        return True

    def collect_sections(self, path: str) -> list[SectionInfo]:
        bin_ = self._get_binary(path)
        secs: list[SectionInfo] = []
        for sec in bin_.sections:
            if getattr(sec, "flags", 0) & 2: # 2 is SHF_ALLOC
                secs.append(SectionInfo(
                    sec.name, sec.virtual_address, sec.offset, sec.size, "ALLOC"
                ))
        return secs

    def collect_relocations(self, path: str) -> list[RelocationInfo]:
        bin_ = self._get_binary(path)
        rels: list[RelocationInfo] = []

        addr_syms = sorted(
            [(s.value, s.value + max(1, s.size), s.name)
             for s in getattr(bin_, "symbols", [])
             if s.name and s.value != 0 and not s.name.startswith(".")],
            key=lambda t: t[0]
        )

        def resolve_addr(addr: int) -> tuple[str, int] | None:
            if not addr_syms: return None
            for start, end, name in addr_syms:
                if start <= addr < end: return name, addr - start
            best = next(( (name, addr - start) for start, _, name in reversed(addr_syms) if start <= addr ), None)
            if best and best[1] <= 0x100000:
                return best
            return None

        byteorder = "little" if int(bin_.header.identity_data) == 1 else "big"
        ptr_size = 8 if int(bin_.header.identity_class) == 2 else 4
        has_rela = any(getattr(e, "tag", 0) == 7 for e in bin_.dynamic_entries)
        m_type = int(bin_.header.machine_type)

        RELOC_MAP = {
            62:  lambda t: "R_X86_64_64" if t == 1 else f"R_X86_64_{t}",
            3:   lambda t: "R_386_32" if t == 1 else f"R_386_{t}",
            183: lambda t: "R_AARCH64_ABS64" if t == 257 else f"R_AARCH64_{t}",
            40:  lambda t: "R_ARM_ABS32" if t == 2 else f"R_ARM_{t}",
            21:  lambda t: "R_PPC64_ADDR64" if t == 38 else f"R_PPC64_{t}",
            243: lambda t: "R_RISCV_64" if t == 2 else f"R_RISCV_{t}",
            8:   lambda t: "R_MIPS_REL32" if t == 3 else f"R_MIPS_{t}"
        }
        reloc_formatter = RELOC_MAP.get(m_type, lambda t: f"R_{t}")

        for rel in getattr(bin_, "relocations", []):
            tv = int(rel.type) & 0xFFFF if hasattr(rel.type, "__int__") else getattr(rel.type, "value", -1) & 0xFFFF
            rel_type_name = reloc_formatter(tv)

            sym_name = rel.symbol.name if rel.has_symbol and rel.symbol and rel.symbol.name else ""
            if sym_name.startswith("."):
                sym_name = ""

            addend = getattr(rel, 'addend', 0)
            if addend == 0 and not getattr(rel, 'is_rela', False) and not has_rela:
                try:
                    raw = bin_.get_content_from_virtual_address(rel.address, ptr_size)
                    if len(raw) == ptr_size:
                        val = int.from_bytes(bytes(raw), byteorder=byteorder, signed=False)
                        if val >= (1 << (ptr_size * 8 - 1)): val -= (1 << (ptr_size * 8))
                        addend = val
                except Exception:
                    pass

            target_address = addend + (getattr(rel.symbol, "value", 0) if rel.has_symbol and rel.symbol else 0)
            if not sym_name and target_address != 0:
                got = resolve_addr(target_address)
                if got is not None:
                    sym_name, addend = got

            rels.append(RelocationInfo(rel.address, getattr(rel, 'info', 0), rel_type_name, (sym_name, addend)))

        return rels

    def byteorder(self, path: str) -> str:
        bin_ = self._get_binary(path)
        return "little" if int(bin_.header.identity_data) == 1 else "big"
