# implibgen/backends/elf.py
from __future__ import annotations
import os
import sys

from implib.base import BinaryBackend, BackendError
from implib.model import Symbol, SectionInfo, RelocationInfo
from implib.log import warn, error


class ElfBackend(BinaryBackend):
    format_name = "elf"

    def matches(self, path: str) -> bool:
        try:
            with open(path, "rb") as f:
                return f.read(4) == b"\x7fELF"
        except OSError:
            return False

    def _require_lief(self):
        try:
            import lief  # noqa: F401
        except ImportError as e:
            error(f"LIEF is required for ELF parsing but not installed. Error: {e!r}")

    def collect_symbols(self, path: str) -> list[Symbol]:
        self._require_lief()
        import lief

        try:
            bin_ = lief.parse(path)
        except Exception:
            bin_ = None

        if bin_ is None or not isinstance(bin_, lief.ELF.Binary):
            error(f"failed to analyze symbols in {path}")
            return []

        by_name: dict[str, Symbol] = {}
        order: list[str] = []

        def _score(sym: Symbol) -> tuple[int, int, int, int]:
            defined = 1 if sym.ndx != "UND" else 0
            typed = 1 if sym.typ != "NOTYPE" else 0
            sized = 1 if sym.size and sym.size > 0 else 0
            valued = 1 if sym.value and sym.value != 0 else 0
            return (defined, typed, sized, valued)

        def _merge(existing: Symbol, new: Symbol, *, new_from_dynsym: bool) -> None:
            if _score(new) > _score(existing):
                existing.bind = new.bind
                existing.typ = new.typ
                existing.ndx = new.ndx
                existing.value = new.value
                existing.size = new.size
            else:
                if existing.typ == "NOTYPE" and new.typ != "NOTYPE":
                    existing.typ = new.typ
                if existing.ndx == "UND" and new.ndx != "UND":
                    existing.ndx = new.ndx
                if existing.size == 0 and new.size:
                    existing.size = new.size
                if existing.value == 0 and new.value:
                    existing.value = new.value
                if existing.bind == "LOCAL" and new.bind != "LOCAL":
                    existing.bind = new.bind
            if new_from_dynsym:
                existing.version = new.version
                existing.default = new.default
            else:
                if existing.version is None and new.version is not None:
                    existing.version = new.version
                    existing.default = new.default

        static_syms = getattr(bin_, "static_symbols", [])
        if not static_syms:
            static_syms = getattr(bin_, "symbols", [])
        dynamic_syms = getattr(bin_, "dynamic_symbols", [])

        for is_dyn, syms in [(False, static_syms), (True, dynamic_syms)]:
            for sym in syms:
                name = sym.name
                if not name:
                    continue

                bind = str(sym.binding).split(".")[-1]
                typ = str(sym.type).split(".")[-1]

                if sym.shndx == lief.ELF.SYMBOL_SECTION_INDEX.UNDEF:
                    ndx = "UND"
                else:
                    ndx = str(sym.shndx)

                ver_name = None
                default = True

                if is_dyn and sym.has_version:
                    sym_ver = sym.symbol_version
                    if sym_ver and sym_ver.has_auxiliary_version:
                        ver_name = sym_ver.symbol_version_auxiliary.name
                    if sym_ver and (sym_ver.value & 0x8000):
                        default = False

                vis = str(sym.visibility).split(".")[-1]
                if vis == "HIDDEN":
                    default = False

                sym_obj = Symbol(
                    name=name,
                    bind=bind,
                    typ=typ,
                    ndx=ndx,
                    value=sym.value,
                    size=sym.size,
                    default=default,
                    version=ver_name,
                )

                if name not in by_name:
                    by_name[name] = sym_obj
                    order.append(name)
                else:
                    _merge(by_name[name], sym_obj, new_from_dynsym=is_dyn)

        out = [by_name[n] for n in order]
        if not out:
            error(f"failed to analyze symbols in {path}")
        return out

    def default_load_name(self, path: str) -> str:
        self._require_lief()
        import lief
        try:
            bin_ = lief.parse(path)
            if bin_ and isinstance(bin_, lief.ELF.Binary):
                for entry in bin_.dynamic_entries:
                    if getattr(entry, "tag", None) == lief.ELF.DYNAMIC_TAGS.SONAME:
                        return getattr(entry, "name", os.path.basename(path))
        except Exception:
            pass
        return os.path.basename(path)

    def supports_vtables(self) -> bool:
        return True

    def collect_sections(self, path: str) -> list[SectionInfo]:
        self._require_lief()
        import lief
        secs: list[SectionInfo] = []
        try:
            bin_ = lief.parse(path)
            if not bin_ or not isinstance(bin_, lief.ELF.Binary):
                error(f"failed to analyze sections in {path}")
                return secs

            for sec in bin_.sections:
                if sec.has(lief.ELF.SECTION_FLAGS.ALLOC):
                    secs.append(SectionInfo(
                        name=sec.name,
                        address=sec.virtual_address,
                        offset=sec.offset,
                        size=sec.size,
                        flags="ALLOC"
                    ))
        except Exception:
            error(f"failed to analyze sections in {path}")
        return secs

    def collect_relocations(self, path: str) -> list[RelocationInfo]:
        self._require_lief()
        import lief

        rels: list[RelocationInfo] = []
        try:
            bin_ = lief.parse(path)
            if not bin_ or not isinstance(bin_, lief.ELF.Binary):
                error(f"failed to analyze relocations in {path}")
                return rels

            addr_syms: list[tuple[int, int, str]] = []
            for sym in getattr(bin_, "symbols", []):
                if sym.name and sym.value != 0:
                    sz = sym.size
                    end = sym.value + sz if sz > 0 else sym.value
                    addr_syms.append((sym.value, end, sym.name))
            addr_syms.sort(key=lambda t: t[0])

            def resolve_addr(addr: int) -> tuple[str, int] | None:
                if not addr_syms: return None
                for start, end, name in addr_syms:
                    if end > start and start <= addr < end: return name, addr - start
                    if end == start and addr == start: return name, 0
                best = None
                for start, _end, name in addr_syms:
                    if start <= addr:
                        best = (name, addr - start)
                    else:
                        break
                if best is None: return None
                name, delta = best
                if delta > 0x100000: return None
                return name, delta

            byteorder = "little" if bin_.header.identity_data == lief.ELF.ELF_DATA.LSB else "big"
            ptr_size = 8 if bin_.header.identity_class == lief.ELF.ELF_CLASS.CLASS64 else 4

            with open(path, "rb") as fh:
                for rel in getattr(bin_, "relocations", []):
                    r_offset = rel.address
                    r_info = getattr(rel, 'info', 0)

                    m_type = bin_.header.machine_type
                    type_val = rel.type
                    rel_type_name = str(type_val).split(".")[-1]

                    if not rel_type_name.startswith("R_"):
                        if m_type == lief.ELF.ARCH.x86_64:
                            rel_type_name = "R_X86_64_" + rel_type_name
                        elif m_type == lief.ELF.ARCH.i386:
                            rel_type_name = "R_386_" + rel_type_name
                        elif m_type == lief.ELF.ARCH.AARCH64:
                            rel_type_name = "R_AARCH64_" + rel_type_name
                        elif m_type == lief.ELF.ARCH.ARM:
                            rel_type_name = "R_ARM_" + rel_type_name
                        elif m_type == lief.ELF.ARCH.PPC64:
                            rel_type_name = "R_PPC64_" + rel_type_name
                        else:
                            rel_type_name = "R_" + rel_type_name

                    sym_name = rel.symbol.name if rel.has_symbol and rel.symbol and rel.symbol.name else ""
                    addend = getattr(rel, 'addend', 0)

                    if addend == 0 and getattr(rel, 'is_rela', False) == False:
                        try:
                            has_rela = bin_.has(lief.ELF.DYNAMIC_TAGS.RELA)
                        except Exception:
                            has_rela = False

                        if not has_rela:
                            try:
                                raw = bin_.get_content_from_virtual_address(rel.address, ptr_size)
                                if len(raw) == ptr_size:
                                    val = int.from_bytes(bytes(raw), byteorder=byteorder, signed=False)
                                    if val >= (1 << (ptr_size*8 - 1)):
                                        val -= (1 << (ptr_size*8))
                                    addend = val
                            except Exception:
                                pass

                    if not sym_name and addend:
                        got = resolve_addr(addend)
                        if got is not None:
                            sym_name, delta = got
                            addend = delta

                    rels.append(RelocationInfo(
                        offset=r_offset,
                        info=r_info,
                        typ=rel_type_name,
                        symbol_addend=(sym_name, addend)
                    ))
        except Exception:
            error(f"failed to analyze relocations in {path}")
        return rels

    def byteorder(self, path: str) -> str:
        self._require_lief()
        import lief
        try:
            bin_ = lief.parse(path)
            if bin_ and isinstance(bin_, lief.ELF.Binary) and bin_.header.identity_data == lief.ELF.ELF_DATA.LSB:
                return "little"
        except Exception:
            pass
        return "big"
