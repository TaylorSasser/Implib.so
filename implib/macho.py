from __future__ import annotations
import os
import lief

from implib.base import BinaryBackend, BackendError
from implib.model import Symbol, SectionInfo, RelocationInfo
from implib.log import error

_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}


class MachOBackend(BinaryBackend):
    format_name = "macho"

    def __init__(self):
        super().__init__()
        self._current_path = None
        self._current_bin = None

    def matches(self, path: str) -> bool:
        try:
            with open(path, "rb") as f:
                return f.read(4) in _MACHO_MAGICS
        except OSError:
            return False

    def _require_lief(self):
        try:
            import lief  # noqa: F401
        except ImportError as e:
            error(f"LIEF is required for Mach-O parsing but not installed. Error: {e!r}")

    def _get_binary(self, path: str):
        if self._current_path != path:
            self._require_lief()
            import lief
            try:
                # Compatibility layer for LIEF 0.14+ renames
                def get_lief_attr(mod, *names):
                    for name in names:
                        try:
                            # Handle nested attributes like MachO.Header.CPU_TYPE
                            parts = name.split('.')
                            obj = mod
                            for p in parts:
                                obj = getattr(obj, p)
                            return obj
                        except AttributeError:
                            continue
                    return None

                # LIEF 0.14+ parse() returns a FatBinary object
                fat_bin = lief.MachO.parse(path)
                if fat_bin is None:
                    raise BackendError(f"LIEF failed to parse Mach-O '{path}'")
                
                target_cpu = None
                if self.arch:
                    target_map = {
                        "aarch64": get_lief_attr(lief.MachO, "Header.CPU_TYPE.ARM64", "CPU_TYPES.ARM64"),
                        "x86_64": get_lief_attr(lief.MachO, "Header.CPU_TYPE.X86_64", "CPU_TYPES.X86_64"),
                        "i386": get_lief_attr(lief.MachO, "Header.CPU_TYPE.I386", "CPU_TYPES.I386"),
                        "arm": get_lief_attr(lief.MachO, "Header.CPU_TYPE.ARM", "CPU_TYPES.ARM"),
                    }
                    target_cpu = target_map.get(self.arch)
                
                if target_cpu:
                    try:
                        self._current_bin = fat_bin.take(target_cpu)
                    except Exception:
                        self._current_bin = fat_bin.at(0)
                else:
                    self._current_bin = fat_bin.at(0)

            except Exception as e:
                if isinstance(e, BackendError): raise
                raise BackendError(f"LIEF failed to parse Mach-O '{path}': {e}")

            self._current_path = path

        return self._current_bin

    def read_data(self, path: str, address: int, size: int) -> bytes:
        bin_ = self._get_binary(path)
        try:
            return bytes(bin_.get_content_from_virtual_address(address, size))
        except Exception:
            return b""

    def collect_symbols(self, path: str) -> list[Symbol]:
        try:
            bin_ = self._get_binary(path)
        except BackendError as e:
            error(str(e))
            return []

        # Compatibility for KIND renames (LIEF 0.14+)
        def get_lief_attr(mod, *names):
            for name in names:
                try:
                    parts = name.split('.')
                    obj = mod
                    for p in parts: obj = getattr(obj, p)
                    if obj is not None: return obj
                except AttributeError: continue
            return None

        EXP_REGULAR = get_lief_attr(lief.MachO, "ExportInfo.KIND.REGULAR", "EXPORT_SYMBOL_KINDS.REGULAR", "KIND.REGULAR", "ExportInfo.REGULAR")
        EXP_REEXPORT = get_lief_attr(lief.MachO, "ExportInfo.KIND.REEXPORT", "EXPORT_SYMBOL_KINDS.REEXPORT", "KIND.REEXPORT", "ExportInfo.REEXPORT")
        EXP_WEAK = get_lief_attr(lief.MachO, "ExportInfo.KIND.WEAK", "EXPORT_SYMBOL_KINDS.WEAK", "KIND.WEAK", "ExportInfo.WEAK")

        all_addrs = sorted({sym.value for sym in bin_.symbols if sym.value != 0})
        func_addrs = {f.address for f in getattr(bin_, "functions", [])}
        
        # Pre-cache section boundaries and segments for faster lookup
        sections_info = []
        for sec in getattr(bin_, "sections", []):
            sections_info.append((
                sec.virtual_address, 
                sec.virtual_address + sec.size, 
                sec.name, 
                getattr(sec, "segment_name", "")
            ))

        import bisect
        def get_exact_size(val: int) -> int:
            if not val: return 0
            idx = bisect.bisect_right(all_addrs, val)
            next_sym_addr = all_addrs[idx] if idx < len(all_addrs) else None
            
            sec_end = 0
            for s_start, s_end, _, _ in sections_info:
                if s_start <= val < s_end:
                    sec_end = s_end
                    break
            
            if next_sym_addr and next_sym_addr < sec_end:
                return next_sym_addr - val
            return max(0, sec_end - val)

        out: list[Symbol] = []
        for sym in getattr(bin_, "exported_symbols", []):
            name = sym.name
            if not name: continue

            if name.startswith("_"):
                name = name[1:]

            val = getattr(sym, "address", getattr(sym, "value", 0))
            size = get_exact_size(val)
            
            # 1. Try to find segment/section by address
            seg_name = ""
            sec_name = ""
            for s_start, s_end, n, s in sections_info:
                if s_start <= val < s_end:
                    sec_name, seg_name = n, s
                    break
            
            # 2. Determine type
            typ = "OBJECT"
            if seg_name in ("__DATA", "__DATA_CONST", "__BSS", "__COMMON"):
                typ = "OBJECT"
            elif seg_name == "__TEXT" or sec_name in ("__text", "__stubs", "__symbol_stub"):
                typ = "FUNC"
            elif val in func_addrs:
                typ = "FUNC"
            else:
                typ = "OBJECT"
            
            export_info = getattr(sym, "export_info", None)
            if export_info and EXP_REEXPORT is not None and export_info.kind == EXP_REEXPORT:
                typ = "FUNC"

            # 3. Binding
            bind = "GLOBAL"
            if export_info:
                if EXP_WEAK is not None and export_info.kind == EXP_WEAK:
                    bind = "WEAK"
            elif not getattr(sym, "is_external", True):
                bind = "LOCAL"

            out.append(Symbol(name, bind, typ, "0", val, size, True, None, demangled=name))

        if not out:
            error(f"failed to analyze symbols in {path}")

        return out

    def default_load_name(self, path: str) -> str:
        import lief
        try:
            bin_ = self._get_binary(path)
            # Compatibility for LOAD_COMMAND_TYPES.ID_DYLIB
            ID_DYLIB = None
            try:
                ID_DYLIB = lief.MachO.LoadCommand.TYPE.ID_DYLIB
            except AttributeError:
                ID_DYLIB = lief.MachO.LOAD_COMMAND_TYPES.ID_DYLIB

            if bin_ and bin_.has_command(ID_DYLIB):
                cmd = bin_.get(ID_DYLIB)
                if cmd and getattr(cmd, "name", ""):
                    # Prefer full path if it's @rpath or absolute
                    full_name = cmd.name
                    if full_name.startswith("@") or full_name.startswith("/"):
                        return full_name
                    return os.path.basename(full_name)
        except Exception:
            pass
        return os.path.basename(path)

    def supports_vtables(self) -> bool:
        return True

    def collect_sections(self, path: str) -> list[SectionInfo]:
        secs: list[SectionInfo] = []
        try:
            bin_ = self._get_binary(path)
            for sec in getattr(bin_, "sections", []):
                # Mach-O sections don't have ALLOC flag, but segments do.
                # If segment is not __PAGEZERO, it's generally allocated.
                flags = "ALLOC" if sec.has_segment and sec.segment.name != "__PAGEZERO" else ""
                secs.append(SectionInfo(
                    name=sec.name,
                    address=sec.virtual_address,
                    offset=sec.offset,
                    size=sec.size,
                    flags=flags
                ))
        except Exception:
            pass
        return secs

    def collect_relocations(self, path: str) -> list[RelocationInfo]:
        rels: list[RelocationInfo] = []
        try:
            bin_ = self._get_binary(path)
            # 1. Traditional relocations
            for rel in getattr(bin_, "relocations", []):
                sym_name = rel.symbol.name if rel.has_symbol and rel.symbol else ""
                if sym_name.startswith("_"): sym_name = sym_name[1:]
                typ = "SYMBOLIC" if sym_name else "RELATIVE"
                rels.append(RelocationInfo(rel.address, 0, typ, (sym_name, getattr(rel, "addend", 0))))
            
            # 2. Dyld bindings (Standard, Lazy, and Weak)
            binding_sources = [
                getattr(bin_, "bindings", []),
                getattr(bin_, "lazy_bindings", []),
                getattr(bin_, "weak_bindings", [])
            ]
            
            for source in binding_sources:
                for b in source:
                    sym_name = b.symbol.name if b.has_symbol and b.symbol else ""
                    if sym_name.startswith("_"): sym_name = sym_name[1:]
                    rels.append(RelocationInfo(b.address, 0, "SYMBOLIC", (sym_name, b.addend)))

            # 3. Rebases (Internal pointers)
            for r in getattr(bin_, "rebases", []):
                rels.append(RelocationInfo(r.address, 0, "RELATIVE", ("", 0)))

        except Exception:
            pass
        return rels

    def byteorder(self, path: str) -> str:
        return "little"
