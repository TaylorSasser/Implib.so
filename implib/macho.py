from __future__ import annotations
import os
from typing import Any

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

    def matches(self, path: str) -> bool:
        try:
            with open(path, "rb") as f:
                return f.read(4) in _MACHO_MAGICS
        except OSError:
            return False

    def _parse_lief_binary(self, path: str) -> Any:
        import lief
        fat_bin = lief.MachO.parse(path)
        if fat_bin is None:
            raise BackendError(f"LIEF failed to parse Mach-O '{path}'")
        
        target_cpu = None
        if self.arch:
            target_map = {
                "aarch64": self._get_lief_attr(lief.MachO, "Header.CPU_TYPE.ARM64", "CPU_TYPES.ARM64"),
                "x86_64": self._get_lief_attr(lief.MachO, "Header.CPU_TYPE.X86_64", "CPU_TYPES.X86_64"),
                "i386": self._get_lief_attr(lief.MachO, "Header.CPU_TYPE.I386", "CPU_TYPES.I386"),
                "arm": self._get_lief_attr(lief.MachO, "Header.CPU_TYPE.ARM", "CPU_TYPES.ARM"),
            }
            target_cpu = target_map.get(self.arch)
        
        if target_cpu:
            try: return fat_bin.take(target_cpu)
            except Exception: pass
        return fat_bin.at(0)

    def _get_section_flags(self, section: Any) -> str:
        # Mach-O sections don't have ALLOC flag, but segments do.
        # If segment is not __PAGEZERO, it's generally allocated.
        return "ALLOC" if section.has_segment and section.segment.name != "__PAGEZERO" else ""

    def collect_symbols(self, path: str) -> list[Symbol]:
        bin_ = self._get_binary(path)
        if bin_ is None: return []

        import lief
        EXP_REEXPORT = self._get_lief_attr(lief.MachO, "ExportInfo.KIND.REEXPORT", "EXPORT_SYMBOL_KINDS.REEXPORT", "KIND.REEXPORT", "ExportInfo.REEXPORT")
        EXP_WEAK = self._get_lief_attr(lief.MachO, "ExportInfo.KIND.WEAK", "EXPORT_SYMBOL_KINDS.WEAK", "KIND.WEAK", "ExportInfo.WEAK")

        sizes = self._calculate_symbol_sizes(bin_, bin_.symbols)
        func_addrs = {f.address for f in getattr(bin_, "functions", [])}
        
        sections_info = []
        for sec in getattr(bin_, "sections", []):
            sections_info.append((sec.virtual_address, sec.virtual_address + sec.size, sec.name, getattr(sec, "segment_name", "")))

        out: list[Symbol] = []
        for sym in getattr(bin_, "exported_symbols", []):
            name = sym.name
            if not name: continue
            if name.startswith("_"): name = name[1:]

            val = getattr(sym, "address", getattr(sym, "value", 0))
            size = sizes.get(val, 0)
            
            seg_name, sec_name = "", ""
            for s_start, s_end, n, s in sections_info:
                if s_start <= val < s_end:
                    sec_name, seg_name = n, s
                    break
            
            typ = "OBJECT"
            if seg_name in ("__DATA", "__DATA_CONST", "__BSS", "__COMMON"): typ = "OBJECT"
            elif seg_name == "__TEXT" or sec_name in ("__text", "__stubs", "__symbol_stub") or val in func_addrs: typ = "FUNC"
            
            export_info = getattr(sym, "export_info", None)
            if export_info and EXP_REEXPORT is not None and export_info.kind == EXP_REEXPORT: typ = "FUNC"

            bind = "GLOBAL"
            if export_info and EXP_WEAK is not None and export_info.kind == EXP_WEAK: bind = "WEAK"
            elif not getattr(sym, "is_external", True): bind = "LOCAL"

            out.append(Symbol(name, bind, typ, "0", val, size, True, None, demangled=name))

        if not out: error(f"failed to analyze symbols in {path}")
        return out

    def default_load_name(self, path: str) -> str:
        import lief
        bin_ = self._get_binary(path)
        if not bin_: return os.path.basename(path)

        ID_DYLIB = self._get_lief_attr(lief.MachO, "LoadCommand.TYPE.ID_DYLIB", "LOAD_COMMAND_TYPES.ID_DYLIB")
        if ID_DYLIB and bin_.has_command(ID_DYLIB):
            cmd = bin_.get(ID_DYLIB)
            if cmd and getattr(cmd, "name", ""):
                full_name = cmd.name
                if full_name.startswith(("@", "/")): return full_name
                return os.path.basename(full_name)
        return os.path.basename(path)

    def supports_vtables(self) -> bool:
        return True

    def collect_relocations(self, path: str) -> list[RelocationInfo]:
        bin_ = self._get_binary(path)
        if not bin_: return []
        rels: list[RelocationInfo] = []

        for rel in getattr(bin_, "relocations", []):
            sym_name = rel.symbol.name if rel.has_symbol and rel.symbol else ""
            if sym_name.startswith("_"): sym_name = sym_name[1:]
            typ = "SYMBOLIC" if sym_name else "RELATIVE"
            rels.append(RelocationInfo(rel.address, 0, typ, (sym_name, getattr(rel, "addend", 0))))
        
        for source in [getattr(bin_, "bindings", []), getattr(bin_, "lazy_bindings", []), getattr(bin_, "weak_bindings", [])]:
            for b in source:
                sym_name = b.symbol.name if b.has_symbol and b.symbol else ""
                if sym_name.startswith("_"): sym_name = sym_name[1:]
                rels.append(RelocationInfo(b.address, 0, "SYMBOLIC", (sym_name, b.addend)))

        for r in getattr(bin_, "rebases", []):
            rels.append(RelocationInfo(r.address, 0, "RELATIVE", ("", 0)))
        return rels

    def byteorder(self, path: str) -> str:
        return "little"
