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
            # https://lief-project.github.io/doc/latest/api/python/macho/header.html#lief.MachO.Header.CPU_TYPE
            target_map = {
                "aarch64": 16777228, # ARM64
                "x86_64": 16777223,  # X86_64
                "i386": 7,           # X86
                "arm": 12,           # ARM
            }
            target_cpu = target_map.get(self.arch)
        
        if target_cpu:
            try: return fat_bin.take(target_cpu)
            except Exception: pass
        return fat_bin.at(0)

    def _get_section_flags(self, section: Any) -> str:
        # Mach-O sections don't have ALLOC flag, but segments do.
        return "ALLOC" if section.has_segment and section.segment.name != "__PAGEZERO" else ""

    def collect_symbols(self, path: str) -> list[Symbol]:
        bin_ = self._get_binary(path)
        if bin_ is None: return []

        all_symbols = list(bin_.symbols)
        sizes = self._calculate_symbol_sizes(bin_, all_symbols)
        func_addrs = {f.address for f in bin_.functions}
        
        sections_info = []
        for sec in bin_.sections:
            sections_info.append((sec.virtual_address, sec.virtual_address + sec.size, sec.name, sec.segment_name))

        out: list[Symbol] = []
        # Pre-process exported symbols
        exported_names = set()
        for sym in bin_.exported_symbols:
            name = sym.name
            if not name: continue
            
            export_info = sym.export_info
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

            flags = int(export_info.flags) if export_info else 0
            ei_str = str(export_info.kind) if export_info else ""
            
            if (flags & 8) or "REEXPORT" in ei_str: typ = "FUNC"

            bind = "GLOBAL"
            if (flags & 4) or "WEAK" in ei_str:
                bind = "WEAK"
            elif not export_info and not sym.is_external:
                # Only mark as LOCAL if it's not in the export trie AND is not external
                bind = "LOCAL"

            demangled = sym.demangled_name or name
            out.append(Symbol(name, bind, typ, "0", val, size, True, True, demangled=demangled))
            exported_names.add(name)

        # Include non-exported symbols for relocation resolution
        for sym in all_symbols:
            name = sym.name
            if not name or name in exported_names: continue
            
            val = sym.value
            size = sizes.get(val, 0)
            
            out.append(Symbol(name, "LOCAL", "OBJECT", "0", val, size, True, False, demangled=sym.demangled_name or name))

        if not out: error(f"failed to analyze symbols in {path}")
        return out

    def default_load_name(self, path: str) -> str:
        bin_ = self._get_binary(path)
        if not bin_: return os.path.basename(path)

        cmd = None
        for c in bin_.commands:
            if int(c.command) == 13: # ID_DYLIB
                cmd = c
                break

        if cmd and cmd.name:
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

        for rel in bin_.relocations:
            sym_name = rel.symbol.name if rel.has_symbol else ""
            typ = "SYMBOLIC" if sym_name else "RELATIVE"
            addend = getattr(rel, "addend", 0)
            rels.append(RelocationInfo(rel.address, 0, typ, (sym_name, addend)))
        
        for source in [bin_.bindings, bin_.lazy_bindings, bin_.weak_bindings]:
            for b in source:
                sym_name = b.symbol.name if b.has_symbol else ""
                rels.append(RelocationInfo(b.address, 0, "SYMBOLIC", (sym_name, b.addend)))

        for r in bin_.rebases:
            rels.append(RelocationInfo(r.address, 0, "RELATIVE", ("", 0)))
        return rels

    def byteorder(self, path: str) -> str:
        return "little"
