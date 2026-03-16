from __future__ import annotations
import os
import bisect
import lief
from implib.base import BinaryBackend, BackendError, MAGIC_MACHO, Symbol, SectionInfo, RelocationInfo
from implib.log import error

class MachOBackend(BinaryBackend):
    format_name = "macho"

    def matches(self) -> bool:
        return self.magic in MAGIC_MACHO

    def collect_symbols(self) -> list[Symbol]:
        if not self.binary:
            return []

        macho: lief.MachO.Binary = self.binary
        
        # Pre-cache for size calculations
        all_addrs = sorted({sym.value for sym in macho.symbols if sym.value != 0})
        next_addr_map = {all_addrs[i]: all_addrs[i+1] for i in range(len(all_addrs)-1)}
        func_sizes = {f.address: f.size for f in macho.functions if f.size > 0}
        func_addrs = set(func_sizes.keys())

        def get_exact_size(val: int) -> int:
            if not val: return 0
            
            # 1. Try LIEF's function metadata
            if val in func_sizes:
                return func_sizes[val]
            
            # 2. Fallback: distance to next symbol or section end
            next_sym_addr = next_addr_map.get(val)
            sec = macho.section_from_virtual_address(val)
            sec_end = (sec.virtual_address + sec.size) if sec else 0
            
            limit = next_sym_addr if next_sym_addr and (not sec_end or next_sym_addr < sec_end) else sec_end
            return max(0, limit - val) if limit else 0

        out: list[Symbol] = []
        for sym in macho.exported_symbols:
            name = sym.name
            if not name: continue

            if name.startswith("_"):
                name = name[1:]

            val = sym.value
            size = get_exact_size(val)

            typ = "OBJECT"
            sec = macho.section_from_virtual_address(val)
            sec_name = sec.name if sec else ""
            seg_name = sec.segment.name if sec and sec.has_segment else ""

            if seg_name in ("__DATA", "__DATA_CONST", "__BSS", "__COMMON"):
                typ = "OBJECT"
            elif seg_name == "__TEXT" or sec_name in ("__text", "__stubs", "__symbol_stub"):
                typ = "FUNC"
            elif val in func_addrs:
                typ = "FUNC"
            elif sym.has_export_info and lief.MachO.ExportInfo.FLAGS.REEXPORT in sym.export_info.flags_list:
                typ = "FUNC"

            bind = "GLOBAL"
            if sym.has_export_info and lief.MachO.ExportInfo.FLAGS.WEAK_DEFINITION in sym.export_info.flags_list:
                bind = "WEAK"
            elif not sym.is_external:
                bind = "LOCAL"

            out.append(Symbol(name, bind, typ, "0", val, size, True, None, demangled=name))

        if not out:
            error(f"failed to analyze symbols in {self.path}")

        return out

    def default_load_name(self) -> str:
        if self.binary:
            try:
                for cmd in self.binary.commands:
                    if cmd.command == lief.MachO.LoadCommand.TYPE.ID_DYLIB:
                        full_name = cmd.name
                        if full_name.startswith("@") or full_name.startswith("/"):
                            return full_name
                        return os.path.basename(full_name)
            except Exception:
                pass
        return os.path.basename(self.path)

    def supports_vtables(self) -> bool:
        return True

    def collect_sections(self) -> list[SectionInfo]:
        secs: list[SectionInfo] = []
        if self.binary:
            try:
                for sec in self.binary.sections:
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

    def collect_relocations(self) -> list[RelocationInfo]:
        rels: list[RelocationInfo] = []
        if self.binary:
            try:
                for rel in self.binary.relocations:
                    sym_name = rel.symbol.name if rel.has_symbol and rel.symbol else ""
                    if sym_name.startswith("_"): sym_name = sym_name[1:]
                    typ = "SYMBOLIC" if sym_name else "RELATIVE"
                    rels.append(RelocationInfo(rel.address, 0, typ, (sym_name, 0)))
                
                for b in self.binary.bindings:
                    sym_name = b.symbol.name if b.has_symbol and b.symbol else ""
                    if sym_name.startswith("_"): sym_name = sym_name[1:]
                    rels.append(RelocationInfo(b.address, 0, "SYMBOLIC", (sym_name, b.addend)))

            except Exception:
                pass
        return rels

    def byteorder(self) -> str:
        return "little"
