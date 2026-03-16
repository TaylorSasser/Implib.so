from __future__ import annotations
import os
import bisect
import lief
from implib.base import BinaryBackend, MAGIC_MACHO, Symbol, SectionInfo, RelocationInfo
from implib.log import error

class MachOBackend(BinaryBackend):
    format_name = "macho"

    def matches(self) -> bool:
        return self.magic in MAGIC_MACHO

    def collect_symbols(self) -> list[Symbol]:
        if not self.binary:
            return []

        all_addrs = sorted({sym.value for sym in self.binary.symbols if sym.value != 0})
        func_addrs = {f.address for f in self.binary.functions}
        
        sections_info = sorted([
            (
                sec.virtual_address, 
                sec.virtual_address + sec.size, 
                sec.name, 
                sec.segment.name if sec.has_segment else ""
            ) for sec in self.binary.sections
        ], key=lambda x: x[0])
        
        sec_starts = [x[0] for x in sections_info]

        def get_sec_info(val: int):
            idx = bisect.bisect_right(sec_starts, val) - 1
            if idx >= 0:
                s_start, s_end, n, s = sections_info[idx]
                if val < s_end:
                    return s_end, n, s
            return 0, "", ""

        def get_exact_size(val: int, sec_end: int) -> int:
            if not val: return 0
            idx = bisect.bisect_right(all_addrs, val)
            next_sym_addr = all_addrs[idx] if idx < len(all_addrs) else None
            
            if next_sym_addr and next_sym_addr < sec_end:
                return next_sym_addr - val
            return max(0, sec_end - val)

        out: list[Symbol] = []
        for sym in self.binary.exported_symbols:
            name = sym.name
            if not name: continue

            if name.startswith("_"):
                name = name[1:]

            val = sym.value
            sec_end, sec_name, seg_name = get_sec_info(val)
            size = get_exact_size(val, sec_end)
            
            typ = "OBJECT"
            export_info = sym.export_info if sym.has_export_info else None

            if seg_name in ("__DATA", "__DATA_CONST", "__BSS", "__COMMON"):
                typ = "OBJECT"
            elif seg_name == "__TEXT" or sec_name in ("__text", "__stubs", "__symbol_stub"):
                typ = "FUNC"
            elif val in func_addrs:
                typ = "FUNC"
            elif export_info and lief.MachO.ExportInfo.FLAGS.REEXPORT in export_info.flags_list:
                typ = "FUNC"

            bind = "GLOBAL"
            if export_info:
                if lief.MachO.ExportInfo.FLAGS.WEAK_DEFINITION in export_info.flags_list:
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
