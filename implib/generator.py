# implib/generator.py
from __future__ import annotations
import os
import re
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Callable, Any

from implib.model import Symbol, SectionInfo, RelocationInfo
from implib.base import BinaryBackend
from implib.log import warn, error


@dataclass(frozen=True)
class GenOptions:
    verbose: int
    quiet: bool
    dlopen: bool
    lazy_load: bool
    thread_safe: bool
    vtables: bool
    no_weak_symbols: bool
    symbol_prefix: str
    dlopen_callback: str
    dlsym_callback: str
    ptr_size: int
    symbol_reloc_types: set[str]

InfoFn = Callable[[str], None]


class Generator:
    def __init__(
            self,
            backend: BinaryBackend,
            *,
            templates_dir: Path,
            common_templates_dir: Path,
            info: InfoFn,
    ) -> None:
        self.backend = backend
        self.templates_dir = templates_dir
        self.common_dir = common_templates_dir
        self.info = info

    def _read_unrelocated_data(self, input_path: str, syms: dict[str, Symbol]) -> dict[str, bytes]:
        data: dict[str, bytes] = {}
        for name, s in sorted(syms.items(), key=lambda it: it[1].value):
            data[name] = self.backend.read_data(input_path, s.value, s.size)
        return data

    def _collect_relocated_data(
            self,
            all_syms: list[Symbol],
            syms: dict[str, Symbol],
            bites: dict[str, bytes],
            rels: list[RelocationInfo],
            opts: GenOptions,
            byteorder: str,
            demangled: dict[str, str],
    ) -> dict[str, list[tuple[str, Any]]]:
        data: dict[str, list[tuple[str, Any]]] = {}
        addr_to_sym = {s.value: s.name for s in all_syms if s.value != 0}

        for name, s in sorted(syms.items()):
            b = bites.get(name)
            assert b is not None
            dname = demangled.get(name, "")
            if "typeinfo name for" in dname:
                data[name] = [("byte", int(x)) for x in b]
                continue

            entries: list[tuple[str, Any]] = []
            for i in range(0, len(b), opts.ptr_size):
                val = int.from_bytes(b[i : i + opts.ptr_size], byteorder=byteorder, signed=False)
                entries.append(("offset", val))

            start, finish = s.value, s.value + s.size
            for rel in rels:
                if rel.typ in opts.symbol_reloc_types and start <= rel.offset < finish:
                    idx = (rel.offset - start) // opts.ptr_size
                    if idx < len(entries):
                        sym_name, addend = rel.symbol_addend
                        if not sym_name:
                            # Try to resolve internal (anonymous) relocation
                            raw_addr = entries[idx][1]
                            masked_addr = raw_addr & 0x0000FFFFFFFFFFFF
                            sym_name = addr_to_sym.get(masked_addr, "")
                            addend = 0
                        
                        if sym_name:
                            entries[idx] = ("reloc", RelocationInfo(rel.offset, 0, rel.typ, (sym_name, addend)))
            data[name] = entries
        return data

    def _generate_vtable_code(self, cls_syms: dict[str, Symbol], cls_data: dict[str, list[tuple[str, Any]]]) -> str:
        c_types = {"reloc": "const void *", "byte": "unsigned char", "offset": "size_t"}
        ss: list[str] = ["#ifdef __cplusplus\nextern \"C\" {\n#endif\n"]

        # Forward declarations for external symbols referenced in vtables
        printed: set[str] = set()
        for data in cls_data.values():
            for typ, val in data:
                if typ == "reloc":
                    sname = re.sub(r"@.*", "", val.symbol_addend[0])
                    if sname and sname not in cls_syms and sname not in printed:
                        printed.add(sname)
                        ss.append(f"extern const char {sname}[];\n")

        # Type definitions and implementations
        code_info: dict[str, tuple[str, str]] = {}
        for name, data in sorted(cls_data.items()):
            is_typeinfo_name = (data and data[0][0] == "byte")
            if is_typeinfo_name:
                decl = "const unsigned char %s[]"
                vals = [f"{v}UL" for _, v in data]
            else:
                fields = " ".join(f"{c_types[t]} f{i};" for i, (t, _) in enumerate(data))
                decl = "const struct { %s } %%s" % fields
                vals = []
                for t, v in data:
                    if t != "reloc": vals.append(f"{v}UL")
                    else:
                        sname, addend = v.symbol_addend
                        sname = re.sub(r"@.*", "", sname)
                        vals.append(f"(const char *)&{sname} + {addend}" if sname else f"{addend}UL")
            code_info[name] = (decl, "{ %s }" % ", ".join(vals))

        for name, (decl, _) in sorted(code_info.items()):
            ss.append(f"typedef {decl % (name + '_type')};\nextern __attribute__((weak)) {name + '_type'} {name};\n")
        for name, (_, init) in sorted(code_info.items()):
            ss.append(f"const {name + '_type'} {name} = {init};\n")

        ss.append("#ifdef __cplusplus\n}  // extern \"C\"\n#endif\n")
        return "".join(ss)

    def run(
            self,
            *,
            input_path: str,
            outdir: Path,
            stem: str,
            load_name: str,
            funs_allowlist: Optional[list[str]],
            opts: GenOptions,
    ) -> None:
        outdir.mkdir(parents=True, exist_ok=True)
        all_exported_symbols = self.backend.collect_symbols(input_path)
        demangled = {s.name: s.demangled for s in all_exported_symbols if s.demangled}

        def is_vtable_name(s: Symbol) -> bool:
            dname = demangled.get(s.name, "")
            if any(x in dname for x in ["vtable for ", "typeinfo ", "typeinfo name for "]): return True
            n = s.name.lstrip('_')
            return n.startswith(("ZTV", "ZTI", "ZTS"))

        def is_exported(s: Symbol) -> bool:
            if s.bind == "LOCAL" or s.typ == "NOTYPE" or s.ndx == "UND" or not s.default: return False
            if s.name in ("", "_init", "_fini"): return False
            if opts.no_weak_symbols and s.bind == "WEAK": return False
            return True

        syms_list = [s for s in all_exported_symbols if is_exported(s)]
        exported_data = [s.name for s in syms_list if (s.typ in ("OBJECT", "COMMON", "TLS") or s.ndx == "COM") and (not opts.vtables or not is_vtable_name(s))]
        if exported_data:
            warn(f"library '{input_path}' contains data symbols which won't be intercepted: " + ", ".join(exported_data))

        all_funs = {s.name for s in syms_list if s.typ == "FUNC"}
        if funs_allowlist is None:
            funs = sorted(all_funs)
            if not funs and not opts.quiet: warn(f"no public functions were found in {input_path}")
        else:
            missing = [n for n in funs_allowlist if n not in all_funs]
            if missing: warn("some user-specified functions are not present in library: " + ", ".join(missing))
            funs = [n for n in funs_allowlist if n in all_funs]

        vtable_text = ""
        if opts.vtables:
            if not self.backend.supports_vtables(): error("vtables not supported for this file format")
            cls_syms = {s.name: s for s in syms_list if is_vtable_name(s)}
            if cls_syms:
                rels = self.backend.collect_relocations(input_path)
                bites = self._read_unrelocated_data(input_path, cls_syms)
                cls_data = self._collect_relocated_data(all_exported_symbols, cls_syms, bites, rels, opts, self.backend.byteorder(input_path), demangled)
                vtable_text = self._generate_vtable_code(cls_syms, cls_data)

        lib_suffix = re.sub(r"[^a-zA-Z_0-9]+", "_", stem)
        if not opts.quiet: self.info(f"Generating {stem}.tramp.S and {stem}.init.c...")

        table_tpl = (self.templates_dir / "table.S.tpl").read_text()
        tramp_tpl = string.Template((self.templates_dir / "trampoline.S.tpl").read_text())

        with (outdir / f"{stem}.tramp.S").open("w") as f:
            f.write(string.Template(table_tpl).substitute(lib_suffix=lib_suffix, table_size=opts.ptr_size * (len(funs) + 1)))
            for i, name in enumerate(funs):
                f.write(tramp_tpl.substitute(lib_suffix=lib_suffix, sym=opts.symbol_prefix + name, offset=i * opts.ptr_size, number=i))

        init_tpl = string.Template((self.common_dir / "init.c.tpl").read_text())
        init_text = init_tpl.substitute(
            lib_suffix=lib_suffix, load_name=load_name,
            dlopen_callback=opts.dlopen_callback, dlsym_callback=opts.dlsym_callback,
            has_dlopen_callback=int(bool(opts.dlopen_callback)), has_dlsym_callback=int(bool(opts.dlsym_callback)),
            no_dlopen=int(not opts.dlopen), lazy_load=int(opts.lazy_load), thread_safe=int(opts.thread_safe),
            sym_names=(",\n  ".join(f"\"{n}\"" for n in funs) + ",") if funs else ""
        )

        with (outdir / f"{stem}.init.c").open("w") as f:
            f.write(init_text)
            if vtable_text: f.write(vtable_text)
