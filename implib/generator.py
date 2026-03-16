# implib/generator.py
from __future__ import annotations
import os
import re
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Callable

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


def _read_unrelocated_data(backend: BinaryBackend, input_path: str, syms: dict[str, Symbol]) -> dict[str, bytes]:
    data: dict[str, bytes] = {}
    for name, s in sorted(syms.items(), key=lambda it: it[1].value):
        data[name] = backend.read_data(input_path, s.value, s.size)
    return data


def _collect_relocated_data(
        all_syms: list[Symbol],
        syms: dict[str, Symbol],
        bites: dict[str, bytes],
        rels: list[RelocationInfo],
        ptr_size: int,
        reloc_types: set[str],
        *,
        byteorder: str,
        demangled: dict[str, str],
) -> dict[str, list[tuple[str, object]]]:
    data: dict[str, list[tuple[str, object]]] = {}
    
    # Pre-cache address to symbol mapping for fast resolution of anonymous relocations
    addr_to_sym = {s.value: s.name for s in all_syms if s.value != 0}

    for name, s in sorted(syms.items()):
        b = bites.get(name)
        assert b is not None
        dname = demangled.get(name, "")
        if dname.startswith("typeinfo name") or "typeinfo name for" in dname:
            data[name] = [("byte", int(x)) for x in b]
            continue

        entries: list[tuple[str, object]] = []
        for i in range(0, len(b), ptr_size):
            val = int.from_bytes(b[i : i + ptr_size], byteorder=byteorder, signed=False)
            entries.append(("offset", val))

        start = s.value
        finish = start + s.size

        for rel in rels:
            if rel.typ in reloc_types and start <= rel.offset < finish:
                i = (rel.offset - start) // ptr_size
                if i < len(entries):
                    sym_name, addend = rel.symbol_addend
                    if not sym_name:
                        # Try to resolve internal (anonymous) relocation using raw address from binary.
                        # On ARM64 macOS, pointers often have high bits set (PAC or rebase tags),
                        # so we mask them out to get the actual address.
                        raw_addr = entries[i][1]
                        masked_addr = raw_addr & 0x0000FFFFFFFFFFFF
                        sym_name = addr_to_sym.get(masked_addr, "")
                        addend = 0
                    
                    if sym_name:
                        # Map to symbolic reference in generated C
                        resolved_rel = RelocationInfo(rel.offset, 0, rel.typ, (sym_name, addend))
                        entries[i] = ("reloc", resolved_rel)
        data[name] = entries
    return data


def _generate_vtables(cls_tables: dict, cls_syms: dict[str, Symbol], cls_data: dict) -> str:
    c_types = {
        "reloc": "const void *",
        "byte": "unsigned char",
        "offset": "size_t",
    }
    ss: list[str] = []
    ss.append("#ifdef __cplusplus\nextern \"C\" {\n#endif\n")

    printed: set[str] = set()
    for _, data in sorted(cls_data.items()):
        for typ, val in data:
            if typ != "reloc":
                continue
            sym_name, _addend = val.symbol_addend
            sym_name = re.sub(r"@.*", "", sym_name)
            if sym_name and sym_name not in cls_syms and sym_name not in printed:
                printed.add(sym_name)
                ss.append(f"extern const char {sym_name}[];\n")

    code_info: dict[str, tuple[str, str]] = {}
    for name, s in sorted(cls_syms.items()):
        data = cls_data[name]
        is_typeinfo_name = False

        if data and data[0][0] == "byte":
            is_typeinfo_name = True

        if is_typeinfo_name:
            declarator = "const unsigned char %s[]"
        else:
            field_types = (f"{c_types[typ]} field_{i};" for i, (typ, _) in enumerate(data))
            declarator = "const struct { %s } %%s" % " ".join(field_types)

        vals: list[str] = []
        for typ, val in data:
            if typ != "reloc":
                vals.append(str(val) + "UL")
            else:
                sym_name, addend = val.symbol_addend
                sym_name = re.sub(r"@.*", "", sym_name)
                if sym_name:
                    vals.append(f"(const char *)&{sym_name} + {addend}")
                else:
                    vals.append(str(addend) + "UL")
        code_info[name] = (declarator, "{ %s }" % ", ".join(vals))

    for name, (decl, _) in sorted(code_info.items()):
        type_name = name + "_type"
        type_decl = decl % type_name
        ss.append(f"typedef {type_decl};\nextern __attribute__((weak)) {type_name} {name};\n")

    for name, (_, init) in sorted(code_info.items()):
        type_name = name + "_type"
        ss.append(f"const {type_name} {name} = {init};\n")

    ss.append("#ifdef __cplusplus\n}  // extern \"C\"\n#endif\n")
    return "".join(ss)


class Generator:
    def __init__(
            self,
            backend: BinaryBackend,
            *,
            templates_dir: str,
            common_templates_dir: str,
            info: InfoFn,
    ) -> None:
        self.backend = backend
        self.templates_dir = Path(templates_dir)
        self.common_dir = Path(common_templates_dir)
        self.info = info

    def run(
            self,
            *,
            input_path: str,
            outdir: str,
            stem: str,
            load_name: str,
            funs_allowlist: Optional[list[str]],
            opts: GenOptions,
    ) -> None:
        Path(outdir).mkdir(parents=True, exist_ok=True)
        all_exported_symbols = self.backend.collect_symbols(input_path)

        demangled: dict[str, str] = {s.name: s.demangled for s in all_exported_symbols if s.demangled}

        def is_exported(s: Symbol) -> bool:
            conditions = [
                s.bind != "LOCAL",
                s.typ != "NOTYPE",
                s.ndx != "UND",
                s.name not in ["", "_init", "_fini"],
                s.default,  # Only intercept default version of symbol
            ]
            if opts.no_weak_symbols:
                conditions.append(s.bind != "WEAK")
            return all(conditions)

        syms_list = [s for s in all_exported_symbols if is_exported(s)]

        def is_vtable_name(name: str, dname: str) -> bool:
            if "vtable for " in dname or "typeinfo " in dname or "typeinfo name for " in dname:
                return True
            # Strip all leading underscores for robust prefix check
            n = name.lstrip('_')
            return n.startswith(("ZTV", "ZTI", "ZTS"))

        def is_data_symbol(s: Symbol) -> bool:
            dname = demangled.get(s.name, "")
            # OBJECT, COMMON, and TLS symbols are data
            if s.typ not in ("OBJECT", "COMMON", "TLS") and s.ndx != "COM":
                return False
            # If vtables are on, we don't warn for intercepted vtable data
            if opts.vtables:
                return not is_vtable_name(s.name, dname)
            return True

        exported_data = [s.name for s in syms_list if is_data_symbol(s)]
        if exported_data:
            warn(
                f"library '{input_path}' contains data symbols which won't be intercepted: "
                + ", ".join(exported_data)
            )

        all_funs: set[str] = set()
        warned_versioned = False
        for s in syms_list:
            if s.typ != "FUNC":
                continue
            if not s.default:
                if not warned_versioned:
                    warn(f"library {input_path} contains versioned symbols which are NYI")
                    warned_versioned = True
                if opts.verbose:
                    self.info(f"Skipping versioned symbol {s.name}")
                continue
            all_funs.add(s.name)

        if funs_allowlist is None:
            funs = sorted(all_funs)
            if not funs and not opts.quiet:
                warn(f"no public functions were found in {input_path}")
        else:
            missing = [n for n in funs_allowlist if n not in all_funs]
            if missing:
                warn("some user-specified functions are not present in library: " + ", ".join(missing))
            funs = [n for n in funs_allowlist if n in all_funs]

        if opts.verbose:
            self.info("Exported functions:")
            for i, fn in enumerate(funs):
                self.info(f"  {i}: {fn}")

        vtable_text = ""
        if opts.vtables:
            if not self.backend.supports_vtables():
                error("vtables not supported for this file format")

            cls_tables: dict[str, dict[str, str]] = {}
            cls_syms: dict[str, Symbol] = {}

            for s in syms_list:
                dname = demangled.get(s.name, "")
                m = re.match(r"^(vtable|typeinfo|typeinfo name) for (.*)", dname)
                if m is not None:
                    typ, cls = m.groups()
                    cls_tables.setdefault(cls, {})[typ] = s.name
                    cls_syms[s.name] = s
                elif is_vtable_name(s.name, dname):
                    # Robust check for mangled prefixes
                    name_no_und = s.name.lstrip('_')
                    for prefix, typ in [("ZTV", "vtable"), ("ZTI", "typeinfo"), ("ZTS", "typeinfo name")]:
                        if name_no_und.startswith(prefix):
                            cls = name_no_und[len(prefix):]
                            cls_tables.setdefault(cls, {})[typ] = s.name
                            cls_syms[s.name] = s
                            break

            if cls_syms:
                rels = self.backend.collect_relocations(input_path)
                byteorder = self.backend.byteorder(input_path)

                bites = _read_unrelocated_data(self.backend, input_path, cls_syms)
                cls_data = _collect_relocated_data(
                    all_exported_symbols,
                    cls_syms,
                    bites,
                    rels,
                    opts.ptr_size,
                    opts.symbol_reloc_types,
                    byteorder=byteorder,
                    demangled=demangled,
                )
                vtable_text = _generate_vtables(cls_tables, cls_syms, cls_data)

        lib_suffix = re.sub(r"[^a-zA-Z_0-9]+", "_", stem)
        tramp_file = f"{stem}.tramp.S"
        init_file = f"{stem}.init.c"

        if not opts.quiet:
            self.info(f"Generating {tramp_file}...")
        table_tpl = (self.templates_dir / "table.S.tpl").read_text()
        tramp_tpl = string.Template((self.templates_dir / "trampoline.S.tpl").read_text())

        with open(os.path.join(outdir, tramp_file), "w") as f:
            f.write(string.Template(table_tpl).substitute(
                lib_suffix=lib_suffix,
                table_size=opts.ptr_size * (len(funs) + 1),
            ))
            for i, name in enumerate(funs):
                f.write(tramp_tpl.substitute(
                    lib_suffix=lib_suffix,
                    sym=opts.symbol_prefix + name,
                    offset=i * opts.ptr_size,
                    number=i,
                ))

        if not opts.quiet:
            self.info(f"Generating {init_file}...")

        sym_names = (",\n  ".join(f"\"{name}\"" for name in funs) + ",") if funs else ""
        init_text = string.Template((self.common_dir / "init.c.tpl").read_text()).substitute(
            lib_suffix=lib_suffix,
            load_name=load_name,
            dlopen_callback=opts.dlopen_callback,
            dlsym_callback=opts.dlsym_callback,
            has_dlopen_callback=int(bool(opts.dlopen_callback)),
            has_dlsym_callback=int(bool(opts.dlsym_callback)),
            no_dlopen=int(not opts.dlopen),
            lazy_load=int(opts.lazy_load),
            thread_safe=int(opts.thread_safe),
            sym_names=sym_names,
        )

        with open(os.path.join(outdir, init_file), "w") as f:
            f.write(init_text)
            if vtable_text:
                f.write(vtable_text)
