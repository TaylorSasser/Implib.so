# implibgen/generator.py
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

def _demangle_many(names: list[str]) -> list[str]:
    """
    Best-effort demangling without spawning c++filt.
    Uses optional 'cxxfilt' module when available; otherwise returns input names.
    """
    try:
        import cxxfilt  # type: ignore
    except ImportError:
        return list(names)
    out: list[str] = []
    for n in names:
        try:
            out.append(cxxfilt.demangle(n, external_only=False))
        except Exception:
            out.append(n)
    return out


def _read_unrelocated_data(input_path: str, syms: dict[str, Symbol], secs: list[SectionInfo]) -> dict[str, bytes]:
    """
    Read raw bytes for each symbol from file offsets computed via section mapping.
    """
    data: dict[str, bytes] = {}

    def is_symbol_in_section(sym: Symbol, sec: SectionInfo) -> bool:
        sec_end = sec.address + sec.size
        is_start_in_section = sec.address <= sym.value < sec_end
        is_end_in_section = sym.value + sym.size <= sec_end
        return is_start_in_section and is_end_in_section

    with open(input_path, "rb") as f:
        for name, s in sorted(syms.items(), key=lambda it: it[1].value):
            sec_matches = [sec for sec in secs if is_symbol_in_section(s, sec)]
            if len(sec_matches) != 1:
                error(
                    f"failed to locate section for interval [{s.value:x}, {s.value + s.size:x})"
                )
            sec = sec_matches[0]
            # Correct file offset: section file offset + (VA - section VA)
            file_off = sec.offset + (s.value - sec.address)
            f.seek(file_off)
            data[name] = f.read(s.size)

    return data


def _collect_relocated_data(
        syms: dict[str, Symbol],
        bites: dict[str, bytes],
        rels: list[RelocationInfo],
        ptr_size: int,
        reloc_types: set[str],
        *,
        byteorder: str,
        demangled: dict[str, str],
) -> dict[str, list[tuple[str, object]]]:
    """
    Reconstruct per-symbol  fields  from raw bytes, and replace pointer slots
    with ('reloc', rel_dict) when a relocation applies.
    """
    data: dict[str, list[tuple[str, object]]] = {}
    for name, s in sorted(syms.items()):
        b = bites.get(name)
        assert b is not None
        dname = demangled.get(name, "")
        if dname.startswith("typeinfo name"):
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
                    entries[i] = ("reloc", rel)
        data[name] = entries
    return data


def _generate_vtables(cls_tables: dict, cls_syms: dict[str, Symbol], cls_data: dict) -> str:
    """
    Same codegen strategy as the legacy script: emit weak externs and const definitions.
    """
    c_types = {
        "reloc": "const void *",
        "byte": "unsigned char",
        "offset": "size_t",
    }
    ss: list[str] = []
    ss.append(
        """\
#ifdef __cplusplus
extern "C" {
#endif
"""
    )

    # externs for referenced symbols not defined in this translation unit
    printed: set[str] = set()
    for _, data in sorted(cls_data.items()):
        for typ, val in data:
            if typ != "reloc":
                continue
            sym_name, _addend = val.symbol_addend
            sym_name = re.sub(r"@.*", "", sym_name)
            if sym_name and sym_name not in cls_syms and sym_name not in printed:
                printed.add(sym_name)
                ss.append(
                    f"""\
extern const char {sym_name}[];
"""
                )

    # build per-symbol struct layouts / initializers
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
                vals.append(f"(const char *)&{sym_name} + {addend}")
        code_info[name] = (declarator, "{ %s }" % ", ".join(vals))

    for name, (decl, _) in sorted(code_info.items()):
        type_name = name + "_type"
        type_decl = decl % type_name
        ss.append(
            f"""\
typedef {type_decl};
extern __attribute__((weak)) {type_name} {name};
"""
        )

    for name, (_, init) in sorted(code_info.items()):
        type_name = name + "_type"
        ss.append(
            f"""\
const {type_name} {name} = {init};
"""
        )

    ss.append(
        """\
#ifdef __cplusplus
}  // extern "C"
#endif
"""
    )
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
        syms = self.backend.collect_symbols(input_path)

        names = [s.name for s in syms]
        demangled_list = _demangle_many(names)
        demangled: dict[str, str] = {n: d for n, d in zip(names, demangled_list)}

        def is_exported(s: Symbol) -> bool:
            conditions = [
                s.bind != "LOCAL",
                s.typ != "NOTYPE",
                s.ndx != "UND",
                s.name not in ["", "_init", "_fini"],
                ]
            if opts.no_weak_symbols:
                conditions.append(s.bind != "WEAK")
            return all(conditions)

        syms = [s for s in syms if is_exported(s)]

        def is_data_symbol(s: Symbol) -> bool:
            dname = demangled.get(s.name, "")
            return (
                    s.typ == "OBJECT"
                    and not (" for " in dname and opts.vtables)
            )

        exported_data = [s.name for s in syms if is_data_symbol(s)]
        if exported_data:
            warn(
                f"library '{input_path}' contains data symbols which won't be intercepted: "
                + ", ".join(exported_data)
            )

        all_funs: set[str] = set()
        warned_versioned = False
        for s in syms:
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
            if self.backend.format_name != "elf":
                if self.backend.format_name == "def":
                    error("vtables not supported for .def files")
                error("vtables not supported for this file format")

            cls_tables: dict[str, dict[str, str]] = {}
            cls_syms: dict[str, Symbol] = {}

            for s in syms:
                dname = demangled.get(s.name, "")
                m = re.match(r"^(vtable|typeinfo|typeinfo name) for (.*)", dname)
                if m is not None:
                    typ, cls = m.groups()
                    cls_tables.setdefault(cls, {})[typ] = s.name
                    cls_syms[s.name] = s

            if cls_syms:
                secs = self.backend.collect_sections(input_path)
                rels = self.backend.collect_relocations(input_path)
                byteorder = self.backend.byteorder(input_path)

                bites = _read_unrelocated_data(input_path, cls_syms, secs)
                cls_data = _collect_relocated_data(
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
