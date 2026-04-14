#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bisect
import configparser
import itertools
import os
import re
import string
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Callable, Any

import lief

ME: str = "implib-gen"

def set_me_from_argv0(argv0: str) -> None:
    global ME
    ME = os.path.basename(argv0)

def warn(msg: str) -> None:
    sys.stderr.write(f"{ME}: warning: {msg}\n")

def error(msg: str) -> None:
    sys.stderr.write(f"{ME}: error: {msg}\n")
    sys.exit(1)

def die(msg: str) -> None:
    sys.stderr.write(f"implib-gen.py: error: {msg}\n")
    sys.exit(1)

def info_printer(quiet: bool) -> Callable[[str], None]:
    return lambda msg: None if quiet else print(msg)

MAGIC_ELF: bytes = b"\x7fELF"
MAGIC_MACHO: set[bytes] = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}

@dataclass
class Symbol:
    name: str
    bind: str
    typ: str
    ndx: str
    value: int = 0
    size: int = 0
    default: bool = True
    version: Optional[str] = None
    demangled: Optional[str] = None

    @property
    def score(self) -> tuple[bool, bool, bool, bool, bool]:
        return self.ndx != "UND", self.bind != "LOCAL", self.typ != "NOTYPE", self.size > 0, self.value != 0

@dataclass
class SectionInfo:
    name: str
    address: int
    offset: int
    size: int
    flags: str

@dataclass
class RelocationInfo:
    offset: int
    info: int
    typ: str
    symbol_addend: tuple[str, int]

class BackendError(RuntimeError): pass

class BinaryBackend(ABC):
    format_name: str
    path: str
    arch: Optional[str]
    magic: bytes
    _bin: Any
    _loaded: bool
    _next_addr_map: dict[int, int]
    _func_sizes: dict[int, int]

    def __init__(self, path: str):
        self.path = path
        self.arch = None
        self._bin = None
        self._loaded = False
        try:
            with open(path, "rb") as f:
                self.magic = f.read(4)
        except OSError:
            self.magic = b""

    def set_arch(self, arch: str) -> None:
        self.arch = arch

    @property
    def is_def(self) -> bool:
        if self.path.lower().endswith(".def"): return True
        try:
            with open(self.path, "r", errors='ignore') as f:
                return any(f.readline().strip().upper() == "EXPORTS" for _ in range(10))
        except OSError:
            return False

    def _collect_def_symbols(self) -> list[Symbol]:
        out: list[Symbol] = []
        try:
            with open(self.path, "r") as f:
                exports_found = False
                for line in (l.split(';')[0].strip() for l in f if l.split(';')[0].strip()):
                    if line.upper() == "EXPORTS":
                        exports_found = True
                    elif exports_found:
                        if m := re.match(r'^\s+([A-Za-z0-9_]+)\s*$', line):
                            out.append(Symbol(m.group(1), "GLOBAL", "FUNC", "1", demangled=m.group(1)))
                        else:
                            break
        except Exception as e:
            error(f"failed to parse .def file '{self.path}': {e}")
        return out

    def _read_def_library_name(self) -> str | None:
        try:
            with open(self.path, "r") as f:
                for line in f:
                    if m := re.match(r"^(?:LIBRARY|NAME)\s+([A-Za-z0-9_.\-]+)$", line.strip(), re.I):
                        return m.group(1)
        except OSError:
            pass
        return os.path.splitext(os.path.basename(self.path))[0] + ".so"

    @property
    def binary(self) -> Any:
        if not self._loaded:
            self._loaded = True
            if self.is_def: return None
            try:
                if (parsed := lief.parse(self.path)) is None: raise BackendError(f"LIEF failed to parse '{self.path}'")

                if isinstance(parsed, lief.MachO.FatBinary):
                    # We don't support X86 mac
                    cpu = lief.MachO.Header.CPU_TYPE.ARM64
                    self._bin = parsed.take(cpu)
                    if self._bin is None:
                        raise BackendError(f"Mach-O FatBinary '{self.path}' does not contain an ARM64 slice.")
                else:
                    self._bin = parsed
            except Exception as e:
                error(str(e) if isinstance(e, BackendError) else f"LIEF failed to parse '{self.path}': {e}")
        return self._bin

    @abstractmethod
    def matches(self) -> bool: ...

    @abstractmethod
    def collect_symbols(self) -> list[Symbol]: ...

    def read_data(self, address: int, size: int) -> bytes:
        try:
            return bytes(self.binary.get_content_from_virtual_address(address, size)) if self.binary else b""
        except Exception:
            return b""

    def default_load_name(self) -> str:
        return self._read_def_library_name() or ""

    def collect_sections(self) -> list[SectionInfo]: return []
    def collect_relocations(self) -> list[RelocationInfo]: return []
    def supports_vtables(self) -> bool: return False
    def byteorder(self) -> str: return "little"

    def _get_exact_size(self, val: int, original_size: int = 0) -> int:
        if original_size > 0: return original_size
        if not val or not self.binary: return 0
        if not hasattr(self, "_func_sizes"):
            all_addrs = sorted({sym.value for sym in self.binary.symbols if sym.value != 0})
            self._next_addr_map = dict(zip(all_addrs, all_addrs[1:]))
            self._func_sizes = {f.address: f.size for f in self.binary.functions if f.size > 0}

        if val in self._func_sizes: return self._func_sizes[val]

        limit = self._next_addr_map.get(val)
        try:
            if sec := self.binary.section_from_virtual_address(val):
                sec_end = sec.virtual_address + sec.size
                limit = min(limit, sec_end) if limit else sec_end
        except Exception:
            pass

        return max(0, limit - val) if limit else 0


class ElfBackend(BinaryBackend):
    format_name: str = "elf"

    @property
    def binary(self) -> Optional[lief.ELF.Binary]:
        return super().binary

    @property
    def default_platform(self) -> str:
        return "linux"

    def matches(self) -> bool:
        return self.is_def or self.magic == MAGIC_ELF

    def collect_symbols(self) -> list[Symbol]:
        if not self.binary: return self._collect_def_symbols()
        by_name: dict[str, Symbol] = {}

        for sym in itertools.chain(self.binary.dynamic_symbols, self.binary.symbols):
            if not sym.name: continue

            ndx = "UND" if sym.imported or sym.shndx == 0 else "ABS" if sym.shndx == 0xFFF1 else "COM" if sym.shndx == 0xFFF2 else str(sym.shndx)

            ver_name, default = None, True
            if sym.has_version and sym.symbol_version:
                default = not (sym.symbol_version.value & 0x8000)
                if sym.symbol_version.symbol_version_auxiliary:
                    ver_name = sym.symbol_version.symbol_version_auxiliary.name

            if sym.visibility == lief.ELF.Symbol.VISIBILITY.HIDDEN:
                default = False

            s_obj = Symbol(name=sym.name, bind=sym.binding.name, typ=sym.type.name, ndx=ndx, value=sym.value,
                           size=self._get_exact_size(sym.value, sym.size), default=default,
                           version=ver_name, demangled=sym.demangled_name or sym.name)

            existing = by_name.get(sym.name)
            if not existing or s_obj.score > existing.score or (existing.version is None and s_obj.version is not None):
                if existing and s_obj.version is None: s_obj.version, s_obj.default = existing.version, existing.default
                by_name[sym.name] = s_obj
            elif s_obj.version is not None and existing.version is not None and s_obj.default and not existing.default:
                by_name[sym.name] = s_obj

        if not by_name: error(f"failed to analyze symbols in {self.path}")
        return list(by_name.values())

    def default_load_name(self) -> str:
        if self.binary is None: return self._read_def_library_name() or os.path.basename(self.path)
        for entry in self.binary.dynamic_entries:
            try:
                if int(entry.tag) == 14: return entry.name
            except Exception:
                pass
        return os.path.basename(self.path)

    def supports_vtables(self) -> bool: return True

    def collect_sections(self) -> list[SectionInfo]:
        return [SectionInfo(s.name, s.virtual_address, s.offset, s.size, "ALLOC") for s in self.binary.sections if
                s.has(lief.ELF.Section.FLAGS.ALLOC)] if self.binary else []

    def collect_relocations(self) -> list[RelocationInfo]:
        if not self.binary: return []

        addr_syms = sorted([(s.value, s.value + max(1, s.size), s.name) for s in self.binary.symbols if
                            s.name and s.value != 0 and not s.name.startswith(".")], key=lambda t: t[0])
        starts = [t[0] for t in addr_syms]
        is_i386 = self.binary.header.machine_type == lief.ELF.ARCH.I386

        rels: list[RelocationInfo] = []
        for rel in self.binary.relocations:
            rel_type = f"R_{rel.type.name}".replace("R_X86_", "R_386_") if is_i386 else f"R_{rel.type.name}"

            try: target_addr = rel.resolve()
            except Exception: target_addr = rel.addend + (rel.symbol.value if rel.has_symbol else 0)

            sym_name, addend = "", target_addr
            if rel.has_symbol and rel.symbol.name and not rel.symbol.name.startswith("."):
                sym_name, addend = rel.symbol.name, target_addr - rel.symbol.value
            elif starts:
                idx = bisect.bisect_right(starts, target_addr) - 1
                if idx >= 0:
                    start, end, name = addr_syms[idx]
                    if target_addr < end or target_addr - start <= 0x100000:
                        sym_name, addend = name, target_addr - start

            rels.append(RelocationInfo(rel.address, rel.info, rel_type, (sym_name, addend)))
        return rels

    def byteorder(self) -> str:
        return "little" if not self.binary or self.binary.header.identity_data == lief.ELF.Header.ELF_DATA.LSB else "big"


class MachOBackend(BinaryBackend):
    format_name: str = "macho"

    @property
    def binary(self) -> Optional[lief.MachO.Binary]:
        return super().binary

    def matches(self) -> bool:
        return self.magic in MAGIC_MACHO

    def default_load_name(self) -> str:
        if self.binary:
            try:
                if cmd := self.binary.get(lief.MachO.LoadCommand.TYPE.ID_DYLIB):
                    return os.path.basename(cmd.name)
            except Exception:
                pass
        return os.path.basename(self.path)

    def collect_symbols(self) -> list[Symbol]:
        if not self.binary: return []

        func_addrs = {f.address for f in self.binary.functions if f.size > 0}
        by_name: dict[str, Symbol] = {}

        for sym in self.binary.symbols:
            if not sym.name or sym.category == lief.MachO.Symbol.CATEGORY.NONE:
                continue

            name = sym.name[1:] if sym.name.startswith("_") else sym.name
            val, size = sym.value, sym.size

            try: sec = self.binary.section_from_virtual_address(val)
            except Exception: sec = None

            typ, bind, ndx, default = "OBJECT", "LOCAL", "0", True

            is_func = val in func_addrs
            if sec and not is_func:
                flags = lief.MachO.Section.FLAGS

                is_code = sec.has(flags.SOME_INSTRUCTIONS) or sec.has(flags.PURE_INSTRUCTIONS)
                is_stub = sec.type == lief.MachO.Section.TYPE.SYMBOL_STUBS
                is_exec = sec.has_segment and sec.segment and (sec.segment.init_protection & lief.MachO.SegmentCommand.VM_PROTECTIONS.X.value)

                if is_code or is_stub or is_exec:
                    is_func = True

            if is_func:
                typ = "FUNC"

            if sym.category == lief.MachO.Symbol.CATEGORY.UNDEFINED:
                ndx = "UND"
                bind = "WEAK" if sym.has_binding_info and sym.binding_info.weak_import else "GLOBAL"

            elif sym.category == lief.MachO.Symbol.CATEGORY.EXTERNAL:
                bind = "GLOBAL"
                if sym.has_export_info and sym.export_info:
                    flags = sym.export_info.flags_list
                    if lief.MachO.ExportInfo.FLAGS.WEAK_DEFINITION in flags: bind = "WEAK"
                    if lief.MachO.ExportInfo.FLAGS.REEXPORT in flags: typ = "FUNC"
                else:
                    default = False

            s_obj = Symbol(name, bind, typ, ndx, val, self._get_exact_size(val, size), default, None, demangled=sym.demangled_name or name)

            existing = by_name.get(name)
            if not existing or s_obj.score > existing.score:
                by_name[name] = s_obj

        if not by_name: error(f"failed to analyze symbols in {self.path}")
        return list(by_name.values())

    def supports_vtables(self) -> bool: return True

    def collect_sections(self) -> list[SectionInfo]:
        return [SectionInfo(s.name, s.virtual_address, s.offset, s.size,
                            "ALLOC" if s.has_segment and s.segment.name != "__PAGEZERO" else "") for s in
                self.binary.sections] if self.binary else []

    def collect_relocations(self) -> list[RelocationInfo]:
        rels: list[RelocationInfo] = []
        if not self.binary: return rels

        for rel in self.binary.relocations:
            sym_name = rel.symbol.name if rel.has_symbol and rel.symbol else ""
            if sym_name.startswith("_"): sym_name = sym_name[1:]
            rels.append(RelocationInfo(rel.address, 0, "SYMBOLIC" if sym_name else "RELATIVE", (sym_name, 0)))

        for b in self.binary.bindings:
            sym_name = b.symbol.name if b.has_symbol and b.symbol else ""
            if sym_name.startswith("_"): sym_name = sym_name[1:]
            rels.append(RelocationInfo(b.address, 0, "SYMBOLIC", (sym_name, b.addend)))

        return rels


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


def _read_unrelocated_data(backend: BinaryBackend, syms: dict[str, Symbol]) -> dict[str, bytes]:
    return {name: backend.read_data(s.value, s.size) for name, s in sorted(syms.items(), key=lambda it: it[1].value)}


def _collect_relocated_data(all_syms: list[Symbol], syms: dict[str, Symbol], bites: dict[str, bytes],
                            rels: list[RelocationInfo], ptr_size: int, reloc_types: set[str], *, byteorder: str,
                            demangled: dict[str, str]) -> dict[str, list]:
    data: dict[str, list] = {}
    addr_to_sym = {s.value: s.name for s in all_syms if s.value != 0}

    for name, s in sorted(syms.items()):
        b, dname = bites[name], demangled.get(name, "")
        if dname.startswith("typeinfo name") or "typeinfo name for" in dname:
            data[name] = [("byte", int(x)) for x in b]
            continue

        entries: list[tuple[str, Any]] = [("offset", int.from_bytes(b[i:i + ptr_size], byteorder=byteorder, signed=False)) for i in
                                          range(0, len(b), ptr_size)]
        for rel in rels:
            if rel.typ in reloc_types and s.value <= rel.offset < s.value + s.size:
                if (i := (rel.offset - s.value) // ptr_size) < len(entries):
                    sym_name, addend = rel.symbol_addend
                    if not sym_name and entries[i][0] == "offset":
                        sym_name, addend = addr_to_sym.get(entries[i][1] & 0x0000FFFFFFFFFFFF, ""), 0
                    if sym_name:
                        entries[i] = ("reloc", RelocationInfo(rel.offset, 0, rel.typ, (sym_name, addend)))
        data[name] = entries
    return data


def _generate_vtables(cls_syms: dict[str, Symbol], cls_data: dict) -> str:
    c_types = {"reloc": "const void *", "byte": "unsigned char", "offset": "size_t"}
    ss: list[str] = ["#ifdef __cplusplus\nextern \"C\" {\n#endif\n"]
    printed: set[str] = set()
    code_info: dict[str, tuple[str, str]] = {}

    for _, data in sorted(cls_data.items()):
        for typ, val in data:
            if typ == "reloc" and (sym_name := re.sub(r"@.*", "", val.symbol_addend[0])) and sym_name not in cls_syms and sym_name not in printed:
                printed.add(sym_name)
                ss.append(f"extern const char {sym_name}[];\n")

    for name, s in sorted(cls_syms.items()):
        data = cls_data[name]
        declarator = "const unsigned char %s[]" if data and data[0][0] == "byte" else "const struct { %s } %%s" % " ".join(
            f"{c_types[typ]} field_{i};" for i, (typ, _) in enumerate(data))

        vals = []
        for typ, val in data:
            if typ != "reloc":
                vals.append(f"{val}UL")
            else:
                sym_name = re.sub(r"@.*", "", val.symbol_addend[0])
                vals.append(f"(const char *)&{sym_name} + {val.symbol_addend[1]}" if sym_name else f"{val.symbol_addend[1]}UL")

        code_info[name] = (declarator, "{ %s }" % ", ".join(vals))

    for name, (decl, init) in sorted(code_info.items()):
        t_name = f"{name}_type"
        ss.append(f"typedef {decl % t_name};\n")
        ss.append(f"extern __attribute__((weak)) {t_name} {name};\n")
        ss.append(f"const {t_name} {name} = {init};\n")

    ss.append("#ifdef __cplusplus\n}  // extern \"C\"\n#endif\n")
    return "".join(ss)


class Generator:
    backend: BinaryBackend
    templates_dir: Path
    common_dir: Path
    info: Callable[[str], None]

    def __init__(self, backend: BinaryBackend, *, templates_dir: str, common_templates_dir: str,
                 info: Callable[[str], None]) -> None:
        self.backend = backend
        self.templates_dir = Path(templates_dir)
        self.common_dir = Path(common_templates_dir)
        self.info = info

    def run(self, *, input_path: str, outdir: str, stem: str, load_name: str, funs_allowlist: list[str] | None,
            opts: GenOptions) -> None:
        Path(outdir).mkdir(parents=True, exist_ok=True)
        all_exported_symbols = self.backend.collect_symbols()
        demangled = {s.name: s.demangled for s in all_exported_symbols if s.demangled}

        syms_list: list[Symbol] = []
        warned_versioned: bool = False

        for s in all_exported_symbols:
            if s.bind == "LOCAL" or s.typ == "NOTYPE" or s.ndx == "UND" or s.name in ("", "_init", "_fini"):
                continue
            if opts.no_weak_symbols and s.bind == "WEAK":
                continue

            if not s.default:
                if s.typ == "FUNC":
                    if not warned_versioned:
                        warn(f"library {input_path} contains hidden/versioned symbols which are NYI")
                        warned_versioned = True
                    if opts.verbose: self.info(f"Skipping hidden/versioned symbol {s.name}")
                continue

            syms_list.append(s)

        def is_vtable_name(name: str, dname: str) -> bool:
            return "vtable for " in dname or "typeinfo " in dname or "typeinfo name for " in dname or name.lstrip('_').startswith(("ZTV", "ZTI", "ZTS"))

        if exported_data := [s.name for s in syms_list if (s.typ in ("OBJECT", "COMMON", "TLS") or s.ndx == "COM") and (
                not opts.vtables or not is_vtable_name(s.name, demangled.get(s.name, "")))]:
            warn(f"library '{input_path}' contains data symbols which won't be intercepted: {', '.join(exported_data)}")

        all_funs = {s.name for s in syms_list if s.typ == "FUNC"}
        funs = sorted(all_funs) if funs_allowlist is None else [n for n in funs_allowlist if n in all_funs]

        if funs_allowlist is None:
            if not funs and not opts.quiet: warn(f"no public functions were found in {input_path}")
        elif missing := [n for n in funs_allowlist if n not in all_funs]:
            warn(f"some user-specified functions are not present in library: {', '.join(missing)}")

        if opts.verbose:
            self.info("Exported functions:")
            for i, fn in enumerate(funs):
                self.info(f"  {i}: {fn}")

        vtable_text = ""
        if opts.vtables:
            if not self.backend.supports_vtables(): error("vtables not supported for this file format")
            cls_tables: dict[str, dict[str, str]] = {}
            cls_syms: dict[str, Symbol] = {}

            for s in syms_list:
                dname = demangled.get(s.name, "")
                if m := re.match(r"^(vtable|typeinfo|typeinfo name) for (.*)", dname):
                    typ, cls_name = m.groups()
                    cls_tables.setdefault(cls_name, {})[typ] = s.name
                    cls_syms[s.name] = s
                elif is_vtable_name(s.name, dname):
                    name_no_und = s.name.lstrip('_')
                    for prefix, typ in [("ZTV", "vtable"), ("ZTI", "typeinfo"), ("ZTS", "typeinfo name")]:
                        if name_no_und.startswith(prefix):
                            cls_name = name_no_und[len(prefix):]
                            cls_tables.setdefault(cls_name, {})[typ] = s.name
                            cls_syms[s.name] = s
                            break

            if cls_syms:
                vtable_text = _generate_vtables(cls_syms, _collect_relocated_data(
                    all_exported_symbols, cls_syms, _read_unrelocated_data(self.backend, cls_syms),
                    self.backend.collect_relocations(), opts.ptr_size, opts.symbol_reloc_types,
                    byteorder=self.backend.byteorder(), demangled=demangled
                ))

        lib_suffix, tramp_file, init_file = re.sub(r"[^a-zA-Z_0-9]+", "_", stem), f"{stem}.tramp.S", f"{stem}.init.c"
        if not opts.quiet: self.info(f"Generating {tramp_file}...")

        with open(os.path.join(outdir, tramp_file), "w") as f:
            f.write(string.Template((self.templates_dir / "table.S.tpl").read_text()).substitute(lib_suffix=lib_suffix, table_size=opts.ptr_size * (len(funs) + 1)))
            tramp_tpl = string.Template((self.templates_dir / "trampoline.S.tpl").read_text())
            for i, name in enumerate(funs):
                f.write(tramp_tpl.substitute(lib_suffix=lib_suffix, sym=opts.symbol_prefix + name, offset=i * opts.ptr_size, number=i))

        if not opts.quiet: self.info(f"Generating {init_file}...")
        with open(os.path.join(outdir, init_file), "w") as f:
            f.write(string.Template((self.common_dir / "init.c.tpl").read_text()).substitute(
                lib_suffix=lib_suffix, load_name=load_name, dlopen_callback=opts.dlopen_callback,
                dlsym_callback=opts.dlsym_callback,
                has_dlopen_callback=int(bool(opts.dlopen_callback)), has_dlsym_callback=int(bool(opts.dlsym_callback)),
                no_dlopen=int(not opts.dlopen), lazy_load=int(opts.lazy_load), thread_safe=int(opts.thread_safe),
                sym_names=(",\n  ".join(f'"{name}"' for name in funs) + ",") if funs else ""
            ) + vtable_text)


def normalize_arch(raw: str) -> str:
    if raw == "arm64": return "aarch64"
    if raw.startswith("arm"): return "arm"
    if re.match(r"^i[0-9]86", raw): return "i386"
    if raw.startswith("amd64"): return "x86_64"
    return raw.split("-")[0]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("library")
    p.add_argument("--platform", choices=["linux", "osx"], default=None)
    p.add_argument("--target", default=os.uname().machine)
    p.add_argument("--outdir", "-o", default="./")
    p.add_argument("--symbol-list")
    p.add_argument("--symbol-prefix", default="")
    p.add_argument("--verbose", "-v", action="count", default=0)
    p.add_argument("-q", "--quiet", action="store_true")

    for name, default in [("dlopen", True), ("lazy-load", True), ("thread-safe", True), ("vtables", False)]:
        dest = name.replace("-", "_")
        p.add_argument(f"--{name}", dest=dest, action="store_true", default=default)
        p.add_argument(f"--no-{name}", dest=dest, action="store_false")

    p.add_argument("--no-weak-symbols", dest="no_weak_symbols", action="store_true", default=False)
    p.add_argument("--dlopen-callback", default="")
    p.add_argument("--dlsym-callback", default="")
    p.add_argument("--library-load-name", default=None)

    args = p.parse_args(argv)
    info = info_printer(args.quiet)

    platform = args.platform or ("osx" if sys.platform == "darwin" else "linux")

    m_backend = MachOBackend(args.library)
    e_backend = ElfBackend(args.library)

    if m_backend.matches():
        backend = m_backend
    elif e_backend.matches():
        backend = e_backend
    else:
        backend = m_backend if platform in ("osx", "darwin") else e_backend

    platform_root = Path(__file__).resolve().parent / "arch" / platform
    arch = normalize_arch(args.target)
    backend.set_arch(arch)

    cfg_path = platform_root / arch / "config.ini"
    if not cfg_path.exists(): die(f"unknown architecture '{arch}' for platform '{platform_root.name}'")

    cfg = configparser.ConfigParser(inline_comment_prefixes=";")
    cfg.read(cfg_path)

    stem = Path(args.library).name
    if stem.lower().endswith(".def"): stem = stem[:-4]

    opts = GenOptions(
        args.verbose, args.quiet, args.dlopen, args.lazy_load, args.thread_safe, args.vtables, args.no_weak_symbols,
        args.symbol_prefix, args.dlopen_callback,
        args.dlsym_callback, int(cfg["Arch"]["PointerSize"]), set(re.split(r"\s*,\s*", cfg["Arch"]["SymbolReloc"]))
    )

    funs_allowlist = None
    if args.symbol_list:
        with open(args.symbol_list, "r") as f:
            funs_allowlist = [line for l in f if (line := re.sub(r"#.*", "", l).strip())]

    Generator(backend, templates_dir=str(platform_root / arch), common_templates_dir=str(platform_root / "common"), info=info).run(
        input_path=args.library, outdir=args.outdir, stem=stem,
        load_name=args.library_load_name or backend.default_load_name(),
        funs_allowlist=funs_allowlist, opts=opts
    )
    return 0

if __name__ == "__main__":
    set_me_from_argv0(sys.argv[0])
    sys.exit(main())
