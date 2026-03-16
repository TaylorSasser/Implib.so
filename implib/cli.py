import argparse
import configparser
import os
import re
import sys
from pathlib import Path
from typing import Optional
from implib.elf import ElfBackend
from implib.macho import MachOBackend
from implib.generator import Generator, GenOptions
from implib.log import info_printer, die, warn, error

def detect_platform_default() -> str:
    return "osx" if sys.platform == "darwin" else "linux"


def normalize_arch(raw: str) -> str:
    if raw == "arm64":
        return "aarch64"
    if raw.startswith("arm"):
        return "arm"
    if re.match(r"^i[0-9]86", raw):
        return "i386"
    if raw.startswith("amd64"):
        return "x86_64"
    return raw.split("-")[0]

def resolve_repo_root() -> Path:
    return Path(__file__).resolve().parent.parent  # assumes implib/ is in repo root


def load_arch_config(platform_root: Path, arch: str) -> tuple[int, set[str]]:
    cfg_path = platform_root / arch / "config.ini"
    if not cfg_path.exists():
        die(f"unknown architecture '{arch}' for platform '{platform_root.name}'")
    cfg = configparser.ConfigParser(inline_comment_prefixes=";")
    cfg.read(str(cfg_path))
    ptr_size = int(cfg["Arch"]["PointerSize"])
    reloc_types = set(re.split(r"\s*,\s*", cfg["Arch"]["SymbolReloc"]))
    return ptr_size, reloc_types


def parse_symbol_list(path: Optional[str]) -> Optional[list[str]]:
    if path is None:
        return None
    out: list[str] = []
    with open(path, "r") as f:
        for line in re.split(r"\r?\n", f.read()):
            line = re.sub(r"#.*", "", line).strip()
            if line:
                out.append(line)
    return out


def pick_backend(path: str, platform: str):
    if platform == "osx":
        m = MachOBackend(path)
        if m.matches(): return m

    e = ElfBackend(path)
    if e.matches(): return e

    return MachOBackend(path) if platform == "osx" else ElfBackend(path)

def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("library")
    p.add_argument("--platform", choices=["linux", "osx"], default=None)
    p.add_argument("--target", default=os.uname().machine)
    p.add_argument("--outdir", "-o", default="./")
    p.add_argument("--symbol-list")
    p.add_argument("--symbol-prefix", default="")
    p.add_argument("--verbose", "-v", action="count", default=0)
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--dlopen", dest="dlopen", action="store_true", default=True)
    p.add_argument("--no-dlopen", dest="dlopen", action="store_false")
    p.add_argument("--lazy-load", dest="lazy_load", action="store_true", default=True)
    p.add_argument("--no-lazy-load", dest="lazy_load", action="store_false")
    p.add_argument("--thread-safe", dest="thread_safe", action="store_true", default=True)
    p.add_argument("--no-thread-safe", dest="thread_safe", action="store_false")
    p.add_argument("--vtables", dest="vtables", action="store_true", default=False)
    p.add_argument("--no-vtables", dest="vtables", action="store_false")
    p.add_argument("--no-weak-symbols", dest="no_weak_symbols", action="store_true", default=False)
    p.add_argument("--dlopen-callback", default="")
    p.add_argument("--dlsym-callback", default="")
    p.add_argument("--library-load-name", default=None)

    args = p.parse_args(argv)
    info = info_printer(args.quiet)

    platform = args.platform or detect_platform_default()
    backend = pick_backend(args.library, platform)

    repo_root = resolve_repo_root()
    platform_root = repo_root / "arch" / platform
    arch = normalize_arch(args.target)
    backend.set_arch(arch)
    ptr_size, _relocs = load_arch_config(platform_root, arch)

    stem = Path(args.library).name
    if stem.lower().endswith(".def"):
        stem = stem[:-4]
    load_name = args.library_load_name or backend.default_load_name()

    templates_dir = platform_root / arch
    common_dir = platform_root / "common"

    opts = GenOptions(
        verbose=args.verbose,
        quiet=args.quiet,
        dlopen=args.dlopen,
        lazy_load=args.lazy_load,
        thread_safe=args.thread_safe,
        vtables=args.vtables,
        no_weak_symbols=args.no_weak_symbols,
        symbol_prefix=args.symbol_prefix,
        dlopen_callback=args.dlopen_callback,
        dlsym_callback=args.dlsym_callback,
        ptr_size=ptr_size,
        symbol_reloc_types=_relocs
    )

    gen = Generator(
        backend,
        templates_dir=str(templates_dir),
        common_templates_dir=str(common_dir),
        info=info
    )

    gen.run(
        input_path=args.library,
        outdir=args.outdir,
        stem=stem,
        load_name=load_name,
        funs_allowlist=parse_symbol_list(args.symbol_list),
        opts=opts,
    )
    return 0
