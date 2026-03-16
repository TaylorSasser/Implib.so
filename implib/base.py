from __future__ import annotations
import os
import re
import lief
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple

from implib.log import error

MAGIC_ELF = b"\x7fELF"
MAGIC_MACHO = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}

@dataclass()
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

@dataclass()
class SectionInfo:
    name: str
    address: int
    offset: int
    size: int
    flags: str

@dataclass()
class RelocationInfo:
    offset: int
    info: int
    typ: str
    symbol_addend: Tuple[str, int]  # (symbol_name, addend)

class BackendError(RuntimeError):
    pass

class BinaryBackend(ABC):
    def __init__(self, path: str):
        self.path = path
        self.arch: Optional[str] = None
        self._bin = None
        self._loaded = False
        self.magic = b""
        try:
            with open(path, "rb") as f:
                self.magic = f.read(4)
        except OSError:
            pass

    def set_arch(self, arch: str) -> None:
        self.arch = arch

    @property
    def is_def(self) -> bool:
        if self.path.lower().endswith(".def"):
            return True
        try:
            with open(self.path, "r", errors='ignore') as f:
                for _ in range(10):
                    line = f.readline().strip().upper()
                    if line == "EXPORTS":
                        return True
        except OSError:
            pass
        return False

    def _collect_def_symbols(self) -> list[Symbol]:
        out: list[Symbol] = []
        try:
            with open(self.path, "r") as f:
                lines = f.readlines()
            exports_found = False
            for line in lines:
                line = line.strip()
                if not line or line.startswith(";"): continue
                if line.upper() == "EXPORTS":
                    exports_found = True
                    continue
                if not exports_found: continue
                m = re.match(r"^([A-Za-z0-9_]+)$", line)
                if m:
                    name = m.group(1)
                    out.append(Symbol(name, "GLOBAL", "FUNC", "1", 0, 0, True, None, demangled=name))
        except Exception as e:
            error(f"failed to parse .def file '{self.path}': {e}")
        return out

    def _read_def_library_name(self) -> str | None:
        try:
            with open(self.path, "r") as f:
                for line in f:
                    line = line.strip()
                    m = re.match(r"^(?:LIBRARY|NAME)\s+([A-Za-z0-9_.\-]+)$", line, re.I)
                    if m: return m.group(1)
        except Exception:
            pass
        return os.path.splitext(os.path.basename(self.path))[0] + ".so"

    @property
    def binary(self):
        if not self._loaded:
            self._loaded = True
            if self.is_def:
                return None
            try:
                fat_bin_or_bin = lief.parse(self.path)
                if fat_bin_or_bin is None:
                    raise BackendError(f"LIEF failed to parse '{self.path}'")
                    
                if isinstance(fat_bin_or_bin, lief.MachO.FatBinary):
                    target_cpu = None
                    if self.arch:
                        target_map = {
                            "aarch64": lief.MachO.Header.CPU_TYPE.ARM64,
                            "x86_64": lief.MachO.Header.CPU_TYPE.X86_64,
                            "i386": lief.MachO.Header.CPU_TYPE.X86,
                            "arm": lief.MachO.Header.CPU_TYPE.ARM,
                        }
                        target_cpu = target_map.get(self.arch)
                    
                    if target_cpu:
                        try:
                            self._bin = fat_bin_or_bin.take(target_cpu)
                        except Exception:
                            self._bin = fat_bin_or_bin.at(0)
                    else:
                        self._bin = fat_bin_or_bin.at(0)
                elif isinstance(fat_bin_or_bin, lief.ELF.Binary):
                    self._bin = fat_bin_or_bin
                else:
                    self._bin = fat_bin_or_bin
            except Exception as e:
                if isinstance(e, BackendError):
                    error(str(e))
                else:
                    error(f"LIEF failed to parse '{self.path}': {e}")
                self._bin = None

        return self._bin

    @property
    @abstractmethod
    def format_name(self) -> str:
        ...

    @abstractmethod
    def matches(self) -> bool:
        ...

    def read_data(self, address: int, size: int) -> bytes:
        if self.binary is None:
            return b""
        try:
            return bytes(self.binary.get_content_from_virtual_address(address, size))
        except Exception:
            return b""

    @abstractmethod
    def collect_symbols(self) -> list[Symbol]:
        ...

    @abstractmethod
    def default_load_name(self) -> str:
        ...

    def collect_sections(self) -> list[SectionInfo]:
        return []

    def collect_relocations(self) -> list[RelocationInfo]:
        return []

    def supports_vtables(self) -> bool:
        return False

    def byteorder(self) -> str:
        return "little"
