from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional, Sequence, Any, Tuple
import os
import bisect

from implib.model import Symbol, SectionInfo, RelocationInfo
from implib.log import error

class BackendError(RuntimeError):
    pass

class BinaryBackend(ABC):
    def __init__(self):
        self.arch: Optional[str] = None
        self._current_path: Optional[str] = None
        self._current_bin: Any = None

    def set_arch(self, arch: str) -> None:
        self.arch = arch

    def _require_lief(self):
        try:
            import lief  # noqa: F401
        except ImportError as e:
            error(f"LIEF is required for {self.format_name} parsing but not installed. Error: {e!r}")

    @abstractmethod
    def _parse_lief_binary(self, path: str) -> Any:
        ...


    def _get_binary(self, path: str) -> Any:
        if self._current_path != path:
            self._require_lief()
            try:
                self._current_bin = self._parse_lief_binary(path)
            except Exception as e:
                self._current_bin = None
            self._current_path = path
        return self._current_bin

    def read_data(self, path: str, address: int, size: int) -> bytes:
        bin_ = self._get_binary(path)
        if bin_ is None:
            return b""
        try:
            return bytes(bin_.get_content_from_virtual_address(address, size))
        except Exception:
            return b""

    def collect_sections(self, path: str) -> list[SectionInfo]:
        bin_ = self._get_binary(path)
        if bin_ is None:
            return []
        secs: list[SectionInfo] = []
        for sec in bin_.sections:
            flags = self._get_section_flags(sec)
            secs.append(SectionInfo(
                sec.name, sec.virtual_address, sec.offset, sec.size, flags
            ))
        return secs

    def _get_section_flags(self, section: Any) -> str:
        return ""

    def _calculate_symbol_sizes(self, bin_: Any, symbols: list[Any]) -> dict[int, int]:
        all_addrs = sorted({sym.value for sym in bin_.symbols if sym.value != 0})
        sections = [(sec.virtual_address, sec.virtual_address + sec.size) for sec in bin_.sections]
        
        sizes = {}
        for sym_val in all_addrs:
            idx = bisect.bisect_right(all_addrs, sym_val)
            next_sym_addr = all_addrs[idx] if idx < len(all_addrs) else None
            
            sec_end = 0
            for start, end in sections:
                if start <= sym_val < end:
                    sec_end = end
                    break
            
            if next_sym_addr and next_sym_addr < sec_end:
                sizes[sym_val] = next_sym_addr - sym_val
            else:
                sizes[sym_val] = max(0, sec_end - sym_val)
        return sizes

    @property
    @abstractmethod
    def format_name(self) -> str:
        ...

    @abstractmethod
    def matches(self, path: str) -> bool:
        ...

    @abstractmethod
    def collect_symbols(self, path: str) -> list[Symbol]:
        ...

    @abstractmethod
    def default_load_name(self, path: str) -> str:
        ...

    def collect_relocations(self, path: str) -> list[RelocationInfo]:
        return []

    def supports_vtables(self) -> bool:
        return False

    def byteorder(self, path: str) -> str:
        return "little"
