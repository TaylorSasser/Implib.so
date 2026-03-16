from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional, Sequence

from implib.model import Symbol, SectionInfo, RelocationInfo

class BackendError(RuntimeError):
    pass

class BinaryBackend(ABC):
    def __init__(self):
        self.arch: Optional[str] = None

    def set_arch(self, arch: str) -> None:
        self.arch = arch

    @abstractmethod
    def read_data(self, path: str, address: int, size: int) -> bytes:
        ...

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

    def collect_sections(self, path: str) -> list[SectionInfo]:
        return []

    def collect_relocations(self, path: str) -> list[RelocationInfo]:
        return []

    def supports_vtables(self) -> bool:
        return False

    def byteorder(self, path: str) -> str:
        return "little"
