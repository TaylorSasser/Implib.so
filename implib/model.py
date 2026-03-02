from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Tuple

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
