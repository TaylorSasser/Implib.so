from __future__ import annotations
import os

from implib.base import BinaryBackend, BackendError
from implib.model import Symbol, SectionInfo, RelocationInfo
from implib.log import error

_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}

class MachOBackend(BinaryBackend):
    format_name = "macho"
    def matches(self, path: str) -> bool:
        try:
            with open(path, "rb") as f:
                return f.read(4) in _MACHO_MAGICS
        except OSError:
            return False

    def _require_lief(self):
        try:
            import lief  # noqa: F401
        except ImportError as e:
            raise BackendError(
                "LIEF is required for Mach-O parsing but not installed. "
                "Install it (e.g., `uv add lief` or `pip install lief`)."
            ) from e

    def _get_binary(self, path: str):
        self._require_lief()
        import lief

        try:
            bin_ = lief.parse(path)
        except Exception:
            bin_ = None

        if bin_ is None:
            raise BackendError(f"LIEF failed to parse Mach-O '{path}'")

        if isinstance(bin_, lief.MachO.FatBinary):
            bin_ = bin_.at(0)

        return bin_

    def collect_symbols(self, path: str) -> list[Symbol]:
        try:
            bin_ = self._get_binary(path)
        except BackendError as e:
            error(str(e))
            return []

        out: list[Symbol] = []

        for sym in getattr(bin_, "exported_symbols", []):
            name = getattr(sym, "name", "")
            if not name:
                continue

            out.append(Symbol(
                name=name,
                bind="GLOBAL",
                typ="FUNC", # Mach-O doesn't explicitly type functions vs objects natively
                ndx="0",    # Placeholder for defined (non-UNDEF)
                value=getattr(sym, "value", 0),
                size=0,     # Mach-O symbol tables don't store explicit sizes
                default=True,
            ))

        # Fallback to exported_functions just in case
        if not out:
            for fn in getattr(bin_, "exported_functions", []):
                name = getattr(fn, "name", "")
                if not name:
                    continue

                out.append(Symbol(
                    name=name,
                    bind="GLOBAL",
                    typ="FUNC",
                    ndx="0",
                    value=getattr(fn, "address", 0),
                    size=0,
                    default=True,
                ))

        if not out:
            error(f"failed to analyze symbols in {path}")

        return out

    def default_load_name(self, path: str) -> str:
        self._require_lief()
        import lief

        try:
            bin_ = self._get_binary(path)

            # macOS dynamic libraries specify their canonical "install name" using LC_ID_DYLIB
            # This serves the same purpose as the DT_SONAME in ELF.
            if bin_ and bin_.has_command(lief.MachO.LOAD_COMMAND_TYPES.ID_DYLIB):
                cmd = bin_.get(lief.MachO.LOAD_COMMAND_TYPES.ID_DYLIB)
                if cmd and getattr(cmd, "name", ""):
                    return cmd.name.split("/")[-1]
        except Exception:
            pass

        return os.path.basename(path)

    def supports_vtables(self) -> bool:
        return False

    def collect_sections(self, path: str) -> list[SectionInfo]:
        secs: list[SectionInfo] = []
        try:
            bin_ = self._get_binary(path)
            for sec in getattr(bin_, "sections", []):
                secs.append(SectionInfo(
                    name=sec.name,
                    address=sec.virtual_address,
                    offset=sec.offset,
                    size=sec.size,
                    flags=str(sec.flags)
                ))
        except Exception:
            pass

        return secs

    def collect_relocations(self, path: str) -> list[RelocationInfo]:
        """Extracts resolved relocations utilizing LIEF's rebasing interpretation."""
        rels: list[RelocationInfo] = []
        try:
            bin_ = self._get_binary(path)
            for rel in getattr(bin_, "relocations", []):
                sym_name = rel.symbol.name if rel.has_symbol and rel.symbol else ""
                rels.append(RelocationInfo(
                    offset=rel.address,
                    info=0,
                    typ="SYMBOLIC" if sym_name else "RELATIVE",
                    symbol_addend=(sym_name, 0)
                ))
        except Exception:
            pass

        return rels

    def byteorder(self, path: str) -> str:
        # Modern Apple environments (macOS x86_64 and arm64) are Little Endian.
        return "little"
