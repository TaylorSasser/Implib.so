import os
import sys

def set_me_from_argv0(argv0: str) -> None:
    global ME
    ME = os.path.basename(argv0)

def warn(msg: str) -> None:
    sys.stderr.write(f"{ME}: warning: {msg}\n")

def error(msg: str) -> "NoReturn":
    sys.stderr.write(f"{ME}: error: {msg}\n")
    raise SystemExit(1)

def die(msg: str) -> None:
    sys.stderr.write(f"implib-gen.py: error: {msg}\n")
    raise SystemExit(1)

def info_printer(quiet: bool):
    def _info(msg: str) -> None:
        if not quiet:
            print(msg)
    return _info
