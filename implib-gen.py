#!/usr/bin/env python3
import sys
from implib.cli import main
from implib.log import set_me_from_argv0

if __name__ == "__main__":
  set_me_from_argv0(sys.argv[0])
  raise SystemExit(main())
