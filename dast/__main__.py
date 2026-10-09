"""Module execution entry point for python -m dast."""

from __future__ import annotations

import sys
from dast.cli import main

if __name__ == "__main__":
    sys.exit(main())

