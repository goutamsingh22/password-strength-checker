"""Allow ``python -m pwcheck`` to work like the ``pwcheck`` script."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
