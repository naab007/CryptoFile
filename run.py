"""Frozen-exe entry point.

PyInstaller treats the entry script as a top-level module — if we pointed
it at ``cryptofile/__main__.py`` directly, relative imports (`from . import
batch`) would fail at runtime with "attempted relative import with no known
parent package". This shim loads ``cryptofile.__main__`` as a proper
package member so those relative imports resolve correctly.

``python -m cryptofile`` still works for development (it sets up the
package context itself via the ``-m`` flag).
"""
from __future__ import annotations

import sys

from cryptofile.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
