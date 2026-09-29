"""Windows runtime compatibility bootstrap for the local PyTorch import.

The active Anaconda installation ships VC++ runtime 14.29 DLLs beside its
``python.exe``. They crash while PyTorch 2.12.1+cpu initializes ``c10.dll``.
Preloading the newer system VC++ runtime makes the Windows loader reuse that
compatible runtime. This does not replace or modify any Conda-managed file.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path


def preload_system_vc_runtime() -> None:
    """Load the system VC++ runtime before importing PyTorch on Windows."""
    if os.name != "nt":
        return
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    for name in ("msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
        path = system32 / name
        if path.exists():
            ctypes.WinDLL(str(path))
