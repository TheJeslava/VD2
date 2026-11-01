"""Compatibility entry point; use dataset_run_hybrid.py for new commands."""
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent))
from _dataset_tool_compat import forward as _forward

_forward(globals(), "dataset_run_hybrid")
