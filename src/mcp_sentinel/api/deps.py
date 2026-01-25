from typing import Generator
from mcp_sentinel.core.multi_engine_scanner import MultiEngineScanner

_scanner = None

def get_scanner() -> MultiEngineScanner:
    global _scanner
    if _scanner is None:
        _scanner = MultiEngineScanner()
    return _scanner
