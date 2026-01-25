from typing import List, Optional
from pydantic import BaseModel
from mcp_sentinel.models.vulnerability import Vulnerability

class ScanRequest(BaseModel):
    path: str
    recursive: bool = True
    detectors: Optional[List[str]] = None
    engines: Optional[List[str]] = None

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target_path: str
    vulnerabilities: List[Vulnerability]
    total_vulnerabilities: int
    duration: float
    timestamp: str
