from fastapi import APIRouter, Depends, HTTPException
from pathlib import Path
import uuid
from datetime import datetime

from mcp_sentinel.api.v1.schemas import ScanRequest, ScanResponse
from mcp_sentinel.api.deps import get_scanner
from mcp_sentinel.core.multi_engine_scanner import MultiEngineScanner

router = APIRouter()

@router.post("/scan", response_model=ScanResponse)
async def scan_path(
    request: ScanRequest,
    scanner: MultiEngineScanner = Depends(get_scanner)
):
    target_path = Path(request.path)
    if not target_path.exists():
        raise HTTPException(status_code=404, detail="Path not found")

    try:
        # scan method returns ScanResult object
        scan_result = await scanner.scan(target_path)
        
        # Calculate duration if not present in statistics
        duration = 0.0
        if scan_result.completed_at and scan_result.started_at:
            duration = (scan_result.completed_at - scan_result.started_at).total_seconds()
        elif scan_result.statistics.scan_duration_seconds:
            duration = scan_result.statistics.scan_duration_seconds
            
        return ScanResponse(
            scan_id=scan_result.scan_id,
            status=scan_result.status,
            target_path=scan_result.target,
            vulnerabilities=scan_result.vulnerabilities,
            total_vulnerabilities=len(scan_result.vulnerabilities),
            duration=duration,
            timestamp=scan_result.started_at.isoformat()
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
