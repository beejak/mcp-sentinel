import pytest
import asyncio
from pathlib import Path
import tempfile
import os
from mcp_sentinel.core.multi_engine_scanner import MultiEngineScanner
from mcp_sentinel.engines.static.static_engine import StaticAnalysisEngine

@pytest.mark.asyncio
async def test_caching_mechanism():
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("import os\nos.system('ls')\n")
        temp_path = Path(f.name)

    try:
        # Initialize scanner with only static engine for speed
        # Disable SAST and AI to be fast
        static_engine = StaticAnalysisEngine(enabled=True)
        scanner = MultiEngineScanner(engines=[static_engine])
        
        # 1. First scan - should miss cache
        result1 = await scanner.scan(temp_path)
        assert result1.status == "completed"
        # Since it's a temp file, cache miss is expected
        # Check that it took some time (though very fast)
        # Check vulnerability found
        assert len(result1.vulnerabilities) > 0
        
        # 2. Second scan - should hit cache
        result2 = await scanner.scan(temp_path)
        assert result2.status == "completed"
        assert result2.statistics.scanned_files == 0  # 0 scanned means cached
        assert len(result2.vulnerabilities) == len(result1.vulnerabilities)
        
        # 3. Modify file
        with open(temp_path, "w") as f:
            f.write("x = 1\n")
            
        # 4. Third scan - should miss cache and update it
        result3 = await scanner.scan(temp_path)
        assert result3.status == "completed"
        assert result3.statistics.scanned_files == 1 # Scanned again
        # Should have 0 vulnerabilities now (variable assignment is safe)
        assert len(result3.vulnerabilities) == 0
        
    finally:
        if temp_path.exists():
            os.unlink(temp_path)
