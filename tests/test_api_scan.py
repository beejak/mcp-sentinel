import pytest
from httpx import ASGITransport, AsyncClient
from mcp_sentinel.api.main import app
from pathlib import Path

@pytest.mark.asyncio
async def test_health():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

@pytest.mark.asyncio
async def test_scan_file():
    # Use a known file
    file_path = Path("tests/fixtures/vulnerable_code_injection.py").absolute()
    
    if not file_path.exists():
        pytest.skip(f"Fixture file not found: {file_path}")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/api/v1/scan",
            json={"path": str(file_path)}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["target_path"] == str(file_path)
        assert "vulnerabilities" in data
        assert "duration" in data
