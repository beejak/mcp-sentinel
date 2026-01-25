from fastapi import FastAPI
from mcp_sentinel.api.v1.endpoints import scan

app = FastAPI(
    title="MCP Sentinel API",
    description="Enterprise-grade security scanner for Model Context Protocol (MCP) servers",
    version="4.1.0",
)

app.include_router(scan.router, prefix="/api/v1", tags=["scan"])

@app.get("/health")
def health_check():
    return {"status": "ok"}
