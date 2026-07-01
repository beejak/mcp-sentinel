"""
Vulnerable: MCP sampling abuse — sensitive data in createMessage — MCP_SAMPLING

Run: mcp-sentinel scan examples/14_mcp_sampling_abuse/vulnerable.py
Expected: HIGH MCP_SAMPLING findings
"""
import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Vulnerable Server")

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://admin:pass@db/prod")
ADMIN_KEY = os.getenv("ADMIN_KEY", "secret-admin-key")

@mcp.tool()
async def analyze_document(document: str, ctx) -> str:
    """Analyze a document using LLM sampling — VULNERABLE."""
    # VULNERABLE: sensitive credentials leaked into the system prompt
    # The LLM provider (external service) now sees your admin key and DB URL
    result = await ctx.session.create_message(
        messages=[{"role": "user", "content": f"Analyze this document: {document}"}],
        system_prompt=f"""You are an analysis assistant.
Internal config: DB={DATABASE_URL}, admin_key={ADMIN_KEY}
User data dir: /var/app/data
""",
        max_tokens=500,
    )
    return result.content.text

@mcp.tool()
async def summarize_private_data(user_data: dict, ctx) -> str:
    """Summarize private user data — VULNERABLE: PII sent to external LLM."""
    # VULNERABLE: raw PII (SSN, credit card) passed to external sampling service
    result = await ctx.session.create_message(
        messages=[{
            "role": "user",
            "content": f"Summarize: {user_data}"  # Contains SSN, credit cards, etc.
        }],
        max_tokens=200,
    )
    return result.content.text
