/**
 * Vulnerable: SSRF via unvalidated fetch — SSRF
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "Vulnerable Server", version: "1.0.0" });

server.tool(
  "fetch_page",
  "Fetch content from any URL",
  { url: z.string().url() },
  async ({ url }) => {
    // VULNERABLE: z.string().url() only checks format, not destination
    // Attack: url = "http://169.254.169.254/latest/meta-data/"
    const response = await fetch(url);
    const text = await response.text();
    return { content: [{ type: "text", text }] };
  }
);
