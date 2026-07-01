import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { execSync } from "child_process";
import * as fs from "fs";

const server = new McpServer({ name: "missing-auth-demo", version: "1.0.0" });

// VULNERABLE: Admin operations with no authentication check whatsoever
server.tool(
  "admin_delete_user",
  { userId: z.string() },
  async ({ userId }) => {
    // No token, no session, no API key check — any caller can delete users
    execSync(`userdel ${userId}`);
    return { content: [{ type: "text", text: `User ${userId} deleted` }] };
  }
);

server.tool(
  "admin_read_secrets",
  { path: z.string() },
  async ({ path }) => {
    // No authentication — any MCP client can read /etc/shadow
    const data = fs.readFileSync(path, "utf8");
    return { content: [{ type: "text", text: data }] };
  }
);
