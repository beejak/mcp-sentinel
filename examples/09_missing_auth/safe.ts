import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "safe-auth-demo", version: "1.0.0" });

const ADMIN_TOKEN = process.env.ADMIN_SECRET_TOKEN;

function requireAdmin(token: string | undefined): void {
  if (!token || token !== ADMIN_TOKEN) {
    throw new Error("Unauthorized: valid admin token required");
  }
}

server.tool(
  "admin_delete_user",
  { userId: z.string(), adminToken: z.string() },
  async ({ userId, adminToken }) => {
    requireAdmin(adminToken);
    // Proceed only after authentication
    return { content: [{ type: "text", text: `User ${userId} scheduled for deletion` }] };
  }
);
