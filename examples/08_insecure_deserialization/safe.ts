import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "safe-deser-demo", version: "1.0.0" });

const ConfigSchema = z.object({
  theme: z.string().optional(),
  language: z.string().optional(),
  pageSize: z.number().int().min(1).max(100).optional(),
});

server.tool("load_config", { payload: z.string() }, async ({ payload }) => {
  // SAFE: Parse with JSON.parse then validate with schema (no eval, no Object.assign from user data)
  let raw: unknown;
  try {
    raw = JSON.parse(payload);
  } catch {
    return { content: [{ type: "text", text: "Invalid JSON" }] };
  }

  const result = ConfigSchema.safeParse(raw);
  if (!result.success) {
    return { content: [{ type: "text", text: `Invalid config: ${result.error.message}` }] };
  }

  return { content: [{ type: "text", text: `Config loaded: ${JSON.stringify(result.data)}` }] };
});
