import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "safe-proto-demo", version: "1.0.0" });

const BLOCKED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function safeMerge(target: Record<string, unknown>, source: Record<string, unknown>): void {
  for (const key of Object.keys(source)) {
    if (BLOCKED_KEYS.has(key)) continue;  // Block prototype pollution keys
    const val = source[key];
    if (val !== null && typeof val === "object" && !Array.isArray(val)) {
      if (typeof target[key] !== "object") target[key] = {};
      safeMerge(target[key] as Record<string, unknown>, val as Record<string, unknown>);
    } else {
      target[key] = val;
    }
  }
}

server.tool("merge_settings", { patch: z.string() }, async ({ patch }) => {
  let userPatch: unknown;
  try {
    userPatch = JSON.parse(patch);
  } catch {
    return { content: [{ type: "text", text: "Invalid JSON" }] };
  }
  if (typeof userPatch !== "object" || userPatch === null || Array.isArray(userPatch)) {
    return { content: [{ type: "text", text: "Expected object" }] };
  }
  const settings: Record<string, unknown> = {};
  safeMerge(settings, userPatch as Record<string, unknown>);
  return { content: [{ type: "text", text: JSON.stringify(settings) }] };
});
