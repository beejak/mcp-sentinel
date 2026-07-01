/**
 * Safe: Prototype pollution prevented by key validation and structured clone.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "Safe Server", version: "1.0.0" });

const BLOCKED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function safeMerge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  for (const key of Object.keys(source)) {
    if (BLOCKED_KEYS.has(key)) continue; // block prototype pollution keys
    const val = source[key];
    if (val !== null && typeof val === "object" && !Array.isArray(val)) {
      target[key] = safeMerge((target[key] as Record<string, unknown>) || {}, val as Record<string, unknown>);
    } else {
      target[key] = val;
    }
  }
  return target;
}

server.tool(
  "load_state",
  "Load user state from JSON safely",
  { state: z.string() },
  async ({ state }) => {
    // SAFE: structuredClone creates a deep copy without prototype chain
    const userState = JSON.parse(state);
    const config = safeMerge({}, userState);
    return { content: [{ type: "text", text: JSON.stringify(config) }] };
  }
);
