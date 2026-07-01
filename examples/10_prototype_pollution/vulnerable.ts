/**
 * Vulnerable: Prototype pollution — PROTOTYPE_POLLUTION
 *
 * Run: mcp-sentinel scan examples/10_prototype_pollution/vulnerable.ts
 * Expected: HIGH PROTOTYPE_POLLUTION findings
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "Vulnerable Server", version: "1.0.0" });

// VULNERABLE: recursive merge without __proto__ guard
function merge(target: any, source: any): any {
  for (const key of Object.keys(source)) {
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key]; // __proto__ survives here
    }
  }
  return target;
}

server.tool(
  "load_state",
  "Load user state from JSON",
  { state: z.string().describe("JSON state string") },
  async ({ state }) => {
    const userState = JSON.parse(state);
    const config = {};
    // Attack: state = '{"__proto__":{"isAdmin":true}}'
    // After merge: ({}).isAdmin === true for ALL objects in this process
    merge(config, userState);
    return { content: [{ type: "text", text: JSON.stringify(config) }] };
  }
);

// VULNERABLE: Object.assign with JSON.parse
server.tool(
  "apply_patch",
  "Apply a configuration patch",
  { patch: z.string() },
  async ({ patch }) => {
    const settings = Object.assign({}, JSON.parse(patch));
    return { content: [{ type: "text", text: "applied" }] };
  }
);
