import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "proto-pollution-demo", version: "1.0.0" });

// VULNERABLE: Recursive merge without __proto__ guard (CWE-1321)
function deepMerge(target: any, source: any): any {
  for (const key of Object.keys(source)) {
    // Missing guard: should check key !== '__proto__' && key !== 'constructor'
    if (typeof source[key] === "object" && source[key] !== null) {
      target[key] = target[key] || {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

server.tool("merge_settings", { patch: z.string() }, async ({ patch }) => {
  const userPatch = JSON.parse(patch);
  const settings = {};
  deepMerge(settings, userPatch);  // Attacker sends {"__proto__": {"isAdmin": true}}
  return { content: [{ type: "text", text: JSON.stringify(settings) }] };
});

// Also vulnerable: direct __proto__ assignment via bracket notation
server.tool("set_property", { key: z.string(), value: z.string() }, async ({ key, value }) => {
  const obj: any = {};
  obj[key] = value;  // key = "__proto__" pollutes the prototype
  return { content: [{ type: "text", text: "OK" }] };
});
