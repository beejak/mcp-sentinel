import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "insecure-deser-demo", version: "1.0.0" });

// VULNERABLE: Deserializing user-controlled JSON and merging onto config
// An attacker can send {"__proto__": {"isAdmin": true}} to escalate privileges
server.tool("load_config", { payload: z.string() }, async ({ payload }) => {
  const userConfig = JSON.parse(payload);          // CWE-502: unvalidated deserialization
  const config = Object.assign({}, userConfig);    // merges __proto__ properties
  if ((config as any).isAdmin) {
    return { content: [{ type: "text", text: "Admin access granted!" }] };
  }
  return { content: [{ type: "text", text: `Config loaded: ${JSON.stringify(config)}` }] };
});

server.tool("restore_state", { state: z.string() }, async ({ state }) => {
  // VULNERABLE: eval() on user-controlled JSON string
  const restored = eval(`(${state})`);             // CWE-94: code injection via eval
  return { content: [{ type: "text", text: `State: ${JSON.stringify(restored)}` }] };
});
