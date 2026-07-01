/**
 * Vulnerable: ReDoS — catastrophic backtracking — REDOS
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "Vulnerable Server", version: "1.0.0" });

server.tool(
  "validate_pattern",
  "Validate text against a pattern",
  { input: z.string() },
  async ({ input }) => {
    // VULNERABLE: (a+)+$ — exponential backtracking, locks Node.js event loop
    // Attack: input = "a".repeat(40) + "b"
    const result1 = /(a+)+$/.test(input);

    // VULNERABLE: alternation with nested quantifier
    const result2 = /^(\w+|\d+)+$/.test(input);

    return { content: [{ type: "text", text: String(result1 && result2) }] };
  }
);
