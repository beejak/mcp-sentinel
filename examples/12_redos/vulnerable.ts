import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "redos-demo", version: "1.0.0" });

// VULNERABLE: Catastrophic backtracking regex applied to user input (CWE-1333)
const EMAIL_RE = /^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\.[a-zA-Z]+$/;  // nested quantifier: (x+)*
const SLUG_RE  = /(a+)+$/;                                         // classic ReDoS pattern

server.tool("validate_email", { email: z.string() }, async ({ email }) => {
  // Attacker sends "aaaaaaaaaaaaaaaaaaa!" — causes exponential backtracking
  const valid = EMAIL_RE.test(email);
  return { content: [{ type: "text", text: valid ? "Valid" : "Invalid" }] };
});

server.tool("validate_slug", { slug: z.string() }, async ({ slug }) => {
  // Even worse: /(a+)+$/ — O(2^n) for strings like "aaaaaaaaaaaaaaaaaaaX"
  const match = SLUG_RE.test(slug);
  return { content: [{ type: "text", text: match ? "Match" : "No match" }] };
});
