import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "safe-redos-demo", version: "1.0.0" });

// SAFE: Rewritten without nested quantifiers; linear time complexity
// Also enforce input length limits before running regex
const EMAIL_RE = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const SLUG_RE  = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

server.tool("validate_email", { email: z.string().max(254) }, async ({ email }) => {
  const valid = EMAIL_RE.test(email);
  return { content: [{ type: "text", text: valid ? "Valid" : "Invalid" }] };
});

server.tool("validate_slug", { slug: z.string().max(128) }, async ({ slug }) => {
  const match = SLUG_RE.test(slug);
  return { content: [{ type: "text", text: match ? "Match" : "No match" }] };
});
