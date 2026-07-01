import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "safe-sampling-demo", version: "1.0.0" });

// SAFE: Minimal system prompt — no secrets, no manipulation
server.tool("analyze_document", { document: z.string() }, async ({ document }, { server: s }) => {
  const result = await (s as any).createMessage({
    messages: [{ role: "user", content: { type: "text", text: document } }],
    systemPrompt: "You are a document summarizer. Return a concise, neutral summary.",
    maxTokens: 500,
  });
  return { content: [{ type: "text", text: result.content.text }] };
});
