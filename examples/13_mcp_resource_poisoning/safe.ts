import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "safe-resource-demo", version: "1.0.0" });

// SAFE: Static, audited resource content — no user-controlled content in resource bodies
const POLICY_SECTIONS: Record<string, string> = {
  "code-of-conduct": "All employees must act with integrity and respect.",
  "data-handling": "Customer data is encrypted at rest and in transit.",
  "security": "Report security incidents to security@company.com within 24 hours.",
};

server.resource(
  "company_policy",
  new ResourceTemplate("policy://{section}", { list: undefined }),
  async (uri) => {
    const section = uri.pathname.replace(/^\//, "");
    const content = POLICY_SECTIONS[section] ?? "Section not found.";
    return {
      contents: [{ uri: uri.href, text: content }],
    };
  }
);
