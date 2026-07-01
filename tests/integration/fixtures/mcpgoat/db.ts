// MCPGoat db.ts — deliberately vulnerable SQLite database module
import { DatabaseSync } from "node:sqlite";

const db = new DatabaseSync(":memory:");
db.exec(`
  CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
  CREATE TABLE secrets  (id INTEGER PRIMARY KEY, name TEXT, secret TEXT);
`);

const ip = db.prepare("INSERT INTO products (id,name,price) VALUES (?,?,?)");
ip.run(1, "Blue Widget", 9.99);
ip.run(2, "Red Widget", 14.5);
ip.run(3, "Green Gadget", 29.0);
ip.run(4, "Yellow Gizmo", 4.25);

const is = db.prepare("INSERT INTO secrets (id,name,secret) VALUES (?,?,?)");
is.run(1, "db_root_password", "hunter2-do-not-share");
is.run(2, "ctf_flag_easy", "MCPGOAT{sql-injection-easy-flag}");
is.run(3, "ctf_flag_moderate", "MCPGOAT{sql-injection-moderate-flag}");
is.run(4, "ctf_flag_difficult", "MCPGOAT{sql-injection-difficult-flag}");

const BLACKLIST = [/UNION/, /--/, /;/, /\/\*/];

// VULNERABLE: raw string interpolation — SQL injection
export function searchProducts(term: string, lvl = "easy"): any[] {
  if (lvl === "difficult") {
    const sql = `SELECT count(*) AS n FROM products WHERE name LIKE '%${term}%'`;
    return db.prepare(sql).all() as any[];
  }
  const sql = `SELECT id, name, price FROM products WHERE name LIKE '%${term}%'`;
  return db.prepare(sql).all() as any[];
}

// SAFE: parameterized query
export function searchProductsSafe(term: string): any[] {
  return db.prepare("SELECT id, name, price FROM products WHERE name LIKE ?").all(`%${term}%`) as any[];
}

export { db };
