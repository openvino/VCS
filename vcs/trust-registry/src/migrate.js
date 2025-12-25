import { readFileSync } from "node:fs";
import { getConfig } from "./config.js";
import { makePool } from "./db.js";

async function main() {
  const cfg = getConfig();
  const pool = makePool(cfg.pgDsn);

  const sql = readFileSync(new URL("../sql/001_init.sql", import.meta.url), "utf8");
  await pool.query(sql);

  await pool.end();
  console.log("migrations: OK");
}

main().catch((e) => {
  console.error("migrations: ERROR", e);
  process.exit(1);
});
