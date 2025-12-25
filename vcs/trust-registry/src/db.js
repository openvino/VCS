import pg from "pg";

export function makePool(pgDsn) {
  if (!pgDsn) throw new Error("PG_DSN is required");
  const { Pool } = pg;
  return new Pool({
    connectionString: pgDsn,
    max: parseInt(process.env.PG_POOL_MAX || "10", 10)
  });
}
