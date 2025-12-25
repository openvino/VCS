export function getConfig() {
  return {
    port: parseInt(process.env.PORT || "8100", 10),
    host: process.env.HOST || "0.0.0.0",
    allowAll: (process.env.ALLOW_ALL || "false").toLowerCase() === "true",

    // Postgres
    pgDsn: process.env.PG_DSN || "",

    // opcional: auth simple para admin (si lo ponés detrás de nginx podés dejarlo vacío)
    adminToken: process.env.ADMIN_TOKEN || ""
  };
}
