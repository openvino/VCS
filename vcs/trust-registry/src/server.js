import Fastify from "fastify";
import { getConfig } from "./config.js";
import { makePool } from "./db.js";

const cfg = getConfig();
const app = Fastify({ logger: true });

const pool = makePool(cfg.pgDsn);

function adminAuth(req, reply) {
  if (!cfg.adminToken) return; // si está vacío, no bloquea (dejalo behind nginx si querés)
  const hdr = req.headers["authorization"] || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice("Bearer ".length) : "";
  if (token !== cfg.adminToken) {
    reply.code(401).send({ error: "unauthorized" });
  }
}

app.get("/healthz", async () => ({ ok: true }));

// ---- Wallet-facing endpoints (misma idea que Go)
async function evaluateWallet(body) {
  const walletDID =
    body?.wallet_did || body?.walletDID || body?.walletDid || body?.wallet || "";

  if (cfg.allowAll || !walletDID) {
    return {
      result: "allowed",
      data: { client_attestation_requested: false },
      message: "allow-all enabled"
    };
  }

  const { rows } = await pool.query(
    "select trusted, reason from trust_entries where did=$1",
    [walletDID.trim()]
  );

  const row = rows[0];
  if (!row?.trusted) {
    const msg = row?.reason ? `wallet not trusted: ${row.reason}` : "wallet not trusted";
    return {
      result: "denied",
      data: { client_attestation_requested: false },
      message: msg
    };
  }

  return {
    result: "allowed",
    data: { client_attestation_requested: false }
  };
}

app.post("/wallet/interactions/issuance", async (req, reply) => {
  try {
    const out = await evaluateWallet(req.body);
    reply.send(out);
  } catch (e) {
    req.log.error(e);
    reply.code(500).send({ result: "denied", message: "internal error" });
  }
});

app.post("/wallet/interactions/presentation", async (req, reply) => {
  try {
    const out = await evaluateWallet(req.body);
    reply.send(out);
  } catch (e) {
    req.log.error(e);
    reply.code(500).send({ result: "denied", message: "internal error" });
  }
});

// ---- Admin endpoints
app.get("/admin/trust", { preHandler: adminAuth }, async () => {
  const { rows } = await pool.query(
    "select did, trusted, reason, updated_at from trust_entries order by updated_at desc"
  );
  return rows;
});

app.get("/admin/trust/:did", { preHandler: adminAuth }, async (req, reply) => {
  const did = req.params.did;
  const { rows } = await pool.query(
    "select did, trusted, reason, updated_at from trust_entries where did=$1",
    [did]
  );
  if (!rows[0]) return reply.code(404).send({ error: "not found" });
  return rows[0];
});

app.put("/admin/trust/:did", { preHandler: adminAuth }, async (req) => {
  const did = req.params.did;
  const trusted = !!req.body?.trusted;
  const reason = req.body?.reason || null;

  await pool.query(
    `insert into trust_entries (did, trusted, reason)
     values ($1, $2, $3)
     on conflict (did) do update
     set trusted=$2, reason=$3, updated_at=now()`,
    [did, trusted, reason]
  );

  return { ok: true };
});

app.delete("/admin/trust/:did", { preHandler: adminAuth }, async (req) => {
  const did = req.params.did;
  await pool.query(
    `insert into trust_entries (did, trusted, reason)
     values ($1, false, 'revoked')
     on conflict (did) do update
     set trusted=false, reason='revoked', updated_at=now()`,
    [did]
  );
  return { ok: true };
});

app.listen({ port: cfg.port, host: cfg.host }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});
