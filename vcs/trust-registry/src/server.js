import Fastify from "fastify";
import { getConfig } from "./config.js";
import { makePool } from "./db.js";

const cfg = getConfig();
const app = Fastify({ logger: true });

const pool = makePool(cfg.pgDsn);

/**
 * Very simple admin auth.
 * If ADMIN_TOKEN is empty, admin endpoints are NOT protected
 * (recommended only when running behind a trusted reverse proxy).
 */
function adminAuth(req, reply) {
  if (!cfg.adminToken) return;

  const hdr = req.headers["authorization"] || "";
  const token = hdr.startsWith("Bearer ")
    ? hdr.slice("Bearer ".length)
    : "";

  if (token !== cfg.adminToken) {
    reply.code(401).send({ error: "unauthorized" });
  }
}

app.get("/healthz", async () => ({ ok: true }));

/**
 * Evaluate wallet trust for issuance or presentation flows.
 *
 * Decision order:
 * 1. ALLOW_ALL=true  -> always allowed
 * 2. No wallet DID  -> allowed (legacy / compatibility mode)
 * 3. Exact DID match (wallet, not revoked)
 * 4. Domain-based trust (wallet, not revoked)
 * 5. Otherwise -> denied
 */
async function evaluateWallet(body) {
  const walletDID =
    body?.wallet_did ||
    body?.walletDID ||
    body?.walletDid ||
    body?.wallet ||
    "";

  // Global bypass (useful while migrating / testing)
  if (cfg.allowAll) {
    return {
      result: "allowed",
      data: { client_attestation_requested: false },
      message: "allow-all enabled"
    };
  }

  // Compatibility mode: some legacy flows do not send wallet DID
  if (!walletDID) {
    return {
      result: "allowed",
      data: { client_attestation_requested: false },
      message: "wallet DID missing (compatibility mode)"
    };
  }

  // ---- 1. Check explicit wallet DID trust
  const { rows } = await pool.query(
    `
    select trusted, reason
    from trust_entries
    where did = $1
      and subject_type = 'wallet'
      and revoked_at is null
    limit 1
    `,
    [walletDID.trim()]
  );

  if (rows[0]?.trusted) {
    return {
      result: "allowed",
      data: { client_attestation_requested: false }
    };
  }

  // ---- 2. Optional fallback: domain-based trust
  const domain =
    body?.domain ||
    body?.wallet_domain ||
    body?.walletDomain ||
    "";

  if (domain) {
    const { rows: drows } = await pool.query(
      `
      select trusted, reason
      from trust_entries
      where domain = $1
        and subject_type = 'wallet'
        and revoked_at is null
      order by updated_at desc
      limit 1
      `,
      [String(domain).trim().toLowerCase()]
    );

    if (drows[0]?.trusted) {
      return {
        result: "allowed",
        data: { client_attestation_requested: false }
      };
    }
  }

  // ---- 3. Default: denied
  const reason =
    rows[0]?.reason ||
    "wallet not trusted";

  return {
    result: "denied",
    data: { client_attestation_requested: false },
    message: reason
  };
}

// ---- Wallet-facing endpoints (called by wallet-sdk / vc-rest)

app.post("/wallet/interactions/issuance", async (req, reply) => {
  try {
    const out = await evaluateWallet(req.body);
    reply.send(out);
  } catch (e) {
    req.log.error(e);
    reply.code(500).send({
      result: "denied",
      message: "internal error"
    });
  }
});

app.post("/wallet/interactions/presentation", async (req, reply) => {
  try {
    const out = await evaluateWallet(req.body);
    reply.send(out);
  } catch (e) {
    req.log.error(e);
    reply.code(500).send({
      result: "denied",
      message: "internal error"
    });
  }
});

// ---- Admin endpoints

/**
 * List all trust entries (wallets, issuers, verifiers).
 */
app.get("/admin/trust", { preHandler: adminAuth }, async () => {
  const { rows } = await pool.query(
    `
    select
      did,
      subject_type,
      domain,
      trusted,
      reason,
      created_at,
      updated_at,
      revoked_at
    from trust_entries
    order by updated_at desc
    `
  );

  return rows;
});

/**
 * Get a single trust entry by DID.
 */
app.get("/admin/trust/:did", { preHandler: adminAuth }, async (req, reply) => {
  const did = req.params.did;

  const { rows } = await pool.query(
    `
    select
      did,
      subject_type,
      domain,
      trusted,
      reason,
      created_at,
      updated_at,
      revoked_at
    from trust_entries
    where did = $1
    `,
    [did]
  );

  if (!rows[0]) {
    return reply.code(404).send({ error: "not found" });
  }

  return rows[0];
});

/**
 * Create or update a trust entry.
 *
 * Body example:
 * {
 *   "trusted": true,
 *   "reason": "approved by ops",
 *   "subject_type": "wallet",
 *   "domain": "openvino.org"
 * }
 */
app.put("/admin/trust/:did", { preHandler: adminAuth }, async (req) => {
  const did = req.params.did;

  const trusted = !!req.body?.trusted;
  const reason = req.body?.reason || null;
  const subjectType = req.body?.subject_type || "wallet";
  const domain = req.body?.domain || null;

  await pool.query(
    `
    insert into trust_entries (did, subject_type, domain, trusted, reason)
    values ($1, $2, $3, $4, $5)
    on conflict (did) do update
    set
      subject_type = $2,
      domain = $3,
      trusted = $4,
      reason = $5,
      revoked_at = null,
      updated_at = now()
    `,
    [did, subjectType, domain, trusted, reason]
  );

  return { ok: true };
});

/**
 * Revoke a DID (soft revoke).
 */
app.delete("/admin/trust/:did", { preHandler: adminAuth }, async (req) => {
  const did = req.params.did;

  await pool.query(
    `
    update trust_entries
    set
      trusted = false,
      revoked_at = now(),
      reason = 'revoked',
      updated_at = now()
    where did = $1
    `,
    [did]
  );

  return { ok: true };
});

// ---- Start server

app.listen({ port: cfg.port, host: cfg.host }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});
