# VCS Deployment Guide

This repository contains everything needed to run the TrustBloc VC REST stack
used at `yankee.openvino.org`.  
Follow the steps below to bring up a fresh server (Ubuntu 22.04+ recommended)
that can issue and verify Verifiable Credentials via OpenID4VCI/VP.

## 0. Prerequisites

Install the base toolchain and runtime dependencies:

```bash
sudo apt update
sudo apt install -y git build-essential curl unzip jq \
    golang-go redis-server mongodb docker.io docker-compose

# Allow your user to run docker
sudo usermod -aG docker "$USER"
newgrp docker
```

> **TLS note**: the stack expects `server.crt`, `server.key` and
> `trustbloc-dev.ca.crt` under `/var/www/VCS/certs`.  
> Use real certificates for production (Let's Encrypt or a corporate CA)
> and keep the private key (`server.key`) outside of version control.

## 1. Clone this repository on the server

```bash
sudo mkdir -p /var/www
cd /var/www
sudo git clone https://github.com/openvino/VCS.git
sudo chown -R "$USER":"$USER" /var/www/VCS
cd /var/www/VCS
```

Repository layout (relative to `/var/www/VCS/`):

```
.
├── profiles/                  # Issuer/verifier profile definitions
├── vcs/                       # TrustBloc vc-rest source code
├── wallet/                    # Flutter wallet + mocks (for testing)
└── certs/                     # Place TLS materials here (not committed)
```

## 2. Datastores (MongoDB & Redis)

> **Note (yankee):** Minikube is legacy in this server and should be stopped/removed if still running.
> It is not required for the VCS deployment described in this guide.

You can either use the distro packages installed in step 0, or run them via Docker.

### MongoDB via Docker

```bash
docker rm -f mongodb
docker run -d --name mongodb \
  -p 27017:27017 \
  -v /var/www/VCS/data/mongodb:/data/db \
  --restart unless-stopped \
  mongo:6.0
```

Optional (create a dedicated user/password):
```bash
docker exec -it mongodb mongosh <<'EOF'
use admin
db.createUser({user: "vcs", pwd: "vcsPass123!", roles: [{role: "root", db: "admin"}]})
EOF
```
Adjust the Mongo connection string in `server.env` accordingly (e.g., `mongodb://vcs:vcsPass123!@localhost:27017`).

### Redis via Docker

```bash
docker rm -f redis
docker run -d --name redis \
  -p 6379:6379 \
  --restart unless-stopped \
  redis:7
```

## 3. Configure environment variables

`vcs/server.env` already contains a working configuration for yankee:

```bash
cd /var/www/VCS/vcs
cp server.env /var/www/VCS/vcs/server.env   # adjust as needed
```

Make sure the MongoDB and Redis URLs in `server.env` match your deployment.

## 4. Build the backend binaries

### 3.1 vc-rest

```bash
cd /var/www/VCS/vcs
make vc-rest
sudo cp .build/bin/vc-rest /usr/local/bin/vc-rest
```

### 3.2 Optional helper binaries

If you plan to run the sample webhook or other internal tools, build them via
`make sample-webhook`, `make vcs-stress`, etc.

## 5. Create systemd service for vc-rest

```bash
sudo tee /etc/systemd/system/vc-rest.service >/dev/null <<'EOF'
[Unit]
Description=TrustBloc VC REST backend
After=network.target mongod.service redis-server.service

[Service]
Type=simple
WorkingDirectory=/var/www/VCS/vcs
EnvironmentFile=/var/www/VCS/vcs/server.env
ExecStart=/usr/local/bin/vc-rest start
Restart=on-failure
User=vcsvc
Group=vcsvc

[Install]
WantedBy=multi-user.target
EOF

# Create the dedicated user + permissions if it does not exist
sudo useradd --system --home /var/www/VCS --shell /usr/sbin/nologin vcs
sudo chown -R vcs:vcs /var/www/VCS

sudo systemctl daemon-reload
sudo systemctl enable --now vc-rest
```

Monitor logs with `journalctl -u vc-rest -f`.

## 6. Linked Domains (DID configuration)

Generate the linked-domain credential and DID document:

```bash
cd /var/www/VCS/vcs
source server.env
cd tools/didconfig
go run .
```

This creates:

- `/var/www/VCS/.well-known/did-configuration.json`
- `/var/www/VCS/vcs/test/bdd/fixtures/file-server/dids/did-ion-bank-issuer.json`

## 7. DID Resolver

### 6.1 Configure resolver rules

`/var/www/VCS/vcs/test/bdd/fixtures/did-resolver/config.json` must contain:

```json
{
  "rules": [
    { "pattern": "^(did:ion:bank_issuer)$",
      "url": "https://yankee.openvino.org/files/dids/did-ion-bank-issuer.json" },
    { "pattern": "^(did:factom:.+)$",
      "url": "https://uniresolver.io/1.0/identifiers/$1" },
    { "pattern": "^(did:key:.+)$" },
    { "pattern": "^(did:orb:.+)$" },
    { "pattern": "^(did:web:.+)$" },
    { "pattern": "^(did:.+)$",
      "url": "http://uni-resolver-web:8080/1.0/identifiers/$1" }
  ]
}
```

### 6.2 Run the resolver container

```bash
cd /var/www/VCS
docker rm -f did-resolver.trustbloc.local
docker run -d --name did-resolver.trustbloc.local \
  -p 8072:8072 \
  -e DID_REST_HOST_URL=0.0.0.0:8072 \
  -e DID_REST_HOST_URL_EXTERNAL=https://yankee.openvino.org/resolver \
  -e DID_REST_CONFIG_FILE=/opt/did-resolver/config.json \
  -e DID_REST_TLS_SYSTEMCERTPOOL=true \
  -e DID_REST_TLS_CACERTS=/etc/tls/trustbloc-dev.ca.crt \
  -e DID_REST_DID_DOMAIN=testnet.orb.local \
  -v /var/www/VCS/vcs/test/bdd/fixtures/did-resolver/config.json:/opt/did-resolver/config.json \
  -v /var/www/VCS/certs:/etc/tls \
  ghcr.io/trustbloc-cicd/did-resolver:v0.0.1-snapshot-58ab302 start
```

Verify:

```bash
curl -k https://yankee.openvino.org/resolver/1.0/identifiers/did:ion:bank_issuer | jq '.service'
```

Expected URL: `https://yankee.openvino.org/.well-known/did-configuration.json`.


## 8. Trust Registry (Node.js + PostgreSQL)

The **Trust Registry** is a core supporting service used during **credential issuance and verification**
to decide whether a given **issuer**, **verifier**, or **wallet interaction** is trusted.

In practice, it answers questions such as:
- Is this issuer allowed to issue credentials?
- Is this verifier trusted to request presentations?
- Are wallet ↔ issuer / wallet ↔ verifier interactions permitted?

`vc-rest`, wallet flows, and some TrustBloc components consult the Trust Registry
during issuance and presentation flows.

---

### 8.1 Architecture & Design

On `yankee`, the Trust Registry is implemented as:

- **Node.js (Fastify) service**
- **PostgreSQL** as the persistence layer
- **Docker Compose** for lifecycle management

Why this setup:
- Replaces the old **static JSON / mock Go registry**
- Allows dynamic enable/disable of issuers and verifiers
- Suitable for production usage
- Can be managed by internal admin services later

The service listens on **localhost only**:

- `127.0.0.1:8100`
- Not publicly exposed

---

### 8.2 Files & Paths (Source of Truth)

Location in the repository:

```
/var/www/VCS/vcs/trust-registry/
├── Dockerfile
├── docker-compose.yml
├── .env
├── package.json
├── src/
│   ├── server.js        # HTTP API (Fastify)
│   ├── migrate.js       # DB migrations runner
│   └── ...
└── sql/
    └── schema.sql       # PostgreSQL schema
```

Docker resources created:

- Network: `trust-registry_trust_registry_net`
- Volume:  `trust-registry_trust_registry_pg`
- Containers:
  - `trust-registry` (Node service)
  - `trust-registry-db` (Postgres)
  - `trust-registry-migrate` (one-shot migration job)

---

### 8.3 Environment variables

Defined via Docker Compose:

- `PORT=8100`
- `HOST=0.0.0.0`
- `ALLOW_ALL=true`  
  > If `true`, the registry allows all checks (bootstrap / dev mode)

- `PG_DSN=postgres://trust_registry:trust_registry@trust-registry-db:5432/trust_registry`

Optional (recommended for future hardening):
- `ADMIN_TOKEN=<secret>` – protect admin endpoints

---

### 8.4 Start / Stop the Trust Registry

---

### 8.4.1 Accessing the Trust Registry database (PostgreSQL)

The Trust Registry database runs **inside the Docker container**
`trust-registry-db` and is **not exposed** on a public port.

To connect to the database, use `docker compose exec` (recommended).

#### Connect using psql (interactive)

From the directory containing `docker-compose.yml`:

```bash
docker compose ps
docker compose exec trust-registry-db psql -U trust_registry -d trust_registry
```

If using the legacy `docker-compose` binary:

```bash
docker-compose exec trust-registry-db psql -U trust_registry -d trust_registry
```

If you are not in the compose directory, you can also use:

```bash
docker exec -it trust-registry-db psql -U trust_registry -d trust_registry
```

---

#### Useful psql commands

Once inside `psql`:

```sql
-- list tables
\dt

-- describe the main trust table
\d trust_entries

-- list recent trust changes
select *
from trust_entries
order by updated_at desc
limit 50;

-- count entries by subject type (issuer / verifier / wallet)
select subject_type, count(*)
from trust_entries
group by subject_type
order by count(*) desc;
```

Exit `psql`:

```sql
\q
```

---

#### Inspect logs (debugging)

If an endpoint appears to hang or time out, inspect the service logs:

```bash
docker compose logs -f trust-registry
docker compose logs -f trust-registry-db
```

---

#### Reset database (DANGER)

⚠️ This removes **all trust registry data**.

```bash
docker compose down -v
docker compose up -d
```

Use this only for development or when explicitly rebuilding the registry.

#### Start (build + run)

```bash
cd /var/www/VCS/vcs/trust-registry
sudo docker compose up -d --build
```

Verify:

```bash
sudo docker compose ps
curl http://127.0.0.1:8100/healthz
```

Expected response:

```json
{ "ok": true }
```

---

#### Stop (keep data)

```bash
cd /var/www/VCS/vcs/trust-registry
sudo docker compose down
```

---

#### Stop + remove data (FULL RESET)

```bash
cd /var/www/VCS/vcs/trust-registry
sudo docker compose down -v
```

⚠️ This deletes the PostgreSQL volume and **all registry data**.

---

### 8.5 Ports & Security

- Exposed only on: `127.0.0.1:8100`
- No public access
- Accessed internally by:
  - `vc-rest`
  - wallet-related flows
  - future admin APIs

Verify it is NOT public:

```bash
curl http://$(hostname -I | awk '{print $1}'):8100/healthz || echo "not public (OK)"
```

---

### 8.6 Relationship with MongoDB & Redis

The Trust Registry **does NOT use**:
- MongoDB
- Redis

Those datastores are used by:
- `vc-rest`
- credential issuance state
- caching, sessions, and profiles

The Trust Registry is intentionally isolated and only depends on PostgreSQL.

---

### 8.7 Deprecated: Go-based Mock Trust Registry

⚠️ **Deprecated on yankee**

Previous deployments used:
- `wallet-sdk/mock-trust-registry` (Go binary)
- Static `rules.json`
- systemd unit: `mock-trust-registry.service`

This is now **disabled and masked**:

```bash
sudo systemctl disable --now mock-trust-registry.service
sudo systemctl mask mock-trust-registry.service
```

Do **NOT** re-enable this service.
The Node.js Trust Registry is the single source of truth.

---

### 8.8 Operational checklist

Quick sanity checks:

```bash
# containers
docker ps | grep trust-registry

# health
curl http://127.0.0.1:8100/healthz

# port binding
sudo ss -lntp | grep 8100
```

---

### 8.9 When to restart

Restart the Trust Registry if:
- Database schema changes
- Registry rules / data are modified
- Environment variables change

```bash
cd /var/www/VCS/vcs/trust-registry
sudo docker compose restart
```

---

### 8.10 Summary

- Trust Registry = **policy & trust decision service**
- Node.js + PostgreSQL
- Local-only, dockerized
- Required for issuance & verification flows
- Replaces legacy Go mock registry

### 7.2 Keycloak (real OAuth) + Cognito Auth Adapter (PROD on yankee)

On **yankee**, the default OAuth/token provider for the stack is now **Keycloak** (real IdP) plus a small compatibility layer called **cognito-auth-adapter**.

Why this exists:
- Some components/tools expect a Cognito-like token endpoint:
  - `POST /cognito/oauth2/token`
- Keycloak provides the real token issuance under:
  - `POST /realms/<realm>/protocol/openid-connect/token`
- The adapter exposes a Cognito-compatible endpoint on **:8095** and forwards internally to Keycloak.

#### Ports and URLs (yankee defaults)

- Keycloak: `http://127.0.0.1:8080`
- Adapter:  `http://127.0.0.1:8095/cognito/oauth2/token`

Realm/client used in this deployment:
- Realm: `vcs`
- Client ID: `rw_token`

#### Install / configure from scratch (server)

> Assumption: you already have Docker running (see prerequisites in section 0).

**A) Start Keycloak container** (example; adapt if you already run Keycloak via another method)

```bash
# Example container name used on yankee
docker rm -f vcs-keycloak || true

docker run -d --name vcs-keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest \
  start-dev
```

**B) Create the realm + client (rw_token)**

Use `kcadm.sh` from inside the container.

```bash
# Login to Keycloak admin
docker exec -i vcs-keycloak /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://127.0.0.1:8080 \
  --realm master \
  --user admin \
  --password admin

# Create realm (ignore if it exists)
docker exec -i vcs-keycloak /opt/keycloak/bin/kcadm.sh create realms -s realm=vcs -s enabled=true || true

# Create client (confidential) (ignore if it exists)
docker exec -i vcs-keycloak /opt/keycloak/bin/kcadm.sh create clients -r vcs \
  -s clientId=rw_token \
  -s enabled=true \
  -s publicClient=false \
  -s directAccessGrantsEnabled=true \
  -s serviceAccountsEnabled=true || true

# Fetch client internal id
CID="$(docker exec -i vcs-keycloak /opt/keycloak/bin/kcadm.sh get clients -r vcs -q clientId=rw_token | jq -r '.[0].id' | tr -d '\r\n')"
echo "CID=$CID"
```

**C) Set/rotate the client secret (single source of truth)**

Generate a strong-looking secret and set it in **both** Keycloak and the adapter env file.

```bash
# Generate a URL-safe secret (no newlines)
NEW_SECRET="$(openssl rand -base64 64 | tr -d '\n' | tr '+/' '-_' | tr -d '=' )"
echo "LEN=${#NEW_SECRET}"

# Update Keycloak client secret
CID="$(docker exec -i vcs-keycloak /opt/keycloak/bin/kcadm.sh get clients -r vcs -q clientId=rw_token | jq -r '.[0].id' | tr -d '\r\n')"
docker exec -i vcs-keycloak /opt/keycloak/bin/kcadm.sh update "clients/$CID" -r vcs -s "secret=$NEW_SECRET"

# Verify secret in Keycloak
docker exec -i vcs-keycloak /opt/keycloak/bin/kcadm.sh get "clients/$CID/client-secret" -r vcs | jq .
```

**D) Configure cognito-auth-adapter (systemd)**

Service unit used on yankee:

```bash
sudo tee /etc/systemd/system/cognito-auth-adapter.service >/dev/null <<'EOF'
[Unit]
Description=VCS Cognito Auth Adapter (Keycloak)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/var/www/VCS/vcs/cognito-auth-adapter.env
ExecStart=/var/www/VCS/vcs/bin/cognito-auth-adapter
Restart=on-failure
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now cognito-auth-adapter
```

Environment file (single canonical version; no duplicates/blank noise):

```bash
sudo tee /var/www/VCS/vcs/cognito-auth-adapter.env >/dev/null <<EOF
HOST_URL=0.0.0.0:8095
KEYCLOAK_BASE_URL=http://127.0.0.1:8080
KEYCLOAK_REALM=vcs
KEYCLOAK_CLIENT_ID=rw_token
KEYCLOAK_CLIENT_SECRET=$NEW_SECRET
EOF

sudo systemctl restart cognito-auth-adapter
sudo systemctl status cognito-auth-adapter --no-pager
```

#### Sanity checks (what we used)

**Check port listener (adapter on 8095):**

```bash
sudo ss -lntp | grep ':8095' || true
sudo lsof -iTCP:8095 -sTCP:LISTEN -n -P || true
```

**Check service logs:**

```bash
sudo journalctl -u cognito-auth-adapter -n 200 --no-pager
# or follow
sudo journalctl -u cognito-auth-adapter -f
```

**(Optional) Inspect adapter → Keycloak traffic** (useful if you suspect wrong client credentials):

```bash
# Keycloak port
sudo tcpdump -ni lo -A -s0 'tcp port 8080 and host 127.0.0.1'

# Adapter port
sudo tcpdump -ni any tcp port 8095
```

#### Token requests (commands that worked)

**1) Directly against Keycloak (ground truth):**

```bash
curl -sS -X POST \
  "http://127.0.0.1:8080/realms/vcs/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=rw_token" \
  --data-urlencode "client_secret=$NEW_SECRET" \
  --data-urlencode "username=usuario" \
  --data-urlencode "password=CLAVE" \
  --data-urlencode "scope=openid" | jq .
```

**2) Through the adapter (Cognito-style endpoint):**

The adapter accepts Cognito-like requests at:
- `POST http://127.0.0.1:8095/cognito/oauth2/token`

The request that worked (Basic auth uses the **user credentials**, while the client credentials go in the form body):

```bash
curl -sS -u 'usuario:CLAVE' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=password' \
  --data-urlencode 'client_id=rw_token' \
  --data-urlencode "client_secret=$NEW_SECRET" \
  --data-urlencode 'scope=openid' \
  http://127.0.0.1:8095/cognito/oauth2/token | jq .
```

> If you see `Invalid client or Invalid client credentials` you have a mismatch between the secret in Keycloak and the secret in `cognito-auth-adapter.env`.

#### Helper script: `get-token.sh`

To avoid retyping curl payloads and to keep the secret in one place, we created a helper script that:
- reads `KEYCLOAK_CLIENT_SECRET` from `/var/www/VCS/vcs/cognito-auth-adapter.env`
- requests a token from the adapter (default)
- optionally requests a token directly from Keycloak (`--keycloak`)

Create it on the server:

```bash
cat > /var/www/VCS/vcs/get-token.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/var/www/VCS/vcs/cognito-auth-adapter.env"
ADAPTER_URL="${ADAPTER_URL:-http://127.0.0.1:8095/cognito/oauth2/token}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://127.0.0.1:8080/realms/vcs/protocol/openid-connect/token}"

CLIENT_ID="${CLIENT_ID:-rw_token}"

# Defaults (override via flags or env vars)
USERNAME="${USERNAME:-usuario}"
PASSWORD="${PASSWORD:-CLAVE}"
SCOPE="${SCOPE:-openid}"

MODE="adapter"   # adapter | keycloak
JUST_TOKEN=0

usage() {
  cat <<USAGE
Usage:
  $(basename "$0") [options]

Options:
  -u, --user USER        Username (default: \$USERNAME)
  -p, --pass PASS        Password (default: \$PASSWORD)
  --scope SCOPE          Scope (default: \$SCOPE)
  --client-id ID         Client ID (default: \$CLIENT_ID)
  --adapter              Call adapter endpoint (default)
  --keycloak             Call keycloak endpoint directly
  -t, --token            Print only access_token
  -h, --help             Show this help

Env overrides:
  ADAPTER_URL, KEYCLOAK_URL, CLIENT_ID, USERNAME, PASSWORD, SCOPE
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--user) USERNAME="$2"; shift 2;;
    -p|--pass) PASSWORD="$2"; shift 2;;
    --scope) SCOPE="$2"; shift 2;;
    --client-id) CLIENT_ID="$2"; shift 2;;
    --adapter) MODE="adapter"; shift;;
    --keycloak) MODE="keycloak"; shift;;
    -t|--token) JUST_TOKEN=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2;;
  esac
done

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: env file not found: $ENV_FILE" >&2
  exit 1
fi

CLIENT_SECRET="$(grep '^KEYCLOAK_CLIENT_SECRET=' "$ENV_FILE" | cut -d= -f2- | tr -d '\r\n')"
if [[ -z "${CLIENT_SECRET}" ]]; then
  echo "ERROR: KEYCLOAK_CLIENT_SECRET not found in $ENV_FILE" >&2
  exit 1
fi

if [[ "$MODE" == "adapter" ]]; then
  RESP="$(curl -sS -u "${USERNAME}:${PASSWORD}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=password' \
    --data-urlencode "client_id=${CLIENT_ID}" \
    --data-urlencode "client_secret=${CLIENT_SECRET}" \
    --data-urlencode "scope=${SCOPE}" \
    "${ADAPTER_URL}")"
else
  RESP="$(curl -sS -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=password' \
    --data-urlencode "client_id=${CLIENT_ID}" \
    --data-urlencode "client_secret=${CLIENT_SECRET}" \
    --data-urlencode "username=${USERNAME}" \
    --data-urlencode "password=${PASSWORD}" \
    --data-urlencode "scope=${SCOPE}" \
    "${KEYCLOAK_URL}")"
fi

if command -v jq >/dev/null 2>&1; then
  if [[ "$JUST_TOKEN" -eq 1 ]]; then
    echo "$RESP" | jq -r '.access_token // empty'
  else
    echo "$RESP" | jq .
  fi
else
  echo "$RESP"
fi
EOF

chmod +x /var/www/VCS/vcs/get-token.sh
```

Usage examples:

```bash
# Adapter (default): full JSON
/var/www/VCS/vcs/get-token.sh

# Adapter: only access_token
/var/www/VCS/vcs/get-token.sh -t

# Directly to Keycloak (full JSON)
/var/www/VCS/vcs/get-token.sh --keycloak

# Override user/pass at call-time
/var/www/VCS/vcs/get-token.sh -u otro -p 'otraClave'
```

> Security note: avoid putting real passwords on the command line in shared environments; prefer exporting `USERNAME` / `PASSWORD` in a secure session.

### 7.2 Cognito mock
> **Note (compat/legacy):** This `cognito-mock` container is still used for specific **BDD/mock** flows that expect Cognito config files under `/app/.cognito/`. However, on **yankee** the primary OAuth/token service is now **Keycloak + cognito-auth-adapter** (see the section above). Keep `cognito-mock` only if you explicitly need those legacy/mock components.

```bash
docker rm -f cognito-mock
docker run -d --name cognito-mock \
  -p 9229:9229 \
  -v /var/www/VCS/vcs/test/bdd/fixtures/cognito-config:/app/.cognito \
  aholovko/cognito-local:0.2.2
```

Make sure `/var/www/VCS/vcs/test/bdd/fixtures/cognito-config/*` matches your issuer
profiles (client ID, secret handle, etc.).

#### IMPORTANT: 9229 vs 8094 (compat bridge used by BDD attestation)

On **yankee**, we run `cognito-mock` (`aholovko/cognito-local`) on **9229** and expose it publicly under **`/cognito/`** via Nginx.

However, some TrustBloc **BDD/mock components** (notably attestation/presentation code) are hardcoded to use:

- base URL: `http://cognito-auth.local:8094/cognito`
- token endpoint: `POST /cognito/oauth2/token`

To keep compatibility, we provide a **local bridge on 127.0.0.1:8094** handled by **Nginx** that proxies to the running `cognito-mock` container.

**Quick checks**:

```bash
# 8094 must be LISTENing on localhost (typically nginx)
sudo ss -lntp | egrep ":8094|:9229" || true

# verify the container is up
sudo docker ps | grep cognito-mock || true
```

**Token endpoint contract (what the caller must send):**

- Method: `POST`
- Content-Type: `application/x-www-form-urlencoded`
- Auth: `Authorization: Basic base64(<client_id>:<client_secret>)`

If you see errors like:

- `content-type must be 'application/x-www-form-urlencoded'`
- `authorization header must be present and use HTTP Basic authentication scheme`

…then the caller is hitting the right endpoint but sending the wrong headers.

**Finding the correct client_id / client_secret**

The credentials are defined by the config mounted into the container:

```bash
sudo docker exec -it cognito-mock ls -la /app/.cognito
sudo docker exec -it cognito-mock cat /app/.cognito/config.json | sed -n '1,200p'
```

Use the values from that file to build the Basic header:

```bash
CLIENT_ID="<from config.json>"
CLIENT_SECRET="<from config.json>"
BASIC="$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64 -w 0)"

curl -sS -i -X POST http://127.0.0.1:8094/cognito/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H "Authorization: Basic $BASIC" \
  --data 'grant_type=client_credentials' | sed -n '1,80p'
```

Expected: `HTTP/1.1 200` with an `access_token`.

If you get `invalid_client`, your `client_id/secret` pair does not match the config.

**Note:** `VC_OAUTH_SECRET` in `vcs/server.env` is used by vc-rest for API auth, but it is **not automatically** the Cognito client secret used by the BDD token endpoint.

### 7.3 Attestation (mock-attestation) + wallet presentation bridge (IMPORTANT)

This stack uses **Attestation** during the **presentation** flow (VP). The TrustBloc wallet will call **Login/Consent** paths under `/login/...` even though the upstream service that implements attestation is **mock-attestation**.

#### Source of truth
- **vc-rest is the source of truth** for what profiles/issuers exist (loaded from `profiles/profiles.json`).
- Nginx must only **route** the wallet requests to the right upstream. It should **not** hardcode issuer/profile logic.

#### What the wallet calls (observed in `nginx/access.log`)
The wallet hits these endpoints on your public domain:
- `POST /login/profiles/<profileID>/<profileVersion>/wallet/attestation/init`
- `POST /login/profiles/<profileID>/<profileVersion>/wallet/attestation/complete`

If these return `502` or `400`, presentation will fail.

#### Upstream that must answer
`mock-attestation` listens on **TLS**:
- `https://127.0.0.1:8097/...` (NOT plain HTTP)

Quick sanity checks:

```bash
# must show LISTEN on :8097
sudo ss -lntp | grep :8097 || true

# direct upstream test (MUST be HTTPS)
curl -k -sS -i \
  -X POST https://127.0.0.1:8097/profiles/profileID/profileVersion/wallet/attestation/init \
  -H 'Content-Type: application/json' \
  --data '{"payload":{"type":"urn:attestation:test"}}' | sed -n '1,40p'
```

If you see:
- `Client sent an HTTP request to an HTTPS server.`

…then you are calling the upstream with `http://` instead of `https://` (or Nginx is proxying with the wrong scheme).

#### Nginx bridge (required)
We add a dedicated **bridge location** so that `/login/.../wallet/attestation/*` is forwarded to the attestation service.

Add this block **above** the generic `location /login/ { ... }` block:

```nginx
# --- BRIDGE: la wallet pega acá ---
# /login/profiles/{id}/{ver}/wallet/attestation/init
# /login/profiles/{id}/{ver}/wallet/attestation/complete
location ~ ^/login(/profiles/[^/]+/[^/]+/wallet/attestation/(init|complete))$ {
    # sacamos el prefijo /login y mandamos al mock-attestation
    rewrite ^/login(/profiles/[^/]+/[^/]+/wallet/attestation/(init|complete))$ $1 break;

    # IMPORTANT: mock-attestation is HTTPS on 8097
    proxy_pass https://127.0.0.1:8097;
    proxy_set_header Host mock-attestation.trustbloc.local;

    proxy_http_version 1.1;
    proxy_ssl_verify off;
    proxy_ssl_server_name on;
    proxy_ssl_name localhost;
}
```

Reload and test:

```bash
sudo nginx -t && sudo systemctl reload nginx

# EXACTO path que usa la wallet
curl -k -sS -i \
  -X POST https://yankee.openvino.org/login/profiles/profileID/profileVersion/wallet/attestation/init \
  -H 'Content-Type: application/json' \
  --data '{"payload":{"type":"urn:attestation:test"}}' | sed -n '1,40p'
```

Expected:
- `HTTP/2 200` with JSON body containing `{ "challenge": ..., "session_id": ... }`.

If you still get `502`, check `nginx/error.log` for `connect() failed (111: Connection refused)`.
That means the upstream (8097) is not reachable or not running.

#### Systemd service name (yankee)
On yankee we run it as:
- `mock-attestation.service`

Useful commands:

```bash
sudo systemctl status mock-attestation --no-pager
sudo journalctl -u mock-attestation -n 100 --no-pager
```

### 7.3 Login/consent + Attestation (if needed)

The repository contains mock components under `wallet/test/mock`.  
Build/run them as required using the provided scripts or Dockerfiles.  
For yankee, these run as systemd services (`loginconsent-mock.service`,
`vc-webhook.service`, `attestation-mock.service`) pointing to binaries built
from `wallet/test/mock`.

## 9. Autostart Docker-based services

Create systemd units so the containers above come back after a reboot.
The pattern below removes any stale container before starting a new one.

### 9.1 DID Resolver

```bash
sudo tee /etc/systemd/system/did-resolver.service >/dev/null <<'EOF'
[Unit]
Description=TrustBloc DID Resolver
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
ExecStartPre=-/usr/bin/docker rm -f did-resolver.trustbloc.local
ExecStart=/usr/bin/docker run --name did-resolver.trustbloc.local \
  -p 8072:8072 \
  -e DID_REST_HOST_URL=0.0.0.0:8072 \
  -e DID_REST_HOST_URL_EXTERNAL=https://yankee.openvino.org/resolver \
  -e DID_REST_CONFIG_FILE=/opt/did-resolver/config.json \
  -e DID_REST_TLS_SYSTEMCERTPOOL=true \
  -e DID_REST_TLS_CACERTS=/etc/tls/trustbloc-dev.ca.crt \
  -e DID_REST_DID_DOMAIN=testnet.orb.local \
  -v /var/www/VCS/vcs/test/bdd/fixtures/did-resolver/config.json:/opt/did-resolver/config.json \
  -v /var/www/VCS/certs:/etc/tls \
  ghcr.io/trustbloc-cicd/did-resolver:v0.0.1-snapshot-58ab302 start
ExecStop=/usr/bin/docker stop did-resolver.trustbloc.local
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now did-resolver
```

### 9.2 Trust Registry

```bash
sudo tee /etc/systemd/system/mock-trust-registry.service >/dev/null <<'EOF'
[Unit]
Description=Mock Trust Registry
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
ExecStartPre=-/usr/bin/docker rm -f mock-trust-registry
ExecStart=/usr/bin/docker run --name mock-trust-registry \
  -p 8100:8100 \
  -e LISTEN_ADDR=:8100 \
  -e RULES_FILE_PATH=/trust-registry/rules.json \
  -e TLS_CERT_PATH=/etc/tls/server.crt \
  -e TLS_KEY_PATH=/etc/tls/server.key \
  -e ROOT_CA_CERTS_PATH=/etc/tls/trustbloc-dev.ca.crt \
  -v /var/www/VCS/certs:/etc/tls \
  -v /var/www/VCS/wallet/test/integration/fixtures/trust-registry:/trust-registry \
  wallet-sdk/mock-trust-registry:latest
ExecStop=/usr/bin/docker stop mock-trust-registry
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now mock-trust-registry
```

### 9.3 Cognito mock

```bash
sudo tee /etc/systemd/system/cognito-mock.service >/dev/null <<'EOF'
[Unit]
Description=Cognito mock
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
ExecStartPre=-/usr/bin/docker rm -f cognito-mock
ExecStart=/usr/bin/docker run --name cognito-mock \
  -p 9229:9229 \
  -v /var/www/VCS/vcs/test/bdd/fixtures/cognito-config:/app/.cognito \
  aholovko/cognito-local:0.2.2
ExecStop=/usr/bin/docker stop cognito-mock
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now cognito-mock
```

Repeat this pattern for any other containerized component (e.g., custom mocks).

## 10. Profiles

`/var/www/VCS/profiles/profiles.json` defines the issuer profile:

```json
{
  "issuers": [
    {
      "issuer": {
        "id": "bank_issuer",
        "version": "v1.0",
        "organizationID": "f13d1va9lp403pb9lyj89vk55",
        "url": "https://yankee.openvino.org/vc",
        "webHook": "https://yankee.openvino.org/webhook/issue",
        "credentialIssuer": "https://yankee.openvino.org/vc-rest-api/oidc/idp/bank_issuer/v1.0/.well-known/openid-credential-issuer",
        "...": "..."
      },
      "createDID": true,
      "didDomain": "https://yankee.openvino.org/vc"
    }
  ]
}
```

> **Source of truth note (IMPORTANT):** `vc-rest` loads all issuer/verifier profiles from `profiles/profiles.json` at startup (this is the authoritative registry of `{id, version}` and related metadata). Nginx should **not** encode profile logic; it should only route requests to the correct upstream services.

Adjust the claim metadata, credential templates, and OIDC config for your domain.
Reload `vc-rest` after changing profiles.

## 11. Test issuance workflow

1. Initiate issuance (generate an OIDC4VCI credential offer):

   ### BANK ISSUER

   Local (from the server):
   ```bash
   curl --location 'http://localhost:9075/issuer/profiles/bank_issuer/v1.0/interactions/initiate-oidc' \
     --header 'Content-Type: application/json' \
     --header 'X-API-Key: rw_token' \
     --header 'X-Tenant-ID: f13d1va9lp403pb9lyj89vk55' \
     --data '{
       "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
       "scope": [],
       "credential_configuration": [
         {
           "credential_template_id": "templateID",
           "claim_data": { "key": "value" }
         }
       ]
     }'
   ```

   Public (from anywhere):
   ```bash
   curl --location 'https://yankee.openvino.org/vc-rest-api/issuer/profiles/bank_issuer/v1.0/interactions/initiate-oidc' \
     --header 'Content-Type: application/json' \
     --header 'X-API-Key: rw_token' \
     --header 'X-Tenant-ID: f13d1va9lp403pb9lyj89vk55' \
     --data '{
       "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
       "scope": [],
       "credential_configuration": [
         { "credential_template_id": "templateID", "claim_data": { "key": "value" } }
       ]
     }'
   ```

   ### MANATOKO

   Public (from anywhere):
   ```bash
   curl --location 'https://yankee.openvino.org/vc-rest-api/issuer/profiles/manatoko_issuer/v1.0/interactions/initiate-oidc' \
     --header 'Content-Type: application/json' \
     --header 'X-API-Key: rw_token' \
     --header 'X-Tenant-ID: f13d1va9lp403pb9lyj89vk55' \
     --data '{
       "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
       "scope": [],
       "credential_configuration": [
         {
           "credential_template_id": "manatoko_employee_template",
           "claim_data": {
             "displayName": "Alice Manatoko",
             "givenName": "Alice",
             "jobTitle": "Engineer",
             "mail": "alice@manatoko.org"
           }
         }
       ]
     }'
   ```

   Copy the returned `openid-credential-offer://...` URL.

2. On a development machine, run the Flutter wallet:
   ```bash
   cd /Users/<you>/Documents/Code/VCS/wallet/demo/app
   flutter clean
   flutter pub get
   flutter run
   ```

3. Scan the QR (or paste the offer URL) in the wallet and follow the prompts.
   Linked-domain validation should succeed thanks to the resolver setup.


## Wallet build notes (Go / gomobile)

This section documents the **exact Go setup** required to build and run the Flutter wallet with `gomobile` bindings.
This is **not optional**: mismatched Go versions will cause hard-to-debug crashes or build failures.

### Go versions (IMPORTANT)

- **Go 1.24.x** → **REQUIRED**
- Go **1.23.x or lower** → ❌ **NOT supported**
- Go **1.25.x (toolchain auto-switching)** → ❌ **DO NOT use**

Reason:
- `golang.org/x/mobile` **requires Go ≥ 1.24**
- `GOTOOLCHAIN=auto` causes silent toolchain switching and breaks `gomobile`
- Go 1.23 builds succeed but crash at runtime (native Go runtime errors)

**Known-good version used in this deployment:**

```text
go version go1.24.11 darwin/arm64
```

### Enforcing the correct Go version (macOS)

Install and pin Go 1.24 using Homebrew:

```bash
brew install go@1.24

brew unlink go@1.23 2>/dev/null || true
brew link --overwrite --force go@1.24
```

Ensure Go **never auto-switches toolchains**:

```bash
go env -w GOTOOLCHAIN=local
```

Verify:

```bash
go version
# must print: go1.24.x
```

### gomobile installation (REQUIRED)

Remove any previously installed binaries:

```bash
rm -f "$(go env GOPATH)/bin/gomobile"
rm -f "$(go env GOPATH)/bin/gobind"
hash -r
```

Install gomobile **with the active Go version**:

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
```

Verify embedded module metadata:

```bash
go version -m "$(which gomobile)" | head -n 20
```

Expected:
- `path golang.org/x/mobile/cmd/gomobile`
- `mod golang.org/x/mobile v0.0.0-...`
- `go1.24.x`

### Android environment variables

```bash
export ANDROID_HOME="$HOME/Library/Android/sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.2.13676358"
```

### gomobile initialization

```bash
rm -rf ~/Library/Caches/gomobile
rm -rf "$(go env GOPATH)/pkg/gomobile"

gomobile init -v
```

Expected output:

```text
Done, build took 0s.
```

### Flutter clean rebuild (MANDATORY after gomobile changes)

From the wallet app directory:

```bash
flutter clean
rm -rf ~/.gradle/caches
rm -rf android/.gradle
flutter pub get
flutter run
```

### Known failure modes

#### ❌ `gomobile version unknown: binary is out of date`

Cause:
- `gomobile` was built with a **different Go version** than the current one.

Fix:

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
```

#### ❌ `fatal error: bulkBarrierPreWrite: unaligned arguments`

Cause:
- Go runtime mismatch (usually Go 1.23 or mixed toolchains)

Fix:
- Force Go 1.24
- Reinstall gomobile
- Full Flutter + Gradle clean

#### ❌ Gradle error: `checkDebugAarMetadata`

Cause:
- Corrupted Gradle transform cache after native rebuilds

Fix:

```bash
rm -rf ~/.gradle/caches
rm -rf android/.gradle
flutter clean
flutter run
```

### TL;DR (do not skip)

```text
✔ Go 1.24.x only
✔ GOTOOLCHAIN=local
✔ gomobile reinstalled after Go changes
✔ Full Flutter + Gradle clean
```

## 12. Troubleshooting

### 12.1 Keycloak / Cognito Auth Adapter

**Symptom:** `Invalid client or Invalid client credentials`  
**Cause:** Client secret mismatch between Keycloak and `cognito-auth-adapter.env`.

**Fix:**
```bash
# Verify secret in Keycloak
CID="$(docker exec -i vcs-keycloak /opt/keycloak/bin/kcadm.sh get clients -r vcs -q clientId=rw_token | jq -r '.[0].id')"
docker exec -i vcs-keycloak /opt/keycloak/bin/kcadm.sh get "clients/$CID/client-secret" -r vcs

# Verify env file
grep KEYCLOAK_CLIENT_SECRET /var/www/VCS/vcs/cognito-auth-adapter.env

# Restart adapter
sudo systemctl restart cognito-auth-adapter
```

---

**Symptom:** `Invalid user credentials`  
**Cause:** Wrong username/password or user not fully initialized in Keycloak.

**Fix:**
```bash
# Inspect user
docker exec -i vcs-keycloak /opt/keycloak/bin/kcadm.sh get users -r vcs | jq .

# Ensure no required actions remain
docker exec -i vcs-keycloak /opt/keycloak/bin/kcadm.sh get "users/<USER_ID>" -r vcs | jq '.requiredActions'

# Reset password
docker exec -i vcs-keycloak /opt/keycloak/bin/kcadm.sh set-password -r vcs \
  --userid <USER_ID> \
  --new-password CLAVE \
  --temporary=false
```

---

**Symptom:** Adapter responds but Keycloak is never hit  
**Cause:** Wrong `KEYCLOAK_BASE_URL` or adapter not restarted.

**Fix:**
```bash
grep KEYCLOAK_BASE_URL /var/www/VCS/vcs/cognito-auth-adapter.env
sudo systemctl restart cognito-auth-adapter
sudo journalctl -u cognito-auth-adapter -n 50 --no-pager
```

---

### 12.2 Port / Network Issues

**Symptom:** Connection refused on `:8095`  
**Fix:**
```bash
sudo ss -lntp | grep :8095
sudo systemctl status cognito-auth-adapter
```

**Symptom:** Keycloak unreachable on `:8080`  
**Fix:**
```bash
docker ps | grep keycloak
curl -I http://127.0.0.1:8080
```

---

### 12.3 Issuance Works, Presentation Fails (Most Common)

**Likely causes:**
1. Attestation bridge missing in Nginx
2. mock-attestation not running
3. Cognito mock / compat bridge missing

**Checks:**
```bash
# mock-attestation must be HTTPS on 8097
sudo ss -lntp | grep :8097

# Public path must proxy correctly
curl -k -i https://yankee.openvino.org/login/profiles/.../wallet/attestation/init

# Cognito compat ports
sudo ss -lntp | egrep ':8094|:9229'
```

---

### 12.4 vc-rest Issues

**Symptom:** Issuer not found / wrong branding  
**Cause:** `profiles.json` edited but vc-rest not restarted.

**Fix:**
```bash
sudo systemctl restart vc-rest
sudo journalctl -u vc-rest -n 50 --no-pager
```

---

### 12.5 Wallet / Flutter Issues

**Symptom:** gomobile crashes or Gradle errors  
**Cause:** Wrong Go version or stale caches.

**Fix (known-good reset):**
```bash
go version        # must be 1.24.x
go env GOTOOLCHAIN

flutter clean
rm -rf ~/.gradle/caches
rm -rf android/.gradle
rm -rf ~/Library/Caches/gomobile
rm -rf $(go env GOPATH)/pkg/gomobile

gomobile init -v
flutter run
```

---

### 12.6 Quick “Bring Everything Back Up” Checklist

```bash
sudo systemctl restart nginx
sudo systemctl restart vc-rest
sudo systemctl restart cognito-auth-adapter
sudo systemctl restart mock-attestation
sudo systemctl restart cognito-mock

docker ps
```

If something still fails:
- Check `journalctl -u <service>`
- Check `nginx/error.log`
- Verify secrets and ports

## 13. Rotate the VC REST data-encryption key

Use the helper script to change `VC_REST_DATA_ENCRYPTION_KEY_ID` in both
`server.env` and the systemd unit:

```bash
cd /var/www/VCS/vcs
./updateKey.sh NEW_KEY_VALUE
```

The script reloads systemd and restarts `vc-rest`.

## 14. Keeping secrets out of Git

- Do **not** commit files inside `/var/www/VCS/certs`, `/var/www/VCS/keys` or
  any real secrets.
- Only the Go source and configuration templates (`profiles/*.json`,
  resolver rules, etc.) belong in Git. Certs and environment-specific values
  must live on the server only.

Once all services are running, visit `https://yankee.openvino.org/vc` and run the
wallet flows to confirm issuance and verification end-to-end. Celebrate! 🎉

---

## Appendix A – Add a new Issuer Profile (OIDC4VCI)

This section documents **end-to-end** how to add a new *issuer profile* (for example `manatoko_issuer`) to an already deployed VCS stack, without breaking existing issuers.

### A.1 Edit `profiles.json`

File:

```text
/var/www/VCS/profiles/profiles.json
```

Inside the `issuers` array, add a new entry with the **minimum complete** structure below:

```json
{
  "issuer": {
    "id": "manatoko_issuer",
    "version": "v1.0",
    "groupID": "group_manatoko_issuer",
    "name": "Manatoko Issuer",
    "organizationID": "f13d1va9lp403pb9lyj89vk55",
    "url": "https://yankee.openvino.org/vc",
    "webHook": "https://yankee.openvino.org/webhook/issue",
    "active": true,

    "vcConfig": {
      "signingAlgorithm": "JsonWebSignature2020",
      "signatureRepresentation": 0,
      "keyType": "ED25519",
      "format": "jwt",
      "didMethod": "ion",
      "status": { "type": "StatusList2021Entry" }
    },

    "oidcConfig": {
      "client_id": "REEMPLAZAR_MANATOKO_CLIENT_ID",
      "client_secret_handle": "REEMPLAZAR_MANATOKO_CLIENT_SECRET_HANDLE",
      "issuer_well_known": "https://yankee.openvino.org/cognito/local_5a9GzRvB/.well-known/openid-configuration",
      "scopes_supported": ["openid", "profile"],
      "grant_types_supported": [
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
      ],
      "response_types_supported": ["code"],
      "token_endpoint_auth_methods_supported": ["none"],
      "enable_dynamic_client_registration": true,
      "pre-authorized_grant_anonymous_access_supported": true,
      "signed_issuer_metadata_supported": true
    },

    "credentialTemplates": [
      {
        "id": "manatoko_employee_template",
        "type": "VerifiedEmployee",
        "contexts": ["https://www.w3.org/2018/credentials/v1"],
        "issuer": "did:ion:manatoko_issuer"
      }
    ],

    "credentialMetadata": {
      "credential_configurations_supported": {
        "VerifiedEmployee_jwt_vc_json_v1": {
          "format": "jwt_vc_json",
          "order": ["displayName", "givenName", "jobTitle"],
          "credential_definition": {
            "type": ["VerifiableCredential", "VerifiedEmployee"],
            "credentialSubject": {
              "displayName": { "value_type": "string" },
              "givenName": { "value_type": "string" },
              "jobTitle": { "value_type": "string" },
              "mail": { "value_type": "string" }
            }
          },
          "cryptographic_binding_methods_supported": ["did"],
          "credential_signing_alg_values_supported": ["Ed25519Signature2018"],
          "display": [
            {
              "name": "Manatoko Client",
              "locale": "en-US",
              "logo": {
                "uri": "https://www.amberoon.com/hubfs/Amberoon%202021/Homepage%202021/footer-lo_2.png"
              },
              "background_color": "#fcca40",
              "text_color": "#FFFFFF"
            }
          ]
        }
      }
    }
  },
  "createDID": true,
  "didDomain": "https://yankee.openvino.org"
}
```

> **Important**
> - `credentialTemplates[].id` **must exist** and is used when initiating issuance.
> - `credential_configurations_supported` controls what appears in the issuer `well-known` endpoint.
> - You can reuse the same logo; updating the `display.name` (branding) is usually enough.

Validate the file:

```bash
sudo jq . /var/www/VCS/profiles/profiles.json >/dev/null && echo "JSON OK"
```

Restart the service:

```bash
sudo systemctl restart vc-rest.service
```

---

### A.2 Verify the Issuer Well-Known endpoint

```bash
curl -sS https://yankee.openvino.org/vc-rest-api/oidc/idp/manatoko_issuer/v1.0/.well-known/openid-credential-issuer | jq .
```

Confirm that:
- `credential_configurations_supported` is present
- the issuer/credential `display.name` matches **Manatoko**

---

### A.3 Issue a credential (from outside the server)

This endpoint is the **only call** your external backend needs to start the issuance flow.

```bash
curl --location 'https://yankee.openvino.org/vc-rest-api/issuer/profiles/manatoko_issuer/v1.0/interactions/initiate-oidc' \
  --header 'Content-Type: application/json' \
  --header 'X-API-Key: rw_token' \
  --header 'X-Tenant-ID: f13d1va9lp403pb9lyj89vk55' \
  --data '{
    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "scope": [],
    "credential_configuration": [
      {
        "credential_template_id": "manatoko_kyc_template",
        "claim_data": {
          "givenName": "Alice",
          "surname": "Manatoko",
          "documentNumber": "A12345678",
          "country": "AR"
        }
      }
    ]
  }'
```

Expected response:

```json
{
  "offer_credential_url": "openid-credential-offer://?...",
  "tx_id": "uuid",
  "user_pin": ""
}
```

You can then:
- turn `offer_credential_url` into a QR code, or
- send it as a deep link to an OIDC4VCI-compatible wallet.

---

### A.4 End-to-end summary

1. Edit `profiles.json`
2. Restart `vc-rest`
3. Verify the issuer `/.well-known/openid-credential-issuer`
4. Call `interactions/initiate-oidc`
5. The wallet consumes the offer and completes issuance

---

### A.5 Common errors

- **`credential template should be specified`**  
  → `credential_template_id` is missing, or it does not match any `credentialTemplates[].id` in the profile.

- **It still shows “Bank Client”**  
  → `vc-rest` was not restarted, or your `credentialMetadata.display.name` is still set to the old value.

- **`invalid_proof`**  
  → You tried calling `/oidc/credential` directly (wrong flow). The intended flow starts from `interactions/initiate-oidc`.

---

### A.6 Design note

An issuer profile is **not limited to employees**. For KYC or other credential types, you can simply:
- add more `credentialTemplates`, and
- add more entries under `credential_configurations_supported`.

You do **not** need a separate verifier per credential type.

---
