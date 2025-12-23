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

## 8. Supporting mock services

### 7.1 Trust Registry

```bash
docker rm -f mock-trust-registry
docker run -d --name mock-trust-registry \
  -p 8100:8100 \
  -e LISTEN_ADDR=:8100 \
  -e RULES_FILE_PATH=/trust-registry/rules.json \
  -e TLS_CERT_PATH=/etc/tls/server.crt \
  -e TLS_KEY_PATH=/etc/tls/server.key \
  -e ROOT_CA_CERTS_PATH=/etc/tls/trustbloc-dev.ca.crt \
  -v /var/www/VCS/certs:/etc/tls \
  -v /var/www/VCS/wallet/test/integration/fixtures/trust-registry:/trust-registry \
  wallet-sdk/mock-trust-registry:latest
```

Quick health check:

```bash
curl -k https://127.0.0.1:8100/wallet/interactions/issuance \
  -H 'Content-Type: application/json' \
  --data @/var/www/VCS/wallet/test/integration/fixtures/trust-registry/issuance_request.json
```

### 7.2 Cognito mock

```bash
docker rm -f cognito-mock
docker run -d --name cognito-mock \
  -p 9229:9229 \
  -v /var/www/VCS/vcs/test/bdd/fixtures/cognito-config:/app/.cognito \
  aholovko/cognito-local:0.2.2
```

Make sure `/var/www/VCS/vcs/test/bdd/fixtures/cognito-config/*` matches your issuer
profiles (client ID, secret handle, etc.).

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

### 12.1 “Volver a levantar todo” (pasos rápidos que usamos en yankee)

#### A) Nginx: validar y recargar

```bash
sudo nginx -t
sudo systemctl reload nginx
# si seguís viendo cosas raras, reinicio completo:
sudo systemctl restart nginx
```

#### B) Linked Domains: servir `/.well-known/did-configuration.json` desde Nginx

En `yankee.openvino.org` expusimos el archivo generado por `tools/didconfig` con un `alias` directo:

```nginx
location = /.well-known/did-configuration.json {
    alias /var/www/VCS/.well-known/did-configuration.json;
    default_type application/json;
}
```

Validación rápida:

```bash
curl -i https://yankee.openvino.org/.well-known/did-configuration.json
```

> Nota: si lo estás pidiendo bajo `/vc-rest-api/.../.well-known/did-configuration.json` y te da `401`, no es el endpoint público correcto. El linked-domain se publica en `/.well-known/did-configuration.json` en el **dominio**.

#### C) Issuance: confirmar que vc-rest responde y genera el offer

Local (desde el server):

```bash
curl -sS http://localhost:9075/issuer/profiles/bank_issuer/v1.0/interactions/initiate-oidc \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: rw_token' \
  -H 'X-Tenant-ID: f13d1va9lp403pb9lyj89vk55' \
  --data '{
    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "scope": [],
    "credential_configuration": [
      {
        "credential_configuration_id": "VerifiedEmployee_jwt_vc_json_v1",
        "claim_data": {
          "displayName": "Alice Bank",
          "givenName": "Alice",
          "jobTitle": "Analyst",
          "mail": "alice@bank.org"
        }
      }
    ]
  }'
```

Público (desde afuera):

```bash
curl -sS https://yankee.openvino.org/vc-rest-api/issuer/profiles/bank_issuer/v1.0/interactions/initiate-oidc \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: rw_token' \
  -H 'X-Tenant-ID: f13d1va9lp403pb9lyj89vk55' \
  --data '{
    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "scope": [],
    "credential_configuration": [
      {
        "credential_configuration_id": "VerifiedEmployee_jwt_vc_json_v1",
        "claim_data": { "displayName": "Alice Bank", "givenName": "Alice", "jobTitle": "Analyst", "mail": "alice@bank.org" }
      }
    ]
  }'
```

Deberías recibir:
- `offer_credential_url` (para QR / deep link)
- `tx_id`

#### D) Flutter wallet (Android): limpieza agresiva que hicimos cuando explotó Gradle/gomobile

```bash
# dentro del proyecto Flutter
dart --version
flutter --version

flutter clean
flutter pub get

# limpiar caches que nos rompían el build
rm -rf ~/.gradle/caches
rm -rf android/.gradle
rm -rf "$HOME/Library/Caches/gomobile"
rm -rf "$(go env GOPATH)/pkg/gomobile"

# re-inicializar gomobile
# (si no lo tenés instalado: go install golang.org/x/mobile/cmd/gomobile@latest)
gomobile init -v

# volver a correr
flutter run
```

Si aparece un error tipo `:app:checkDebugAarMetadata` con `datastore-core/.../aar-metadata.properties (No such file or directory)`, normalmente se resuelve con el wipe de `~/.gradle/caches` + `android/.gradle` y un rebuild limpio.

- `vc-rest` errors about linked domains → regenerate DID artifacts (`go run .`)
  and restart the resolver container.
- `cognito-mock` failing → ensure `/app/.cognito/config.json` matches the
  client ID/secret in your issuer profile.
- Docker services not starting on boot → wrap the `docker run` commands in
  systemd units (`docker run --restart unless-stopped` is another option).

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
