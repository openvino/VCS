# Openvino Trust Registry (minimal)

This is a **minimal** Trust Registry service you can run on your server to satisfy the Wallet SDK calls:

- POST `/wallet/interactions/issuance`
- POST `/wallet/interactions/presentation`

By default it runs in **allow-all** mode (no attestation required, no trust checks).

## Run

```bash
go mod tidy
go run . -addr :8098 -allow-all=true
```

Or build:

```bash
go build -o trust-registry .
./trust-registry -addr :8098 -allow-all=true
```

## Env vars

- `TR_ADDR` (default `:8098`)
- `TR_ALLOW_ALL` (default `true`)
- `TR_TLS_CERT` and `TR_TLS_KEY` (optional)

## Admin endpoints (no auth)

Put behind nginx basic auth / firewall.

- GET `/admin/trust` (list)
- PUT `/admin/trust/{did}` body: `{"trusted":true,"reason":"..."}` 
- DELETE `/admin/trust/{did}`

## Next step: on-chain store

Replace `MemoryStore` with an implementation backed by your contract (e.g., `IsTrusted(did)` + `SetTrusted/Revoked` tx).
