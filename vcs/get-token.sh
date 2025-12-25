#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/var/www/VCS/vcs/cognito-auth-adapter.env"
ADAPTER_URL="${ADAPTER_URL:-http://127.0.0.1:8095/cognito/oauth2/token}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://127.0.0.1:8080/realms/vcs/protocol/openid-connect/token}"

CLIENT_ID="${CLIENT_ID:-rw_token}"

# Defaults (podés overridear por env var)
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
