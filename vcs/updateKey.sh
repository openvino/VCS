#!/usr/bin/env bash

set -euo pipefail

# Usage:
#   ./scripts/update_vc_rest_key.sh [NEW_KEY]
# Si no pasas un parámetro, usa la última clave registrada.
NEW_KEY="${1:-Vy_LB7mYawUOMDEkAvT2hdIGK1RIlxqVmoky090OLcR1ZpTBrQ}"

SERVER_ENV_PATH="/var/www/VCS/vcs/server.env"
UNIT_FILE_PATH="/etc/systemd/system/vc-rest.service"

echo "Updating VC_REST_DATA_ENCRYPTION_KEY_ID to: ${NEW_KEY}"

sudo sed -i -E "s|^(export VC_REST_DATA_ENCRYPTION_KEY_ID=).*|\1${NEW_KEY}|" "${SERVER_ENV_PATH}"
sudo sed -i -E "s|(Environment=VC_REST_DATA_ENCRYPTION_KEY_ID=).*|\1${NEW_KEY}|" "${UNIT_FILE_PATH}"

sudo systemctl daemon-reload
sudo systemctl restart vc-rest.service

echo "Done. vc-rest service restarted."

