#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

CERT_DIR=".local/certs"

if [[ ! -f "$CERT_DIR/app.localtest.me.crt" ]]; then
    echo "ERROR: Certificates not found. Run ./scripts/create-local-certs.sh first."
    exit 1
fi

cd apps/ui-dashboard

if [[ ! -d "venv" ]]; then
    python3 -m venv venv
fi

source venv/bin/activate
pip install -q -r requirements.txt

# Tell Python requests to trust the mkcert local CA
export REQUESTS_CA_BUNDLE="$(mkcert -CAROOT)/rootCA.pem"

exec streamlit run main.py \
    --server.sslCertFile="../../$CERT_DIR/app.localtest.me.crt" \
    --server.sslKeyFile="../../$CERT_DIR/app.localtest.me.key" \
    --server.port=8501
