#!/usr/bin/env bash
set -euo pipefail

CERTS_DIR=".local/certs"
mkdir -p "$CERTS_DIR"

# Ensure mkcert CA is installed (idempotent)
mkcert -install

# Generate certs for all local domains
mkcert -cert-file "$CERTS_DIR/app.localtest.me.crt" \
       -key-file "$CERTS_DIR/app.localtest.me.key" \
       app.localtest.me

mkcert -cert-file "$CERTS_DIR/idp.localtest.me.crt" \
       -key-file "$CERTS_DIR/idp.localtest.me.key" \
       idp.localtest.me

mkcert -cert-file "$CERTS_DIR/portal.localtest.me.crt" \
       -key-file "$CERTS_DIR/portal.localtest.me.key" \
       portal.localtest.me

# If a cluster is running, update the secrets in istio-system
if kubectl get namespace istio-system >/dev/null 2>&1; then
    echo "Updating TLS secrets in istio-system..."
    kubectl create secret tls app-localtest-me-tls -n istio-system \
        --key="$CERTS_DIR/app.localtest.me.key" \
        --cert="$CERTS_DIR/app.localtest.me.crt" \
        --dry-run=client -o yaml | kubectl apply -f -

    kubectl create secret tls idp-localtest-me-tls -n istio-system \
        --key="$CERTS_DIR/idp.localtest.me.key" \
        --cert="$CERTS_DIR/idp.localtest.me.crt" \
        --dry-run=client -o yaml | kubectl apply -f -
fi
