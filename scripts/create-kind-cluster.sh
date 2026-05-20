#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

CLUSTER_NAME="istio-security"

if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
    echo "Cluster ${CLUSTER_NAME} already exists. Skipping creation."
else
    echo "Creating kind cluster ${CLUSTER_NAME}..."
    mkdir -p ./data/postgres
    kind create cluster --name "$CLUSTER_NAME" --config kind/cluster.yaml
fi

echo "Applying base namespaces..."
kubectl apply -f deployment/base/namespaces.yaml

echo "Installing Istio..."
istioctl install -f deployment/networking/istio-profile.yaml -y

echo "Generating local TLS certificates..."
./scripts/create-local-certs.sh

echo "Creating TLS secrets in istio-system..."
kubectl create secret tls app-localtest-me-tls -n istio-system \
    --key=".local/certs/app.localtest.me.key" \
    --cert=".local/certs/app.localtest.me.crt" \
    --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret tls idp-localtest-me-tls -n istio-system \
    --key=".local/certs/idp.localtest.me.key" \
    --cert=".local/certs/idp.localtest.me.crt" \
    --dry-run=client -o yaml | kubectl apply -f -

echo "Applying base service accounts..."
kubectl apply -f deployment/base/service-accounts.yaml

echo "Applying Gateway and VirtualService..."
kubectl apply -f deployment/networking/gateway.yaml
kubectl apply -f deployment/networking/virtualservice-bootstrap.yaml

echo "Cluster bootstrap complete. Waiting for ready..."
./scripts/wait-for-ready.sh
