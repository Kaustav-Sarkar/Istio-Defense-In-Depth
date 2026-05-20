#!/usr/bin/env bash
set -euo pipefail

if [[ ! -d deployment/data ]]; then
  echo "Error: deployment/data/ is missing."
  exit 1
fi

echo "Deploying Platform (Phase 1 & 2)..."

kubectl apply -f deployment/base/namespaces.yaml
kubectl apply -f deployment/base/service-accounts.yaml

kubectl apply -f deployment/networking/gateway.yaml
kubectl apply -f deployment/networking/virtualservice-bootstrap.yaml
kubectl apply -f deployment/networking/keycloak-virtualservice.yaml
kubectl apply -f deployment/networking/envoyfilter-gateway-prestrip.yaml

echo "Creating postgres migrations ConfigMap..."
kubectl create configmap postgres-migrations -n zt-data \
  --from-file=db/migrations/ \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f deployment/data/

echo "Waiting for postgres..."
kubectl wait --for=condition=ready pod -l app=postgres -n zt-data --timeout=120s

echo "Waiting for postgres-migration job..."
kubectl wait --for=condition=complete job/postgres-migration -n zt-data --timeout=120s

kubectl apply -f deployment/identity/

kubectl create configmap cerbos-policies --from-file=cerbos/policies/ -n zt-security --dry-run=client -o yaml | kubectl apply -f -
kubectl create configmap cerbos-tests --from-file=test_suite_test.yaml=cerbos/tests/test_suite_test.yaml -n zt-security --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deployment/security-services/
kubectl apply -f deployment/security/

echo "Waiting for core services..."
kubectl wait --for=condition=ready pod -l app=keycloak -n zt-identity --timeout=120s
kubectl wait --for=condition=ready pod -l app=vault -n zt-security --timeout=120s
kubectl wait --for=condition=ready pod -l app=cerbos -n zt-security --timeout=120s

echo "Waiting for vault-bootstrap job..."
kubectl wait --for=condition=complete job/vault-bootstrap -n zt-security --timeout=120s

kubectl apply -f deployment/security/

kubectl apply -f deployment/apps/

echo "Platform deployed successfully."
