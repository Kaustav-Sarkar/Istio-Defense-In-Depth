#!/usr/bin/env bash
set -euo pipefail

echo "Validating Kubernetes manifests with client-side dry run..."
kubectl apply --dry-run=client --validate=false -f deployment/base/
kubectl apply --dry-run=client --validate=false -f deployment/networking/gateway.yaml
kubectl apply --dry-run=client --validate=false -f deployment/networking/virtualservice-bootstrap.yaml
kubectl apply --dry-run=client --validate=false -f deployment/networking/keycloak-virtualservice.yaml
kubectl apply --dry-run=client --validate=false -f deployment/networking/envoyfilter-gateway-prestrip.yaml
kubectl apply --dry-run=client --validate=false -f deployment/data/
kubectl apply --dry-run=client --validate=false -f deployment/identity/
kubectl apply --dry-run=client --validate=false -f deployment/security-services/
kubectl apply --dry-run=client --validate=false -f deployment/security/
kubectl apply --dry-run=client --validate=false -f deployment/apps/

echo "Running Istio config analysis..."
istioctl analyze -A
