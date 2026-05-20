#!/usr/bin/env bash
set -euo pipefail

echo "Waiting for Istio control plane..."
kubectl wait --for=condition=ready pod -l app=istiod -n istio-system --timeout=120s

echo "Waiting for Istio Ingress Gateway..."
kubectl wait --for=condition=ready pod -l app=istio-ingressgateway -n istio-system --timeout=120s

echo "All base components are ready."
